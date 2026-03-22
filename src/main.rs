use std::{env, sync::Arc};

use anyhow::Context;
use futures::StreamExt;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::{
    Api,
    runtime::{Controller, WatchStreamExt, metadata_watcher, watcher},
};
use tokio::{
    signal::unix::{SignalKind, signal},
    task::JoinSet,
};
use tracing::{error, info, level_filters::LevelFilter};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use operator::{CfdTunnel, WatchNamespace};

#[cfg(debug_assertions)]
const DEFAULT_OPERATOR_NAME: &str = "cfd-dev-operator";
#[cfg(not(debug_assertions))]
const DEFAULT_OPERATOR_NAME: &str = "cfd-operator";
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::filter::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let operator_name = env::var("OPERATOR_NAME").unwrap_or(DEFAULT_OPERATOR_NAME.to_string());
    let operator_namespace = env::var("OPERATOR_NAMESPACE")
        .expect("OPERATOR_NAMESPACE must be set to the namespace the operator is running in.");
    let watch_namespaces = env::var("WATCH_NAMESPACE")
        .map(|env| {
            env.split(",")
                .map(|namespace| WatchNamespace::Only(namespace.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or(vec![WatchNamespace::All]);
    assert_ne!(
        watch_namespaces.len(),
        0,
        "At least one namespace must be specified in WATCH_NAMESPACE if it is provided"
    );

    let mut join_set = JoinSet::new();

    let k8s_client = kube::Client::try_default()
        .await
        .context("KUBECONFIG not valid or missing")?;
    let use_streaming_lists = {
        let k8s_version = k8s_client
            .apiserver_version()
            .await
            .context("Failed to get k8s api server version")?;
        let (major, minor): (usize, usize) = (
            k8s_version.major.parse().expect("major"),
            k8s_version.minor.parse().expect("minor"),
        );
        major >= 1 && minor >= 33
    };

    for watch_namespace in watch_namespaces {
        let crd_watch_api: Api<CfdTunnel> = watch_namespace.watch_api(k8s_client.clone());
        let endpointslice_watch_api: Api<EndpointSlice> =
            watch_namespace.watch_api(k8s_client.clone());

        let ctx = Arc::new(operator::Context {
            name: operator_name.clone(),
            namespace: operator_namespace.clone(),
            watch_namespace: watch_namespace.clone(),
            k8s_client: k8s_client.clone(),
            crd_watch_api: crd_watch_api.clone(),
            endpointslice_watch_api: endpointslice_watch_api.clone(),
        });

        let mut watcher_config = watcher::Config::default();
        if use_streaming_lists {
            watcher_config = watcher_config.streaming_lists();
        }

        let endpointslice_metadata_stream =
            metadata_watcher(endpointslice_watch_api.clone(), watcher_config.clone())
                .default_backoff()
                .touched_objects();

        let controller = Controller::new(crd_watch_api.clone(), watcher_config.clone());
        let crd_reader = controller.store();

        let mut int_sig = signal(SignalKind::interrupt())?;
        let mut term_sig = signal(SignalKind::terminate())?;

        let controller_stream = controller
            .watches_stream(endpointslice_metadata_stream, move |partial_object_meta| {
                operator::map_endpointslice_to_crd_ref(&crd_reader, &partial_object_meta)
            })
            .graceful_shutdown_on(async move {
                int_sig.recv().await;
            })
            .graceful_shutdown_on(async move {
                term_sig.recv().await;
            })
            .run(operator::run_once, operator::error_policy, ctx);

        join_set.spawn(async move {
            controller_stream
                .for_each(|msg| {
                    match msg {
                        Err(error) => {
                            error!(error = error.to_string(), "reconciliation failed");
                        }
                        Ok((tunnel, action)) => {
                            info!(
                                tunnel = format!("{tunnel:?}"),
                                action = format!("{action:?}"),
                                "object reconciled"
                            );
                        }
                    };

                    futures::future::ready(())
                })
                .await;
        });
    }

    join_set.join_all().await;

    Ok(())
}
