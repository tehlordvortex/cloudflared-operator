use std::{env, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use futures::{FutureExt, StreamExt, TryStreamExt};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::{
    Api,
    api::ObjectMeta,
    runtime::{
        Controller, Predicate, WatchStreamExt, controller, metadata_watcher, predicates,
        reflector::{self, Lookup},
        watcher,
    },
};
use metrics_exporter_prometheus::PrometheusBuilder;
use tokio::{
    signal::unix::{SignalKind, signal},
    time::interval,
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, trace, warn};

use operator::CfdTunnel;

#[cfg(debug_assertions)]
const DEFAULT_OPERATOR_NAME: &str = "cfd-dev-operator";
#[cfg(not(debug_assertions))]
const DEFAULT_OPERATOR_NAME: &str = "cfd-operator";
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let operator_namespace = env::var("OPERATOR_NAMESPACE")
        .expect("OPERATOR_NAMESPACE must be set to the namespace the operator is running in.");
    let operator_name = env::var("OPERATOR_NAME").unwrap_or(DEFAULT_OPERATOR_NAME.to_string());
    let _otel_guard = operator::tracing::init_subscriber(&operator_name, &operator_namespace);

    let metrics_addr = env::var("METRICS_ADDR")
        .unwrap_or("0.0.0.0:9000".into())
        .parse::<SocketAddr>()?;

    PrometheusBuilder::new()
        .with_http_listener(metrics_addr)
        .install()?;

    let process_collector = metrics_process::Collector::default();
    process_collector.describe();
    operator::metrics::describe();

    let watch_namespaces = env::var("WATCH_NAMESPACE")
        .map(|env| {
            env.split(",")
                .map(|namespace| namespace.to_string())
                .collect::<Vec<_>>()
        })
        // .unwrap_or(vec![WatchNamespace::All]);
        .unwrap_or(vec![]);

    let dry_run = env::var("DRY_RUN")
        .unwrap_or("false".to_string())
        .to_lowercase()
        .parse::<bool>()?;

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

    let cancel_token = CancellationToken::new();
    let process_metrics = {
        let cancel_token = cancel_token.clone();
        async move {
            let mut interval = interval(Duration::from_secs(15));
            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => break,
                    _ = interval.tick() => {
                        process_collector.collect();
                    }
                }
            }
        }
    };

    let mut watcher_config = watcher::Config::default();
    if use_streaming_lists {
        watcher_config = watcher_config.streaming_lists();
    }

    let crd_watch_api: Api<CfdTunnel> = Api::all(k8s_client.clone());
    let (crd_reader, crd_writer) = reflector::store();
    let match_namespace = {
        let watch_namespaces = watch_namespaces.clone();
        move |metadata: &ObjectMeta| {
            watch_namespaces.is_empty()
                || watch_namespaces.iter().any(|watch_namespace| {
                    watch_namespace == metadata.namespace.as_ref().expect("namespaced")
                })
        }
    };
    let match_operator_name = {
        let operator_name = operator_name.clone();
        move |metadata: &ObjectMeta| {
            metadata
                .labels
                .as_ref()
                .and_then(|labels| {
                    labels
                        .get("cfd-operator.vrtx.sh/operator-name")
                        .map(|name| name == &operator_name)
                })
                .unwrap_or(true)
        }
    };

    let crd_stream = watcher(crd_watch_api, watcher_config.clone())
        .default_backoff()
        .try_filter_map({
            let operator_name = operator_name.clone();
            let match_namespace = match_namespace.clone();
            let match_operator_name = match_operator_name.clone();
            move |event| {
                futures::future::ready(Ok(match event {
                    watcher::Event::InitApply(ref tunnel)
                        if !(match_namespace(&tunnel.metadata)
                            && match_operator_name(&tunnel.metadata)) =>
                    {
                        trace!(
                            operator_name,
                            ?event,
                            kind = %CfdTunnel::kind(&()),
                            "drop event, filters did not match"
                        );
                        None
                    }
                    watcher::Event::Apply(tunnel)
                        if !(match_namespace(&tunnel.metadata)
                            && match_operator_name(&tunnel.metadata)) =>
                    {
                        let event = watcher::Event::Delete(tunnel);
                        trace!(
                            operator_name,
                            ?event,
                            kind = %CfdTunnel::kind(&()),
                            "filters no longer match, convert to delete event"
                        );
                        Some(event)
                    }
                    _ => Some(event),
                }))
            }
        })
        .reflect(crd_writer)
        .applied_objects()
        .predicate_filter(
            Predicate::combine(predicates::generation, predicates::finalizers),
            Default::default(),
        );

    let endpointslice_watch_api: Api<EndpointSlice> = Api::all(k8s_client.clone());

    let endpointslice_metadata_stream =
        metadata_watcher(endpointslice_watch_api, watcher_config.clone())
            .default_backoff()
            .try_filter_map({
                let operator_name = operator_name.clone();
                move |event| {
                    futures::future::ready(Ok(match event {
                        watcher::Event::InitApply(ref endpointslice)
                            if !match_namespace(&endpointslice.metadata) =>
                        {
                            trace!(
                                operator_name,
                                ?event,
                                kind = %EndpointSlice::kind(&()),
                                "drop event, filters did not match"
                            );
                            None
                        }
                        watcher::Event::Apply(endpointslice)
                            if !match_namespace(&endpointslice.metadata) =>
                        {
                            let event = watcher::Event::Delete(endpointslice);
                            trace!(
                                operator_name,
                                ?event,
                                kind = %EndpointSlice::kind(&()),
                                "filters no longer match, convert to delete event"
                            );
                            Some(event)
                        }
                        _ => Some(event),
                    }))
                }
            })
            .touched_objects()
            .predicate_filter(predicates::generation, Default::default());

    let mut int_sig = signal(SignalKind::interrupt())?;
    let mut term_sig = signal(SignalKind::terminate())?;
    let ctx = Arc::new(operator::Context {
        name: operator_name.clone(),
        namespace: operator_namespace.clone(),
        dry_run,
        k8s_client,
    });
    let controller = Controller::for_stream(crd_stream, crd_reader.clone())
        .watches_stream(endpointslice_metadata_stream, move |partial_object_meta| {
            operator::map_endpointslice_to_crd_ref(&crd_reader, &partial_object_meta)
        })
        .graceful_shutdown_on(async move {
            int_sig.recv().await;
        })
        .graceful_shutdown_on(async move {
            term_sig.recv().await;
        })
        .run(operator::run_once, operator::error_policy, ctx.clone())
        .for_each(|msg| {
            match msg {
                Err(controller::Error::ReconcilerFailed(error, object_ref)) => {
                    error!(operator_name, %error, %object_ref, "reconciliation failed");
                }
                Err(error) => {
                    warn!(operator_name, %error, "unexpected error");
                }
                Ok((tunnel, action)) => {
                    info!(operator_name, ?tunnel, ?action, "object reconciled");
                }
            };

            futures::future::ready(())
        })
        .map(|result| {
            cancel_token.cancel();
            result
        });

    info!(
        name = operator_name,
        namespace = operator_namespace,
        watch_namespaces = ?watch_namespaces,
        use_streaming_lists,
        "running, metrics: {metrics_addr}"
    );

    futures::join!(process_metrics, controller);

    Ok(())
}
