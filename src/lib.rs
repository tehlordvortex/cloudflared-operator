pub mod controller;
mod ext_cr;
pub use controller::*;

use std::fmt::Debug;

use cloudflare::framework::response::ApiFailure;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("resource not found: {0}")]
    ResourceNotFound(#[source] kube::Error),
    #[error("get resource failed: {0}")]
    Get(#[source] kube::Error),
    #[error("list resource failed: {0}")]
    List(#[source] kube::Error),
    #[error("patch resource failed: {0}")]
    Patch(#[source] kube::Error),
    #[error("delete resource(s) failed: {0}")]
    Delete(#[source] kube::Error),
    #[error("cloudflare tunnel request failed: {0}")]
    CfTunnel(ApiFailure),
    #[error("cloudflare error: {0}")]
    CfError(cloudflare::framework::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
pub type Result<T, E = Error> = std::result::Result<T, E>;

pub mod metrics {
    use metrics::{Unit, describe_counter, describe_histogram};

    pub fn describe() {
        describe_counter!(
            "cfdtunnel_controller_reconciliations_total",
            Unit::Count,
            "reconciliation attempts"
        );
        describe_counter!(
            "cfdtunnel_controller_reconciliation_errors_total",
            Unit::Count,
            "failed reconciliation attempts"
        );
        describe_counter!(
            "cfdtunnel_controller_cloudflare_errors_total",
            Unit::Count,
            "cloudflare errors encountered during reconciliation"
        );
        describe_histogram!(
            "cfdtunnel_controller_reconciliation_duration_seconds",
            Unit::Seconds,
            "time spent in reconciliation"
        );
    }
}

mod otel {
    use opentelemetry::KeyValue;
    use opentelemetry_sdk::{
        Resource,
        trace::{RandomIdGenerator, Sampler, SdkTracerProvider},
    };
    use opentelemetry_semantic_conventions::{
        SCHEMA_URL,
        attribute::{DEPLOYMENT_ENVIRONMENT_NAME, SERVICE_VERSION},
    };

    pub struct OtelGuard {
        pub tracer_provider: SdkTracerProvider,
    }

    impl Drop for OtelGuard {
        fn drop(&mut self) {
            if let Err(err) = self.tracer_provider.shutdown() {
                eprintln!("{err:?}");
            }
        }
    }

    #[cfg(debug_assertions)]
    const ENVIRONMENT: &str = "development";
    #[cfg(not(debug_assertions))]
    const ENVIRONMENT: &str = "production";

    fn resource(name: &str, namespace: &str) -> Resource {
        Resource::builder()
            .with_service_name(env!("CARGO_PKG_NAME"))
            .with_schema_url(
                [
                    KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
                    KeyValue::new(DEPLOYMENT_ENVIRONMENT_NAME, ENVIRONMENT),
                    KeyValue::new("operator.name", name.to_string()),
                    KeyValue::new("operator.namespace", namespace.to_string()),
                ],
                SCHEMA_URL,
            )
            .build()
    }

    pub fn init_tracer_provider(name: &str, namespace: &str) -> SdkTracerProvider {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .build()
            .unwrap();

        SdkTracerProvider::builder()
            .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
                1.0,
            ))))
            .with_id_generator(RandomIdGenerator::default())
            .with_resource(resource(name, namespace))
            .with_batch_exporter(exporter)
            .build()
    }
}

pub mod tracing {
    use opentelemetry::{global, trace::TracerProvider};
    use std::env;
    use tracing::level_filters::LevelFilter;
    use tracing_opentelemetry::OpenTelemetryLayer;
    use tracing_subscriber::{EnvFilter, Layer, layer::SubscriberExt, util::SubscriberInitExt};

    use crate::otel;

    pub fn init_subscriber(name: &str, namespace: &str) -> otel::OtelGuard {
        let tracer_provider = otel::init_tracer_provider(name, namespace);
        global::set_tracer_provider(tracer_provider.clone());
        let tracer = tracer_provider.tracer("cloudflared-operator");

        let fmt_filter = EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .from_env_lossy();
        let otel_filter = EnvFilter::builder().parse_lossy(
            env::var("OTEL_TRACES_FILTER")
                .unwrap_or("operator=trace,kube_runtime=trace,kube_client=trace".into()),
        );

        tracing_subscriber::registry()
            .with(fmt_filter)
            .with(tracing_subscriber::fmt::layer())
            .with(OpenTelemetryLayer::new(tracer).with_filter(otel_filter))
            .init();

        otel::OtelGuard { tracer_provider }
    }
}
