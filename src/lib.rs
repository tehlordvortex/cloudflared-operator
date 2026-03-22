pub mod controller;
use std::fmt::Debug;

use cloudflare::framework::response::ApiFailure;
pub use controller::*;
use metrics::{Unit, describe_counter, describe_histogram};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("resource not found: {0}")]
    ResourceNotFound(#[source] kube::Error),
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

#[derive(Debug, Clone, PartialEq)]
pub enum WatchNamespace {
    All,
    Only(String),
}

impl WatchNamespace {
    pub fn watch_api<K>(&self, client: kube::Client) -> kube::Api<K>
    where
        K: kube::Resource<Scope = k8s_openapi::NamespaceResourceScope>,
        <K as kube::Resource>::DynamicType: std::default::Default,
    {
        match self {
            WatchNamespace::Only(namespace) => kube::Api::namespaced(client, namespace),
            WatchNamespace::All => kube::Api::all(client),
        }
    }
}

pub fn describe_metrics() {
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
