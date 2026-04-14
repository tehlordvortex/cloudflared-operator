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
