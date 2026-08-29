#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Kube(#[from] kube::Error),

    #[error("{0}")]
    KubeCommon(#[from] k8s_common::Error),

    #[error("Route allocation error: {0}")]
    RouteAllocationError(#[from] crate::routing::RouteError),

    #[error("Lease manager error: {0}")]
    LeaseManager(#[from] kube_lease_manager::LeaseManagerError),

    #[error("Template \"{0}\" not found")]
    TemplateNotFound(String),

    #[error("{0}")]
    InvalidOverride(String),

    #[error("{0}")]
    TemplateBuildError(String),

    #[error("Failed to apply {kind} \"{name}\": {source}")]
    ApplyResource {
        kind: &'static str,
        name: String,
        #[source]
        source: Box<kube::Error>,
    },

    #[error("Status reconciliation failed for {kind}: {source}")]
    StatusReconciliationError {
        kind: String,
        #[source]
        source: Box<Error>,
    },

    #[error("{0}")]
    Custom(String),
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Custom(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Custom(s.to_string())
    }
}
