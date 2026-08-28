#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Kube(#[from] kube::Error),

    #[error("{0}")]
    KubeCommon(#[from] k8s_common::Error),

    #[error("Lease manager error: {0}")]
    LeaseManager(#[from] kube_lease_manager::LeaseManagerError),

    #[error("Template \"{0}\" not found")]
    TemplateNotFound(String),

    #[error("{0}")]
    TemplateBuildError(String),

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
