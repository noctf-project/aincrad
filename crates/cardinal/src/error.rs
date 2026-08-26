#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),

    #[error("Kubernetes common error: {0}")]
    KubeCommon(#[from] k8s_common::Error),

    #[error("Template resolution error: {0}")]
    TemplateNotFound(String),

    #[error("Template build error: {0}")]
    TemplateBuildError(String),

    #[error("Template generation shifted for instance {instance_name}: target_gen {target_gen}")]
    TemplateGenShifted {
        instance_name: String,
        target_gen: String,
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
