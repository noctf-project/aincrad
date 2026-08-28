#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Kubernetes error: {0}")]
    Kube(#[from] kube::Error),
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
