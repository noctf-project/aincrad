mod port_finder;
pub mod port_map;
pub mod tls;

pub use port_map::{Port, PortCandidate, PortError, PortMap};
pub use tls::{derive_hostname, format_tls_host, sanitize_prefix};

use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum RouteError {
    #[error(transparent)]
    Port(#[from] PortError),
    #[error("route must specify either tcp or tls configuration")]
    MissingTarget,
}
