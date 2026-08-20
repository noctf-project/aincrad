use std::net::IpAddr;

use chrono::{DateTime, Utc};
use tracing::info;

pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;
pub mod proto_capnp {
    include!(concat!(env!("OUT_DIR"), "/proto_capnp.rs"));
}

#[derive(Clone)]
pub struct Session {
    pub uid: Vec<u8>,
    pub addr: IpAddr,
    pub timestamp: DateTime<Utc>,
}
