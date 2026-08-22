use std::{net::IpAddr, ops::RangeInclusive};

use chrono::{DateTime, Utc};

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

