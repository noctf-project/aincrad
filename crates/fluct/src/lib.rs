use std::net::IpAddr;

use chrono::{DateTime, Utc};

pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Clone)]
pub struct Session {
    pub uid: Vec<u8>,
    pub addr: IpAddr,
    pub timestamp: DateTime<Utc>,
}
