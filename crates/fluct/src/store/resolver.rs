use moka::{Expiry, future::Cache};
use rand::{Rng, RngExt, rngs::SmallRng};
use std::{
    borrow::Cow,
    cell::{Cell, RefCell},
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use tokio::net::lookup_host;
use tracing::debug;

thread_local! {
    // Each OS thread lazily initializes its own instance with fresh OS entropy
    static RNG: RefCell<SmallRng> = RefCell::new(rand::make_rng());
}

pub struct ResolverExpiryPolicy {
    pub negative_ttl: Duration,
    pub positive_ttl: Duration,
}

impl Default for ResolverExpiryPolicy {
    fn default() -> Self {
        Self {
            negative_ttl: Duration::from_secs(3),
            positive_ttl: Duration::from_secs(5),
        }
    }
}

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverError {
    #[error("invalid hostname format")]
    InvalidHostname,

    #[error("invalid port number")]
    InvalidPort,

    #[error("empty input")]
    EmptyInput,

    #[error("dns resolution failed")]
    DnsResolutionFailed,
}

impl Expiry<String, Result<Vec<IpAddr>, ResolverError>> for ResolverExpiryPolicy {
    fn expire_after_create(
        &self,
        _key: &String,
        value: &Result<Vec<IpAddr>, ResolverError>,
        _created_at: Instant,
    ) -> Option<Duration> {
        match value {
            // Dynamic positive TTL clamped within safe bounds
            Ok(_) => Some(self.positive_ttl),
            Err(_) => Some(self.negative_ttl),
        }
    }
}

fn normalize_host_strict(host: &str) -> Result<Cow<'_, str>, ResolverError> {
    let host = host.strip_suffix('.').unwrap_or(host);

    if host.contains(':') {
        return Err(ResolverError::InvalidHostname);
    }

    if host.is_empty() || host.starts_with('.') || host.ends_with('.') || host.contains("..") {
        return Err(ResolverError::InvalidHostname);
    }
    if host.bytes().any(|b| b.is_ascii_uppercase()) {
        Ok(Cow::Owned(host.to_ascii_lowercase()))
    } else {
        Ok(Cow::Borrowed(host))
    }
}

#[derive(Clone)]
pub struct Resolver {
    cache: Cache<String, Result<Vec<IpAddr>, ResolverError>>,
}

impl Resolver {
    pub fn new(size: usize, expiry: ResolverExpiryPolicy) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(size as u64)
                .expire_after(expiry)
                .build(),
        }
    }

    pub async fn resolve(&self, target: &str) -> Result<SocketAddr, ResolverError> {
        let target = target.trim();
        if target.is_empty() {
            return Err(ResolverError::EmptyInput);
        }
        if let Ok(addr) = target.parse::<SocketAddr>() {
            return Ok(addr);
        }
        let (host, port) = target.rsplit_once(':').ok_or(ResolverError::InvalidPort)?;
        let port: u16 = port.parse().map_err(|_| ResolverError::InvalidPort)?;

        let host = normalize_host_strict(host)?;
        let result = if let Some(cached_res) = self.cache.get(host.as_ref()).await {
            cached_res
        } else {
            let host_key = host.into_owned();
            self.cache
                .get_with(host_key.clone(), async {
                    let stream = match lookup_host((host_key.as_str(), 0)).await {
                        Ok(s) => s,
                        Err(e) => {
                            debug!("error resolving dns: {}", e);
                            return Err(ResolverError::DnsResolutionFailed);
                        }
                    };

                    let mut ips: Vec<IpAddr> = stream.map(|addr| addr.ip()).collect();
                    if ips.is_empty() {
                        return Err(ResolverError::DnsResolutionFailed);
                    }
                    ips.dedup();
                    Ok(ips)
                })
                .await
        }?;

        let selected = match result.as_slice() {
            [single] => *single,
            multiple => RNG.with(|rng| {
                let mut rng = rng.borrow_mut();
                multiple[rng.random_range(0..multiple.len())]
            }),
        };
        Ok(SocketAddr::new(selected, port))
    }
}
