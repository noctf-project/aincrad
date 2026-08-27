use chrono::{DateTime, Duration as ChronoDuration, Utc};
use k8s_common::crd::CTFInstance;
use std::time::Duration;

/// Extracts and parses the expiry date from a CTFInstance.
pub fn parse_expires_at(instance: &CTFInstance) -> Option<DateTime<Utc>> {
    instance
        .metadata
        .annotations
        .as_ref()?
        .get(k8s_common::labels::EXPIRES_AT_ANNOTATION)?
        .parse::<DateTime<Utc>>()
        .ok()
}

/// Calculates remaining TTL duration until expiration, returning None if expired or not set.
pub fn calculate_remaining_ttl(expires_at: Option<DateTime<Utc>>) -> Option<Duration> {
    let expires_at = expires_at?;
    let remaining = expires_at - Utc::now();
    if remaining > ChronoDuration::zero() {
        remaining.to_std().ok()
    } else {
        None
    }
}

/// Checks whether an instance has expired.
pub fn is_expired(expires_at: Option<DateTime<Utc>>) -> bool {
    if let Some(expires_at) = expires_at {
        Utc::now() >= expires_at
    } else {
        false
    }
}
