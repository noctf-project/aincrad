use chrono::{DateTime, Duration as ChronoDuration, Utc};
use std::time::Duration;

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
