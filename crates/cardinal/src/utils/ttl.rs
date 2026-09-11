use chrono::{DateTime, Duration as ChronoDuration, Utc};
use k8s_common::crd::Instance;
use std::time::Duration;

/// Extracts and parses the expiry date from a Instance.
pub fn parse_expires_at(instance: &Instance) -> Option<DateTime<Utc>> {
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

/// Parses duration strings like `"20m"`, `"1h"`, `"45s"`, or raw integer seconds `"1200"`.
pub fn parse_duration(input: &str) -> Result<Duration, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("duration string is empty".to_string());
    }

    // Try parsing as integer seconds directly
    if let Ok(secs) = input.parse::<u64>() {
        return Ok(Duration::from_secs(secs));
    }

    let (num_part, unit) = input
        .find(|c: char| !c.is_ascii_digit())
        .map(|idx| input.split_at(idx))
        .ok_or_else(|| "missing duration unit (e.g. 's', 'm', 'h')".to_string())?;

    let num: u64 = num_part
        .trim()
        .parse()
        .map_err(|e| format!("invalid number in duration: {e}"))?;

    let multiplier = match unit.trim().to_ascii_lowercase().as_str() {
        "s" | "sec" | "secs" | "seconds" => 1,
        "m" | "min" | "mins" | "minutes" => 60,
        "h" | "hr" | "hrs" | "hours" => 3600,
        "d" | "day" | "days" => 86400,
        other => return Err(format!("unknown duration unit '{other}'")),
    };

    Ok(Duration::from_secs(num * multiplier))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("1200").unwrap(), Duration::from_secs(1200));
        assert_eq!(parse_duration("45s").unwrap(), Duration::from_secs(45));
        assert_eq!(parse_duration("20m").unwrap(), Duration::from_secs(1200));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("2d").unwrap(), Duration::from_secs(172800));
        assert_eq!(
            parse_duration(" 15 min ").unwrap(),
            Duration::from_secs(900)
        );

        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("20x").is_err());
    }
}
