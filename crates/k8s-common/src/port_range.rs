use std::ops::RangeInclusive;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PortRange(pub RangeInclusive<u16>);

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        self.0.contains(&port)
    }

    pub fn overlaps(&self, other: &PortRange) -> bool {
        self.0.start() <= other.0.end() && other.0.start() <= self.0.end()
    }
}

/// Parses a single port (e.g. "8080") or a range (e.g. "20000-29999").
pub fn parse_port_range(s: &str) -> Result<PortRange, String> {
    let s = s.trim();
    if let Some((start_str, end_str)) = s.split_once('-') {
        let start: u16 = start_str
            .trim()
            .parse()
            .map_err(|_| format!("invalid min port '{start_str}' in range '{s}'"))?;
        let end: u16 = end_str
            .trim()
            .parse()
            .map_err(|_| format!("invalid max port '{end_str}' in range '{s}'"))?;

        if start > end {
            return Err(format!(
                "min port {start} cannot be greater than max port {end}"
            ));
        }

        Ok(PortRange(start..=end))
    } else {
        let port: u16 = s
            .parse()
            .map_err(|_| format!("invalid port or port range '{s}'"))?;
        Ok(PortRange(port..=port))
    }
}

/// Parses comma-separated port ranges (e.g. "20000-24999,26000-29999,8080").
pub fn parse_port_ranges(s: &str) -> Result<Vec<PortRange>, String> {
    s.split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(parse_port_range)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_port_range_valid() {
        let range = parse_port_range("20000-29999").unwrap();
        assert_eq!(range, PortRange(20000..=29999));
        assert!(range.contains(20000));
        assert!(range.contains(25000));
        assert!(range.contains(29999));
        assert!(!range.contains(19999));
        assert!(!range.contains(30000));
    }

    #[test]
    fn test_parse_port_range_single_port() {
        let range = parse_port_range("8080-8080").unwrap();
        assert_eq!(range, PortRange(8080..=8080));
        assert!(range.contains(8080));
        assert!(!range.contains(8081));

        let single = parse_port_range("8080").unwrap();
        assert_eq!(single, PortRange(8080..=8080));
        assert!(single.contains(8080));
        assert!(!single.contains(8081));
    }

    #[test]
    fn test_parse_port_ranges_multiple() {
        let ranges = parse_port_ranges("1000-2000, 3000-4000, 8080").unwrap();
        assert_eq!(
            ranges,
            vec![
                PortRange(1000..=2000),
                PortRange(3000..=4000),
                PortRange(8080..=8080),
            ]
        );
    }

    #[test]
    fn test_parse_port_range_invalid_format() {
        assert!(parse_port_range("abc").is_err());
        assert!(parse_port_range("abc-def").is_err());
        assert!(parse_port_range("30000-20000").is_err());
    }

    #[test]
    fn test_port_range_overlaps() {
        let r1 = PortRange(10000..=20000);
        let r2 = PortRange(15000..=25000);
        let r3 = PortRange(20001..=30000);

        assert!(r1.overlaps(&r2));
        assert!(r2.overlaps(&r1));
        assert!(!r1.overlaps(&r3));
        assert!(!r3.overlaps(&r1));
    }
}
