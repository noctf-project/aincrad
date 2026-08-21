use std::ops::RangeInclusive;
use std::path::PathBuf;

use addr::parse_domain_name;
use clap::Parser;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::{services::routes::RoutesService, store::secrets::SecretsStore};

pub struct ServiceContext {
    pub config: ServiceConfig,
    pub routes_service: RoutesService,
    pub secrets_store: SecretsStore,
    pub shutdown: CancellationToken,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange(pub RangeInclusive<u16>);

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        self.0.contains(&port)
    }

    pub fn overlaps(&self, other: &PortRange) -> bool {
        self.0.start() <= other.0.end() && other.0.start() <= self.0.end()
    }
}

fn parse_port_range(s: &str) -> Result<PortRange, String> {
    let (start_str, end_str) = s.split_once('-').ok_or_else(|| {
        format!("invalid port range '{s}', expected format 'MIN-MAX' (e.g. 20000-29999)")
    })?;

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
}

#[derive(Clone, Serialize, Deserialize, Parser)]
pub struct ServiceConfig {
    /// Host to listen on
    #[clap(long, default_value = "[::]")]
    pub host: String,

    /// Root secret name
    #[clap(long, default_value = "aincrad-roots")]
    pub secret_root: String,

    /// HTTP listening port for Kubernetes webhooks and stats
    #[clap(long, default_value = "8000")]
    pub http_port: u16,

    /// Listening port for TLS challenges
    #[clap(long, default_value = "4433")]
    pub tls_port: u16,

    /// Reserved port range for fixed port requests (e.g. 20000-29999)
    #[clap(long, default_value = "20000-29999", value_parser = parse_port_range)]
    pub reserved_ports: PortRange,

    /// Auto port range for dynamic port allocation (e.g. 30000-32767)
    #[clap(long, default_value = "30000-32767", value_parser = parse_port_range)]
    pub auto_ports: PortRange,

    /// Public Key File
    #[arg(long)]
    pub tls_cert: PathBuf,

    /// Private Key File
    #[arg(long)]
    pub tls_key: PathBuf,

    /// Optional Hostname Suffix
    #[clap(long, default_value = "", value_parser = parse_hostname_suffix)]
    pub hostname_suffix: String,

    /// CTF flag prefix
    #[clap(long, default_value = "CTF")]
    pub flag_prefix: String,

    /// Logs Directory
    #[clap(long, default_value = "./data/")]
    pub logs_dir: String,
}

impl ServiceConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.http_port == self.tls_port {
            return Err(format!(
                "http-port ({}) cannot be the same as tls-port ({})",
                self.http_port, self.tls_port
            ));
        }
        if self.reserved_ports.contains(self.tls_port) {
            return Err(format!(
                "tls-port ({}) overlaps with reserved-ports ({:?})",
                self.tls_port, self.reserved_ports.0
            ));
        }
        if self.auto_ports.contains(self.tls_port) {
            return Err(format!(
                "tls-port ({}) overlaps with auto-ports ({:?})",
                self.tls_port, self.auto_ports.0
            ));
        }
        if self.reserved_ports.contains(self.http_port) {
            return Err(format!(
                "http-port ({}) overlaps with reserved-ports ({:?})",
                self.http_port, self.reserved_ports.0
            ));
        }
        if self.auto_ports.contains(self.http_port) {
            return Err(format!(
                "http-port ({}) overlaps with auto-ports ({:?})",
                self.http_port, self.auto_ports.0
            ));
        }
        if self.reserved_ports.overlaps(&self.auto_ports) {
            return Err(format!(
                "reserved-ports ({:?}) and auto-ports ({:?}) overlap",
                self.reserved_ports.0, self.auto_ports.0
            ));
        }
        Ok(())
    }
}

fn parse_hostname_suffix(s: &str) -> Result<String, String> {
    if s.is_empty() {
        return Ok("".to_string());
    }
    let domain = parse_domain_name(s).map_err(|e| format!("invalid domain name '{s}': {e}"))?;
    Ok(domain.as_str().trim_matches('.').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_config_parsing() {
        let args = [
            "fluct",
            "--tls-cert",
            "cert.pem",
            "--tls-key",
            "key.pem",
            "--hostname-suffix",
            "example.com",
            "--http-port",
            "9000",
            "--reserved-ports",
            "10000-19999",
            "--auto-ports",
            "20000-29999",
        ];
        let cfg = ServiceConfig::try_parse_from(args).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.tls_cert, PathBuf::from("cert.pem"));
        assert_eq!(cfg.tls_key, PathBuf::from("key.pem"));
        assert_eq!(cfg.hostname_suffix, "example.com".to_string());
        assert_eq!(cfg.http_port, 9000);
        assert_eq!(cfg.flag_prefix, "CTF");
        assert_eq!(cfg.reserved_ports, PortRange(10000..=19999));
        assert_eq!(cfg.auto_ports, PortRange(20000..=29999));
    }

    #[test]
    fn test_service_config_validation_overlap() {
        let args = [
            "fluct",
            "--tls-cert",
            "cert.pem",
            "--tls-key",
            "key.pem",
            "--reserved-ports",
            "20000-30000",
            "--auto-ports",
            "25000-35000",
        ];
        let cfg = ServiceConfig::try_parse_from(args).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_parse_hostname_suffix() {
        assert_eq!(parse_hostname_suffix(""), Ok("".to_string()));
        assert_eq!(
            parse_hostname_suffix("example.com"),
            Ok("example.com".to_string())
        );
        assert!(parse_hostname_suffix("example.com.").unwrap() == "example.com");
        assert!(parse_hostname_suffix("invalid..domain").is_err());
    }
}
