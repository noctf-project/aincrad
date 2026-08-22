use std::ops::RangeInclusive;
use std::path::PathBuf;

use addr::parse_domain_name;
use clap::Parser;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use fluct::Error;

use crate::{services::routes::RoutesService, store::secrets::SecretsStore};

pub fn parse_config() -> Result<ServiceConfig, Error> {
    let raw = RawServiceConfig::parse();
    raw.into_validated()
}

#[cfg(test)]
pub fn parse_config_from<I, T>(itr: I) -> Result<ServiceConfig, Error>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let raw = RawServiceConfig::try_parse_from(itr)?;
    raw.into_validated()
}

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

/// Private CLI argument parser
#[derive(Clone, Debug, Serialize, Deserialize, Parser)]
struct RawServiceConfig {
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

    #[clap(long)]
    pub dnat_port: Option<u16>,

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

impl RawServiceConfig {
    fn into_validated(self) -> Result<ServiceConfig, Error> {
        let config = ServiceConfig {
            host: self.host,
            secret_root: self.secret_root,
            http_port: self.http_port,
            tls_port: self.tls_port,
            reserved_ports: self.reserved_ports,
            auto_ports: self.auto_ports,
            dnat_port: self.dnat_port,
            tls_cert: self.tls_cert,
            tls_key: self.tls_key,
            hostname_suffix: self.hostname_suffix,
            flag_prefix: self.flag_prefix,
            logs_dir: self.logs_dir,
        };
        config.validate()?;
        Ok(config)
    }
}

/// Public validated configuration struct
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub host: String,
    pub secret_root: String,
    pub http_port: u16,
    pub tls_port: u16,
    pub reserved_ports: PortRange,
    pub auto_ports: PortRange,
    pub dnat_port: Option<u16>,
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
    pub hostname_suffix: String,
    pub flag_prefix: String,
    pub logs_dir: String,
}

impl ServiceConfig {
    fn validate(&self) -> Result<(), String> {
        let mut single_ports = vec![("http-port", self.http_port), ("tls-port", self.tls_port)];
        if let Some(port) = self.dnat_port {
            single_ports.push(("dnat-port", port));
        }

        // Check single port equality collisions
        for i in 0..single_ports.len() {
            for j in (i + 1)..single_ports.len() {
                if single_ports[i].1 == single_ports[j].1 {
                    return Err(format!(
                        "{} ({}) cannot be the same as {} ({})",
                        single_ports[i].0, single_ports[i].1, single_ports[j].0, single_ports[j].1
                    ));
                }
            }
        }

        // Check single port vs range collisions
        let ranges = [
            ("reserved-ports", &self.reserved_ports),
            ("auto-ports", &self.auto_ports),
        ];
        for (name, port) in &single_ports {
            for (rname, range) in &ranges {
                if range.contains(*port) {
                    return Err(format!(
                        "{name} ({port}) overlaps with {rname} ({:?})",
                        range.0
                    ));
                }
            }
        }

        // Check range vs range collision
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
        let cfg = parse_config_from(args).unwrap();
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
        assert!(parse_config_from(args).is_err());
    }

    #[test]
    fn test_service_config_dnat_port_validation() {
        let args = [
            "fluct",
            "--tls-cert",
            "cert.pem",
            "--tls-key",
            "key.pem",
            "--reserved-ports",
            "20000-29999",
            "--auto-ports",
            "30000-39999",
            "--dnat-port",
            "25000",
        ];
        assert!(parse_config_from(args).is_err());
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
