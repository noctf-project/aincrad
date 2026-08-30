use std::path::PathBuf;

use clap::Parser;
pub use k8s_common::{PortRange, parse_port_range};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use fluct::Error;

use crate::{services::routes::RoutesService, store::resolver::Resolver};

pub struct ServiceContext {
    pub config: ServiceConfig,
    pub resolver: Resolver,
    pub routes_service: RoutesService,
    pub shutdown: CancellationToken,
}

/// Public validated configuration struct
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub host: String,
    pub tls_port: u16,
    pub port_ranges: Vec<PortRange>,
    pub system_namespace: Option<String>,
    pub tproxy_port: Option<u16>,
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
    pub flag_prefix: String,
    pub logs_dir: String,
    pub max_log_size: usize,
}

/// Private CLI argument parser
#[derive(Clone, Debug, Serialize, Deserialize, Parser)]
#[command(name = "fluct", about = "Fluct CTF router service")]
pub struct RawServiceConfig {
    /// Host to listen on
    #[clap(long, default_value = "[::]")]
    pub host: String,

    /// Listening port for TLS challenges
    #[clap(long, default_value = "4433")]
    pub tls_port: u16,

    /// Port range(s) for TCP routing (can be specified multiple times, e.g. --port-range 20000-29999 --port-range 30000-32767)
    #[clap(
        long = "port-range",
        action = clap::ArgAction::Append,
        value_parser = parse_port_range,
    )]
    pub port_ranges: Option<Vec<PortRange>>,

    /// Optional Kubernetes namespace to watch for CTFProxyRoute objects (defaults to active kubeconfig namespace)
    #[arg(long)]
    pub system_namespace: Option<String>,

    /// Internal listener port for Netfilter TCP redirection. This feature requires root in
    /// container and NET_ADMIN
    #[arg(long, alias = "dnat-port")]
    pub tproxy_port: Option<u16>,

    /// Public Key File
    #[arg(long)]
    pub tls_cert: PathBuf,

    /// Private Key File
    #[arg(long)]
    pub tls_key: PathBuf,

    /// CTF flag prefix
    #[clap(long, default_value = "CTF")]
    pub flag_prefix: String,

    /// Logs Directory
    #[clap(long, default_value = "./data/")]
    pub logs_dir: String,

    /// Maximum size in bytes of retained traffic log per connection
    #[clap(long, default_value = "1048576")]
    pub max_log_size: usize,
}

impl TryFrom<RawServiceConfig> for ServiceConfig {
    type Error = Error;

    fn try_from(raw: RawServiceConfig) -> Result<Self, Self::Error> {
        let port_ranges = raw
            .port_ranges
            .unwrap_or_else(|| vec![PortRange(20000..=32767)]);

        let config = ServiceConfig {
            host: raw.host,
            tls_port: raw.tls_port,
            port_ranges,
            system_namespace: raw.system_namespace,
            tproxy_port: raw.tproxy_port,
            tls_cert: raw.tls_cert,
            tls_key: raw.tls_key,
            flag_prefix: raw.flag_prefix,
            logs_dir: raw.logs_dir,
            max_log_size: raw.max_log_size,
        };
        config.validate()?;
        Ok(config)
    }
}

pub fn parse_config() -> Result<ServiceConfig, Error> {
    let raw = RawServiceConfig::parse();
    ServiceConfig::try_from(raw)
}

#[cfg(test)]
pub fn parse_config_from<I, T>(itr: I) -> Result<ServiceConfig, Error>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let raw = RawServiceConfig::try_parse_from(itr)?;
    ServiceConfig::try_from(raw)
}

impl ServiceConfig {
    fn validate(&self) -> Result<(), String> {
        let mut single_ports = vec![("tls-port", self.tls_port)];
        if let Some(port) = self.tproxy_port {
            single_ports.push(("tproxy-port", port));
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

        // Check range vs range overlap collisions
        for i in 0..self.port_ranges.len() {
            for j in (i + 1)..self.port_ranges.len() {
                if self.port_ranges[i].overlaps(&self.port_ranges[j]) {
                    return Err(format!(
                        "port range {:?} overlaps with port range {:?}",
                        self.port_ranges[i].0, self.port_ranges[j].0
                    ));
                }
            }
        }

        // Check single port vs range collisions
        for (name, port) in &single_ports {
            for range in &self.port_ranges {
                if range.contains(*port) {
                    return Err(format!(
                        "{name} ({port}) overlaps with port range {:?}",
                        range.0
                    ));
                }
            }
        }

        Ok(())
    }
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
            "--port-range",
            "10000-19999",
            "--port-range",
            "20000-29999",
            "--system-namespace",
            "aincrad-system",
        ];
        let cfg = parse_config_from(args).unwrap();
        assert_eq!(cfg.tls_cert, PathBuf::from("cert.pem"));
        assert_eq!(cfg.tls_key, PathBuf::from("key.pem"));
        assert_eq!(cfg.system_namespace, Some("aincrad-system".to_string()));
        assert_eq!(cfg.flag_prefix, "CTF");
        assert_eq!(cfg.max_log_size, 1048576);
        assert_eq!(
            cfg.port_ranges,
            vec![PortRange(10000..=19999), PortRange(20000..=29999)]
        );
    }

    #[test]
    fn test_service_config_max_log_size() {
        let args = [
            "fluct",
            "--tls-cert",
            "cert.pem",
            "--tls-key",
            "key.pem",
            "--max-log-size",
            "65536",
        ];
        let cfg = parse_config_from(args).unwrap();
        assert_eq!(cfg.max_log_size, 65536);
    }

    #[test]
    fn test_service_config_default_port_range() {
        let args = ["fluct", "--tls-cert", "cert.pem", "--tls-key", "key.pem"];
        let cfg = parse_config_from(args).unwrap();
        assert_eq!(cfg.port_ranges, vec![PortRange(20000..=32767)]);
        assert_eq!(cfg.system_namespace, None);
    }

    #[test]
    fn test_service_config_validation_overlap() {
        let args = [
            "fluct",
            "--tls-cert",
            "cert.pem",
            "--tls-key",
            "key.pem",
            "--port-range",
            "20000-30000",
            "--port-range",
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
            "--port-range",
            "20000-29999",
            "--dnat-port",
            "25000",
        ];
        assert!(parse_config_from(args).is_err());
    }
}
