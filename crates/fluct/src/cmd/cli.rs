use std::path::PathBuf;

use addr::parse_domain_name;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

use fluct::Error;

use crate::config::{PortRange, ServiceConfig};

#[derive(Clone, Debug, Parser)]
#[command(name = "fluct", about = "Fluct CTF router service")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Clone, Debug, Subcommand)]
pub enum Commands {
    /// Run the fluct router service
    Run(RawServiceConfig),

    /// Generate the Kubernetes CustomResourceDefinition (CRD) manifest
    Crd {
        /// Output format: yaml or json
        #[arg(long, default_value = "yaml")]
        format: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceAction {
    Run(ServiceConfig),
    PrintCrd { format: String },
}

impl Cli {
    pub fn into_action(self) -> Result<ServiceAction, Error> {
        match self.command {
            Commands::Crd { format } => Ok(ServiceAction::PrintCrd { format }),
            Commands::Run(args) => Ok(ServiceAction::Run(ServiceConfig::try_from(args)?)),
        }
    }
}

pub fn parse_config() -> Result<ServiceAction, Error> {
    let cli = Cli::parse();
    cli.into_action()
}

#[cfg(test)]
pub fn parse_config_from<I, T>(itr: I) -> Result<ServiceAction, Error>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = Cli::try_parse_from(itr)?;
    cli.into_action()
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
pub struct RawServiceConfig {
    /// Host to listen on
    #[clap(long, default_value = "[::]")]
    pub host: String,

    /// HTTP listening port for Kubernetes webhooks and stats
    #[clap(long, default_value = "32600")]
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

    /// Internal listener port for Netfilter TCP redirection. This feature requires root in
    /// container and NET_ADMIN
    #[arg(long)]
    pub tproxy_port: Option<u16>,

    /// Public Key File
    #[arg(long)]
    pub tls_cert: PathBuf,

    /// Private Key File
    #[arg(long)]
    pub tls_key: PathBuf,

    /// Optional Hostname Suffix / Challenge Domain
    #[clap(long, default_value = "", value_parser = parse_hostname_suffix, alias = "hostname-suffix")]
    pub challenge_domain: String,

    /// Kubernetes Cluster Domain
    #[clap(long, default_value = "cluster.local")]
    pub cluster_domain: String,

    /// CTF flag prefix
    #[clap(long, default_value = "CTF")]
    pub flag_prefix: String,

    /// Logs Directory
    #[clap(long, default_value = "./data/")]
    pub logs_dir: String,
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
            "run",
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
        let action = parse_config_from(args).unwrap();
        let ServiceAction::Run(cfg) = action else {
            panic!("expected ServiceAction::Run");
        };
        assert_eq!(cfg.tls_cert, PathBuf::from("cert.pem"));
        assert_eq!(cfg.tls_key, PathBuf::from("key.pem"));
        assert_eq!(cfg.challenge_domain, "example.com".to_string());
        assert_eq!(cfg.cluster_domain, "cluster.local".to_string());
        assert_eq!(cfg.http_port, 9000);
        assert_eq!(cfg.flag_prefix, "CTF");
        assert_eq!(cfg.reserved_ports, PortRange(10000..=19999));
        assert_eq!(cfg.auto_ports, PortRange(20000..=29999));
    }

    #[test]
    fn test_crd_subcommand_parsing() {
        let args = ["fluct", "crd", "--format", "json"];
        let action = parse_config_from(args).unwrap();
        assert_eq!(
            action,
            ServiceAction::PrintCrd {
                format: "json".to_string()
            }
        );
    }

    #[test]
    fn test_run_subcommand_parsing() {
        let args = [
            "fluct",
            "run",
            "--tls-cert",
            "cert.pem",
            "--tls-key",
            "key.pem",
            "--http-port",
            "9000",
        ];
        let action = parse_config_from(args).unwrap();
        let ServiceAction::Run(cfg) = action else {
            panic!("expected ServiceAction::Run");
        };
        assert_eq!(cfg.tls_cert, PathBuf::from("cert.pem"));
    }

    #[test]
    fn test_service_config_validation_overlap() {
        let args = [
            "fluct",
            "run",
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
            "run",
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
