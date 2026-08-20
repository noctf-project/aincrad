use std::path::PathBuf;

use clap::Parser;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::store::{RoutesStore, SecretsStore};

pub struct ServiceContext {
    pub config: ServiceConfig,
    pub challenges_store: RoutesStore,
    pub secrets_store: SecretsStore,
    pub shutdown: CancellationToken,
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

    /// TLS host
    #[arg(long, default_value = "[::]")]
    pub tls_host: String,

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

    /// Raw TCP challenge namespaces
    #[clap(long)]
    pub tcp_namespace: Option<String>,

    /// Logs Directory
    #[clap(long, default_value = "./data/")]
    pub logs_dir: String,
}

fn parse_hostname_suffix(s: &str) -> Result<String, String> {
    if s == "" {
        return Ok("".to_string());
    }
    if s.starts_with('.') || s.len() == 0 {
        return Ok("".to_string());
    }
    return Ok(format!(".{s}"));
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
            "--tcp-namespace",
            "my-ns",
            "--http-port",
            "9000",
        ];
        let cfg = ServiceConfig::try_parse_from(args).unwrap();
        assert_eq!(cfg.tls_cert, PathBuf::from("cert.pem"));
        assert_eq!(cfg.tls_key, PathBuf::from("key.pem"));
        assert_eq!(cfg.hostname_suffix, ".example.com".to_string());
        assert_eq!(cfg.tcp_namespace, Some("my-ns".to_string()));
        assert_eq!(cfg.http_port, 9000);
        assert_eq!(cfg.flag_prefix, "CTF");
    }
}
