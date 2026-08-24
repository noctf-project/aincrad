use std::ops::RangeInclusive;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use fluct::Error;

use crate::{cmd::cli::RawServiceConfig, services::routes::RoutesService};

pub struct ServiceContext {
    pub config: ServiceConfig,
    pub routes_service: RoutesService,
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

/// Public validated configuration struct
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub host: String,
    pub http_port: u16,
    pub tls_port: u16,
    pub reserved_ports: PortRange,
    pub auto_ports: PortRange,
    pub tproxy_port: Option<u16>,
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
    pub challenge_domain: String,
    pub cluster_domain: String,
    pub flag_prefix: String,
    pub logs_dir: String,
}

impl TryFrom<RawServiceConfig> for ServiceConfig {
    type Error = Error;

    fn try_from(raw: RawServiceConfig) -> Result<Self, Self::Error> {
        let config = ServiceConfig {
            host: raw.host,
            http_port: raw.http_port,
            tls_port: raw.tls_port,
            reserved_ports: raw.reserved_ports,
            auto_ports: raw.auto_ports,
            tproxy_port: raw.tproxy_port,
            tls_cert: raw.tls_cert,
            tls_key: raw.tls_key,
            challenge_domain: raw.challenge_domain,
            cluster_domain: raw.cluster_domain,
            flag_prefix: raw.flag_prefix,
            logs_dir: raw.logs_dir,
        };
        config.validate()?;
        Ok(config)
    }
}

impl ServiceConfig {
    fn validate(&self) -> Result<(), String> {
        let mut single_ports = vec![("http-port", self.http_port), ("tls-port", self.tls_port)];
        if let Some(port) = self.tproxy_port {
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