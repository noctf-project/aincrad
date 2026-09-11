use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct Opts {
    pub config: Option<PathBuf>,
    pub listen_addr: Option<std::net::SocketAddr>,
}

impl Opts {
    pub fn parse_args() -> Self {
        let mut opts = Opts {
            config: std::env::var("CARDINAL_CONFIG").ok().map(PathBuf::from),
            listen_addr: std::env::var("LISTEN_ADDR")
                .ok()
                .and_then(|s| s.parse().ok()),
        };

        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            if arg == "-c" || arg == "--config" {
                if let Some(val) = args.next() {
                    opts.config = Some(PathBuf::from(val));
                }
            } else if let Some(val) = arg.strip_prefix("--config=") {
                opts.config = Some(PathBuf::from(val));
            } else if arg == "-l" || arg == "--listen" {
                if let Some(val) = args.next() {
                    opts.listen_addr = val.parse().ok();
                }
            } else if let Some(val) = arg.strip_prefix("--listen=") {
                opts.listen_addr = val.parse().ok();
            }
        }

        opts
    }
}
