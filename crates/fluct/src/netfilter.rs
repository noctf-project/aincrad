use std::{io, os::fd::RawFd, process::Stdio, sync::Arc};

use tokio::io::AsyncWriteExt;
use tracing::warn;

use crate::store::routes::ProxyStore;

const TABLE_NAME: &str = "fluct";
const PREROUTING: &str = "prerouting";
const SET_NAME: &str = "active";

/// Operations dispatched to netfilter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetfilterOp {
    Add(u16),
    Remove(u16),
    Flush,
}

/// Sets IP_TRANSPARENT on a socket file descriptor for Linux TPROXY.
pub fn set_ip_transparent(fd: RawFd) -> io::Result<()> {
    const IP_TRANSPARENT: libc::c_int = 19;
    let opt: libc::c_int = 1;
    let res = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IP,
            IP_TRANSPARENT,
            &opt as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if res != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Builds the list of top-level commands to initialize the table, set, chain, and rules in an interactive session.
fn build_init_commands(dest: u16, priority: i32, mark: u32) -> Vec<String> {
    vec![
        format!("add table inet {TABLE_NAME}"),
        format!("flush table inet {TABLE_NAME}"),
        format!("add set inet {TABLE_NAME} {SET_NAME} {{ type inet_service; }}"),
        format!(
            "add chain inet {TABLE_NAME} {PREROUTING} {{ type filter hook {PREROUTING} priority {priority}; policy accept; }}"
        ),
        format!(
            "add rule inet {TABLE_NAME} {PREROUTING} tcp dport @{SET_NAME} tproxy to :{dest} meta mark set 0x{mark:08x}"
        ),
    ]
}

/// Manages an interactive `nft -i` session.
#[allow(dead_code)]
pub struct NetfilterSession {
    dest: u16,
    priority: i32,
    mark: u32,
    store: Arc<ProxyStore>,
    tls_port: Option<u16>,
    child: Option<tokio::process::Child>,
    stdin: Option<tokio::process::ChildStdin>,
}

#[allow(dead_code)]
impl NetfilterSession {
    /// Creates a new `NetfilterSession` configuration.
    pub fn new(
        dest: u16,
        priority: i32,
        mark: u32,
        store: Arc<ProxyStore>,
        tls_port: Option<u16>,
    ) -> Self {
        Self {
            dest,
            priority,
            mark,
            store,
            tls_port,
            child: None,
            stdin: None,
        }
    }

    /// Formats an `add element` command for the port set.
    fn add_element_cmd(port: u16) -> String {
        format!("add element inet {TABLE_NAME} {SET_NAME} {{ {port} }}")
    }

    /// Formats a `delete element` command for the port set.
    fn delete_element_cmd(port: u16) -> String {
        format!("delete element inet {TABLE_NAME} {SET_NAME} {{ {port} }}")
    }

    /// Formats a `flush set` command for the port set.
    fn flush_set_cmd() -> String {
        format!("flush set inet {TABLE_NAME} {SET_NAME}")
    }

    /// Spawns the interactive `nft -i` session and applies the initial rules and active routes.
    pub async fn start(&mut self) -> io::Result<()> {
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
        }
        self.stdin = None;

        let mut child = tokio::process::Command::new("nft")
            .arg("-i")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("failed to capture nft stdin"))?;

        self.child = Some(child);
        self.stdin = Some(stdin);

        for cmd in build_init_commands(self.dest, self.priority, self.mark) {
            self.send_command(&cmd).await?;
        }

        if let Some(tls) = self.tls_port {
            self.send_command(&Self::add_element_cmd(tls)).await?;
        }

        for port in self.store.active_tcp_ports() {
            if self.tls_port != Some(port) {
                self.send_command(&Self::add_element_cmd(port)).await?;
            }
        }

        Ok(())
    }

    /// Sends a raw command followed by a newline and flushes stdin in a single atomic write.
    async fn send_command(&mut self, cmd: &str) -> io::Result<()> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| io::Error::other("session is not running"))?;

        let mut buf = Vec::with_capacity(cmd.len() + 1);
        buf.extend_from_slice(cmd.as_bytes());
        buf.push(b'\n');

        stdin.write_all(&buf).await?;
        stdin.flush().await?;
        Ok(())
    }

    /// Adds a port to the allowed ports set if valid in store and not the TLS port.
    pub async fn add(&mut self, port: u16) -> io::Result<()> {
        if self.tls_port == Some(port) || !self.store.is_valid_port(port) {
            return Ok(());
        }
        let cmd = Self::add_element_cmd(port);
        self.send_command(&cmd).await
    }

    /// Removes a port from the allowed ports set if valid in store and not the TLS port.
    pub async fn remove(&mut self, port: u16) -> io::Result<()> {
        if self.tls_port == Some(port) || !self.store.is_valid_port(port) {
            return Ok(());
        }
        let cmd = Self::delete_element_cmd(port);
        self.send_command(&cmd).await
    }

    /// Flushes all entries from the allowed ports set and re-adds the TLS port.
    pub async fn flush(&mut self) -> io::Result<()> {
        let cmd = Self::flush_set_cmd();
        self.send_command(&cmd).await?;
        if let Some(tls) = self.tls_port {
            self.send_command(&Self::add_element_cmd(tls)).await?;
        }
        Ok(())
    }

    /// Closes the interactive session by flushing the table, sending `quit`, and awaiting process termination.
    pub async fn close(&mut self) -> io::Result<()> {
        if self.stdin.is_some() {
            let _ = self
                .send_command(&format!("flush table inet {TABLE_NAME}"))
                .await;
            let _ = self.send_command("quit").await;
            drop(self.stdin.take());
        }

        if let Some(mut child) = self.child.take() {
            child.wait().await?;
        }

        Ok(())
    }
}

impl Drop for NetfilterSession {
    fn drop(&mut self) {
        if let Some(stdin) = self.stdin.take() {
            use std::os::fd::AsRawFd;
            let cmd = format!("flush table inet {TABLE_NAME}\nquit\n");
            unsafe {
                libc::write(
                    stdin.as_raw_fd(),
                    cmd.as_ptr() as *const libc::c_void,
                    cmd.len(),
                );
            }
            drop(stdin);
        }

        if let Some(pid) = self.child.take().and_then(|c| c.id()) {
            let mut status = 0;
            unsafe {
                libc::waitpid(pid as libc::pid_t, &mut status, 0);
            }
        }
    }
}

/// Spawns the netfilter session and background worker task.
pub async fn spawn_worker(
    dest: u16,
    priority: i32,
    mark: u32,
    store: Arc<ProxyStore>,
    tls_port: Option<u16>,
    mut rx: tokio::sync::mpsc::Receiver<NetfilterOp>,
) -> io::Result<tokio::task::JoinHandle<()>> {
    let mut session = NetfilterSession::new(dest, priority, mark, store, tls_port);
    session.start().await?;

    Ok(tokio::spawn(async move {
        while let Some(op) = rx.recv().await {
            match op {
                NetfilterOp::Add(port) => {
                    if let Err(e) = session.add(port).await {
                        warn!("failed to add port {port} to netfilter: {e}");
                    }
                }
                NetfilterOp::Remove(port) => {
                    if let Err(e) = session.remove(port).await {
                        warn!("failed to remove port {port} from netfilter: {e}");
                    }
                }
                NetfilterOp::Flush => {
                    if let Err(e) = session.flush().await {
                        warn!("failed to flush netfilter: {e}");
                    }
                }
            }
        }
        let _ = session.close().await;
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_init_commands() {
        let cmds = build_init_commands(100, -150, 0x0a17c4ad);

        assert_eq!(cmds.len(), 5);
        assert_eq!(cmds[0], "add table inet fluct");
        assert_eq!(cmds[1], "flush table inet fluct");
        assert_eq!(cmds[2], "add set inet fluct active { type inet_service; }");
        assert_eq!(
            cmds[3],
            "add chain inet fluct prerouting { type filter hook prerouting priority -150; policy accept; }"
        );
        assert_eq!(
            cmds[4],
            "add rule inet fluct prerouting tcp dport @active tproxy to :100 meta mark set 0x0a17c4ad"
        );
    }

    #[test]
    fn test_session_new() {
        let store = Arc::new(ProxyStore::new(vec![]));
        let session = NetfilterSession::new(100, -150, 0x0a17c4ad, store, Some(4433));

        assert_eq!(session.dest, 100);
        assert_eq!(session.priority, -150);
        assert_eq!(session.mark, 0x0a17c4ad);
        assert_eq!(session.tls_port, Some(4433));
        assert!(session.stdin.is_none());
        assert!(session.child.is_none());
    }

    #[test]
    fn test_session_element_cmds() {
        assert_eq!(
            NetfilterSession::add_element_cmd(1337),
            "add element inet fluct active { 1337 }"
        );
        assert_eq!(
            NetfilterSession::add_element_cmd(8080),
            "add element inet fluct active { 8080 }"
        );
        assert_eq!(
            NetfilterSession::delete_element_cmd(1337),
            "delete element inet fluct active { 1337 }"
        );
        assert_eq!(
            NetfilterSession::delete_element_cmd(8080),
            "delete element inet fluct active { 8080 }"
        );
        assert_eq!(
            NetfilterSession::flush_set_cmd(),
            "flush set inet fluct active"
        );
    }

    #[tokio::test]
    async fn test_session_add_remove_validation() {
        use crate::config::PortRange;

        let store = Arc::new(ProxyStore::new(vec![PortRange(20000..=30000)]));
        let mut session = NetfilterSession::new(100, -150, 0x0a17c4ad, store, Some(4433));

        // TLS port is forbidden: returns Ok(()) without sending to stdin
        assert!(session.add(4433).await.is_ok());
        assert!(session.remove(4433).await.is_ok());

        // Out-of-range port is rejected: returns Ok(()) without sending to stdin
        assert!(session.add(10005).await.is_ok());
        assert!(session.remove(10005).await.is_ok());

        // Valid in-range port attempts to send, which errors because session isn't running
        assert!(session.add(20005).await.is_err());
        assert!(session.remove(20005).await.is_err());
    }

    #[tokio::test]
    async fn test_session_flush_unstarted() {
        let store = Arc::new(ProxyStore::new(vec![]));
        let mut session = NetfilterSession::new(100, -150, 0x0a17c4ad, store, Some(4433));

        // Flush on an unstarted session attempts to write and errors
        assert!(session.flush().await.is_err());
    }

    #[test]
    fn test_session_store_reflection() {
        use k8s_common::crd::{CTFProxyRoute, CTFProxyRouteSpec};
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

        let store = Arc::new(ProxyStore::new(vec![]));
        let session = NetfilterSession::new(100, -150, 0x0a17c4ad, store.clone(), Some(4433));

        assert!(session.store.active_tcp_ports().is_empty());

        store.insert(CTFProxyRoute {
            metadata: ObjectMeta {
                name: Some("p20005".into()),
                ..Default::default()
            },
            spec: CTFProxyRouteSpec {
                backend: "10.0.0.1:80".into(),
                ..Default::default()
            },
        });

        assert_eq!(session.store.active_tcp_ports(), vec![20005]);
    }
}
