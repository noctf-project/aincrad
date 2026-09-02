use std::{ffi::CStr, io, os::fd::RawFd, sync::Arc};

use mnl::{Bus, Socket, cb_run};
use nftnl::{
    Batch, Chain, ChainType, FinalizedBatch, Hook, MsgType, Policy, ProtoFamily, Rule, Table,
    expr::{CmpOp, Immediate, Lookup, Meta, Register},
    nft_expr,
    set::Set,
};
use tracing::warn;

use crate::store::routes::ProxyStore;

const TABLE_NAME: &CStr = c"fluct";
const PREROUTING: &CStr = c"prerouting";
const SET_NAME: &CStr = c"active";

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

struct NetlinkSocket(Socket);
unsafe impl Send for NetlinkSocket {}

impl std::ops::Deref for NetlinkSocket {
    type Target = Socket;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

fn send_and_process(socket: &Socket, batch: &FinalizedBatch) -> io::Result<()> {
    let portid = socket.portid();
    socket.send_all(batch)?;

    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    let mut expected_seqs = batch.sequence_numbers();
    while !expected_seqs.is_empty() {
        for message in socket.recv(&mut buffer[..])? {
            let message = message?;
            let Some(expected_seq) = expected_seqs.next() else {
                break;
            };
            cb_run(message, expected_seq, portid)?;
        }
    }
    Ok(())
}

fn build_init_batch(dest: u16, priority: i32, mark: u32, initial_ports: &[u16]) -> FinalizedBatch {
    let table = Table::new(TABLE_NAME, ProtoFamily::Inet);
    let mut chain = Chain::new(PREROUTING, &table);
    chain.set_hook(Hook::PreRouting, priority);
    chain.set_type(ChainType::Filter);
    chain.set_policy(Policy::Accept);

    let mut set: Set<u16> = Set::new_named(SET_NAME, 1, &table, ProtoFamily::Inet);
    for &port in initial_ports {
        set.add(&port);
    }

    let mut batch = Batch::new();
    batch.add(&table, MsgType::Add);
    batch.add(&set, MsgType::Add);
    batch.add_iter(set.elems_iter(), MsgType::Add);
    batch.add(&chain, MsgType::Add);

    let mut rule = Rule::new(&chain);
    rule.add_expr(&Meta::L4Proto);
    rule.add_expr(&nftnl::expr::Cmp::new(CmpOp::Eq, 6u8));
    rule.add_expr(&nft_expr!(payload tcp dport));
    rule.add_expr(&Lookup::new(&set));
    rule.add_expr(&Immediate::new(dest.to_be(), Register::Reg1));
    rule.add_expr(&nft_expr!(tproxy port Register::Reg1));
    rule.add_expr(&Immediate::new(mark, Register::Reg1));
    rule.add_expr(&Meta::Mark { set: true });
    batch.add(&rule, MsgType::Add);

    batch.finalize()
}

/// Manages a native netlink connection to nftables.
pub struct NetfilterSession {
    dest: u16,
    priority: i32,
    mark: u32,
    store: Arc<ProxyStore>,
    tls_port: Option<u16>,
    socket: Option<NetlinkSocket>,
}

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
            socket: None,
        }
    }

    /// Initializes the netlink session and applies the initial table, chain, set, and TPROXY rule.
    pub fn start(&mut self) -> io::Result<()> {
        let socket = NetlinkSocket(Socket::new(Bus::Netfilter)?);

        let table = Table::new(TABLE_NAME, ProtoFamily::Inet);
        let mut del_batch = Batch::new();
        del_batch.add(&table, MsgType::Del);
        let _ = send_and_process(&socket, &del_batch.finalize());

        let mut initial_ports = Vec::new();
        if let Some(tls) = self.tls_port {
            initial_ports.push(tls);
        }
        for port in self.store.active_tcp_ports() {
            if self.tls_port != Some(port) {
                initial_ports.push(port);
            }
        }

        let finalized = build_init_batch(self.dest, self.priority, self.mark, &initial_ports);

        send_and_process(&socket, &finalized)?;
        self.socket = Some(socket);
        Ok(())
    }

    /// Adds a port to the active netfilter set.
    pub fn add(&mut self, port: u16) -> io::Result<()> {
        if self.tls_port == Some(port) {
            return Ok(());
        }
        if !self.store.is_valid_port(port) {
            return Ok(());
        }
        let Some(socket) = &self.socket else {
            return Err(io::Error::other("netfilter session not started"));
        };

        let table = Table::new(TABLE_NAME, ProtoFamily::Inet);
        let mut set: Set<u16> = Set::new_named(SET_NAME, 1, &table, ProtoFamily::Inet);
        set.add(&port);

        let mut batch = Batch::new();
        batch.add_iter(set.elems_iter(), MsgType::Add);
        match send_and_process(socket, &batch.finalize()) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Removes a port from the active netfilter set.
    pub fn remove(&mut self, port: u16) -> io::Result<()> {
        if self.tls_port == Some(port) {
            return Ok(());
        }
        if !self.store.is_valid_port(port) {
            return Ok(());
        }
        let Some(socket) = &self.socket else {
            return Err(io::Error::other("netfilter session not started"));
        };

        let table = Table::new(TABLE_NAME, ProtoFamily::Inet);
        let mut set: Set<u16> = Set::new_named(SET_NAME, 1, &table, ProtoFamily::Inet);
        set.add(&port);

        let mut batch = Batch::new();
        batch.add_iter(set.elems_iter(), MsgType::Del);
        match send_and_process(socket, &batch.finalize()) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Flushes all active ports from the set, retaining the TLS port.
    pub fn flush(&mut self) -> io::Result<()> {
        let Some(socket) = &self.socket else {
            return Err(io::Error::other("netfilter session not started"));
        };

        let table = Table::new(TABLE_NAME, ProtoFamily::Inet);
        let mut set: Set<u16> = Set::new_named(SET_NAME, 1, &table, ProtoFamily::Inet);

        let mut batch = Batch::new();
        batch.add(&set.flush(), MsgType::Del);

        if let Some(tls) = self.tls_port {
            set.add(&tls);
            batch.add_iter(set.elems_iter(), MsgType::Add);
        }

        send_and_process(socket, &batch.finalize())
    }

    /// Closes the netfilter session and deletes the table.
    pub fn close(&mut self) -> io::Result<()> {
        if let Some(socket) = self.socket.take() {
            let table = Table::new(TABLE_NAME, ProtoFamily::Inet);
            let mut batch = Batch::new();
            batch.add(&table, MsgType::Del);
            let _ = send_and_process(&socket, &batch.finalize());
        }
        Ok(())
    }
}

impl Drop for NetfilterSession {
    fn drop(&mut self) {
        if let Some(socket) = self.socket.take() {
            let table = Table::new(TABLE_NAME, ProtoFamily::Inet);
            let mut batch = Batch::new();
            batch.add(&table, MsgType::Del);
            let _ = send_and_process(&socket, &batch.finalize());
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
    session.start()?;

    Ok(tokio::spawn(async move {
        while let Some(op) = rx.recv().await {
            match op {
                NetfilterOp::Add(port) => {
                    if let Err(e) = session.add(port) {
                        warn!("failed to add port {port} to netfilter: {e}");
                    }
                }
                NetfilterOp::Remove(port) => {
                    if let Err(e) = session.remove(port) {
                        warn!("failed to remove port {port} from netfilter: {e}");
                    }
                }
                NetfilterOp::Flush => {
                    if let Err(e) = session.flush() {
                        warn!("failed to flush netfilter active ports: {e}");
                    }
                }
            }
        }
        let _ = session.close();
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_init_batch() {
        let batch = build_init_batch(100, -150, 0x0a17c4ad, &[20005]);
        assert!(!batch.sequence_numbers().is_empty());
    }

    #[test]
    fn test_session_new() {
        let store = Arc::new(ProxyStore::new(vec![]));
        let session = NetfilterSession::new(100, -150, 0x0a17c4ad, store, Some(4433));

        assert_eq!(session.dest, 100);
        assert_eq!(session.priority, -150);
        assert_eq!(session.mark, 0x0a17c4ad);
        assert_eq!(session.tls_port, Some(4433));
        assert!(session.socket.is_none());
    }

    #[test]
    fn test_session_add_remove_validation() {
        use crate::config::PortRange;

        let store = Arc::new(ProxyStore::new(vec![PortRange(20000..=30000)]));
        let mut session = NetfilterSession::new(100, -150, 0x0a17c4ad, store, Some(4433));

        assert!(session.add(4433).is_ok());
        assert!(session.remove(4433).is_ok());

        assert!(session.add(10005).is_ok());
        assert!(session.remove(10005).is_ok());

        assert!(session.add(20005).is_err());
        assert!(session.remove(20005).is_err());
    }

    #[test]
    fn test_session_flush_unstarted() {
        let store = Arc::new(ProxyStore::new(vec![]));
        let mut session = NetfilterSession::new(100, -150, 0x0a17c4ad, store, Some(4433));

        assert!(session.flush().is_err());
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
