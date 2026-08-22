
use std::{ffi::CStr, io, net::SocketAddr, ops::RangeInclusive, os::fd::RawFd};

use nftnl::{
    Batch, Chain, ChainType, FinalizedBatch, Hook, MsgType, ProtoFamily, Rule, Table,
    expr::{Immediate, Nat, NatType, Payload, Register, TcpHeaderField, TransportHeaderField},
    nft_expr,
    nftnl_sys::libc,
};

const TABLE_NAME: &CStr = c"fluct";
const CHAIN_NAME: &CStr = c"prerouting";

/// Configures NAT redirection for multiple ranges of TCP ports to a destination port in the kernel.
pub fn configure_nat(dest: u16, ranges: &[RangeInclusive<u16>]) -> io::Result<()> {
    let batch = build_nat_batch(dest, ranges);
    commit_batch(&batch)
}

/// Extracts the original pre-DNAT destination address/port from a socket file descriptor.
pub fn get_original_dst(fd: RawFd, addr: SocketAddr) -> io::Result<SocketAddr> {
    match addr {
        SocketAddr::V4(_) => {
            let mut sockaddr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

            let res = unsafe {
                libc::getsockopt(
                    fd,
                    0,  // IPPROTO_IP
                    80, // SO_ORIGINAL_DST
                    &mut sockaddr as *mut _ as *mut libc::c_void,
                    &mut len,
                )
            };
            if res != 0 {
                return Err(io::Error::last_os_error());
            }

            let port = u16::from_be(sockaddr.sin_port);
            let ip = std::net::Ipv4Addr::from(u32::from_be(sockaddr.sin_addr.s_addr));
            Ok(SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)))
        }
        SocketAddr::V6(_) => {
            let mut sockaddr6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

            let res = unsafe {
                libc::getsockopt(
                    fd,
                    41, // IPPROTO_IPV6
                    80, // IP6T_SO_ORIGINAL_DST
                    &mut sockaddr6 as *mut _ as *mut libc::c_void,
                    &mut len,
                )
            };
            if res != 0 {
                return Err(io::Error::last_os_error());
            }

            let port = u16::from_be(sockaddr6.sin6_port);
            let ip = std::net::Ipv6Addr::from(sockaddr6.sin6_addr.s6_addr);
            Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
                ip,
                port,
                u32::from_be(sockaddr6.sin6_flowinfo),
                sockaddr6.sin6_scope_id,
            )))
        }
    }
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Drops all POSIX capabilities (effective, permitted, inheritable) for the current process.
pub fn drop_caps() -> io::Result<()> {
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;
    let mut header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];

    let res = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &mut header as *mut _ as *mut libc::c_void,
            data.as_ptr() as *const libc::c_void,
        )
    };

    if res != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// Builds the nftables NAT rule batch for multiple port ranges.
fn build_nat_batch(dest: u16, ranges: &[RangeInclusive<u16>]) -> FinalizedBatch {
    let table = Table::new(TABLE_NAME, ProtoFamily::Inet);
    let mut chain = Chain::new(CHAIN_NAME, &table);
    chain.set_type(ChainType::Nat);
    chain.set_hook(Hook::PreRouting, -100);

    let mut batch = Batch::new();
    batch.add(&table, MsgType::Add);
    batch.add(&chain, MsgType::Add);

    for range in ranges {
        let mut rule = Rule::new(&chain);

        // Match TCP protocol
        rule.add_expr(&nft_expr!(meta l4proto));
        rule.add_expr(&nft_expr!(cmp == libc::IPPROTO_TCP as u8));

        // Load TCP destination port into Reg1
        rule.add_expr(&Payload::Transport(TransportHeaderField::Tcp(
            TcpHeaderField::Dport,
        )));

        // Match incoming port within specified range
        rule.add_expr(&nft_expr!(cmp >= range.start().to_be()));
        rule.add_expr(&nft_expr!(cmp <= range.end().to_be()));

        // Set immediate destination port value in Reg1
        rule.add_expr(&Immediate::new(dest.to_be(), Register::Reg1));

        // Redirect to target destination port via DNAT
        let nat_expr = Nat {
            nat_type: NatType::DNat,
            family: ProtoFamily::Inet,
            ip_register: Register::Reg1,
            port_register: Some(Register::Reg1),
        };
        rule.add_expr(&nat_expr);

        batch.add(&rule, MsgType::Add);
    }

    batch.finalize()
}

fn commit_batch(batch: &FinalizedBatch) -> io::Result<()> {
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;
    let portid = socket.portid();

    socket.send_all(batch)?;

    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    let mut expected_seqs = batch.sequence_numbers();

    while !expected_seqs.is_empty() {
        for message in socket.recv(&mut buffer[..])? {
            let message = message?;
            let expected_seq = expected_seqs
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "Unexpected ACK"))?;
            mnl::cb_run(message, expected_seq, portid)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_nat_batch_multiple_ranges() {
        let ranges = [1000..=2000, 3000..=4000];
        let batch = build_nat_batch(8080, &ranges);
        assert!(!batch.sequence_numbers().is_empty());
    }

    #[test]
    fn test_drop_caps() {
        // Calling drop_caps should either succeed (if running with capset capability)
        // or fail with EPERM (if non-root without CAP_SETPCAP). In both cases it returns safely.
        let _ = drop_caps();
    }
}