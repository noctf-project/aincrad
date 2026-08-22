use std::{ffi::CStr, io, mem::MaybeUninit, net::SocketAddr, ops::RangeInclusive, os::fd::RawFd};

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
        SocketAddr::V4(_) => get_original_dst_v4(fd),
        SocketAddr::V6(v6_addr) => {
            if v6_addr.ip().to_ipv4_mapped().is_some() {
                if let Ok(v4_dst) = get_original_dst_v4(fd) {
                    return Ok(v4_dst);
                }
            }
            get_original_dst_v6(fd)
        }
    }
}

fn get_original_dst_v4(fd: RawFd) -> io::Result<SocketAddr> {
    let mut sockaddr = MaybeUninit::<libc::sockaddr_in>::zeroed();
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    let res = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            sockaddr.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };
    if res != 0 {
        return Err(io::Error::last_os_error());
    }
    let sockaddr = unsafe { sockaddr.assume_init() };

    let port = u16::from_be(sockaddr.sin_port);
    let ip = std::net::Ipv4Addr::from(u32::from_be(sockaddr.sin_addr.s_addr));
    Ok(SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)))
}

fn get_original_dst_v6(fd: RawFd) -> io::Result<SocketAddr> {
    let mut sockaddr6 = MaybeUninit::<libc::sockaddr_in6>::zeroed();
    let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

    let res = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IPV6,
            80, // IP6T_SO_ORIGINAL_DST
            sockaddr6.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };
    if res != 0 {
        return Err(io::Error::last_os_error());
    }

    let sockaddr6 = unsafe { sockaddr6.assume_init() };

    let port = u16::from_be(sockaddr6.sin6_port);
    let ip = std::net::Ipv6Addr::from(sockaddr6.sin6_addr.s6_addr);

    if let Some(v4_ip) = ip.to_ipv4_mapped() {
        return Ok(SocketAddr::V4(std::net::SocketAddrV4::new(v4_ip, port)));
    }

    let flowinfo = u32::from_be(sockaddr6.sin6_flowinfo);
    let scope_id = sockaddr6.sin6_scope_id;
    Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
        ip, port, flowinfo, scope_id,
    )))
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

/// Builds the nftables NAT rule batch for multiple port ranges (supporting IPv4 and IPv6).
fn build_nat_batch(dest: u16, ranges: &[RangeInclusive<u16>]) -> FinalizedBatch {
    let table = Table::new(TABLE_NAME, ProtoFamily::Inet);
    let mut chain = Chain::new(CHAIN_NAME, &table);
    chain.set_type(ChainType::Nat);
    chain.set_hook(Hook::PreRouting, -100);

    let mut batch = Batch::new();
    batch.add(&table, MsgType::Add);
    batch.add(&chain, MsgType::Add);

    let ip_v4 = u32::from(std::net::Ipv4Addr::new(127, 0, 0, 1)).to_be();
    let ip_v6 = std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).octets();

    for range in ranges {
        add_nat_rule(
            &mut batch,
            &chain,
            range,
            libc::NFPROTO_IPV4 as u8,
            ProtoFamily::Ipv4,
            ip_v4,
            dest,
        );
        add_nat_rule(
            &mut batch,
            &chain,
            range,
            libc::NFPROTO_IPV6 as u8,
            ProtoFamily::Ipv6,
            ip_v6,
            dest,
        );
    }

    batch.finalize()
}

fn add_nat_rule<T>(
    batch: &mut Batch,
    chain: &Chain,
    range: &RangeInclusive<u16>,
    nfproto: u8,
    family: ProtoFamily,
    ip_data: T,
    dest: u16,
) where
    Immediate<T>: nftnl::expr::Expression,
{
    let mut rule = Rule::new(chain);

    // Match L3 and L4 protocols
    rule.add_expr(&nft_expr!(meta nfproto));
    rule.add_expr(&nft_expr!(cmp == nfproto));
    rule.add_expr(&nft_expr!(meta l4proto));
    rule.add_expr(&nft_expr!(cmp == libc::IPPROTO_TCP as u8));

    // Load and match TCP destination port range
    rule.add_expr(&Payload::Transport(TransportHeaderField::Tcp(
        TcpHeaderField::Dport,
    )));
    rule.add_expr(&nft_expr!(cmp >= range.start().to_be()));
    rule.add_expr(&nft_expr!(cmp <= range.end().to_be()));

    // Set destination IP in Reg1 and target port in Reg2
    rule.add_expr(&Immediate::new(ip_data, Register::Reg1));
    rule.add_expr(&Immediate::new(dest.to_be(), Register::Reg2));

    // Redirect to target destination port via DNAT
    let nat_expr = Nat {
        nat_type: NatType::DNat,
        family,
        ip_register: Register::Reg1,
        port_register: Some(Register::Reg2),
    };
    rule.add_expr(&nat_expr);

    batch.add(&rule, MsgType::Add);
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
