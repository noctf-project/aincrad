use std::{io, mem::MaybeUninit, net::SocketAddr, os::fd::RawFd};

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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV6, TcpListener};
    use std::os::fd::AsRawFd;

    use super::*;

    #[test]
    fn test_get_original_dst_v4_non_nat_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local_addr = listener.local_addr().unwrap();

        // On non-NAT sockets, SO_ORIGINAL_DST returns an error (ENOENT/ENOPROTOOPT/EINVAL)
        let result = get_original_dst(listener.as_raw_fd(), local_addr);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_original_dst_v6_non_nat_socket() {
        let listener = match TcpListener::bind("[::1]:0") {
            Ok(l) => l,
            Err(_) => return, // IPv6 disabled on host
        };
        let local_addr = listener.local_addr().unwrap();

        let result = get_original_dst(listener.as_raw_fd(), local_addr);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_original_dst_ipv4_mapped_v6_addr() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mapped_addr = SocketAddr::V6(SocketAddrV6::new(
            Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped(),
            listener.local_addr().unwrap().port(),
            0,
            0,
        ));

        // When passed an IPv4-mapped IPv6 address, get_original_dst should route through get_original_dst_v4
        let result = get_original_dst(listener.as_raw_fd(), mapped_addr);
        assert!(result.is_err());
    }
}
