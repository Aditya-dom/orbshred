use std::collections::HashSet;
use std::net::Ipv4Addr;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use anyhow::Result;

use crate::registry::{ShredEvent, SourceId};

/// One routing entry per pcap source sharing a socket.
/// The capture loop checks each packet against all routes and sends a ShredEvent
/// for every matching source, using a single timestamp.
#[allow(dead_code)]
pub struct PcapRoute {
    pub source_id: SourceId,
    pub include_ips: HashSet<Ipv4Addr>,
    pub exclude_ips: HashSet<Ipv4Addr>,
}

/// Spawn a single AF_PACKET capture thread for the given port/interface,
/// routing packets to one or more sources based on IP filters.
pub async fn run(
    port: u16,
    interface: String,
    recv_buf_size: usize,
    routes: Vec<PcapRoute>,
    tx: mpsc::UnboundedSender<ShredEvent>,
    cancel: CancellationToken,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        tokio::task::spawn_blocking(move || {
            if let Err(e) = linux::capture_loop(port, &interface, recv_buf_size, &routes, &tx, &cancel) {
                tracing::error!("Raw packet capture error: {:#}", e);
            }
        });
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (port, interface, recv_buf_size, routes, tx, cancel);
        anyhow::bail!("Raw packet capture (AF_PACKET) is only supported on Linux")
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::net::Ipv4Addr;
    use std::time::Instant;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;
    use tracing::{info, warn};

    use crate::registry::ShredEvent;
    use crate::shred::parse_shred_key;
    use super::PcapRoute;

    /// Extract the source IPv4 address from a raw Ethernet frame.
    /// Source IP is at byte offset 26 (14-byte Ethernet header + 12 bytes into IP header).
    fn extract_src_ip(buf: &[u8]) -> Option<Ipv4Addr> {
        if buf.len() < 30 { return None; }
        Some(Ipv4Addr::new(buf[26], buf[27], buf[28], buf[29]))
    }

    /// Extract the UDP payload from a raw Ethernet frame.
    /// Returns None if not IPv4/UDP or fragmented.
    fn extract_udp_payload(buf: &[u8]) -> Option<&[u8]> {
        if buf.len() < 42 { return None; }
        if u16::from_be_bytes([buf[12], buf[13]]) != 0x0800 { return None; }
        let ip_start = 14;
        let ihl = ((buf[ip_start] & 0x0f) * 4) as usize;
        if ihl < 20 || buf.len() < ip_start + ihl + 8 { return None; }
        if buf[ip_start + 9] != 17 { return None; }
        if u16::from_be_bytes([buf[ip_start + 6], buf[ip_start + 7]]) & 0x1fff != 0 {
            return None;
        }
        let udp_start = ip_start + ihl;
        let payload_start = udp_start + 8;
        let udp_len = u16::from_be_bytes([buf[udp_start + 4], buf[udp_start + 5]]) as usize;
        let payload_len = udp_len.saturating_sub(8);
        if payload_start + payload_len > buf.len() { return None; }
        Some(&buf[payload_start..payload_start + payload_len])
    }

    /// Check whether this packet's source IP matches a route's filter.
    fn route_matches(route: &PcapRoute, src_ip: Option<Ipv4Addr>) -> bool {
        let has_filter = !route.include_ips.is_empty() || !route.exclude_ips.is_empty();
        if !has_filter {
            return true;
        }
        let Some(ip) = src_ip else { return false };
        if !route.include_ips.is_empty() && !route.include_ips.contains(&ip) {
            return false;
        }
        if !route.exclude_ips.is_empty() && route.exclude_ips.contains(&ip) {
            return false;
        }
        true
    }

    pub fn capture_loop(
        port: u16,
        interface: &str,
        recv_buf_size: usize,
        routes: &[PcapRoute],
        tx: &mpsc::UnboundedSender<ShredEvent>,
        cancel: &CancellationToken,
    ) -> anyhow::Result<()> {
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_IP as u16).to_be() as libc::c_int,
            )
        };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EPERM) {
                anyhow::bail!(
                    "Permission denied: AF_PACKET requires CAP_NET_RAW. \
                     Grant it with: sudo setcap cap_net_raw=eip ./orbshred"
                );
            }
            return Err(err.into());
        }

        // Classic BPF filter: udp dst port <port>
        let port_u32 = port as u32;
        let filter: [libc::sock_filter; 11] = [
            libc::sock_filter { code: 0x28, jt: 0, jf: 0,  k: 12       },
            libc::sock_filter { code: 0x15, jt: 0, jf: 8,  k: 0x0800   },
            libc::sock_filter { code: 0x30, jt: 0, jf: 0,  k: 23       },
            libc::sock_filter { code: 0x15, jt: 0, jf: 6,  k: 0x11     },
            libc::sock_filter { code: 0x28, jt: 0, jf: 0,  k: 20       },
            libc::sock_filter { code: 0x45, jt: 4, jf: 0,  k: 0x1fff   },
            libc::sock_filter { code: 0xb1, jt: 0, jf: 0,  k: 14       },
            libc::sock_filter { code: 0x48, jt: 0, jf: 0,  k: 16       },
            libc::sock_filter { code: 0x15, jt: 0, jf: 1,  k: port_u32 },
            libc::sock_filter { code: 0x06, jt: 0, jf: 0,  k: 0xffff   },
            libc::sock_filter { code: 0x06, jt: 0, jf: 0,  k: 0        },
        ];
        let prog = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr() as *mut libc::sock_filter,
        };
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &prog as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
            )
        } < 0 {
            unsafe { libc::close(fd); }
            return Err(std::io::Error::last_os_error().into());
        }

        if !interface.is_empty() {
            let ifindex = unsafe {
                let name = CString::new(interface)?;
                libc::if_nametoindex(name.as_ptr())
            };
            if ifindex == 0 {
                unsafe { libc::close(fd); }
                anyhow::bail!("Interface '{}' not found", interface);
            }
            let sll = libc::sockaddr_ll {
                sll_family:   libc::AF_PACKET as u16,
                sll_protocol: (libc::ETH_P_IP as u16).to_be(),
                sll_ifindex:  ifindex as i32,
                sll_hatype:   0,
                sll_pkttype:  0,
                sll_halen:    0,
                sll_addr:     [0; 8],
            };
            if unsafe {
                libc::bind(
                    fd,
                    &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                )
            } < 0 {
                unsafe { libc::close(fd); }
                return Err(std::io::Error::last_os_error().into());
            }
        }

        if recv_buf_size > 0 {
            let size = recv_buf_size as libc::c_int;
            unsafe {
                libc::setsockopt(
                    fd, libc::SOL_SOCKET, libc::SO_RCVBUF,
                    &size as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }

        // 100ms receive timeout so cancellation is checked regularly
        let tv = libc::timeval { tv_sec: 0, tv_usec: 100_000 };
        unsafe {
            libc::setsockopt(
                fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }

        let iface_display = if interface.is_empty() { "all" } else { interface };
        info!(
            "Raw packet capture started (port={}, iface={}, {} route{})",
            port, iface_display, routes.len(),
            if routes.len() == 1 { "" } else { "s" }
        );

        let mut buf = vec![0u8; 2048];
        let mut raw_count: u64 = 0;
        let mut parsed_count: u64 = 0;
        // Per-route match counter for logging
        let mut route_counts: Vec<u64> = vec![0; routes.len()];

        let has_any_filter = routes.iter().any(|r| !r.include_ips.is_empty() || !r.exclude_ips.is_empty());

        loop {
            if cancel.is_cancelled() { break; }

            let n = unsafe {
                libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
            };
            let received_at = Instant::now();

            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut
                {
                    continue;
                }
                warn!("Raw packet capture recv error: {}", err);
                continue;
            }

            raw_count += 1;
            let frame = &buf[..n as usize];

            let src_ip = if has_any_filter { extract_src_ip(frame) } else { None };

            if let Some(payload) = extract_udp_payload(frame) {
                if let Some(key) = parse_shred_key(payload) {
                    parsed_count += 1;
                    for (i, route) in routes.iter().enumerate() {
                        if route_matches(route, src_ip) {
                            route_counts[i] += 1;
                            let _ = tx.send(ShredEvent {
                                source: route.source_id,
                                key: key.clone(),
                                received_at,
                            });
                        }
                    }
                }
            }
        }

        unsafe { libc::close(fd); }
        info!(
            "Raw packet capture stopped ({} packets, {} parsed as shreds)",
            raw_count, parsed_count
        );
        for (i, route) in routes.iter().enumerate() {
            info!("  route {:?}: {} shreds matched", route.source_id, route_counts[i]);
        }
        Ok(())
    }
}
