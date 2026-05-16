use std::collections::HashSet;
use std::net::Ipv4Addr;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use anyhow::Result;

use crate::registry::{DropCounters, ShredEvent, SourceId};

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
    anchor: crate::sources::kernel_ts::ClockAnchor,
    pin_cpu: Option<usize>,
    tx: mpsc::Sender<ShredEvent>,
    drops: DropCounters,
    cancel: CancellationToken,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        tokio::task::spawn_blocking(move || {
            if let Some(cpu) = pin_cpu {
                match crate::sources::affinity::pin_current_thread(cpu) {
                    Ok(()) => tracing::info!("pcap: pinned capture thread to CPU {}", cpu),
                    Err(e) => tracing::warn!("pcap: failed to pin to CPU {}: {}", cpu, e),
                }
            }
            if let Err(e) = linux::capture_loop(port, &interface, recv_buf_size, &routes, anchor, &tx, &drops, &cancel) {
                tracing::error!("Raw packet capture error: {:#}", e);
            }
        });
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (port, interface, recv_buf_size, routes, anchor, pin_cpu, tx, drops, cancel);
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

    use crate::registry::{DropCounters, ShredEvent};
    use crate::shred::parse_shred_key;
    use super::PcapRoute;

    /// Return the offset of the IP header within an Ethernet frame, handling a
    /// single 802.1Q VLAN tag if present. Returns None if the frame is too short
    /// or the ethertype is not IPv4 (after unwrapping VLAN).
    fn ip_header_offset(buf: &[u8]) -> Option<usize> {
        if buf.len() < 14 { return None; }
        let ethertype = u16::from_be_bytes([buf[12], buf[13]]);
        if ethertype == 0x0800 {
            Some(14)
        } else if ethertype == 0x8100 {
            if buf.len() < 18 { return None; }
            let inner = u16::from_be_bytes([buf[16], buf[17]]);
            if inner == 0x0800 { Some(18) } else { None }
        } else {
            None
        }
    }

    /// Extract the source IPv4 address from a raw Ethernet frame (IPv4 or VLAN+IPv4).
    fn extract_src_ip(buf: &[u8]) -> Option<Ipv4Addr> {
        let ip_start = ip_header_offset(buf)?;
        let src_off = ip_start + 12;
        if buf.len() < src_off + 4 { return None; }
        Some(Ipv4Addr::new(buf[src_off], buf[src_off + 1], buf[src_off + 2], buf[src_off + 3]))
    }

    /// Extract the UDP payload from a raw Ethernet frame.
    /// Returns None if not IPv4/UDP or fragmented. Handles a single 802.1Q VLAN tag.
    fn extract_udp_payload(buf: &[u8]) -> Option<&[u8]> {
        let ip_start = ip_header_offset(buf)?;
        if buf.len() < ip_start + 20 { return None; }
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
        anchor: crate::sources::kernel_ts::ClockAnchor,
        tx: &mpsc::Sender<ShredEvent>,
        drops: &DropCounters,
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

        // Build the filter as the platform-independent `SockFilter` mirror,
        // then reinterpret-cast at the syscall boundary. Layout compatibility
        // with `libc::sock_filter` is verified at compile time.
        const _: () = assert!(
            std::mem::size_of::<crate::sources::bpf_filter::SockFilter>()
                == std::mem::size_of::<libc::sock_filter>(),
            "SockFilter layout must match libc::sock_filter",
        );
        let filter = crate::sources::bpf_filter::build_bpf_filter(port);
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

        // Try to enable kernel-side timestamps. AF_PACKET fully supports
        // SO_TIMESTAMPNS — failure here is unusual but recoverable.
        let kernel_ts_enabled =
            match crate::sources::kernel_ts::enable_kernel_timestamps(fd) {
                Ok(()) => true,
                Err(e) => {
                    warn!("AF_PACKET: SO_TIMESTAMPNS unavailable, using userland timestamps: {}", e);
                    false
                }
            };

        let iface_display = if interface.is_empty() { "all" } else { interface };
        info!(
            "Raw packet capture started (port={}, iface={}, {} route{}, {})",
            port, iface_display, routes.len(),
            if routes.len() == 1 { "" } else { "s" },
            if kernel_ts_enabled { "kernel timestamps" } else { "userland timestamps" }
        );

        let mut buf = vec![0u8; 2048];
        let mut raw_count: u64 = 0;
        let mut parsed_count: u64 = 0;
        // Per-route match counter for logging
        let mut route_counts: Vec<u64> = vec![0; routes.len()];

        let has_any_filter = routes.iter().any(|r| !r.include_ips.is_empty() || !r.exclude_ips.is_empty());

        loop {
            if cancel.is_cancelled() { break; }

            let (n, received_at) = if kernel_ts_enabled {
                match crate::sources::kernel_ts::recv_with_timestamp(fd, &mut buf, &anchor) {
                    Ok((n, ts)) => (n as isize, ts),
                    Err(err) => {
                        if err.kind() == std::io::ErrorKind::WouldBlock
                            || err.kind() == std::io::ErrorKind::TimedOut
                        {
                            continue;
                        }
                        warn!("Raw packet capture recv error: {}", err);
                        continue;
                    }
                }
            } else {
                let n = unsafe {
                    libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
                };
                let ts = Instant::now();
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
                (n, ts)
            };

            raw_count += 1;
            let frame = &buf[..n as usize];

            let src_ip = if has_any_filter { extract_src_ip(frame) } else { None };

            if let Some(payload) = extract_udp_payload(frame) {
                if let Some(key) = parse_shred_key(payload) {
                    parsed_count += 1;
                    for (i, route) in routes.iter().enumerate() {
                        if route_matches(route, src_ip) {
                            route_counts[i] += 1;
                            let event = ShredEvent {
                                source: route.source_id,
                                key,
                                received_at,
                            };
                            if tx.try_send(event).is_err() {
                                drops.inc(route.source_id);
                            }
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

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Build an Ethernet+IPv4+UDP frame with optional 802.1Q VLAN tag.
        fn build_frame(vlan_tag: Option<u16>, src_ip: [u8; 4], dst_port: u16, payload: &[u8]) -> Vec<u8> {
            let mut buf = Vec::new();
            // dst MAC (6) + src MAC (6)
            buf.extend_from_slice(&[0u8; 12]);
            // VLAN tag if requested
            if let Some(vid) = vlan_tag {
                buf.extend_from_slice(&[0x81, 0x00]);                  // 802.1Q TPID
                buf.extend_from_slice(&(vid & 0x0fff).to_be_bytes());  // PCP/DEI/VID
            }
            // Inner ethertype: IPv4
            buf.extend_from_slice(&[0x08, 0x00]);
            // IPv4 header (20 bytes, no options)
            let total_len = (20 + 8 + payload.len()) as u16;
            buf.push(0x45);                              // version 4, IHL 5
            buf.push(0x00);                              // TOS
            buf.extend_from_slice(&total_len.to_be_bytes());
            buf.extend_from_slice(&[0x00, 0x00]);        // identification
            buf.extend_from_slice(&[0x00, 0x00]);        // flags+fragoff (none)
            buf.push(64);                                // TTL
            buf.push(17);                                // proto = UDP
            buf.extend_from_slice(&[0x00, 0x00]);        // checksum (unused)
            buf.extend_from_slice(&src_ip);              // src IP
            buf.extend_from_slice(&[10, 0, 0, 1]);       // dst IP
            // UDP header (8 bytes)
            buf.extend_from_slice(&1234u16.to_be_bytes());  // src port
            buf.extend_from_slice(&dst_port.to_be_bytes());
            let udp_len = (8 + payload.len()) as u16;
            buf.extend_from_slice(&udp_len.to_be_bytes());
            buf.extend_from_slice(&[0x00, 0x00]);        // checksum (unused)
            buf.extend_from_slice(payload);
            buf
        }

        #[test]
        fn ip_header_offset_plain_ipv4() {
            let f = build_frame(None, [1, 2, 3, 4], 8001, &[]);
            assert_eq!(ip_header_offset(&f), Some(14));
        }

        #[test]
        fn ip_header_offset_vlan_tagged_ipv4() {
            let f = build_frame(Some(10), [1, 2, 3, 4], 8001, &[]);
            assert_eq!(ip_header_offset(&f), Some(18));
        }

        #[test]
        fn ip_header_offset_rejects_non_ip_ethertype() {
            let mut buf = vec![0u8; 12];
            buf.extend_from_slice(&[0x08, 0x06]); // ARP
            assert_eq!(ip_header_offset(&buf), None);
        }

        #[test]
        fn ip_header_offset_rejects_vlan_carrying_non_ipv4() {
            let mut buf = vec![0u8; 12];
            buf.extend_from_slice(&[0x81, 0x00]); // VLAN TPID
            buf.extend_from_slice(&[0x00, 0x0a]); // VID 10
            buf.extend_from_slice(&[0x86, 0xdd]); // IPv6 ethertype
            assert_eq!(ip_header_offset(&buf), None);
        }

        #[test]
        fn ip_header_offset_truncated_frame() {
            assert_eq!(ip_header_offset(&[0u8; 13]), None);
            // VLAN header present but inner ethertype truncated
            let mut buf = vec![0u8; 12];
            buf.extend_from_slice(&[0x81, 0x00]);
            buf.extend_from_slice(&[0x00, 0x0a]);
            assert_eq!(ip_header_offset(&buf), None);
        }

        #[test]
        fn extract_src_ip_plain_and_vlan() {
            let plain = build_frame(None, [7, 8, 9, 10], 8001, &[]);
            assert_eq!(extract_src_ip(&plain), Some(Ipv4Addr::new(7, 8, 9, 10)));
            let vlan = build_frame(Some(42), [11, 12, 13, 14], 8001, &[]);
            assert_eq!(extract_src_ip(&vlan), Some(Ipv4Addr::new(11, 12, 13, 14)));
        }

        #[test]
        fn extract_udp_payload_plain_and_vlan() {
            let payload = b"hello-shred";
            let plain = build_frame(None, [1, 2, 3, 4], 8001, payload);
            assert_eq!(extract_udp_payload(&plain), Some(&payload[..]));
            let vlan = build_frame(Some(7), [1, 2, 3, 4], 8001, payload);
            assert_eq!(extract_udp_payload(&vlan), Some(&payload[..]));
        }

        #[test]
        fn extract_udp_payload_rejects_non_udp() {
            let mut f = build_frame(None, [1, 2, 3, 4], 8001, b"x");
            f[14 + 9] = 6; // change proto to TCP
            assert_eq!(extract_udp_payload(&f), None);
        }

        #[test]
        fn extract_udp_payload_rejects_fragmented() {
            let mut f = build_frame(None, [1, 2, 3, 4], 8001, b"x");
            // Set non-zero fragment offset (low 13 bits of flags+fragoff at IP+6).
            f[14 + 6] = 0x00;
            f[14 + 7] = 0x01;
            assert_eq!(extract_udp_payload(&f), None);
        }

        #[test]
        fn route_matches_include_and_exclude() {
            let route = PcapRoute {
                source_id: SourceId(1),
                include_ips: [Ipv4Addr::new(1, 1, 1, 1)].into_iter().collect(),
                exclude_ips: HashSet::new(),
            };
            assert!(route_matches(&route, Some(Ipv4Addr::new(1, 1, 1, 1))));
            assert!(!route_matches(&route, Some(Ipv4Addr::new(2, 2, 2, 2))));
            assert!(!route_matches(&route, None));

            let route = PcapRoute {
                source_id: SourceId(1),
                include_ips: HashSet::new(),
                exclude_ips: [Ipv4Addr::new(9, 9, 9, 9)].into_iter().collect(),
            };
            assert!(route_matches(&route, Some(Ipv4Addr::new(1, 1, 1, 1))));
            assert!(!route_matches(&route, Some(Ipv4Addr::new(9, 9, 9, 9))));
        }
    }
}
