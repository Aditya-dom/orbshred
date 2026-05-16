use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::str::FromStr;
use std::time::{Duration, Instant};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use anyhow::Result;

use crate::config::DoubleZeroConfig;
use crate::registry::{DropCounters, ShredEvent, SourceId};
use crate::shred::parse_shred_key;
use crate::sources::kernel_ts::ClockAnchor;

pub async fn run(
    config: DoubleZeroConfig,
    source_id: SourceId,
    anchor: ClockAnchor,
    tx: mpsc::Sender<ShredEvent>,
    drops: DropCounters,
    cancel: CancellationToken,
) -> Result<()> {
    let pin_cpu = config.pin_cpu;
    tokio::task::spawn_blocking(move || {
        if let Some(cpu) = pin_cpu {
            match crate::sources::affinity::pin_current_thread(cpu) {
                Ok(()) => info!("DoubleZero: pinned listener thread to CPU {}", cpu),
                Err(e) => warn!("DoubleZero: failed to pin to CPU {}: {}", cpu, e),
            }
        }

        let multicast_ip = match Ipv4Addr::from_str(&config.multicast_group) {
            Ok(ip) => ip,
            Err(e) => {
                error!("Invalid multicast group IP: {}", e);
                return;
            }
        };

        // Create a UDP socket with SO_REUSEADDR
        let socket = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) {
            Ok(s) => s,
            Err(e) => {
                error!("DoubleZero: socket create failed: {}", e);
                return;
            }
        };

        socket.set_reuse_address(true).ok();
        #[cfg(unix)]
        socket.set_reuse_port(true).ok();

        let bind_addr: SocketAddr = format!("0.0.0.0:{}", config.port).parse().unwrap();
        if let Err(e) = socket.bind(&bind_addr.into()) {
            error!("DoubleZero: bind failed: {}", e);
            return;
        }

        // Join multicast using interface index (ip_mreqn) rather than interface IP.
        // doublezero1 is a WireGuard tunnel and may have no routable IPv4 address,
        // so the classic ip_mreq approach (join_multicast_v4 by IP) would silently
        // fall back to INADDR_ANY and join on the wrong interface.
        if let Err(e) = join_multicast_by_index(&socket, multicast_ip, &config.interface) {
            error!("DoubleZero: join_multicast failed: {}", e);
            return;
        }

        // Disable receiving multicast from all groups system-wide (IP_MULTICAST_ALL=0)
        // This ensures we only get packets for groups we explicitly joined
        #[cfg(target_os = "linux")]
        unsafe {
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();
            let val: libc::c_int = 0;
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_MULTICAST_ALL,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        socket.set_read_timeout(Some(Duration::from_millis(100))).ok();

        let std_socket: UdpSocket = socket.into();
        let kernel_ts_enabled = enable_kernel_ts_on_udp(&std_socket);
        info!(
            "DoubleZero multicast listener started (group={}, port={}, iface={}, {})",
            multicast_ip, config.port, config.interface,
            if kernel_ts_enabled { "kernel timestamps" } else { "userland timestamps" }
        );

        let mut raw_count: u64 = 0;
        let mut parsed_count: u64 = 0;
        let mut last_log = std::time::Instant::now();
        run_dz_recv_loop(
            &std_socket,
            source_id,
            &anchor,
            &tx,
            &drops,
            &cancel,
            kernel_ts_enabled,
            &mut raw_count,
            &mut parsed_count,
            &mut last_log,
        );
        if raw_count > 0 {
            info!(
                "DoubleZero listener stopped ({} raw packets, {} parsed)",
                raw_count, parsed_count
            );
        } else {
            warn!("DoubleZero listener stopped — zero packets received (multicast join may have failed or iptables is blocking)");
        }
    });

    Ok(())
}

/// Join a multicast group using the interface index (ip_mreqn) rather than its IP address.
/// This is required for interfaces like doublezero1 that may have no IPv4 address assigned.
#[cfg(target_os = "linux")]
fn join_multicast_by_index(socket: &Socket, multicast_ip: Ipv4Addr, iface_name: &str) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::io::AsRawFd;

    let iface_index = unsafe {
        let name = CString::new(iface_name)?;
        libc::if_nametoindex(name.as_ptr())
    };
    if iface_index == 0 {
        anyhow::bail!("Interface '{}' not found (if_nametoindex returned 0)", iface_name);
    }

    let octets = multicast_ip.octets();
    let mreqn = libc::ip_mreqn {
        imr_multiaddr: libc::in_addr {
            s_addr: u32::from_be_bytes(octets).to_be(),
        },
        imr_address: libc::in_addr { s_addr: 0 }, // INADDR_ANY
        imr_ifindex: iface_index as libc::c_int,
    };

    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_ADD_MEMBERSHIP,
            &mreqn as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::ip_mreqn>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn join_multicast_by_index(socket: &Socket, multicast_ip: Ipv4Addr, iface_name: &str) -> Result<()> {
    // On non-Linux (e.g. macOS for local testing): fall back to join by interface IP
    let iface_ip = get_interface_ip(iface_name).unwrap_or(Ipv4Addr::UNSPECIFIED);
    socket.join_multicast_v4(&multicast_ip, &iface_ip)?;
    Ok(())
}

#[cfg(target_os = "linux")]
const RECV_BATCH_SIZE: usize = 64;

#[cfg(target_os = "linux")]
fn enable_kernel_ts_on_udp(socket: &UdpSocket) -> bool {
    use std::os::unix::io::AsRawFd;
    match crate::sources::kernel_ts::enable_kernel_timestamps(socket.as_raw_fd()) {
        Ok(()) => true,
        Err(e) => {
            warn!("DoubleZero: SO_TIMESTAMPNS unavailable, using userland timestamps: {}", e);
            false
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn enable_kernel_ts_on_udp(_socket: &UdpSocket) -> bool { false }

#[allow(clippy::too_many_arguments)]
fn run_dz_recv_loop(
    socket: &UdpSocket,
    source_id: SourceId,
    anchor: &ClockAnchor,
    tx: &mpsc::Sender<ShredEvent>,
    drops: &DropCounters,
    cancel: &CancellationToken,
    kernel_ts_enabled: bool,
    raw_count: &mut u64,
    parsed_count: &mut u64,
    last_log: &mut std::time::Instant,
) {
    #[cfg(target_os = "linux")]
    if kernel_ts_enabled {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        let mut batch = crate::sources::kernel_ts::BatchRecv::new(RECV_BATCH_SIZE, 1280);
        loop {
            if cancel.is_cancelled() { break; }
            match batch.recvmmsg(fd) {
                Ok(0) => continue,
                Ok(n) => for i in 0..n {
                    let frame = batch.frame(i);
                    *raw_count += 1;
                    if *raw_count == 1 {
                        let dump_len = frame.len().min(96);
                        let hex: String = frame[..dump_len]
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(" ");
                        info!(
                            "DoubleZero: first packet (kernel-ts) len={} header bytes: {}",
                            frame.len(), hex
                        );
                    }
                    if let Some(key) = parse_shred_key(frame) {
                        *parsed_count += 1;
                        let event = ShredEvent {
                            source: source_id,
                            key,
                            received_at: batch.timestamp(i, anchor),
                        };
                        if tx.try_send(event).is_err() {
                            drops.inc(source_id);
                        }
                    } else {
                        debug!("DoubleZero: packet len={} did not parse as shred", frame.len());
                    }
                    if last_log.elapsed() >= Duration::from_secs(5) {
                        info!(
                            "DoubleZero: {} raw packets received, {} parsed as shreds",
                            *raw_count, *parsed_count
                        );
                        *last_log = std::time::Instant::now();
                    }
                },
                Err(e) => warn!("DoubleZero recvmmsg error: {}", e),
            }
        }
        return;
    }

    // Fallback path (userland timestamps, single recv).
    let _ = anchor;
    let _ = kernel_ts_enabled;
    let mut buf = vec![0u8; 1280];
    loop {
        if cancel.is_cancelled() { break; }
        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                let received_at = Instant::now();
                *raw_count += 1;
                if *raw_count == 1 {
                    let dump_len = len.min(96);
                    let hex: String = buf[..dump_len]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    info!(
                        "DoubleZero: first packet from {} len={} header bytes: {}",
                        src, len, hex
                    );
                }
                if let Some(key) = parse_shred_key(&buf[..len]) {
                    *parsed_count += 1;
                    let event = ShredEvent { source: source_id, key, received_at };
                    if tx.try_send(event).is_err() {
                        drops.inc(source_id);
                    }
                } else {
                    debug!("DoubleZero: packet len={} did not parse as shred", len);
                }
                if last_log.elapsed() >= Duration::from_secs(5) {
                    info!(
                        "DoubleZero: {} raw packets received, {} parsed as shreds",
                        *raw_count, *parsed_count
                    );
                    *last_log = std::time::Instant::now();
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                  || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => warn!("DoubleZero recv error: {}", e),
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn get_interface_ip(iface_name: &str) -> Option<Ipv4Addr> {
    use std::process::Command;
    let output = Command::new("ip")
        .args(["addr", "show", iface_name])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&output.stdout);
    for line in s.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("inet ") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if let Some(addr_cidr) = parts.get(1) {
                let addr = addr_cidr.split('/').next()?;
                return Ipv4Addr::from_str(addr).ok();
            }
        }
    }
    None
}
