use std::net::UdpSocket;
use std::time::Instant;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use anyhow::Result;

use crate::config::RawUdpConfig;
use crate::registry::{DropCounters, ShredEvent, SourceId};
use crate::shred::parse_shred_key;
use crate::sources::kernel_ts::ClockAnchor;

/// Batch size for `recvmmsg`-based reception (Linux + kernel-ts path).
/// Sized to comfortably amortize syscall cost during slot-boundary bursts
/// while keeping memory footprint trivial (~80 KB at MTU 1280 × 64 frames).
#[cfg(target_os = "linux")]
const RECV_BATCH_SIZE: usize = 64;

pub async fn run(
    config: RawUdpConfig,
    source_id: SourceId,
    anchor: ClockAnchor,
    tx: mpsc::Sender<ShredEvent>,
    drops: DropCounters,
    cancel: CancellationToken,
) -> Result<()> {
    let bind_addr = config.bind_addr.clone();
    let pin_cpu = config.pin_cpu;

    tokio::task::spawn_blocking(move || {
        if let Some(cpu) = pin_cpu {
            match crate::sources::affinity::pin_current_thread(cpu) {
                Ok(()) => info!("Raw UDP: pinned listener thread to CPU {}", cpu),
                Err(e) => warn!("Raw UDP: failed to pin to CPU {}: {}", cpu, e),
            }
        }

        let socket = match UdpSocket::bind(&bind_addr) {
            Ok(s) => s,
            Err(e) => {
                error!("Raw UDP: failed to bind {}: {}", bind_addr, e);
                return;
            }
        };

        if config.recv_buf_size > 0 {
            if let Ok(cloned) = socket.try_clone() {
                let s2 = socket2::Socket::from(cloned);
                let _ = s2.set_recv_buffer_size(config.recv_buf_size);
            }
        }

        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(100)))
            .ok();

        let kernel_ts_enabled = enable_kernel_ts_on_udp(&socket);
        info!(
            "Raw UDP listener started on {} ({})",
            bind_addr,
            if kernel_ts_enabled { "kernel timestamps, batched recvmmsg" } else { "userland timestamps" }
        );

        run_recv_loop(socket, source_id, anchor, tx, drops, cancel, kernel_ts_enabled);
        info!("Raw UDP listener stopped");
    });

    Ok(())
}

#[cfg(target_os = "linux")]
fn run_recv_loop(
    socket: UdpSocket,
    source_id: SourceId,
    anchor: ClockAnchor,
    tx: mpsc::Sender<ShredEvent>,
    drops: DropCounters,
    cancel: CancellationToken,
    kernel_ts_enabled: bool,
) {
    use std::os::unix::io::AsRawFd;
    let fd = socket.as_raw_fd();
    if kernel_ts_enabled {
        let mut batch = crate::sources::kernel_ts::BatchRecv::new(RECV_BATCH_SIZE, 1280);
        loop {
            if cancel.is_cancelled() { break; }
            match batch.recvmmsg(fd) {
                Ok(0) => continue,
                Ok(n) => {
                    for i in 0..n {
                        let frame = batch.frame(i);
                        if let Some(key) = parse_shred_key(frame) {
                            let event = ShredEvent {
                                source: source_id,
                                key,
                                received_at: batch.timestamp(i, &anchor),
                            };
                            if tx.try_send(event).is_err() {
                                drops.inc(source_id);
                            }
                        }
                    }
                }
                Err(e) => warn!("Raw UDP recvmmsg error: {}", e),
            }
        }
    } else {
        single_recv_loop(socket, source_id, tx, drops, cancel);
    }
}

#[cfg(not(target_os = "linux"))]
fn run_recv_loop(
    socket: UdpSocket,
    source_id: SourceId,
    _anchor: ClockAnchor,
    tx: mpsc::Sender<ShredEvent>,
    drops: DropCounters,
    cancel: CancellationToken,
    _kernel_ts_enabled: bool,
) {
    single_recv_loop(socket, source_id, tx, drops, cancel);
}

fn single_recv_loop(
    socket: UdpSocket,
    source_id: SourceId,
    tx: mpsc::Sender<ShredEvent>,
    drops: DropCounters,
    cancel: CancellationToken,
) {
    let mut buf = vec![0u8; 1280];
    loop {
        if cancel.is_cancelled() { break; }
        match socket.recv_from(&mut buf) {
            Ok((len, _)) => {
                let received_at = Instant::now();
                if let Some(key) = parse_shred_key(&buf[..len]) {
                    let event = ShredEvent { source: source_id, key, received_at };
                    if tx.try_send(event).is_err() {
                        drops.inc(source_id);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                  || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => warn!("Raw UDP recv error: {}", e),
        }
    }
}

#[cfg(target_os = "linux")]
fn enable_kernel_ts_on_udp(socket: &UdpSocket) -> bool {
    use std::os::unix::io::AsRawFd;
    match crate::sources::kernel_ts::enable_kernel_timestamps(socket.as_raw_fd()) {
        Ok(()) => true,
        Err(e) => {
            warn!("Could not enable SO_TIMESTAMPNS, falling back to userland timestamps: {}", e);
            false
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn enable_kernel_ts_on_udp(_socket: &UdpSocket) -> bool { false }
