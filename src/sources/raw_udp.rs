use std::net::UdpSocket;
use std::time::Instant;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use anyhow::Result;

use crate::config::RawUdpConfig;
use crate::registry::{ShredEvent, SourceId};
use crate::shred::parse_shred_key;

pub async fn run(
    config: RawUdpConfig,
    source_id: SourceId,
    tx: mpsc::UnboundedSender<ShredEvent>,
    cancel: CancellationToken,
) -> Result<()> {
    let bind_addr = config.bind_addr.clone();

    tokio::task::spawn_blocking(move || {
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

        info!("Raw UDP listener started on {}", bind_addr);
        let mut buf = vec![0u8; 1280];

        loop {
            if cancel.is_cancelled() {
                break;
            }

            match socket.recv_from(&mut buf) {
                Ok((len, _addr)) => {
                    let received_at = Instant::now();
                    if let Some(key) = parse_shred_key(&buf[..len]) {
                        let _ = tx.send(ShredEvent { source: source_id, key, received_at });
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => {
                    warn!("Raw UDP recv error: {}", e);
                }
            }
        }
        info!("Raw UDP listener stopped");
    });

    Ok(())
}
