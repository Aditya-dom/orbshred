use std::time::Instant;
use std::collections::HashMap;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;
use tracing::{info, warn};
use anyhow::Result;
use futures::StreamExt;

use crate::config::YellowstoneConfig;
use crate::registry::{GrpcLatencyEvent, SlotEvent, SourceId};

pub mod proto {
    pub mod geyser {
        tonic::include_proto!("geyser");
    }
}

use proto::geyser::geyser_client::GeyserClient;
use proto::geyser::{
    subscribe_update::UpdateOneof, SlotStatus, SubscribeRequest, SubscribeRequestFilterAccounts,
    SubscribeRequestFilterEntry, SubscribeRequestFilterSlots,
};

pub async fn run(
    config: YellowstoneConfig,
    source_id: SourceId,
    account_source_id: Option<SourceId>,
    tx: mpsc::UnboundedSender<SlotEvent>,
    grpc_tx: mpsc::UnboundedSender<GrpcLatencyEvent>,
    cancel: CancellationToken,
) -> Result<()> {
    tokio::spawn(async move {
        loop {
            if cancel.is_cancelled() {
                break;
            }

            match connect_and_stream(&config, &tx, &grpc_tx, &cancel, source_id, account_source_id).await {
                Ok(()) => break,
                Err(e) => {
                    warn!("Yellowstone stream error: {}, reconnecting...", e);
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                        _ = cancel.cancelled() => { break; }
                    }
                }
            }
        }
        info!("Yellowstone listener stopped");
    });

    Ok(())
}

/// Recorded when Yellowstone delivers an entry event for a slot.
struct EntryRecord {
    #[allow(dead_code)]
    starting_tx_index: u64,
    #[allow(dead_code)]
    tx_count: u64,
    received_at: Instant,
}

async fn connect_and_stream(
    config: &YellowstoneConfig,
    tx: &mpsc::UnboundedSender<SlotEvent>,
    grpc_tx: &mpsc::UnboundedSender<GrpcLatencyEvent>,
    cancel: &CancellationToken,
    source_id: SourceId,
    account_source_id: Option<SourceId>,
) -> anyhow::Result<()> {
    let channel = Channel::from_shared(config.endpoint.clone())?
        .connect()
        .await?;

    info!("Yellowstone: connected to {}", config.endpoint);

    let mut slots_filter = HashMap::new();
    slots_filter.insert(
        "bench".to_string(),
        SubscribeRequestFilterSlots {
            filter_by_commitment: None,
            interslot_updates: Some(true),
        },
    );

    let has_account = !config.account_pubkey.is_empty() && account_source_id.is_some();

    // When account_pubkey is set: also subscribe to account updates and entry events.
    // Entry events let us timestamp exactly when each entry was processed — the baseline
    // for measuring pure gRPC delivery overhead (entry processed → account update delivered).
    let mut accounts_filter = HashMap::new();
    let mut entry_filter = HashMap::new();
    if has_account {
        accounts_filter.insert(
            "bench_account".to_string(),
            SubscribeRequestFilterAccounts {
                account: vec![config.account_pubkey.clone()],
                owner: vec![],
            },
        );
        entry_filter.insert("bench_entry".to_string(), SubscribeRequestFilterEntry {});
    }

    let request = SubscribeRequest {
        slots: slots_filter,
        accounts: accounts_filter,
        transactions: HashMap::new(),
        transactions_status: HashMap::new(),
        blocks: HashMap::new(),
        blocks_meta: HashMap::new(),
        entry: entry_filter,
        // PROCESSED = 0; deliver account updates as early as possible
        commitment: if has_account { Some(0) } else { None },
        accounts_data_slice: vec![],
        ping: None,
    };

    let (tx_req, rx_req) = tokio::sync::mpsc::channel(4);
    tx_req.send(request).await?;

    let x_token = config.x_token.clone();
    let mut grpc_request =
        tonic::Request::new(tokio_stream::wrappers::ReceiverStream::new(rx_req));
    if !x_token.is_empty() {
        grpc_request.metadata_mut().insert(
            "x-token",
            x_token.parse().map_err(|e: tonic::metadata::errors::InvalidMetadataValue| {
                anyhow::anyhow!("Invalid x-token metadata value: {}", e)
            })?,
        );
    }

    let mut client = GeyserClient::new(channel);
    let response = client.subscribe(grpc_request).await?;
    let mut stream = response.into_inner();

    // slot → list of entries received, used to find the entry baseline for each account update.
    // We only populate this when has_account is true.
    let mut entry_map: HashMap<u64, Vec<EntryRecord>> = HashMap::new();
    let mut max_slot_seen: u64 = 0;

    loop {
        let msg: Option<Result<proto::geyser::SubscribeUpdate, tonic::Status>> =
            tokio::select! {
                msg = stream.next() => msg,
                _ = cancel.cancelled() => None,
            };

        match msg {
            Some(Ok(update)) => {
                let received_at = Instant::now();
                match update.update_oneof {
                    Some(UpdateOneof::Slot(slot_update)) => {
                        if slot_update.status == SlotStatus::SlotFirstShredReceived as i32 {
                            let _ = tx.send(SlotEvent {
                                source: source_id,
                                slot: slot_update.slot,
                                received_at,
                            });
                        }
                    }
                    Some(UpdateOneof::Entry(entry_update)) => {
                        let slot = entry_update.slot;
                        max_slot_seen = max_slot_seen.max(slot);
                        entry_map.entry(slot).or_default().push(EntryRecord {
                            starting_tx_index: entry_update.starting_transaction_index,
                            tx_count: entry_update.executed_transaction_count,
                            received_at,
                        });
                        // Keep only recent slots to bound memory
                        if max_slot_seen > 300 {
                            entry_map.retain(|&s, _| s >= max_slot_seen - 300);
                        }
                    }
                    Some(UpdateOneof::Account(acct_update)) => {
                        // Skip startup snapshots
                        if !acct_update.is_startup {
                            if let Some(aid) = account_source_id {
                                // Emit the slot-vs-first-shred measurement (existing behaviour)
                                let _ = tx.send(SlotEvent {
                                    source: aid,
                                    slot: acct_update.slot,
                                    received_at,
                                });

                                // Emit gRPC overhead: find the latest entry delivered for this
                                // slot that arrived before this account update.
                                // In Geyser's replay order, entries precede account updates for
                                // the same entry, so this gives us the most recent entry whose
                                // processing triggered the account change.
                                if let Some(entries) = entry_map.get(&acct_update.slot) {
                                    if let Some(entry) = entries
                                        .iter()
                                        .filter(|e| e.received_at <= received_at)
                                        .max_by_key(|e| e.received_at)
                                    {
                                        let delta_ns = received_at
                                            .duration_since(entry.received_at)
                                            .as_nanos() as u64;
                                        let _ = grpc_tx.send(GrpcLatencyEvent {
                                            source: aid,
                                            latency_ns: delta_ns,
                                        });
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            Some(Err(e)) => return Err(e.into()),
            None => break,
        }
    }

    Ok(())
}
