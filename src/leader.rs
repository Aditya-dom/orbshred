use std::collections::HashSet;
use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::info;

#[derive(Deserialize)]
struct RpcResponse {
    result: Option<serde_json::Value>,
    error: Option<serde_json::Value>,
}

/// Fetch the leader schedule from the RPC and return the set of slots
/// assigned to `leader_pubkey` for the current epoch.
pub async fn fetch_leader_slots(rpc_url: &str, leader_pubkey: &str) -> Result<HashSet<u64>> {
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getLeaderSchedule",
        "params": [
            null,
            { "identity": leader_pubkey }
        ]
    });

    info!("Fetching leader schedule for {} from {}", leader_pubkey, rpc_url);

    let resp: RpcResponse = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("Failed to connect to RPC: {}", rpc_url))?
        .json()
        .await
        .with_context(|| "Failed to parse RPC response")?;

    if let Some(err) = resp.error {
        anyhow::bail!("RPC error: {}", err);
    }

    let result = resp.result
        .ok_or_else(|| anyhow::anyhow!("RPC returned no result for getLeaderSchedule"))?;

    // The result is { "ValidatorPubkey": [slot_index, slot_index, ...] }
    // slot_index values are offsets from the epoch's first slot.
    // We also need the epoch info to convert to absolute slots.
    let schedule_map = result.as_object()
        .ok_or_else(|| anyhow::anyhow!("Expected object in leader schedule result"))?;

    let slot_indices: Vec<u64> = schedule_map
        .get(leader_pubkey)
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_u64()).collect())
        .unwrap_or_default();

    if slot_indices.is_empty() {
        anyhow::bail!(
            "Validator {} has no leader slots in the current epoch. \
             Check if the pubkey is correct and the validator is active.",
            leader_pubkey
        );
    }

    // Get the epoch's first slot
    let epoch_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getEpochInfo"
    });

    let epoch_resp: RpcResponse = client
        .post(rpc_url)
        .json(&epoch_body)
        .send()
        .await
        .with_context(|| "Failed to fetch epoch info")?
        .json()
        .await
        .with_context(|| "Failed to parse epoch info response")?;

    if let Some(err) = epoch_resp.error {
        anyhow::bail!("RPC error on getEpochInfo: {}", err);
    }

    let epoch_result = epoch_resp.result
        .ok_or_else(|| anyhow::anyhow!("No result from getEpochInfo"))?;

    let absolute_slot = epoch_result.get("absoluteSlot")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("Missing absoluteSlot in epoch info"))?;
    let slot_index = epoch_result.get("slotIndex")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("Missing slotIndex in epoch info"))?;

    let epoch_first_slot = absolute_slot - slot_index;

    let leader_slots: HashSet<u64> = slot_indices
        .into_iter()
        .map(|idx| epoch_first_slot + idx)
        .collect();

    let current_slot = absolute_slot;
    let future_slots: Vec<u64> = leader_slots.iter()
        .filter(|&&s| s > current_slot)
        .copied()
        .collect();

    if future_slots.is_empty() {
        anyhow::bail!(
            "Validator {} has {} leader slots in the current epoch but all are in the past \
             (current slot: {}). No upcoming leader slots to benchmark.",
            leader_pubkey,
            leader_slots.len(),
            current_slot
        );
    }

    let next_leader_slot = *future_slots.iter().min().unwrap();
    info!(
        "Leader schedule loaded: {} has {} leader slots in current epoch ({} upcoming, next: {})",
        leader_pubkey,
        leader_slots.len(),
        future_slots.len(),
        next_leader_slot
    );

    Ok(leader_slots)
}
