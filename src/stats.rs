use std::time::Instant;
use crate::registry::{Registry, SourceId};
use crate::shred::ShredType;

/// Stats for a shred-level source (Raw UDP, Jito UDP, DoubleZero, …)
#[derive(Debug, Default)]
pub struct SourceStats {
    pub id: SourceId,
    pub name: String,
    pub received: u64,
    pub data_shreds: u64,
    pub code_shreds: u64,
    pub wins: u64,
    pub missed: u64,
    pub dupes: u64,
    /// Latency deltas in nanoseconds (vs global first arrival)
    pub latency_ns: Vec<u64>,
}

/// Stats for an entry/slot-level source (Yellowstone, Jito gRPC entries)
#[derive(Debug)]
pub struct EntrySourceStats {
    pub id: SourceId,
    pub name: String,
    pub slots_seen: u64,
    /// Latency vs first shred arrival for same slot (nanoseconds)
    pub latency_ns: Vec<u64>,
}

#[derive(Debug, Default)]
pub struct Percentiles {
    pub p50: u64,
    pub p90: u64,
    pub p95: u64,
    pub p99: u64,
    pub p99_9: u64,
    pub max: u64,
    #[allow(dead_code)]
    pub min: u64,
    #[allow(dead_code)]
    pub mean: u64,
}

pub fn compute_percentiles(mut v: Vec<u64>) -> Percentiles {
    if v.is_empty() {
        return Percentiles::default();
    }
    v.sort_unstable();
    let mean = v.iter().sum::<u64>() / v.len() as u64;
    Percentiles {
        min: v[0],
        p50: percentile(&v, 50.0),
        p90: percentile(&v, 90.0),
        p95: percentile(&v, 95.0),
        p99: percentile(&v, 99.0),
        p99_9: percentile(&v, 99.9),
        max: *v.last().unwrap(),
        mean,
    }
}

pub fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 * p / 100.0).ceil() as usize).saturating_sub(1);
    sorted[idx.min(sorted.len() - 1)]
}

#[derive(Debug, Default)]
pub struct SlotStats {
    pub total_slots: u64,
    /// One entry per active entry-level source
    pub entry_sources: Vec<EntrySourceStats>,
}

/// Per-source gRPC overhead stats: entry processed → account update delivered.
/// Only populated for Yellowstone sources with an account_pubkey configured.
#[derive(Debug)]
pub struct GrpcOverheadStats {
    #[allow(dead_code)]
    pub id: SourceId,
    pub name: String,
    pub samples: u64,
    pub latency_ns: Vec<u64>,
}

pub struct BenchmarkStats {
    pub sources: Vec<SourceStats>,
    pub total_unique_shreds: u64,
    pub slot_stats: SlotStats,
    pub grpc_overhead: Vec<GrpcOverheadStats>,
    pub duration_secs: f64,
    pub min_slot: u64,
    pub max_slot: u64,
}

pub fn compute_stats(
    registry: &Registry,
    active_shred_sources: &[(SourceId, String)],
    active_entry_sources: &[(SourceId, String)],
    duration_secs: f64,
) -> BenchmarkStats {
    let total_unique_shreds = registry.shreds.len() as u64;

    let mut min_slot = u64::MAX;
    let mut max_slot = 0u64;
    for entry in registry.slots.iter() {
        let slot = *entry.key();
        min_slot = min_slot.min(slot);
        max_slot = max_slot.max(slot);
    }
    if min_slot == u64::MAX {
        min_slot = 0;
    }

    // Per shred-level source stats
    let mut source_stats: Vec<SourceStats> = active_shred_sources
        .iter()
        .map(|(id, name)| SourceStats { id: *id, name: name.clone(), ..Default::default() })
        .collect();

    for entry in registry.shreds.iter() {
        let key = entry.key();
        let rec = entry.value();

        for stats in &mut source_stats {
            let arrivals_from_source: Vec<Instant> = rec
                .arrivals
                .iter()
                .filter(|(src, _)| *src == stats.id)
                .map(|(_, t)| *t)
                .collect();

            if arrivals_from_source.is_empty() {
                stats.missed += 1;
                continue;
            }

            let first = *arrivals_from_source.iter().min().unwrap();
            stats.received += 1;
            match key.shred_type {
                ShredType::Data => stats.data_shreds += 1,
                ShredType::Code => stats.code_shreds += 1,
            }
            if arrivals_from_source.len() > 1 {
                stats.dupes += (arrivals_from_source.len() - 1) as u64;
            }
            let delta = first.duration_since(rec.first_seen).as_nanos() as u64;
            if delta == 0 {
                stats.wins += 1;
            }
            stats.latency_ns.push(delta);
        }
    }

    // Per entry/slot-level source stats
    let mut slot_stats = SlotStats {
        total_slots: registry.slots.len() as u64,
        entry_sources: active_entry_sources
            .iter()
            .map(|(id, name)| EntrySourceStats { id: *id, name: name.clone(), slots_seen: 0, latency_ns: vec![] })
            .collect(),
    };

    for slot_entry in registry.slots.iter() {
        let rec = slot_entry.value();
        for entry_stats in &mut slot_stats.entry_sources {
            if let Some(&(_, arrival)) = rec
                .entry_arrivals
                .iter()
                .find(|(s, _)| *s == entry_stats.id)
            {
                entry_stats.slots_seen += 1;
                let delta = if arrival >= rec.first_shred_at {
                    arrival.duration_since(rec.first_shred_at).as_nanos() as u64
                } else {
                    0
                };
                entry_stats.latency_ns.push(delta);
            }
        }
    }

    // gRPC overhead stats: entry processed → account update delivered
    let grpc_overhead: Vec<GrpcOverheadStats> = active_entry_sources
        .iter()
        .filter_map(|(id, name)| {
            registry.grpc_latencies.get(id).map(|samples| {
                let v = samples.clone();
                let count = v.len() as u64;
                GrpcOverheadStats { id: *id, name: name.clone(), samples: count, latency_ns: v }
            })
        })
        .collect();

    BenchmarkStats {
        sources: source_stats,
        total_unique_shreds,
        slot_stats,
        grpc_overhead,
        duration_secs,
        min_slot,
        max_slot,
    }
}
