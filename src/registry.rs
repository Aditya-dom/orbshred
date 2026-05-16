use std::time::Instant;
use dashmap::DashMap;
use crate::shred::ShredKey;

/// Dynamic source identifier — assigned sequentially at startup.
/// Use the name map in main/stats for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct SourceId(pub u32);

/// Event from a shred-level source (Raw UDP, Jito UDP, DoubleZero)
pub struct ShredEvent {
    pub source: SourceId,
    pub key: ShredKey,
    pub received_at: Instant,
}

/// Event from an entry/slot-level source (Yellowstone, Jito gRPC entries)
pub struct SlotEvent {
    pub source: SourceId,
    pub slot: u64,
    pub received_at: Instant,
}

/// A single gRPC overhead sample: time from entry processed → account update delivered.
/// This measures pure Yellowstone gRPC delivery latency, not shred assembly time.
pub struct GrpcLatencyEvent {
    pub source: SourceId,
    pub latency_ns: u64,
}

/// Per-shred record in the registry
pub struct ShredRecord {
    pub first_seen: Instant,
    pub first_source: SourceId,
    /// All arrivals: (source, time). May have multiple from same source (dupes).
    pub arrivals: Vec<(SourceId, Instant)>,
}

/// Per-slot record
pub struct SlotRecord {
    /// Earliest arrival across all shred-level sources
    pub first_shred_at: Instant,
    /// First arrival per entry-level source
    pub entry_arrivals: Vec<(SourceId, Instant)>,
}

pub struct Registry {
    pub shreds: DashMap<ShredKey, ShredRecord>,
    pub slots: DashMap<u64, SlotRecord>,
    /// Per-source gRPC overhead samples (entry processed → account update delivered), in nanoseconds.
    pub grpc_latencies: DashMap<SourceId, Vec<u64>>,
    pub start_time: Instant,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            shreds: DashMap::new(),
            slots: DashMap::new(),
            grpc_latencies: DashMap::new(),
            start_time: Instant::now(),
        }
    }

    pub fn record_grpc_latency(&self, event: GrpcLatencyEvent) {
        self.grpc_latencies
            .entry(event.source)
            .or_default()
            .push(event.latency_ns);
    }

    pub fn record_shred(&self, event: ShredEvent) {
        let slot = event.key.slot;

        self.shreds
            .entry(event.key)
            .and_modify(|rec| {
                rec.arrivals.push((event.source, event.received_at));
            })
            .or_insert_with(|| ShredRecord {
                first_seen: event.received_at,
                first_source: event.source,
                arrivals: vec![(event.source, event.received_at)],
            });

        // Track earliest shred arrival per slot
        self.slots
            .entry(slot)
            .and_modify(|rec| {
                if event.received_at < rec.first_shred_at {
                    rec.first_shred_at = event.received_at;
                }
            })
            .or_insert_with(|| SlotRecord {
                first_shred_at: event.received_at,
                entry_arrivals: vec![],
            });
    }

    pub fn record_slot_event(&self, event: SlotEvent) {
        self.slots
            .entry(event.slot)
            .and_modify(|rec| {
                if let Some(existing) = rec
                    .entry_arrivals
                    .iter_mut()
                    .find(|(s, _)| *s == event.source)
                {
                    if event.received_at < existing.1 {
                        existing.1 = event.received_at;
                    }
                } else {
                    rec.entry_arrivals.push((event.source, event.received_at));
                }
            })
            .or_insert_with(|| SlotRecord {
                first_shred_at: event.received_at,
                entry_arrivals: vec![(event.source, event.received_at)],
            });
    }
}
