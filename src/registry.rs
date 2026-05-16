use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use dashmap::DashMap;
use crate::shred::ShredKey;
use crate::sources::kernel_ts::ClockAnchor;

/// Dynamic source identifier — assigned sequentially at startup.
/// Use the name map in main/stats for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct SourceId(pub u32);

/// Per-source counter for events dropped due to bounded-channel backpressure.
/// Cheap to clone (internally `Arc<DashMap>`); pass to each source's run().
#[derive(Clone, Default)]
pub struct DropCounters {
    inner: Arc<DashMap<SourceId, AtomicU64>>,
}

impl DropCounters {
    pub fn new() -> Self { Self::default() }

    /// Increment the drop counter for `src` by 1.
    pub fn inc(&self, src: SourceId) {
        self.inner
            .entry(src)
            .or_default()
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Read the current drop count for `src` (0 if no drops were recorded).
    pub fn get(&self, src: SourceId) -> u64 {
        self.inner
            .get(&src)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
}

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
    /// Shared anchor for converting kernel `CLOCK_REALTIME` timestamps into
    /// `Instant`s compatible with `start_time` and per-shred arrivals. Sources
    /// that opt into kernel-side timestamping read this once at startup.
    pub clock_anchor: ClockAnchor,
}

impl Registry {
    pub fn new() -> Self {
        let clock_anchor = ClockAnchor::capture();
        Self {
            shreds: DashMap::new(),
            slots: DashMap::new(),
            grpc_latencies: DashMap::new(),
            start_time: clock_anchor.instant,
            clock_anchor,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shred::{ShredKey, ShredType};
    use std::time::Duration;

    fn key(slot: u64, index: u32) -> ShredKey {
        ShredKey { slot, index, shred_type: ShredType::Data }
    }

    #[test]
    fn first_arrival_sets_first_seen_and_first_source() {
        let reg = Registry::new();
        let t0 = Instant::now();
        let k = key(100, 0);
        reg.record_shred(ShredEvent { source: SourceId(1), key: k, received_at: t0 });

        let rec = reg.shreds.get(&k).unwrap();
        assert_eq!(rec.first_source, SourceId(1));
        assert_eq!(rec.first_seen, t0);
        assert_eq!(rec.arrivals.len(), 1);
        assert_eq!(rec.arrivals[0], (SourceId(1), t0));
    }

    #[test]
    fn duplicate_from_same_source_appends_without_touching_first_seen() {
        let reg = Registry::new();
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_micros(50);
        let k = key(100, 0);

        reg.record_shred(ShredEvent { source: SourceId(1), key: k, received_at: t0 });
        reg.record_shred(ShredEvent { source: SourceId(1), key: k, received_at: t1 });

        let rec = reg.shreds.get(&k).unwrap();
        assert_eq!(rec.first_seen, t0, "first_seen must not change on duplicate");
        assert_eq!(rec.first_source, SourceId(1));
        assert_eq!(rec.arrivals.len(), 2);
    }

    #[test]
    fn second_source_appends_arrival() {
        let reg = Registry::new();
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_micros(20);
        let k = key(100, 0);

        reg.record_shred(ShredEvent { source: SourceId(1), key: k, received_at: t0 });
        reg.record_shred(ShredEvent { source: SourceId(2), key: k, received_at: t1 });

        let rec = reg.shreds.get(&k).unwrap();
        assert_eq!(rec.first_source, SourceId(1));
        assert_eq!(rec.first_seen, t0);
        assert_eq!(rec.arrivals.len(), 2);
        assert!(rec.arrivals.contains(&(SourceId(1), t0)));
        assert!(rec.arrivals.contains(&(SourceId(2), t1)));
    }

    #[test]
    fn slot_first_shred_tracks_earliest_arrival() {
        let reg = Registry::new();
        let t0 = Instant::now();
        let t_later = t0 + Duration::from_millis(2);
        let t_earlier = t0 - Duration::from_millis(1);

        // Insert later first, then earlier — slot first_shred_at must shrink to earliest.
        reg.record_shred(ShredEvent { source: SourceId(1), key: key(100, 0), received_at: t_later });
        reg.record_shred(ShredEvent { source: SourceId(2), key: key(100, 1), received_at: t_earlier });

        let slot = reg.slots.get(&100).unwrap();
        assert_eq!(slot.first_shred_at, t_earlier);
    }

    #[test]
    fn slot_first_shred_does_not_move_later() {
        let reg = Registry::new();
        let t0 = Instant::now();
        let t_later = t0 + Duration::from_millis(5);

        reg.record_shred(ShredEvent { source: SourceId(1), key: key(100, 0), received_at: t0 });
        reg.record_shred(ShredEvent { source: SourceId(1), key: key(100, 1), received_at: t_later });

        let slot = reg.slots.get(&100).unwrap();
        assert_eq!(slot.first_shred_at, t0);
    }

    #[test]
    fn record_slot_event_inserts_then_updates_to_earlier() {
        let reg = Registry::new();
        let t0 = Instant::now();
        let t_later = t0 + Duration::from_millis(10);
        let t_earlier = t0 - Duration::from_millis(1);

        // Initial insert (no shred event yet, so first_shred_at = received_at).
        reg.record_slot_event(SlotEvent { source: SourceId(9), slot: 200, received_at: t_later });
        // Same source with earlier instant: should overwrite the stored arrival.
        reg.record_slot_event(SlotEvent { source: SourceId(9), slot: 200, received_at: t_earlier });
        // Later instant from same source: must NOT overwrite.
        reg.record_slot_event(SlotEvent { source: SourceId(9), slot: 200, received_at: t_later });

        let slot = reg.slots.get(&200).unwrap();
        let entry = slot.entry_arrivals.iter().find(|(s, _)| *s == SourceId(9)).unwrap();
        assert_eq!(entry.1, t_earlier);
        assert_eq!(slot.entry_arrivals.len(), 1, "same source must not duplicate");
    }

    #[test]
    fn record_slot_event_separate_sources_both_recorded() {
        let reg = Registry::new();
        let t0 = Instant::now();

        reg.record_slot_event(SlotEvent { source: SourceId(9), slot: 200, received_at: t0 });
        reg.record_slot_event(SlotEvent { source: SourceId(10), slot: 200, received_at: t0 + Duration::from_millis(3) });

        let slot = reg.slots.get(&200).unwrap();
        assert_eq!(slot.entry_arrivals.len(), 2);
    }

    #[test]
    fn record_grpc_latency_accumulates_per_source() {
        let reg = Registry::new();
        reg.record_grpc_latency(GrpcLatencyEvent { source: SourceId(7), latency_ns: 1_000 });
        reg.record_grpc_latency(GrpcLatencyEvent { source: SourceId(7), latency_ns: 2_500 });
        reg.record_grpc_latency(GrpcLatencyEvent { source: SourceId(8), latency_ns: 500 });

        let s7 = reg.grpc_latencies.get(&SourceId(7)).unwrap();
        assert_eq!(s7.value().as_slice(), &[1_000u64, 2_500u64]);
        let s8 = reg.grpc_latencies.get(&SourceId(8)).unwrap();
        assert_eq!(s8.value().as_slice(), &[500u64]);
    }
}
