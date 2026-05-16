use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::Instant;
use serde::Serialize;
use chrono::Utc;
use anyhow::Result;

use crate::registry::{Registry, SourceId};

#[derive(Serialize)]
struct ShredLogEntry {
    slot: u64,
    index: u32,
    shred_type: String,
    first_source: String,
    first_seen_ns: u64,
    arrivals: Vec<ArrivalEntry>,
}

#[derive(Serialize)]
struct ArrivalEntry {
    source: String,
    delta_ns: u64,
}

pub fn write_log(
    registry: &Registry,
    path: &str,
    start: Instant,
    source_names: &HashMap<SourceId, String>,
) -> Result<()> {
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);

    writeln!(writer, "// orbshred log — {}", Utc::now().to_rfc3339())?;

    for entry in registry.shreds.iter() {
        let key = entry.key();
        let rec = entry.value();

        // Collect one entry per source (earliest arrival)
        let mut by_source: HashMap<SourceId, Instant> = HashMap::new();
        for &(src, t) in &rec.arrivals {
            by_source
                .entry(src)
                .and_modify(|existing| { if t < *existing { *existing = t; } })
                .or_insert(t);
        }

        let mut arrivals: Vec<ArrivalEntry> = by_source
            .iter()
            .map(|(src, &t)| ArrivalEntry {
                source: source_names.get(src).cloned().unwrap_or_else(|| format!("source_{}", src.0)),
                delta_ns: t.duration_since(rec.first_seen).as_nanos() as u64,
            })
            .collect();
        arrivals.sort_by_key(|a| a.delta_ns);

        let first_source = source_names
            .get(&rec.first_source)
            .cloned()
            .unwrap_or_else(|| format!("source_{}", rec.first_source.0));

        let log_entry = ShredLogEntry {
            slot: key.slot,
            index: key.index,
            shred_type: key.shred_type.to_string(),
            first_source,
            first_seen_ns: rec.first_seen.duration_since(start).as_nanos() as u64,
            arrivals,
        };

        writeln!(writer, "{}", serde_json::to_string(&log_entry)?)?;
    }

    writer.flush()?;
    Ok(())
}
