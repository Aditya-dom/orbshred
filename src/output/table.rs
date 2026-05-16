use tabled::{settings::Style, Table, Tabled};
use crate::stats::{compute_percentiles, BenchmarkStats, GrpcOverheadStats, SourceStats};

fn fmt_ns(ns: u64) -> String {
    if ns == 0 {
        return "  0 µs".to_string();
    }
    if ns < 1_000 {
        format!("{:>3} ns", ns)
    } else if ns < 1_000_000 {
        format!("{:>5.1} µs", ns as f64 / 1_000.0)
    } else if ns < 1_000_000_000 {
        format!("{:>5.1} ms", ns as f64 / 1_000_000.0)
    } else {
        format!("{:>5.2}  s", ns as f64 / 1_000_000_000.0)
    }
}

fn coverage(received: u64, total: u64) -> String {
    if total == 0 {
        return "  N/A".to_string();
    }
    format!("{:>5.1}%", received as f64 / total as f64 * 100.0)
}

fn num_fmt(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

#[derive(Tabled)]
struct LatencyRow {
    #[tabled(rename = "Source")]
    source: String,
    #[tabled(rename = "Shreds")]
    shreds: String,
    #[tabled(rename = "  p50  ")]
    p50: String,
    #[tabled(rename = "  p90  ")]
    p90: String,
    #[tabled(rename = "  p95  ")]
    p95: String,
    #[tabled(rename = "  p99  ")]
    p99: String,
    #[tabled(rename = " p99.9 ")]
    p99_9: String,
    #[tabled(rename = "   max  ")]
    max: String,
}

#[derive(Tabled)]
struct WinRow {
    #[tabled(rename = "Source")]
    source: String,
    #[tabled(rename = "Won First")]
    wins: String,
    #[tabled(rename = "Total Received")]
    total_received: String,
    #[tabled(rename = "Win Rate")]
    win_rate: String,
}

#[derive(Tabled)]
struct CoverageRow {
    #[tabled(rename = "Source")]
    source: String,
    #[tabled(rename = "Received")]
    received: String,
    #[tabled(rename = "Coverage")]
    coverage: String,
    #[tabled(rename = "Dupes")]
    dupes: String,
    #[tabled(rename = "Missed")]
    missed: String,
    #[tabled(rename = "Drops")]
    drops: String,
}

#[derive(Tabled)]
struct ShredTypeRow {
    #[tabled(rename = "Source")]
    source: String,
    #[tabled(rename = "Data Shreds")]
    data: String,
    #[tabled(rename = "FEC Shreds")]
    code: String,
}

#[derive(Tabled)]
struct SlotRow {
    #[tabled(rename = "Source")]
    source: String,
    #[tabled(rename = "Slots")]
    slots: String,
    #[tabled(rename = "Drops")]
    drops: String,
    #[tabled(rename = "  p50  ")]
    p50: String,
    #[tabled(rename = "  p90  ")]
    p90: String,
    #[tabled(rename = "  p95  ")]
    p95: String,
    #[tabled(rename = "  p99  ")]
    p99: String,
    #[tabled(rename = "   max  ")]
    max: String,
}

#[derive(Tabled)]
struct GrpcOverheadRow {
    #[tabled(rename = "Source")]
    source: String,
    #[tabled(rename = "Samples")]
    samples: String,
    #[tabled(rename = "  p50  ")]
    p50: String,
    #[tabled(rename = "  p90  ")]
    p90: String,
    #[tabled(rename = "  p95  ")]
    p95: String,
    #[tabled(rename = "  p99  ")]
    p99: String,
    #[tabled(rename = "   max  ")]
    max: String,
}

fn grpc_overhead_row(s: &GrpcOverheadStats) -> GrpcOverheadRow {
    let p = compute_percentiles(s.latency_ns.clone());
    GrpcOverheadRow {
        source: s.name.clone(),
        samples: num_fmt(s.samples),
        p50: fmt_ns(p.p50),
        p90: fmt_ns(p.p90),
        p95: fmt_ns(p.p95),
        p99: fmt_ns(p.p99),
        max: fmt_ns(p.max),
    }
}

pub fn print_results(stats: &BenchmarkStats, start_time: chrono::DateTime<chrono::Utc>, leader_pubkey: Option<&str>) {
    let total = stats.total_unique_shreds;

    // Header
    let title = format!(
        " SHRED BENCHMARK  ·  {:.0}s  ·  {} unique shreds  ·  {} sources ",
        stats.duration_secs,
        num_fmt(total),
        stats.sources.len()
    );
    let slots_line = format!(
        "Slots: {} → {} ({} observed)",
        num_fmt(stats.min_slot),
        num_fmt(stats.max_slot),
        num_fmt(stats.slot_stats.total_slots),
    );
    let width = 90;
    println!();
    println!("╔{}╗", "═".repeat(width));
    println!("║{:^width$}║", title, width = width);
    println!("║{:^width$}║", slots_line, width = width);
    if let Some(pubkey) = leader_pubkey {
        let leader_line = format!("Leader filter: {}", pubkey);
        println!("║{:^width$}║", leader_line, width = width);
    }
    println!(
        "║{:^width$}║",
        format!(
            "started {}",
            start_time.format("%Y-%m-%d %H:%M:%S UTC")
        ),
        width = width
    );
    println!("╚{}╝", "═".repeat(width));
    println!();

    // Latency table — sorted by p50 ascending (fastest first)
    println!("LATENCY RELATIVE TO FIRST ARRIVAL  (per shred, data + FEC combined)");
    let mut latency_data: Vec<(u64, LatencyRow)> = stats
        .sources
        .iter()
        .map(|s| {
            let p = compute_percentiles(s.latency_ns.clone());
            let p50_raw = p.p50;
            (p50_raw, LatencyRow {
                source: s.name.clone(),
                shreds: num_fmt(s.received),
                p50: fmt_ns(p.p50),
                p90: fmt_ns(p.p90),
                p95: fmt_ns(p.p95),
                p99: fmt_ns(p.p99),
                p99_9: fmt_ns(p.p99_9),
                max: fmt_ns(p.max),
            })
        })
        .collect();
    latency_data.sort_by_key(|(p50, _)| *p50);
    let latency_rows: Vec<LatencyRow> = latency_data.into_iter().map(|(_, r)| r).collect();
    println!("{}", Table::new(latency_rows).with(Style::sharp()));
    println!();

    // First-arrival wins — sorted by most wins descending
    println!("FIRST ARRIVAL WINS  (which source received each shred first)");
    let mut win_data: Vec<(u64, WinRow)> = stats
        .sources
        .iter()
        .map(|s| {
            let rate = if s.received > 0 {
                format!("{:.1}%", s.wins as f64 / s.received as f64 * 100.0)
            } else {
                "N/A".to_string()
            };
            (s.wins, WinRow {
                source: s.name.clone(),
                wins: num_fmt(s.wins),
                total_received: num_fmt(s.received),
                win_rate: rate,
            })
        })
        .collect();
    win_data.sort_by(|a, b| b.0.cmp(&a.0));
    let win_rows: Vec<WinRow> = win_data.into_iter().map(|(_, r)| r).collect();
    println!("{}", Table::new(win_rows).with(Style::sharp()));
    println!();

    // Coverage — sorted by highest received descending
    println!("COVERAGE & RELIABILITY");
    let mut cov_data: Vec<(u64, CoverageRow)> = stats
        .sources
        .iter()
        .map(|s| {
            (s.received, CoverageRow {
                source: s.name.clone(),
                received: num_fmt(s.received),
                coverage: coverage(s.received, total),
                dupes: num_fmt(s.dupes),
                missed: num_fmt(s.missed),
                drops: num_fmt(s.drops),
            })
        })
        .collect();
    cov_data.sort_by(|a, b| b.0.cmp(&a.0));
    let cov_rows: Vec<CoverageRow> = cov_data.into_iter().map(|(_, r)| r).collect();
    println!("{}", Table::new(cov_rows).with(Style::sharp()));
    println!();

    // Shred type breakdown — sorted by highest received descending
    println!("SHRED TYPE BREAKDOWN");
    let mut sources_by_received: Vec<&SourceStats> = stats.sources.iter().collect();
    sources_by_received.sort_by(|a, b| b.received.cmp(&a.received));
    let type_rows: Vec<ShredTypeRow> = sources_by_received
        .iter()
        .map(|s| {
            let total_s = s.data_shreds + s.code_shreds;
            let data_pct = if total_s > 0 {
                s.data_shreds * 100 / total_s
            } else {
                0
            };
            let code_pct = if total_s > 0 {
                s.code_shreds * 100 / total_s
            } else {
                0
            };
            ShredTypeRow {
                source: s.name.clone(),
                data: format!("{} ({}%)", num_fmt(s.data_shreds), data_pct),
                code: format!("{} ({}%)", num_fmt(s.code_shreds), code_pct),
            }
        })
        .collect();
    println!("{}", Table::new(type_rows).with(Style::sharp()));
    println!();

    // Entry/slot-level sources — sorted by p50 ascending (fastest first)
    let mut entry_data: Vec<(u64, SlotRow)> = stats
        .slot_stats
        .entry_sources
        .iter()
        .filter(|s| s.slots_seen > 0)
        .map(|s| {
            let p = compute_percentiles(s.latency_ns.clone());
            let p50_raw = p.p50;
            (p50_raw, SlotRow {
                source: s.name.clone(),
                slots: num_fmt(s.slots_seen),
                drops: num_fmt(s.drops),
                p50: fmt_ns(p.p50),
                p90: fmt_ns(p.p90),
                p95: fmt_ns(p.p95),
                p99: fmt_ns(p.p99),
                max: fmt_ns(p.max),
            })
        })
        .collect();
    entry_data.sort_by_key(|(p50, _)| *p50);
    let entry_rows: Vec<SlotRow> = entry_data.into_iter().map(|(_, r)| r).collect();
    if !entry_rows.is_empty() {
        println!("SLOT / ENTRY LATENCY  vs first shred arrival (any source)");
        println!("(time from earliest shred received across all sources → gRPC delivery; includes shred assembly + execution)");
        println!("{}", Table::new(entry_rows).with(Style::sharp()));
        println!();
    }

    // gRPC overhead table — sorted by p50 ascending (fastest first)
    let mut grpc_data: Vec<(u64, GrpcOverheadRow)> = stats
        .grpc_overhead
        .iter()
        .filter(|s| s.samples > 0)
        .map(|s| {
            let p = compute_percentiles(s.latency_ns.clone());
            (p.p50, grpc_overhead_row(s))
        })
        .collect();
    grpc_data.sort_by_key(|(p50, _)| *p50);
    let grpc_rows: Vec<GrpcOverheadRow> = grpc_data.into_iter().map(|(_, r)| r).collect();
    if !grpc_rows.is_empty() {
        println!("YELLOWSTONE gRPC OVERHEAD  (entry processed → account update delivered)");
        println!("(pure gRPC latency after the validator executes the entry — shred assembly time excluded)");
        println!("{}", Table::new(grpc_rows).with(Style::sharp()));
        println!();
    }

    println!();
}
