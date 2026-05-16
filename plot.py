#!/usr/bin/env python3
"""Generate interactive HTML report from orbshred JSON log."""

import json
import sys
from collections import defaultdict
from math import floor
from pathlib import Path


def percentile(sorted_xs, q):
    """Linear-interpolation percentile (NumPy-style) without the dep.
    q in [0, 100]; sorted_xs must be sorted ascending."""
    n = len(sorted_xs)
    if n == 0:
        return None
    if n == 1:
        return sorted_xs[0]
    rank = (q / 100.0) * (n - 1)
    lo = int(floor(rank))
    hi = min(lo + 1, n - 1)
    frac = rank - lo
    return sorted_xs[lo] + frac * (sorted_xs[hi] - sorted_xs[lo])

try:
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots
except ImportError:
    print("Install plotly: pip install plotly")
    sys.exit(1)


def load_log(path):
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            entries.append(json.loads(line))
    return entries


def build_report(entries, output_path):
    # Collect per-source latency data
    source_deltas = defaultdict(list)       # source -> [delta_ns]
    source_over_time = defaultdict(lambda: {"t": [], "delta": []})  # source -> {t[], delta[]}
    slot_wins = defaultdict(lambda: defaultdict(int))  # slot -> {source -> count}
    slot_deltas = defaultdict(lambda: defaultdict(list))  # slot -> {source -> [delta_ns]}
    all_sources = set()

    for e in entries:
        t_ns = e["first_seen_ns"]
        slot = e["slot"]
        first_source = e["first_source"]
        slot_wins[slot][first_source] += 1

        for a in e["arrivals"]:
            src = a["source"]
            delta = a["delta_ns"]
            all_sources.add(src)
            source_deltas[src].append(delta)
            source_over_time[src]["t"].append(t_ns / 1e9)  # seconds
            source_over_time[src]["delta"].append(delta / 1e6)  # ms
            slot_deltas[slot][src].append(delta)

    sources = sorted(all_sources)

    fig = make_subplots(
        rows=4, cols=1,
        subplot_titles=(
            "Latency Distribution (histogram)",
            "Latency Over Time (scatter)",
            "Per-Slot Median Latency (line — p50 solid, p90 dashed)",
            "Per-Slot First Arrival Wins (stacked bar)",
        ),
        vertical_spacing=0.07,
        row_heights=[0.25, 0.25, 0.25, 0.25],
    )

    colors = [
        "#636EFA", "#EF553B", "#00CC96", "#AB63FA",
        "#FFA15A", "#19D3F3", "#FF6692", "#B6E880",
        "#FF97FF", "#FECB52",
    ]

    # 1) Histogram
    for i, src in enumerate(sources):
        deltas_ms = [d / 1e6 for d in source_deltas[src]]
        fig.add_trace(
            go.Histogram(
                x=deltas_ms,
                name=src,
                opacity=0.7,
                marker_color=colors[i % len(colors)],
                legendgroup=src,
                nbinsx=200,
            ),
            row=1, col=1,
        )
    fig.update_xaxes(title_text="Latency (ms)", row=1, col=1)
    fig.update_yaxes(title_text="Count", row=1, col=1)

    # 2) Scatter — latency over time
    for i, src in enumerate(sources):
        data = source_over_time[src]
        step = max(1, len(data["t"]) // 50_000)
        fig.add_trace(
            go.Scattergl(
                x=data["t"][::step],
                y=data["delta"][::step],
                mode="markers",
                marker=dict(size=2, color=colors[i % len(colors)], opacity=0.5),
                name=src,
                legendgroup=src,
                showlegend=False,
            ),
            row=2, col=1,
        )
    fig.update_xaxes(title_text="Time since start (s)", row=2, col=1)
    fig.update_yaxes(title_text="Latency (ms)", row=2, col=1)

    # 3) Per-slot median latency lines (Grafana-style)
    slots_sorted = sorted(slot_deltas.keys())
    slot_labels = [str(s) for s in slots_sorted]
    for i, src in enumerate(sources):
        p50_vals = []
        p90_vals = []
        for s in slots_sorted:
            ds = slot_deltas[s].get(src)
            if ds:
                sorted_ds = sorted(ds)
                p50_vals.append(percentile(sorted_ds, 50) / 1e6)
                p90_vals.append(percentile(sorted_ds, 90) / 1e6)
            else:
                p50_vals.append(None)
                p90_vals.append(None)

        color = colors[i % len(colors)]
        # p50 — solid line
        fig.add_trace(
            go.Scatter(
                x=slot_labels, y=p50_vals,
                mode="lines",
                name=src,
                legendgroup=src,
                showlegend=False,
                line=dict(color=color, width=2),
                connectgaps=False,
            ),
            row=3, col=1,
        )
        # p90 — dashed line
        fig.add_trace(
            go.Scatter(
                x=slot_labels, y=p90_vals,
                mode="lines",
                name=f"{src} p90",
                legendgroup=src,
                showlegend=False,
                line=dict(color=color, width=1, dash="dash"),
                connectgaps=False,
            ),
            row=3, col=1,
        )
    fig.update_xaxes(title_text="Slot", row=3, col=1)
    fig.update_yaxes(title_text="Latency (ms)", row=3, col=1)

    # 4) Per-slot stacked bar
    slot_labels_wins = [str(s) for s in sorted(slot_wins.keys())]
    slots_sorted_wins = sorted(slot_wins.keys())
    for i, src in enumerate(sources):
        counts = [slot_wins[s].get(src, 0) for s in slots_sorted_wins]
        fig.add_trace(
            go.Bar(
                x=slot_labels_wins,
                y=counts,
                name=src,
                legendgroup=src,
                showlegend=False,
                marker_color=colors[i % len(colors)],
            ),
            row=4, col=1,
        )
    fig.update_xaxes(title_text="Slot", row=4, col=1)
    fig.update_yaxes(title_text="Shreds Won", row=4, col=1)

    # Build a color legend string like "● Source A  ● Source B  ● Source C"
    legend_parts = []
    for i, src in enumerate(sources):
        color = colors[i % len(colors)]
        legend_parts.append(f'<span style="color:{color}">●</span> {src}')
    legend_text = "&nbsp;&nbsp;&nbsp;".join(legend_parts)

    # Add color legend annotation above each subplot
    subplot_y_positions = [1.0, 0.735, 0.47, 0.205]
    annotations = list(fig.layout.annotations)
    for y_pos in subplot_y_positions:
        annotations.append(dict(
            text=legend_text,
            xref="paper", yref="paper",
            x=0.5, y=y_pos - 0.015,
            showarrow=False,
            font=dict(size=11),
            xanchor="center", yanchor="top",
        ))

    fig.update_layout(
        title="Orbshred Report",
        height=2200,
        template="plotly_dark",
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5),
        barmode="stack",
        annotations=annotations,
    )

    fig.write_html(str(output_path), include_plotlyjs="cdn")
    print(f"Report written to {output_path}")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <shreds.jsonl> [output.html]")
        sys.exit(1)

    log_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else Path(log_path).with_suffix(".html")

    entries = load_log(log_path)
    print(f"Loaded {len(entries)} shred entries")
    build_report(entries, output_path)


if __name__ == "__main__":
    main()
