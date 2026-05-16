# orbshred

Connects to multiple Solana shred sources simultaneously, records nanosecond-precision arrival times per `(slot, index, shred_type)` tuple, and prints comparison tables showing which source is fastest, most complete, and cheapest in overhead.

All latency numbers are relative — measured against the earliest arrival across all running sources on the same machine. No clock sync required.

---

## Sources

### Raw UDP

Binds a UDP port and receives raw Turbine shreds directly from the Solana gossip network — the same way a validator's TVU socket does. You need to be in the Turbine shred tree, either by running a validator or by having one forward shreds to your port.

**Measures:** how fast the public Turbine network delivers each shred to your IP. This is the baseline everything else is compared against.

---

### Raw Capture (AF_PACKET)

Opens a raw `AF_PACKET` socket (Linux only, requires `CAP_NET_RAW`) that captures UDP packets at the kernel level without binding to the port. This lets you observe shreds arriving on your validator's TVU port without conflicting with the validator process that already owns it.

The tool installs a classic BPF filter in the kernel so only packets on the configured port reach userspace.

```bash
sudo setcap cap_net_raw=eip ./target/release/orbshred
```

**IP filtering:** each pcap source can optionally filter by source IP. Use `source_ips` to only capture packets from specific IPs, or `exclude_ips` to ignore specific IPs. This lets you measure individual shred providers that deliver to the same TVU port. Multiple pcap sources on the same port and interface share a single socket — one `recv()` per packet, one timestamp, routed to all matching sources.

**Measures:** exactly what your running validator receives, timestamped the instant the packet exits the kernel receive path — the most direct possible view of Turbine delivery to your node.

---

### Jito ShredStream

Jito runs a shred relay network that receives Turbine shreds and re-distributes them. Supports two modes:

**Direct mode** — your machine authenticates with a Jito block engine, sends periodic heartbeats containing your public IP and port, and Jito delivers raw UDP shreds directly to you. No proxy process needed.

**Proxy mode** — you run `jito-shredstream-proxy` locally. It handles auth and heartbeats, then forwards shreds to a local UDP port you configure.

Both modes deliver identical raw shred data. The Jito source also supports a gRPC sub-connection (`proxy_grpc_addr`) that receives fully assembled entries — these appear as a separate row in the slot/entry latency table.

**Measures:** how much latency Jito's relay adds on top of direct Turbine. If Jito wins more shreds than Raw UDP, it means Jito's network has a better path to some leaders than the public gossip graph.

---

### DoubleZero

DoubleZero operates a private fiber network for Solana infrastructure. Shreds are distributed over a multicast group and arrive as raw UDP on a specific network interface. Requires an on-chain subscription and the `doublezerod` daemon running on your machine.

DoubleZero does not cover all validators — currently roughly 20% of stake. For leaders on that subset its path is often faster; for everyone else it has no data.

**Measures:** whether DoubleZero's private network reaches you faster than the public internet (Turbine) or Jito's relay, on a per-shred basis.

---

### Yellowstone gRPC

Yellowstone is a Geyser plugin running inside a Solana validator. It does not expose raw shreds — it exposes processed validator state. The tool uses it in two ways:

**Slot (FIRST_SHRED_RECEIVED)**
Subscribes to slot status updates. The `SLOT_FIRST_SHRED_RECEIVED` event fires the moment the validator's TVU first receives the opening shred of a new slot.

Measures: how long after the earliest shred across all your sources arrives does the connected validator see it. A small delta (2–10 ms) means your raw sources and the validator are on similar network paths. Shown in the *slot/entry latency* table.

**Account subscription** *(optional — set `account_pubkey` in config)*
Subscribes to account updates for a specific account at `PROCESSED` commitment, plus the entry stream.

Produces **two separate measurements**:

1. *Slot/entry latency table* — time from the earliest shred received for the slot (across all sources) → account update delivered. This is mostly shred assembly + block execution time (~200–300 ms for a typical slot), not gRPC overhead.

2. *gRPC overhead table* — time from Yellowstone delivering the entry event for the slot → Yellowstone delivering the account update for the transaction inside that entry. This is the pure Yellowstone gRPC delivery latency, with shred assembly and execution time removed. This is the number to watch if you want to evaluate or improve your Yellowstone connection.

---

## Output tables

**LATENCY RELATIVE TO FIRST ARRIVAL**
Per-shred latency delta vs the globally fastest source. If Raw UDP has p50 = 0 µs and DoubleZero has p50 = 18 µs, DoubleZero consistently lags by ~18 µs at the median. Sources with a lot of zero-deltas are frequently first.

**FIRST ARRIVAL WINS**
For each shred, which source delivered it first. Shows `Won First` (count), `Total Received` (how many shreds that source saw), and `Win Rate` (Won First / Total Received). A source with low total received but high win rate is fast when it has the data — it just doesn't cover all validators.

**COVERAGE & RELIABILITY**
What fraction of all observed shreds each source received. A source can be fast but still miss shreds — coverage shows reliability.

**SHRED TYPE BREAKDOWN**
Data shreds carry actual block content. FEC (code) shreds are Reed-Solomon parity for erasure recovery. High FEC counts with low data counts may indicate the source is only sending recovery data, not primary shreds.

**SLOT / ENTRY LATENCY vs first shred arrival (any source)**
For Yellowstone and Jito gRPC entries: latency from the earliest shred received across all your running sources → the gRPC notification. Measured at slot granularity. Includes shred assembly time, so numbers in the hundreds of milliseconds are expected for account updates — this does not mean gRPC is slow.

**YELLOWSTONE gRPC OVERHEAD (entry processed → account update delivered)**
Only shown when `account_pubkey` is configured. Measures the pure latency Yellowstone adds after the validator finishes executing the entry containing your transaction. This isolates the gRPC pipeline from everything else. Typical values are 0.5–10 ms.

---

## Configuration

Copy `config.example.toml` to `config.toml`. All fields are optional except at least one source must be enabled. Multiple instances of any source type are supported.

```toml
# Fixed duration
duration_secs = 60

# Or slot range (run stops ~2s after a shred beyond end_slot arrives)
# start_slot = 350000000
# end_slot   = 350001000

# Only record shreds from a specific leader's slots (optional)
# leader_pubkey = "YourValidatorPubkey..."
# rpc_url = "http://127.0.0.1:8899"

[[sources.raw_udp]]
name = "Turbine"
bind_addr = "0.0.0.0:8001"

[[sources.pcap]]
name = "TVU Capture"
port      = 8001        # your validator's TVU port
interface = "eth0"      # optional — omit to capture all interfaces

# Multiple pcap sources on the same port share one socket.
# Use source_ips / exclude_ips to measure individual providers.
#[[sources.pcap]]
#name = "Provider A"
#port = 8001
#source_ips = ["1.1.1.1"]
#
#[[sources.pcap]]
#name = "Turbine (excl. Provider A)"
#port = 8001
#exclude_ips = ["1.1.1.1"]

[[sources.jito]]
name = "Jito Frankfurt"
block_engine_url  = "https://frankfurt.mainnet.block-engine.jito.wtf"
auth_keypair_path = "/path/to/keypair.json"
desired_regions   = ["frankfurt"]
public_ip         = "1.2.3.4"
udp_bind_addr     = "0.0.0.0:20000"

[[sources.doublezero]]
name = "DoubleZero"
multicast_group = "233.84.178.1"
port            = 7733
interface       = "doublezero1"

[[sources.yellowstone]]
name = "Yellowstone"
endpoint       = "http://127.0.0.1:10000"
account_pubkey = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"  # optional
account_name   = "Token Program"                                   # optional display name
```

---

## Usage

### Build prerequisites

- Rust toolchain (`rustup`, stable)
- `protoc` (Protocol Buffers compiler) — required by `tonic-build` at compile time
  - macOS: `brew install protobuf`
  - Debian/Ubuntu: `sudo apt-get install -y protobuf-compiler`
  - Or download from <https://github.com/protocolbuffers/protobuf/releases> and set `PROTOC=/path/to/protoc`

### Build & run

```bash
cargo build --release

# Run with default config.toml
./target/release/orbshred

# Override duration and log file
./target/release/orbshred --duration 120 --log-file run.log

# Slot range mode (duration ignored when start/end slot set)
./target/release/orbshred --config slot-range.toml
```

Raw packet capture requires the `cap_net_raw` capability on the binary:
```bash
sudo setcap cap_net_raw=eip ./target/release/orbshred
```

---

## Plots

Enable the log file in your config to record per-shred data:

```toml
[output]
log_file = "orbshred.log"
```

Then generate an interactive HTML report:

```bash
python3 -m venv venv
source venv/bin/activate
pip install plotly

python3 plot.py orbshred.log report.html
```

To view the report from a remote server:

```bash
python3 -m http.server 8080
```

Then open `http://<server-ip>:8080/report.html` in your browser.

The report includes:
- **Latency distribution** — histogram showing how many shreds arrived at each delay
- **Latency over time** — scatter plot revealing spikes and patterns over the run
- **CDF curves** — cumulative distribution comparing sources (the full version of the percentile table)
- **Per-slot stacked bar** — which source won each slot's shreds, showing leader correlation

---

## Limitations

- All latency numbers are relative to the fastest source on the same machine — not absolute wall-clock latency from block production
- Cannot compare across machines (no clock sync)
- With only one source enabled, the latency table shows all zeros
- Yellowstone measurements are at slot/entry granularity and cannot be directly compared to per-shred numbers
- Raw packet capture and DoubleZero are Linux-only
