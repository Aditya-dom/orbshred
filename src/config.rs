use serde::Deserialize;

fn default_silence_timeout() -> u64 { 30 }
fn default_true() -> bool { true }

#[derive(Debug, Deserialize, Default)]
pub struct Config {
    /// Run for this many seconds. Omit or set to 0 when using start_slot/end_slot.
    #[serde(default)]
    pub duration_secs: u64,
    /// Only record shreds at or after this slot (optional).
    #[serde(default)]
    pub start_slot: Option<u64>,
    /// Stop the run once a shred beyond this slot is seen (optional).
    #[serde(default)]
    pub end_slot: Option<u64>,
    /// Stop if no shreds are received for this many seconds (default: 30).
    #[serde(default = "default_silence_timeout")]
    pub silence_timeout_secs: u64,
    /// Only record shreds from slots where this validator is leader (optional).
    /// Base58-encoded validator identity pubkey.
    #[serde(default)]
    pub leader_pubkey: String,
    /// RPC endpoint for fetching leader schedule. Required when leader_pubkey is set.
    #[serde(default)]
    pub rpc_url: String,
    #[serde(default)]
    pub sources: SourcesConfig,
    #[serde(default)]
    pub output: OutputConfig,
}

#[derive(Debug, Deserialize, Default)]
pub struct SourcesConfig {
    #[serde(default)]
    pub raw_udp: Vec<RawUdpConfig>,
    #[serde(default)]
    pub jito: Vec<JitoConfig>,
    #[serde(default)]
    pub doublezero: Vec<DoubleZeroConfig>,
    #[serde(default)]
    pub yellowstone: Vec<YellowstoneConfig>,
    #[serde(default)]
    pub pcap: Vec<PcapConfig>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct PcapConfig {
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// UDP port to capture (e.g. your validator's TVU port).
    #[serde(default)]
    pub port: u16,
    /// Network interface to capture on (e.g. "eth0").
    /// Leave empty to capture on all interfaces.
    #[serde(default)]
    pub interface: String,
    /// Socket receive buffer size in bytes. 0 = kernel default.
    #[serde(default)]
    pub recv_buf_size: usize,
    /// Only capture packets from these source IPs (optional).
    /// When set, only shreds from these IPs are recorded for this source.
    #[serde(default)]
    pub source_ips: Vec<String>,
    /// Exclude packets from these source IPs (optional).
    /// When set, shreds from these IPs are ignored for this source.
    #[serde(default)]
    pub exclude_ips: Vec<String>,
    /// Pin the capture thread to a specific CPU. Most useful after kernel
    /// timestamping is enabled and the residual jitter is wakeup-bound.
    /// Linux only; ignored elsewhere.
    #[serde(default)]
    pub pin_cpu: Option<usize>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct RawUdpConfig {
    #[serde(default)]
    pub name: String,
    /// Defaults to true — omit to enable, set false to disable.
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub bind_addr: String,
    #[serde(default)]
    pub recv_buf_size: usize,
    /// Pin the listener thread to a specific CPU (Linux only). See PcapConfig::pin_cpu.
    #[serde(default)]
    pub pin_cpu: Option<usize>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct JitoConfig {
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    // === Direct block engine connection ===
    #[serde(default)]
    pub block_engine_url: String,
    #[serde(default)]
    pub auth_keypair_path: String,
    #[serde(default)]
    pub desired_regions: Vec<String>,
    #[serde(default)]
    pub public_ip: String,
    #[serde(default)]
    pub udp_bind_addr: String,
    // === Already-running jito-shredstream-proxy ===
    #[serde(default)]
    pub proxy_udp_addr: String,
    #[serde(default)]
    pub proxy_grpc_addr: String,
    /// Pin the UDP listener thread to a specific CPU (Linux only). See PcapConfig::pin_cpu.
    #[serde(default)]
    pub pin_cpu: Option<usize>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct DoubleZeroConfig {
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub multicast_group: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub interface: String,
    /// Pin the listener thread to a specific CPU (Linux only). See PcapConfig::pin_cpu.
    #[serde(default)]
    pub pin_cpu: Option<usize>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct YellowstoneConfig {
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub x_token: String,
    /// Optional: base58 account pubkey to subscribe to.
    /// When set, measures how long after the first slot shred it takes
    /// Yellowstone to deliver the account update at processed commitment.
    #[serde(default)]
    pub account_pubkey: String,
    /// Display name for the account measurement row (optional).
    #[serde(default)]
    pub account_name: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct OutputConfig {
    #[serde(default)]
    pub log_file: String,
}
