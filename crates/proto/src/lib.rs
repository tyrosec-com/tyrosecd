//! Protocol agent ↔ central server (Protobuf over HTTPS, mTLS).
//!
//! Messages are defined here directly as `prost` structs (no protoc
//! required). The file `proto/tyrosd.proto` in this repository describes the same
//! schema for other languages and must be kept in sync.
//!
//! Transport:
//! - `POST /v1/enroll`     EnrollRequest  → EnrollResponse (without client certificate, with one-time token)
//! - `POST /v1/batch`      Batch (zstd)   → BatchAck       (mTLS)
//! - `POST /v1/heartbeat`  Heartbeat      → HeartbeatAck   (mTLS)
//!
//! Tamper evidence: every `Envelope` carries `seq` (gapless, increasing) and
//! `prev_hash` = SHA-256 of the encoded preceding envelope.

/// Protocol version (master plan 27.2 B5). The central server accepts at least N-1.
pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Clone, PartialEq, prost::Message)]
pub struct EnrollRequest {
    #[prost(string, tag = "1")]
    pub token: String,
    #[prost(string, tag = "2")]
    pub csr_pem: String,
    #[prost(message, optional, tag = "3")]
    pub host: Option<HostInfo>,
    #[prost(uint32, tag = "4")]
    pub protocol: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct EnrollResponse {
    #[prost(string, tag = "1")]
    pub host_id: String,
    /// Client certificate (signed by the central server's agent CA)
    #[prost(string, tag = "2")]
    pub cert_pem: String,
    /// CA the agent uses to verify the server certificate (self-hosted/test only; otherwise empty = Web PKI)
    #[prost(string, tag = "3")]
    pub server_ca_pem: String,
    #[prost(string, tag = "4")]
    pub tenant: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct HostInfo {
    #[prost(string, tag = "1")]
    pub hostname: String,
    #[prost(string, tag = "2")]
    pub os: String,
    #[prost(string, tag = "3")]
    pub kernel: String,
    #[prost(string, tag = "4")]
    pub arch: String,
    #[prost(string, tag = "5")]
    pub agent_version: String,
    #[prost(string, tag = "6")]
    pub backend: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Batch {
    #[prost(uint32, tag = "1")]
    pub protocol: u32,
    /// encoded `Envelope`s, exactly as in the spool (the hash chain runs over these bytes)
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub envelopes: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct BatchAck {
    /// highest durably stored seq (the agent may delete everything ≤ this)
    #[prost(uint64, tag = "1")]
    pub acked_seq: u64,
    /// paths for which the central server lacks the base → send full content
    #[prost(string, repeated, tag = "2")]
    pub resync_paths: Vec<String>,
    /// broken chain detected (info only; the central server raises the alert itself)
    #[prost(bool, tag = "3")]
    pub chain_gap: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Envelope {
    #[prost(uint64, tag = "1")]
    pub seq: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub prev_hash: Vec<u8>,
    #[prost(int64, tag = "3")]
    pub ts_ns: i64,
    #[prost(oneof = "envelope::Body", tags = "10, 11, 12, 13, 14, 15, 16, 17, 18")]
    pub body: Option<envelope::Body>,
}

pub mod envelope {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Body {
        #[prost(message, tag = "10")]
        File(super::FileEvent),
        #[prost(message, tag = "11")]
        Content(super::FileContent),
        #[prost(message, tag = "12")]
        Metrics(super::MetricBatch),
        #[prost(message, tag = "13")]
        Lifecycle(super::Lifecycle),
        #[prost(message, tag = "14")]
        Check(super::CheckReport),
        #[prost(message, tag = "15")]
        Login(super::LoginEvent),
        #[prost(message, tag = "16")]
        Inventory(super::InventoryReport),
        /// Detection in the agent (reverse shell, shell from the web server, mining/spam connection …)
        #[prost(message, tag = "17")]
        Detection(super::Detection),
        /// Result of an action from the central server (restore, quarantine, block IP)
        #[prost(message, tag = "18")]
        ActionResult(super::ActionResult),
    }
}

/// Job from the central server (via the heartbeat response). Fixed kinds only; the agent executes them only
/// if they are enabled locally on the server (`tyrosecd actions enable`).
#[derive(Clone, PartialEq, prost::Message)]
pub struct Action {
    #[prost(uint64, tag = "1")]
    pub id: u64,
    /// restore | quarantine | block_ip | unblock_ip
    #[prost(string, tag = "2")]
    pub kind: String,
    #[prost(string, tag = "3")]
    pub path: String,
    #[prost(string, tag = "4")]
    pub ip: String,
    /// Block duration in seconds (0 = permanent)
    #[prost(uint32, tag = "5")]
    pub duration_s: u32,
    /// Content for restore (zstd)
    #[prost(bytes = "vec", tag = "6")]
    pub content_zstd: Vec<u8>,
    /// SHA-256 of the content (checked after decompression)
    #[prost(bytes = "vec", tag = "7")]
    pub content_hash: Vec<u8>,
    /// File mode for a restored file that no longer exists
    #[prost(uint32, tag = "8")]
    pub mode: u32,
    /// Parameters as JSON (decoy: values such as user/password/secret address – never file content)
    #[prost(string, tag = "9")]
    pub params: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ActionResult {
    #[prost(uint64, tag = "1")]
    pub id: u64,
    #[prost(bool, tag = "2")]
    pub ok: bool,
    #[prost(string, tag = "3")]
    pub message: String,
}

/// Traffic per port in the last minute (estimated from TCP connections)
#[derive(Clone, PartialEq, prost::Message)]
pub struct PortTraffic {
    #[prost(uint32, tag = "1")]
    pub port: u32,
    /// in = service on this server, out = destination port of an outgoing connection
    #[prost(string, tag = "2")]
    pub dir: String,
    #[prost(uint64, tag = "3")]
    pub rx_bytes: u64,
    #[prost(uint64, tag = "4")]
    pub tx_bytes: u64,
    #[prost(uint32, tag = "5")]
    pub conns: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct FileMeta {
    #[prost(uint64, tag = "1")]
    pub size: u64,
    #[prost(uint32, tag = "2")]
    pub mode: u32,
    #[prost(uint32, tag = "3")]
    pub uid: u32,
    #[prost(uint32, tag = "4")]
    pub gid: u32,
    #[prost(uint64, tag = "5")]
    pub ino: u64,
    #[prost(int64, tag = "6")]
    pub mtime_ns: i64,
    #[prost(int64, tag = "7")]
    pub ctime_ns: i64,
    #[prost(bytes = "vec", tag = "8")]
    pub caps: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct FileEvent {
    /// CREATE, MODIFY, DELETE, RENAME, ATTRIB, WRITE_NOCHANGE, OVERFLOW
    #[prost(string, tag = "1")]
    pub op: String,
    #[prost(string, tag = "2")]
    pub path: String,
    #[prost(string, tag = "3")]
    pub old_path: String,
    #[prost(string, tag = "4")]
    pub backend: String,
    #[prost(int64, tag = "5")]
    pub first_ts_ns: i64,
    #[prost(int32, tag = "6")]
    pub pid: i32,
    #[prost(string, tag = "7")]
    pub exe: String,
    #[prost(string, tag = "8")]
    pub comm: String,
    #[prost(string, repeated, tag = "9")]
    pub proc_chain: Vec<String>,
    /// full, redacted, hash, meta
    #[prost(string, tag = "10")]
    pub mode: String,
    /// Hash of the base (stored version) against which `patch` was created
    #[prost(bytes = "vec", tag = "11")]
    pub base_hash: Vec<u8>,
    /// Hash of the raw content
    #[prost(bytes = "vec", tag = "12")]
    pub raw_hash: Vec<u8>,
    /// Hash of the stored (possibly masked) version after the change
    #[prost(bytes = "vec", tag = "13")]
    pub stored_hash: Vec<u8>,
    /// unified diff (zstd), only if a base exists
    #[prost(bytes = "vec", tag = "14")]
    pub patch_zstd: Vec<u8>,
    /// full (possibly masked) content (zstd) if no base exists
    #[prost(bytes = "vec", tag = "15")]
    pub content_zstd: Vec<u8>,
    #[prost(message, optional, tag = "16")]
    pub meta: Option<FileMeta>,
    #[prost(string, tag = "17")]
    pub note: String,
    #[prost(uint32, tag = "18")]
    pub diff_lines: u32,
}

/// Full content on request of the central server (resync).
#[derive(Clone, PartialEq, prost::Message)]
pub struct FileContent {
    #[prost(string, tag = "1")]
    pub path: String,
    #[prost(bytes = "vec", tag = "2")]
    pub stored_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub content_zstd: Vec<u8>,
    /// Content was not (or no longer) present
    #[prost(bool, tag = "4")]
    pub missing: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct MetricBatch {
    #[prost(message, repeated, tag = "1")]
    pub points: Vec<MetricPoint>,
}

/// 1-minute aggregate (master plan 23.3)
#[derive(Clone, PartialEq, prost::Message)]
pub struct MetricPoint {
    #[prost(int64, tag = "1")]
    pub ts_ns: i64,
    #[prost(float, tag = "2")]
    pub cpu_pct_avg: f32,
    #[prost(float, tag = "3")]
    pub cpu_pct_max: f32,
    #[prost(float, tag = "4")]
    pub load1: f32,
    #[prost(uint64, tag = "5")]
    pub mem_total: u64,
    #[prost(uint64, tag = "6")]
    pub mem_used: u64,
    #[prost(uint64, tag = "7")]
    pub swap_total: u64,
    #[prost(uint64, tag = "8")]
    pub swap_used: u64,
    #[prost(uint64, tag = "9")]
    pub net_rx_bps: u64,
    #[prost(uint64, tag = "10")]
    pub net_tx_bps: u64,
    #[prost(message, repeated, tag = "11")]
    pub disks: Vec<DiskUsage>,
    #[prost(float, tag = "12")]
    pub steal_pct: f32,
    #[prost(uint32, tag = "13")]
    pub procs: u32,
    /// Pressure (PSI, "some" avg60 in %): wait time for CPU, memory, IO; -1 = not available
    #[prost(float, tag = "14")]
    pub psi_cpu: f32,
    #[prost(float, tag = "15")]
    pub psi_mem: f32,
    #[prost(float, tag = "16")]
    pub psi_io: f32,
    /// Processes with the most CPU time in this minute
    #[prost(message, repeated, tag = "17")]
    pub top: Vec<TopProc>,
    /// Traffic per port (since agent 0.3.0)
    #[prost(message, repeated, tag = "18")]
    pub ports: Vec<PortTraffic>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct TopProc {
    #[prost(string, tag = "1")]
    pub comm: String,
    #[prost(float, tag = "2")]
    pub cpu_pct: f32,
    #[prost(uint64, tag = "3")]
    pub rss_kb: u64,
    #[prost(uint32, tag = "4")]
    pub pid: u32,
}

/// Detection in the agent; the central server turns it into an alert (deduplicated)
#[derive(Clone, PartialEq, prost::Message)]
pub struct Detection {
    #[prost(string, tag = "1")]
    pub rule: String,
    /// critical | high | medium | low
    #[prost(string, tag = "2")]
    pub severity: String,
    #[prost(string, tag = "3")]
    pub title: String,
    #[prost(string, tag = "4")]
    pub detail: String,
    #[prost(uint32, tag = "5")]
    pub pid: u32,
    #[prost(string, tag = "6")]
    pub exe: String,
    #[prost(string, repeated, tag = "7")]
    pub proc_chain: Vec<String>,
    /// Key for deduplication in the central server (e.g. destination IP:port + program)
    #[prost(string, tag = "8")]
    pub key: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct DiskUsage {
    #[prost(string, tag = "1")]
    pub mount: String,
    #[prost(uint64, tag = "2")]
    pub total: u64,
    #[prost(uint64, tag = "3")]
    pub used: u64,
    #[prost(uint64, tag = "4")]
    pub inodes_total: u64,
    #[prost(uint64, tag = "5")]
    pub inodes_used: u64,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Lifecycle {
    /// start, stop, backend
    #[prost(string, tag = "1")]
    pub kind: String,
    #[prost(message, optional, tag = "2")]
    pub host: Option<HostInfo>,
    #[prost(string, tag = "3")]
    pub detail: String,
}

/// Report of the compromise check (JSON, see tyrosd-check::Report)
#[derive(Clone, PartialEq, prost::Message)]
pub struct CheckReport {
    #[prost(bytes = "vec", tag = "1")]
    pub json_zstd: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Heartbeat {
    #[prost(uint64, tag = "1")]
    pub last_seq: u64,
    #[prost(uint64, tag = "2")]
    pub spool_bytes: u64,
    #[prost(uint64, tag = "3")]
    pub spool_items: u64,
    #[prost(string, tag = "4")]
    pub backend: String,
    #[prost(string, tag = "5")]
    pub agent_version: String,
    #[prost(uint64, tag = "6")]
    pub uptime_s: u64,
    #[prost(uint64, tag = "7")]
    pub rss_kb: u64,
    /// locally enabled actions (agent.toml `actions`), so the web interface can offer them
    #[prost(string, repeated, tag = "8")]
    pub actions: Vec<String>,
    /// loaded YARA rule pack ("r1", empty = none), rules, memory after loading, last error (since 0.5.0)
    #[prost(string, tag = "9")]
    pub rules_version: String,
    #[prost(uint32, tag = "10")]
    pub rules_count: u32,
    #[prost(uint64, tag = "11")]
    pub rules_rss_kb: u64,
    #[prost(string, tag = "12")]
    pub rules_error: String,
    /// process memory (since 0.6.0): proc connector active, kernel messages lost since start, lookups of exited
    /// processes answered from memory since start
    #[prost(bool, tag = "13")]
    pub proc_tracking: bool,
    #[prost(uint64, tag = "14")]
    pub proc_lost: u64,
    #[prost(uint64, tag = "15")]
    pub proc_recalled: u64,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct HeartbeatAck {
    #[prost(uint32, tag = "1")]
    pub interval_s: u32,
    /// available agent version (empty = no update). The agent only installs
    /// signed, higher versions – the central server cannot force anything.
    #[prost(string, tag = "2")]
    pub update_version: String,
    /// Download base of the release (manifest.json, manifest.json.sig, binaries)
    #[prost(string, tag = "3")]
    pub update_base: String,
    /// The central server requests a compromise check (button in the web interface)
    #[prost(bool, tag = "4")]
    pub run_check: bool,
    /// pending actions (at most a few per heartbeat)
    #[prost(message, repeated, tag = "5")]
    pub actions: Vec<Action>,
    /// current YARA rule pack ("r1") and its base URL (…/rules/r1) – the agent only loads signed, higher packs
    /// from an allowed source (update_sources)
    #[prost(string, tag = "6")]
    pub rules_version: String,
    #[prost(string, tag = "7")]
    pub rules_base: String,
}

/// Hash chain: SHA-256 over the encoded envelope (computed by the caller,
/// so that this crate stays free of crypto dependencies).
pub fn encode_envelope(e: &Envelope) -> Vec<u8> {
    use prost::Message;
    e.encode_to_vec()
}

/// Login (SSH). Successes individually, failed attempts aggregated per source.
#[derive(Clone, PartialEq, prost::Message)]
pub struct LoginEvent {
    /// ssh
    #[prost(string, tag = "1")]
    pub service: String,
    #[prost(bool, tag = "2")]
    pub success: bool,
    #[prost(string, tag = "3")]
    pub user: String,
    #[prost(string, tag = "4")]
    pub ip: String,
    #[prost(uint32, tag = "5")]
    pub port: u32,
    /// publickey, password, keyboard-interactive/pam, …
    #[prost(string, tag = "6")]
    pub method: String,
    #[prost(string, tag = "7")]
    pub key_type: String,
    /// e.g. SHA256:…
    #[prost(string, tag = "8")]
    pub key_fp: String,
    /// Count (for aggregated failed attempts)
    #[prost(uint32, tag = "9")]
    pub count: u32,
    /// User does not exist
    #[prost(bool, tag = "10")]
    pub invalid_user: bool,
    /// Start of the aggregation window
    #[prost(int64, tag = "11")]
    pub first_ts_ns: i64,
}

/// Server inventory (services, processes, ports, firewall) as JSON (see tyrosd-inventory)
#[derive(Clone, PartialEq, prost::Message)]
pub struct InventoryReport {
    #[prost(bytes = "vec", tag = "1")]
    pub json_zstd: Vec<u8>,
}
