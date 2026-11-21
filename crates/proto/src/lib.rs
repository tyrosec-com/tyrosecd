//! Protokoll Agent ↔ Zentrale (Protobuf über HTTPS, mTLS).
//!
//! Nachrichten sind hier direkt als `prost`-Strukturen definiert (kein protoc
//! nötig). Die Datei `proto/tyrosd.proto` in diesem Repository beschreibt dasselbe
//! Schema für andere Sprachen und muss synchron gehalten werden.
//!
//! Transport:
//! - `POST /v1/enroll`     EnrollRequest  → EnrollResponse (ohne Client-Zertifikat, mit Einmal-Token)
//! - `POST /v1/batch`      Batch (zstd)   → BatchAck       (mTLS)
//! - `POST /v1/heartbeat`  Heartbeat      → HeartbeatAck   (mTLS)
//!
//! Manipulationsnachweis: Jede `Envelope` trägt `seq` (lückenlos steigend) und
//! `prev_hash` = SHA-256 der kodierten Vorgänger-Envelope.

/// Protokollversion (Hauptplan 27.2 B5). Zentrale akzeptiert mindestens N-1.
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
    /// Client-Zertifikat (signiert von der Agent-CA der Zentrale)
    #[prost(string, tag = "2")]
    pub cert_pem: String,
    /// CA, mit der der Agent das Server-Zertifikat prüft (nur Self-hosted/Test; sonst leer = Web-PKI)
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
    /// kodierte `Envelope`s, exakt wie im Spool (Hash-Kette läuft über diese Bytes)
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub envelopes: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct BatchAck {
    /// höchste dauerhaft gespeicherte seq (Agent darf alles ≤ löschen)
    #[prost(uint64, tag = "1")]
    pub acked_seq: u64,
    /// Pfade, für die der Zentrale die Basis fehlt → vollen Inhalt senden
    #[prost(string, repeated, tag = "2")]
    pub resync_paths: Vec<String>,
    /// Kette gebrochen erkannt (nur Info; Zentrale alarmiert selbst)
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
        /// Erkennung im Agent (Reverse Shell, Shell aus dem Webserver, Mining/Spam-Verbindung …)
        #[prost(message, tag = "17")]
        Detection(super::Detection),
        /// Ergebnis einer Aktion aus der Zentrale (Wiederherstellen, Quarantäne, IP sperren)
        #[prost(message, tag = "18")]
        ActionResult(super::ActionResult),
    }
}

/// Auftrag der Zentrale (über die Heartbeat-Antwort). Nur feste Arten; der Agent führt sie nur aus,
/// wenn sie auf dem Server lokal freigeschaltet sind (`tyrosecd actions enable`).
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
    /// Sperrdauer in Sekunden (0 = dauerhaft)
    #[prost(uint32, tag = "5")]
    pub duration_s: u32,
    /// Inhalt für restore (zstd)
    #[prost(bytes = "vec", tag = "6")]
    pub content_zstd: Vec<u8>,
    /// SHA-256 des Inhalts (Prüfung nach dem Entpacken)
    #[prost(bytes = "vec", tag = "7")]
    pub content_hash: Vec<u8>,
    /// Dateirechte für eine wiederhergestellte, nicht mehr vorhandene Datei
    #[prost(uint32, tag = "8")]
    pub mode: u32,
    /// Parameter als JSON (Köder: Werte wie Benutzer/Passwort/geheime Adresse – nie ein Datei-Inhalt)
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

/// Verkehr je Port in der letzten Minute (Schätzung aus TCP-Verbindungen)
#[derive(Clone, PartialEq, prost::Message)]
pub struct PortTraffic {
    #[prost(uint32, tag = "1")]
    pub port: u32,
    /// in = Dienst auf diesem Server, out = Ziel-Port einer ausgehenden Verbindung
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
    /// Hash der Basis (gespeicherte Fassung), gegen die `patch` erzeugt wurde
    #[prost(bytes = "vec", tag = "11")]
    pub base_hash: Vec<u8>,
    /// Hash des Rohinhalts
    #[prost(bytes = "vec", tag = "12")]
    pub raw_hash: Vec<u8>,
    /// Hash der gespeicherten (ggf. maskierten) Fassung nach der Änderung
    #[prost(bytes = "vec", tag = "13")]
    pub stored_hash: Vec<u8>,
    /// unified diff (zstd), nur bei vorhandener Basis
    #[prost(bytes = "vec", tag = "14")]
    pub patch_zstd: Vec<u8>,
    /// voller (ggf. maskierter) Inhalt (zstd), wenn keine Basis existiert
    #[prost(bytes = "vec", tag = "15")]
    pub content_zstd: Vec<u8>,
    #[prost(message, optional, tag = "16")]
    pub meta: Option<FileMeta>,
    #[prost(string, tag = "17")]
    pub note: String,
    #[prost(uint32, tag = "18")]
    pub diff_lines: u32,
}

/// Voller Inhalt auf Anforderung der Zentrale (resync).
#[derive(Clone, PartialEq, prost::Message)]
pub struct FileContent {
    #[prost(string, tag = "1")]
    pub path: String,
    #[prost(bytes = "vec", tag = "2")]
    pub stored_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub content_zstd: Vec<u8>,
    /// Inhalt war nicht (mehr) vorhanden
    #[prost(bool, tag = "4")]
    pub missing: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct MetricBatch {
    #[prost(message, repeated, tag = "1")]
    pub points: Vec<MetricPoint>,
}

/// 1-Minuten-Aggregat (Hauptplan 23.3)
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
    /// Druck (PSI, „some“ avg60 in %): Wartezeit auf CPU, Speicher, IO; -1 = nicht verfügbar
    #[prost(float, tag = "14")]
    pub psi_cpu: f32,
    #[prost(float, tag = "15")]
    pub psi_mem: f32,
    #[prost(float, tag = "16")]
    pub psi_io: f32,
    /// Prozesse mit der meisten CPU-Zeit in dieser Minute
    #[prost(message, repeated, tag = "17")]
    pub top: Vec<TopProc>,
    /// Verkehr je Port (ab Agent 0.3.0)
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

/// Erkennung im Agent; die Zentrale macht daraus einen Alarm (dedupliziert)
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
    /// Schlüssel für die Entdopplung in der Zentrale (z. B. Ziel-IP:Port + Programm)
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

/// Bericht des Kompromittierungs-Checks (JSON, siehe tyrosd-check::Report)
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
    /// lokal freigeschaltete Aktionen (agent.toml `actions`), damit die Oberfläche sie anbieten kann
    #[prost(string, repeated, tag = "8")]
    pub actions: Vec<String>,
    /// geladenes YARA-Regelpaket („r1“, leer = keins), Regeln, Speicher nach dem Laden, letzter Fehler (ab 0.5.0)
    #[prost(string, tag = "9")]
    pub rules_version: String,
    #[prost(uint32, tag = "10")]
    pub rules_count: u32,
    #[prost(uint64, tag = "11")]
    pub rules_rss_kb: u64,
    #[prost(string, tag = "12")]
    pub rules_error: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct HeartbeatAck {
    #[prost(uint32, tag = "1")]
    pub interval_s: u32,
    /// verfügbare Agent-Version (leer = kein Update). Der Agent installiert nur
    /// signierte, höhere Versionen – die Zentrale kann nichts erzwingen.
    #[prost(string, tag = "2")]
    pub update_version: String,
    /// Download-Basis des Releases (manifest.json, manifest.json.sig, Binaries)
    #[prost(string, tag = "3")]
    pub update_base: String,
    /// Zentrale bittet um einen Kompromittierungs-Check (Knopf in der Web-Oberfläche)
    #[prost(bool, tag = "4")]
    pub run_check: bool,
    /// ausstehende Aktionen (höchstens wenige je Heartbeat)
    #[prost(message, repeated, tag = "5")]
    pub actions: Vec<Action>,
    /// aktuelles YARA-Regelpaket („r1“) und seine Basis-URL (…/rules/r1) – der Agent lädt nur signierte, höhere Pakete
    /// von einer erlaubten Quelle (update_sources)
    #[prost(string, tag = "6")]
    pub rules_version: String,
    #[prost(string, tag = "7")]
    pub rules_base: String,
}

/// Hash-Kette: SHA-256 über die kodierte Envelope (wird vom Aufrufer berechnet,
/// damit dieses Crate ohne Krypto-Abhängigkeit bleibt).
pub fn encode_envelope(e: &Envelope) -> Vec<u8> {
    use prost::Message;
    e.encode_to_vec()
}

/// Anmeldung (SSH). Erfolge einzeln, Fehlversuche je Quelle aggregiert.
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
    /// z. B. SHA256:…
    #[prost(string, tag = "8")]
    pub key_fp: String,
    /// Anzahl (bei aggregierten Fehlversuchen)
    #[prost(uint32, tag = "9")]
    pub count: u32,
    /// Benutzer existiert nicht
    #[prost(bool, tag = "10")]
    pub invalid_user: bool,
    /// Beginn des Aggregationsfensters
    #[prost(int64, tag = "11")]
    pub first_ts_ns: i64,
}

/// Server-Inventar (Dienste, Prozesse, Ports, Firewall) als JSON (siehe tyrosd-inventory)
#[derive(Clone, PartialEq, prost::Message)]
pub struct InventoryReport {
    #[prost(bytes = "vec", tag = "1")]
    pub json_zstd: Vec<u8>,
}
