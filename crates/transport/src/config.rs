//! Agent-Konfiguration `/etc/tyrosecd/agent.toml` (nur root-schreibbar).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentConfig {
    /// z. B. https://ingest.tyrosec.com
    pub server: String,
    /// von der Zentrale beim Enrollment vergeben
    #[serde(default)]
    pub host_id: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    /// Wurzeln für Echtzeit-Ereignisse
    #[serde(default = "default_roots")]
    pub roots: Vec<String>,
    /// Wurzeln für den Abgleich-Scan (leer = Standardprofile)
    #[serde(default)]
    pub scan_roots: Vec<String>,
    #[serde(default = "default_scan_interval")]
    pub scan_interval_s: u64,
    /// Spool-Grenze in MB (bei Überschreitung werden Inhalte/Diffs weggelassen)
    #[serde(default = "default_spool_mb")]
    pub spool_mb: u64,
    /// harte Spool-Grenze in MB (Zentrale lange nicht erreichbar): darüber werden die ältesten Nachrichten
    /// verworfen, zuerst Datei-Ereignisse/Metriken. Wirksam höchstens 10 % des freien Platzes der Datenpartition.
    #[serde(default = "default_spool_max_mb")]
    pub spool_max_mb: u64,
    /// Budget für Diff-Basis-Inhalte in MB
    #[serde(default = "default_cache_mb")]
    pub cache_mb: u64,
    /// Ereignisse zusätzlich lokal als JSON-Zeilen schreiben (Diagnose)
    #[serde(default)]
    pub events_jsonl: Option<String>,
    /// Metriken alle n Sekunden erfassen (Übertragung als 1-Minuten-Aggregat)
    #[serde(default = "default_metrics_interval")]
    pub metrics_interval_s: u64,
    /// HTTPS-Proxy (sonst Umgebungsvariable HTTPS_PROXY)
    #[serde(default)]
    pub proxy: Option<String>,
    /// Selbst-Update, wenn die Zentrale eine neue signierte Version meldet (Hauptplan 12.4)
    #[serde(default = "default_true")]
    pub auto_update: bool,
    /// YARA-Regelpaket laden und Dateien damit prüfen (ab 0.5.0; Paket kommt signiert von get.tyrosec.com)
    #[serde(default = "default_true")]
    pub yara: bool,
    /// Beaconing-Stichprobe: alle 30 s neue ausgehende Verbindungen vermerken (ab 0.5.2, nur lesen)
    #[serde(default = "default_true")]
    pub beaconing: bool,
    /// feste Update-Quelle (sonst die von der Zentrale gemeldete)
    #[serde(default)]
    pub update_base: Option<String>,
    /// erlaubte Update-Quellen (Präfixe); von der Zentrale gemeldete Quellen außerhalb
    /// dieser Liste werden ignoriert. Ein lokal gesetztes `update_base` gilt immer.
    #[serde(default = "default_update_sources")]
    pub update_sources: Vec<String>,
    /// Inventar (Dienste, Ports, Firewall) alle n Sekunden prüfen
    #[serde(default = "default_inventory_interval")]
    pub inventory_interval_s: u64,
    /// Aktionen, die die Zentrale auslösen darf (restore, quarantine, block_ip). Standard: keine.
    /// Nur lokal per `tyrosecd actions enable` änderbar – eine übernommene Zentrale kann sie nicht einschalten.
    #[serde(default)]
    pub actions: Vec<String>,
    /// zusätzliche Ordner (außer den erkannten Webroots), in denen Wiederherstellen erlaubt ist – landen im
    /// systemd-Drop-in (`ReadWritePaths=`). Nur lokal per `tyrosecd actions enable --path …` änderbar.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub action_paths: Vec<String>,
}

fn default_update_sources() -> Vec<String> {
    crate::update::DEFAULT_UPDATE_SOURCES.iter().map(|s| s.to_string()).collect()
}

fn default_inventory_interval() -> u64 {
    600
}

fn default_true() -> bool {
    true
}

fn default_data_dir() -> String {
    "/var/lib/tyrosecd".into()
}
fn default_roots() -> Vec<String> {
    vec!["/".into()]
}
fn default_scan_interval() -> u64 {
    6 * 3600
}
fn default_spool_mb() -> u64 {
    200
}
fn default_spool_max_mb() -> u64 {
    512
}
fn default_cache_mb() -> u64 {
    500
}
fn default_metrics_interval() -> u64 {
    15
}

/// Adresse der Zentrale seit 17.11.2026: Port 443 auf eigener IP – ein späterer Umzug ist nur noch eine DNS-Änderung.
pub const SERVER_DEFAULT: &str = "https://ingest.tyrosec.com";
/// Frühere Standardadressen, die der Agent selbst auf `SERVER_DEFAULT` umstellt (nur genau diese; eigene
/// Adressen, Self-hosted und Tests bleiben unangetastet).
pub const SERVER_LEGACY: &[&str] = &["https://app.tyrosec.com:8443"];

/// Muss die Adresse umgestellt werden? Nur exakt eine frühere Standardadresse (mit oder ohne „/“ am Ende).
pub fn legacy_server(server: &str) -> bool {
    SERVER_LEGACY.contains(&server.trim_end_matches('/'))
}

impl AgentConfig {
    pub fn load(path: &str) -> Result<AgentConfig> {
        let s = std::fs::read_to_string(path).with_context(|| format!("Konfiguration {path}"))?;
        let mut c: AgentConfig = toml::from_str(&s)?;
        // frühe Installationen (vor dem Domainwechsel) haben den Platzhalter als einzige Update-Quelle gespeichert
        for u in c.update_sources.iter_mut() {
            if u.starts_with("https://get.tyrosd.example") {
                *u = crate::update::DEFAULT_UPDATE_SOURCES[0].to_string();
            }
        }
        Ok(c)
    }

    pub fn save(&self, path: &str) -> Result<()> {
        if let Some(d) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(d)?;
        }
        let tmp = format!("{path}.tmp");
        std::fs::write(&tmp, toml::to_string_pretty(self)?)?;
        set_mode(&tmp, 0o600);
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn key_path(&self) -> String {
        format!("{}/agent.key", self.data_dir)
    }
    pub fn cert_path(&self) -> String {
        format!("{}/agent.crt", self.data_dir)
    }
    /// CA für das Server-Zertifikat (nur Self-hosted/Test; sonst Web-PKI)
    pub fn server_ca_path(&self) -> String {
        format!("{}/server-ca.crt", self.data_dir)
    }
    pub fn state_path(&self) -> String {
        format!("{}/state.redb", self.data_dir)
    }
    pub fn spool_path(&self) -> String {
        format!("{}/spool.redb", self.data_dir)
    }
    pub fn enrolled(&self) -> bool {
        !self.host_id.is_empty() && std::path::Path::new(&self.cert_path()).exists()
    }
}

pub fn set_mode(path: &str, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(test)]
mod server_tests {
    use super::*;

    #[test]
    fn only_exact_legacy_default_is_migrated() {
        assert!(legacy_server("https://app.tyrosec.com:8443"));
        assert!(legacy_server("https://app.tyrosec.com:8443/"));
        for s in ["https://ingest.tyrosec.com", "https://app.tyrosec.com", "https://app.tyrosec.com:8444",
            "http://app.tyrosec.com:8443", "https://ingest.example.org:8443", "https://localhost:8443", ""] {
            assert!(!legacy_server(s), "{s}");
        }
        assert!(!legacy_server(SERVER_DEFAULT));
    }
}
