//! Agent configuration `/etc/tyrosecd/agent.toml` (writable by root only).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentConfig {
    /// e.g. https://ingest.tyrosec.com
    pub server: String,
    /// assigned by the central server during enrollment
    #[serde(default)]
    pub host_id: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    /// roots for real-time events
    #[serde(default = "default_roots")]
    pub roots: Vec<String>,
    /// roots for the reconciliation scan (empty = default profiles)
    #[serde(default)]
    pub scan_roots: Vec<String>,
    #[serde(default = "default_scan_interval")]
    pub scan_interval_s: u64,
    /// spool limit in MB (when exceeded, contents/diffs are omitted)
    #[serde(default = "default_spool_mb")]
    pub spool_mb: u64,
    /// hard spool limit in MB (central server unreachable for a long time): above it the oldest messages are
    /// discarded, file events/metrics first. Effective at most 10 % of the free space on the data partition.
    #[serde(default = "default_spool_max_mb")]
    pub spool_max_mb: u64,
    /// budget for diff base contents in MB
    #[serde(default = "default_cache_mb")]
    pub cache_mb: u64,
    /// additionally write events locally as JSON lines (diagnostics)
    #[serde(default)]
    pub events_jsonl: Option<String>,
    /// collect metrics every n seconds (transmitted as a 1-minute aggregate)
    #[serde(default = "default_metrics_interval")]
    pub metrics_interval_s: u64,
    /// HTTPS proxy (otherwise environment variable HTTPS_PROXY)
    #[serde(default)]
    pub proxy: Option<String>,
    /// self-update when the central server reports a new signed version (main plan 12.4)
    #[serde(default = "default_true")]
    pub auto_update: bool,
    /// load the YARA rule package and scan files with it (since 0.5.0; the package comes signed from get.tyrosec.com)
    #[serde(default = "default_true")]
    pub yara: bool,
    /// beaconing sample: record new outgoing connections every 30 s (since 0.5.2, read-only)
    #[serde(default = "default_true")]
    pub beaconing: bool,
    /// fixed update source (otherwise the one reported by the central server)
    #[serde(default)]
    pub update_base: Option<String>,
    /// allowed update sources (prefixes); sources reported by the central server outside
    /// this list are ignored. A locally set `update_base` always applies.
    #[serde(default = "default_update_sources")]
    pub update_sources: Vec<String>,
    /// check the inventory (services, ports, firewall) every n seconds
    #[serde(default = "default_inventory_interval")]
    pub inventory_interval_s: u64,
    /// actions the central server may trigger (restore, quarantine, block_ip). Default: none.
    /// Can only be changed locally via `tyrosecd actions enable` – a compromised central server cannot enable them.
    #[serde(default)]
    pub actions: Vec<String>,
    /// additional directories (besides the detected webroots) in which restoring is allowed – they end up in the
    /// systemd drop-in (`ReadWritePaths=`). Can only be changed locally via `tyrosecd actions enable --path …`.
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

/// Address of the central server since 2026-11-17: port 443 on its own IP – a later move is just a DNS change.
pub const SERVER_DEFAULT: &str = "https://ingest.tyrosec.com";
/// Former default addresses that the agent itself switches to `SERVER_DEFAULT` (exactly these only; custom
/// addresses, self-hosted and tests stay untouched).
pub const SERVER_LEGACY: &[&str] = &["https://app.tyrosec.com:8443"];

/// Does the address need to be switched? Only an exact former default address (with or without a trailing "/").
pub fn legacy_server(server: &str) -> bool {
    SERVER_LEGACY.contains(&server.trim_end_matches('/'))
}

impl AgentConfig {
    pub fn load(path: &str) -> Result<AgentConfig> {
        let s = std::fs::read_to_string(path).with_context(|| format!("configuration {path}"))?;
        let mut c: AgentConfig = toml::from_str(&s)?;
        // early installations (before the domain change) stored the placeholder as their only update source
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
    /// CA for the server certificate (self-hosted/test only; otherwise Web PKI)
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
