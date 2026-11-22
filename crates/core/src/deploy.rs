//! Deploy window (main plan 7.2): CI/deploy scripts announce a deploy via
//! `tyrosd deploy start|end`. The running agent reads the
//! marker (file, writable by root only) and tags events within the window with
//! `deploy:<label>`. The central server groups them instead of alerting on each one.

use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeployMarker {
    pub label: String,
    /// Unix seconds; after that the window counts as ended (protects against a forgotten `end`)
    pub until: u64,
    /// Optional: only paths under these prefixes (e.g. webroot)
    #[serde(default)]
    pub paths: Vec<String>,
}

pub struct DeployWindow {
    path: String,
    cache: Mutex<(Instant, Option<DeployMarker>)>,
}

fn now_s() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl DeployWindow {
    pub fn new(path: impl Into<String>) -> DeployWindow {
        DeployWindow { path: path.into(), cache: Mutex::new((Instant::now() - Duration::from_secs(10), None)) }
    }

    /// Label if `p` lies within an active deploy window (marker read at most once per second).
    pub fn label_for(&self, p: &str) -> Option<String> {
        let mut c = self.cache.lock().unwrap();
        if c.0.elapsed() > Duration::from_secs(1) {
            c.1 = std::fs::read(&self.path).ok().and_then(|d| serde_json::from_slice::<DeployMarker>(&d).ok());
            c.0 = Instant::now();
        }
        let m = c.1.as_ref()?;
        if m.until < now_s() {
            return None;
        }
        if !m.paths.is_empty() && !m.paths.iter().any(|x| p.starts_with(x.as_str())) {
            return None;
        }
        Some(m.label.clone())
    }

    pub fn start(path: &str, label: &str, minutes: u64, paths: Vec<String>) -> anyhow::Result<()> {
        let m = DeployMarker { label: label.to_string(), until: now_s() + minutes * 60, paths };
        if let Some(d) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(d)?;
        }
        let tmp = format!("{path}.tmp");
        std::fs::write(&tmp, serde_json::to_vec(&m)?)?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }

    pub fn end(path: &str) -> anyhow::Result<()> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}
