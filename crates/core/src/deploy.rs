//! Deploy-Fenster (Hauptplan 7.2): CI/Deploy-Skripte melden per
//! `tyrosd deploy start|end` einen Deploy. Der laufende Agent liest den
//! Marker (Datei, nur root-schreibbar) und versieht Ereignisse im Fenster mit
//! `deploy:<label>`. Die Zentrale gruppiert sie, statt einzeln zu alarmieren.

use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeployMarker {
    pub label: String,
    /// Unix-Sekunden; danach gilt das Fenster als beendet (Schutz vor vergessenem `end`)
    pub until: u64,
    /// Optional: nur Pfade unter diesen Präfixen (z. B. Webroot)
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

    /// Label, falls `p` in einem aktiven Deploy-Fenster liegt (Marker höchstens 1×/s gelesen).
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
