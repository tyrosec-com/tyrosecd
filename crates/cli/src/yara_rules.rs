//! YARA rule pack in the agent: load the stored pack at startup,
//! fetch new packs as announced in the heartbeat response (signed, allowed source only, higher only), swap them
//! without a restart, keep the previous one on errors. Scanning is done by the webshell checker (writes of web
//! code, new files in temp folders).

use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use tyrosd_transport::{rules, update};
use tyrosd_yara::{Engine, Hit};

use crate::monitor::log;

static ENGINE: RwLock<Option<Arc<Engine>>> = RwLock::new(None);
static BUSY: AtomicBool = AtomicBool::new(false);
static WARNED_SOURCE: AtomicBool = AtomicBool::new(false);
/// after an error, retry at most once per hour (Unix seconds of the next attempt)
static RETRY_AT: AtomicU64 = AtomicU64::new(0);

/// files are scanned up to this size at most
pub const MAX_WEB: u64 = 2 << 20;
pub const MAX_OTHER: u64 = 8 << 20;

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("VmRSS:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn set_status(version: &str, count: usize, rss: u64, error: &str) {
    if let Ok(mut s) = rules::STATUS.lock() {
        if !version.is_empty() {
            s.version = version.to_string();
            s.count = count as u32;
            s.rss_kb = rss;
        }
        s.error = error.to_string();
    }
}

pub fn loaded_version() -> Option<String> {
    ENGINE.read().ok()?.as_ref().map(|e| e.version.clone())
}

/// load the stored pack (error → previous pack); runs in its own thread, the agent starts immediately
fn load(data_dir: &str) {
    let mut tries = 0;
    while let Some(v) = rules::current(data_dir) {
        tries += 1;
        let before = rss_kb();
        match Engine::load(&rules::dir(data_dir, &v), &v) {
            Ok(e) => {
                let delta = rss_kb().saturating_sub(before);
                log(format!("YARA rules {v}: {} rules loaded ({} ms, +{} MB)", e.count, e.compile_ms, delta / 1024));
                set_status(&v, e.count, delta, "");
                *ENGINE.write().unwrap() = Some(Arc::new(e));
                return;
            }
            Err(e) => {
                log(format!("YARA rules {v} failed to load: {e:#}"));
                set_status("", 0, 0, &format!("{v}: {e:#}"));
                if tries > 3 || rules::fall_back(data_dir, &v).is_none() {
                    return;
                }
            }
        }
    }
}

pub fn start(data_dir: String) {
    let _ = std::thread::Builder::new().name("yara-load".into()).spawn(move || load(&data_dir));
}

/// Heartbeat response: newer pack offered → fetch and load
pub fn on_ack(version: &str, base: &str, sources: &[String], data_dir: &str) {
    let Some(want) = rules::number(version) else { return };
    let have = loaded_version().or_else(|| rules::current(data_dir));
    if have.as_deref().and_then(rules::number).is_some_and(|h| h >= want) || now() < RETRY_AT.load(Ordering::Relaxed) {
        return;
    }
    if !update::source_allowed(base, sources) {
        if !WARNED_SOURCE.swap(true, Ordering::SeqCst) {
            log(format!("Rule source {base} not allowed (update_sources) – ignored"));
        }
        return;
    }
    if BUSY.swap(true, Ordering::SeqCst) {
        return;
    }
    let (base, dd) = (base.to_string(), data_dir.to_string());
    let _ = std::thread::Builder::new().name("yara-update".into()).spawn(move || {
        match rules::fetch_newer(&base, &dd, have.as_deref()) {
            Ok(Some(v)) => {
                log(format!("YARA rule pack {v} fetched"));
                load(&dd);
            }
            Ok(None) => {}
            Err(e) => {
                log(format!("YARA rule pack rejected: {e:#}"));
                set_status("", 0, 0, &format!("{e:#}"));
                RETRY_AT.store(now() + 3600, Ordering::Relaxed);
            }
        }
        BUSY.store(false, Ordering::SeqCst);
    });
}

/// Scan a file (reads at most `limit` bytes; larger files are not scanned)
pub fn scan_path(path: &str, limit: u64) -> Vec<Hit> {
    let Some(engine) = ENGINE.read().ok().and_then(|g| g.clone()) else { return Vec::new() };
    // do not follow symlinks (a website user could replace the file between event and scan with a link to
    // a root file), non-blocking (FIFO); regular files only (below)
    use std::os::unix::fs::OpenOptionsExt;
    let Ok(f) = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path) else {
        return Vec::new();
    };
    let Ok(meta) = f.metadata() else { return Vec::new() };
    if !meta.is_file() || meta.len() == 0 || meta.len() > limit {
        return Vec::new();
    }
    let mut data = Vec::with_capacity(meta.len() as usize);
    if f.take(limit).read_to_end(&mut data).is_err() {
        return Vec::new();
    }
    engine.scan(&data)
}

/// new/changed file in a temp folder (drop location for downloaded malware)
pub fn tmp_file(path: &str) -> bool {
    let l = tyrosd_core::container::effective(path);
    (l.starts_with("/tmp/") || l.starts_with("/var/tmp/") || l.starts_with("/dev/shm/")) && !l.contains("/systemd-private-")
}
