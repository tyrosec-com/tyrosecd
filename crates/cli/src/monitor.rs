//! Monitoring: start the backend (fanotify → inotify), initial scan, periodic
//! and overflow scans, orderly shutdown. Shared by `watch` and `run`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tyrosd_core::debounce::Debouncer;
use tyrosd_core::Processor;
use tyrosd_source_scan::ScanConfig;

pub static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

pub fn install_signal_handler() {
    // SAFETY: the handler only sets an atomic.
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
    }
}

pub fn log(msg: impl AsRef<str>) {
    eprintln!("[tyrosecd] {}", msg.as_ref());
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BackendChoice {
    Auto,
    Fanotify,
    Inotify,
    None,
}

pub struct MonitorOpts {
    pub backend: BackendChoice,
    pub roots: Vec<String>,
    pub scan: ScanConfig,
    pub scan_interval: Duration,
    pub start_scan: bool,
    pub debounce: Duration,
    pub unlimited_queue: bool,
}

#[allow(dead_code)] // trigger(): for manual scans (later a command interface)
pub struct Monitor {
    pub backend: &'static str,
    rescan_rx: mpsc::Receiver<&'static str>,
    rescan_tx: mpsc::Sender<&'static str>,
    opts: MonitorOpts,
    proc: Arc<Processor>,
}

impl Monitor {
    /// Starts the real-time backend (before the scan, so nothing is lost).
    pub fn start(proc: Arc<Processor>, opts: MonitorOpts) -> Result<Monitor> {
        let deb = Debouncer::new(proc.clone(), opts.debounce, Duration::from_secs(2));
        let (rescan_tx, rescan_rx) = mpsc::channel::<&'static str>();
        let mut chosen = "none";
        let b = opts.backend;
        if b == BackendChoice::Auto || b == BackendChoice::Fanotify {
            match tyrosd_source_fanotify::FanotifySource::raise_queue_limit(262_144) {
                Some((a, n)) if a != n => log(format!("fanotify queue: {a} → {n} events")),
                Some((a, _)) => log(format!("fanotify queue: {a} events")),
                None => {}
            }
            match tyrosd_source_fanotify::FanotifySource::new(&opts.roots, proc.policy.clone(), opts.unlimited_queue) {
                Ok(src) => {
                    for m in &src.marks {
                        log(format!("fanotify mark {} ({}): {}", m.path, m.fstype, m.error.clone().unwrap_or_else(|| "ok".into())));
                    }
                    log(format!("fanotify: {} directories pre-resolved", src.prewarmed));
                    chosen = "fanotify";
                    // Hybrid: file systems that fanotify cannot mark (e.g. /dev/shm on kernel < 5.12)
                    // are handled by inotify – only these, limited to their file system, same processing chain
                    let failed: Vec<String> = src.marks.iter().filter(|m| !m.ok).map(|m| m.path.clone()).collect();
                    if !failed.is_empty() {
                        match tyrosd_source_inotify::InotifySource::new(&failed, proc.policy.clone(), true) {
                            Ok(isrc) => {
                                log(format!("Hybrid: inotify takes over {} ({} watches), fanotify marking not possible there", failed.join(", "), isrc.stats.watches));
                                let d = deb.clone();
                                let tx = rescan_tx.clone();
                                std::thread::Builder::new().name("inotify-hybrid".into()).spawn(move || {
                                    if let Err(e) = isrc.run(d, move || {
                                        let _ = tx.send("overflow");
                                    }) {
                                        log(format!("inotify (hybrid) ended: {e:#}"));
                                    }
                                })?;
                            }
                            Err(e) => log(format!("Hybrid: inotify not possible for {}: {e:#}", failed.join(", "))),
                        }
                    }
                    let d = deb.clone();
                    let tx = rescan_tx.clone();
                    std::thread::Builder::new().name("fanotify".into()).spawn(move || {
                        if let Err(e) = src.run(d, move || {
                            let _ = tx.send("overflow");
                        }) {
                            log(format!("fanotify ended: {e:#}"));
                        }
                    })?;
                }
                Err(e) if b == BackendChoice::Auto => log(format!("fanotify not available ({e:#}) → inotify")),
                Err(e) => return Err(e),
            }
        }
        // Trial run "real-time protection": only report program starts from /tmp, /dev/shm, upload folders
        // (prevent nothing)
        match tyrosd_source_fanotify::exec::ExecWatch::new() {
            Ok(w) => {
                log(format!("Program starts (protection trial run): {}", w.marked.join(", ")));
                let d = deb.clone();
                std::thread::Builder::new().name("exec-watch".into()).spawn(move || {
                    if let Err(e) = w.run(d) {
                        log(format!("Program starts (trial run) ended: {e:#}"));
                    }
                })?;
            }
            Err(e) => log(format!("Program starts (protection trial run) not available: {e:#}")),
        }
        if chosen == "none" && (b == BackendChoice::Auto || b == BackendChoice::Inotify) {
            let t = Instant::now();
            let src = tyrosd_source_inotify::InotifySource::new(&opts.roots, proc.policy.clone(), false)?;
            log(format!(
                "inotify: {} watches in {:.1} s (limit {} → {}, errors {}, without watch due to cap {})",
                src.stats.watches,
                t.elapsed().as_secs_f64(),
                src.stats.limit_before,
                src.stats.limit_after,
                src.stats.add_errors,
                src.stats.capped
            ));
            chosen = "inotify";
            let d = deb.clone();
            let tx = rescan_tx.clone();
            std::thread::Builder::new().name("inotify".into()).spawn(move || {
                if let Err(e) = src.run(d, move || {
                    let _ = tx.send("overflow");
                }) {
                    log(format!("inotify ended: {e:#}"));
                }
            })?;
        }
        if chosen == "none" {
            log("no real-time backend – reconciliation scans only");
        }
        if opts.start_scan {
            let _ = rescan_tx.send("start");
        }
        Ok(Monitor { backend: chosen, rescan_rx, rescan_tx, opts, proc })
    }

    /// Trigger a scan from outside.
    #[allow(dead_code)]
    pub fn trigger(&self, reason: &'static str) {
        let _ = self.rescan_tx.send(reason);
    }

    /// Main loop until STOP. Afterwards persist the state.
    pub fn run_until_stop(self) -> Result<()> {
        let mut last_scan = Instant::now() - Duration::from_secs(3600);
        let mut scans_done = 0u32;
        // Webroots after overflow: earliest overflow not yet re-checked (Unix seconds) and last run
        let mut webroot_since: Option<i64> = None;
        let mut last_webroot = Instant::now() - Duration::from_secs(3600);
        let mut webroot_job: Option<WebrootRescan> = None;
        let started = Instant::now();
        loop {
            if STOP.load(Ordering::Relaxed) {
                // Persist state incl. real-time events (the initial scan afterwards only finds real gaps)
                match tyrosd_source_scan::save_state(&self.proc, scans_done > 0 || self.proc.state.is_complete()) {
                    Ok(n) => log(format!("State saved ({n} B)")),
                    Err(e) => log(format!("State not saved: {e:#}")),
                }
                log(format!("Stop · statistics {}", serde_json::to_string(&*self.proc.stats.lock().unwrap())?));
                return Ok(());
            }
            let reason = match self.rescan_rx.recv_timeout(Duration::from_millis(500)) {
                Ok(r) => r,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // Downgrade of a hot folder ended: catch up on files skipped there via a re-scan
                    // (only after the first complete capture – a partial scan must not finalize the baseline)
                    let due = if self.proc.state.is_complete() { self.proc.take_due_rescans() } else { Vec::new() };
                    let due: Vec<String> = due.into_iter().filter(|d| std::path::Path::new(d).is_dir()).collect();
                    if !due.is_empty() {
                        log(format!("Re-scan after downgrade: {}", due.join(", ")));
                        let cfg = ScanConfig { roots: due, ..self.opts.scan.clone() };
                        match tyrosd_source_scan::scan(&cfg, &self.proc) {
                            Ok(r) => log(format!("Re-scan done: {}", serde_json::to_string(&r)?)),
                            Err(e) => log(format!("Re-scan error: {e:#}")),
                        }
                        continue;
                    }
                    // Re-check webroots after an overflow – at most every 10 min, covers the period since the first
                    // still open overflow (the default locations are covered by the reconciliation scan)
                    if webroot_job.is_none() {
                        if let Some(since) = webroot_since.filter(|_| last_webroot.elapsed() >= WEBROOT_RESCAN_EVERY) {
                            webroot_since = None;
                            webroot_job = Some(WebrootRescan::new(since - 120, crate::decoy::webroots()));
                            last_webroot = Instant::now() - WEBROOT_STEP_PAUSE;
                        }
                    }
                    // in stages: at most WEBROOT_STEP_BUDGET at a time, then a WEBROOT_STEP_PAUSE pause
                    if webroot_job.is_some() && last_webroot.elapsed() >= WEBROOT_STEP_PAUSE {
                        let job = webroot_job.as_mut().unwrap();
                        let done = job.step(&self.proc, WEBROOT_STEP_BUDGET);
                        last_webroot = Instant::now();
                        if done {
                            let (r, since) = (job.summary(), job.since());
                            webroot_job = None;
                            log(format!("Web root re-check after overflow: {r}"));
                            // Result to the central server (attached to the open overflow alert, no separate alert)
                            if let Some(sp) = REPORT_SPOOL.get() {
                                let _ = sp.push(tyrosd_core::now_ns(), tyrosd_proto::envelope::Body::Detection(tyrosd_proto::Detection {
                                    rule: "overflow_rescan".into(), severity: "info".into(), title: "Re-check of the web roots after overflow".into(),
                                    detail: r, key: format!("overflow_rescan|{since}"), ..Default::default()
                                }));
                            }
                        }
                        continue;
                    }
                    if last_scan.elapsed() >= self.opts.scan_interval {
                        "interval"
                    } else {
                        continue;
                    }
                }
                Err(_) => return Ok(()),
            };
            if reason == "overflow" {
                if started.elapsed() < WEBROOT_START_GRACE {
                    log("Overflow shortly after startup – web roots are not re-checked");
                } else {
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
                    webroot_since.get_or_insert(now);
                }
            }
            // Overflow rescans at most every 30 s
            if reason == "overflow" && last_scan.elapsed() < Duration::from_secs(30) {
                continue;
            }
            last_scan = Instant::now();
            log(format!("Scan ({reason}) …"));
            match tyrosd_source_scan::scan(&self.opts.scan, &self.proc) {
                Ok(r) => {
                    scans_done += 1;
                    log(format!("Scan done: {}", serde_json::to_string(&r)?))
                }
                Err(e) => log(format!("Scan error: {e:#}")),
            }
        }
    }
}

/// Spool for messages to the central server (set by main at startup)
pub static REPORT_SPOOL: std::sync::OnceLock<Arc<tyrosd_transport::Spool>> = std::sync::OnceLock::new();

/// Re-check webroots after an overflow at most this often
const WEBROOT_RESCAN_EVERY: Duration = Duration::from_secs(600);
/// pass on at most this many changed files per re-check
const WEBROOT_RESCAN_MAX_FILES: usize = 20_000;
/// one stage of the re-check takes at most this long, then a pause (real-world case: 2.5 million files, 133 s at a time)
pub const WEBROOT_STEP_BUDGET: Duration = Duration::from_secs(45);
pub const WEBROOT_STEP_PAUSE: Duration = Duration::from_secs(60);
/// Overflows this soon after startup (restart spike, initial scan) do not trigger a re-check of the webroots
pub const WEBROOT_START_GRACE: Duration = Duration::from_secs(180);

/// Re-check of the webroots after an overflow: files changed since `since` (ctime – also
/// renames/mode changes) go into normal processing (check, webshell/YARA scan). Reads metadata only; content
/// only for changed files. Runs in stages (`step` with a time budget) and resumes at the last checked path.
/// Closes the gap when the kernel drops events under load and the reconciliation scan does not cover webroots
/// outside the default locations.
pub struct WebrootRescan {
    since: i64,
    roots: Vec<String>,
    idx: usize,
    checkpoint: Option<std::path::PathBuf>,
    seen: usize,
    changed: usize,
    steps: u32,
    ms: u128,
}

impl WebrootRescan {
    pub fn new(since: i64, mut roots: Vec<String>) -> Self {
        roots.sort();
        roots.dedup();
        WebrootRescan { since, roots, idx: 0, checkpoint: None, seen: 0, changed: 0, steps: 0, ms: 0 }
    }

    /// One stage; returns true when all webroots are done.
    pub fn step(&mut self, proc: &Processor, budget: Duration) -> bool {
        use std::os::unix::fs::MetadataExt;
        let t = Instant::now();
        self.steps += 1;
        while self.idx < self.roots.len() {
            let root = self.roots[self.idx].clone();
            let mut it = walkdir::WalkDir::new(&root).follow_links(false).same_file_system(true).sort_by_file_name().into_iter();
            let mut last: Option<std::path::PathBuf> = None;
            let mut n = 0usize;
            while let Some(entry) = it.next() {
                let Ok(e) = entry else { continue };
                let path = e.path();
                // resume: skip everything up to and including the checkpoint (whole folder if the checkpoint is not
                // inside it)
                if let Some(cp) = &self.checkpoint {
                    if path <= cp.as_path() {
                        if e.file_type().is_dir() && !cp.starts_with(path) {
                            it.skip_current_dir();
                        }
                        continue;
                    }
                }
                n += 1;
                if n % 256 == 0 && t.elapsed() >= budget {
                    if let Some(l) = last {
                        self.checkpoint = Some(l);
                        self.ms += t.elapsed().as_millis();
                        return false;
                    }
                }
                let p = path.to_string_lossy();
                if e.file_type().is_dir() {
                    let name = e.file_name().to_string_lossy();
                    if matches!(name.as_ref(), "node_modules" | ".git" | ".cache") || proc.policy.mode_for(&p) == tyrosd_core::policy::ContentMode::Ignore {
                        it.skip_current_dir();
                    }
                    last = Some(path.to_path_buf());
                    continue;
                }
                last = Some(path.to_path_buf());
                if !e.file_type().is_file() {
                    continue;
                }
                self.seen += 1;
                let Ok(m) = e.metadata() else { continue };
                if m.ctime() < self.since || proc.policy.mode_for(&p) == tyrosd_core::policy::ContentMode::Ignore {
                    continue;
                }
                self.changed += 1;
                proc.process(tyrosd_core::processor::Input {
                    ts_ns: tyrosd_core::now_ns(),
                    first_ts_ns: tyrosd_core::now_ns(),
                    backend: tyrosd_core::event::Backend::Scan,
                    op: tyrosd_core::event::Op::Modify,
                    path: p.into_owned(),
                    old_path: None,
                    proc: None,
                    note: Some("overflow_rescan".into()),
                    quiet_nochange: true,
                });
                if self.changed >= WEBROOT_RESCAN_MAX_FILES {
                    self.idx = self.roots.len();
                    break;
                }
            }
            self.checkpoint = None;
            self.idx += 1;
        }
        self.ms += t.elapsed().as_millis();
        true
    }

    pub fn summary(&self) -> String {
        format!(
            "{} web roots, {} files checked, {} changed since the overflow ({} ms in {} step{})",
            self.roots.len(),
            self.seen,
            self.changed,
            self.ms,
            self.steps,
            if self.steps == 1 { "" } else { "s" }
        )
    }

    pub fn since(&self) -> i64 {
        self.since
    }
}

#[cfg(test)]
mod rescan_tests {
    use super::*;

    #[test]
    fn rescan_runs_in_steps_and_resumes_without_gaps_or_repeats() {
        let base = std::env::temp_dir().join(format!("tyrosd-rescan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let root = base.join("www");
        for d in ["a", "b/c", "b/d", "e"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        let mut files = 0;
        for (d, k) in [("a", 300), ("b/c", 300), ("b/d", 10), ("e", 300)] {
            for i in 0..k {
                std::fs::write(root.join(d).join(format!("f{i:04}.txt")), b"x").unwrap();
                files += 1;
            }
        }
        let st = tyrosd_core::state::State::open(&base.join("s.redb").to_string_lossy(), 4, 1 << 20).unwrap();
        let sink = tyrosd_core::sink::JsonlSink::open(Some(&base.join("e.jsonl").to_string_lossy())).unwrap();
        let proc = Processor::new(Arc::new(tyrosd_core::policy::Policy::default_policy()), st, Box::new(sink), tyrosd_core::hash::Algo::Sha256);
        let mut r = WebrootRescan::new(0, vec![root.to_string_lossy().into_owned()]);
        let mut steps = 0;
        while !r.step(&proc, Duration::ZERO) {
            steps += 1;
            assert!(steps < 50, "no progress");
        }
        assert!(steps >= 2, "in steps ({steps})");
        assert_eq!((r.seen, r.changed), (files, files), "each file exactly once");
        assert!(r.summary().contains("steps"));
        std::fs::remove_dir_all(&base).ok();
    }
}
