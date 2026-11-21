//! Überwachung: Backend starten (fanotify → inotify), Start-Scan, periodische
//! und Overflow-Scans, geordnetes Stoppen. Gemeinsam für `watch` und `run`.

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
    // SAFETY: Handler setzt nur ein Atomic.
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

#[allow(dead_code)] // trigger(): für manuelle Scans (später Kommando-Schnittstelle)
pub struct Monitor {
    pub backend: &'static str,
    rescan_rx: mpsc::Receiver<&'static str>,
    rescan_tx: mpsc::Sender<&'static str>,
    opts: MonitorOpts,
    proc: Arc<Processor>,
}

impl Monitor {
    /// Startet das Echtzeit-Backend (vor dem Scan, damit nichts verloren geht).
    pub fn start(proc: Arc<Processor>, opts: MonitorOpts) -> Result<Monitor> {
        let deb = Debouncer::new(proc.clone(), opts.debounce, Duration::from_secs(2));
        let (rescan_tx, rescan_rx) = mpsc::channel::<&'static str>();
        let mut chosen = "none";
        let b = opts.backend;
        if b == BackendChoice::Auto || b == BackendChoice::Fanotify {
            match tyrosd_source_fanotify::FanotifySource::raise_queue_limit(262_144) {
                Some((a, n)) if a != n => log(format!("fanotify-Warteschlange: {a} → {n} Ereignisse")),
                Some((a, _)) => log(format!("fanotify-Warteschlange: {a} Ereignisse")),
                None => {}
            }
            match tyrosd_source_fanotify::FanotifySource::new(&opts.roots, proc.policy.clone(), opts.unlimited_queue) {
                Ok(src) => {
                    for m in &src.marks {
                        log(format!("fanotify mark {} ({}): {}", m.path, m.fstype, m.error.clone().unwrap_or_else(|| "ok".into())));
                    }
                    log(format!("fanotify: {} Verzeichnisse vorab aufgelöst", src.prewarmed));
                    chosen = "fanotify";
                    // Hybrid: Dateisysteme, die fanotify nicht markieren kann (z. B. /dev/shm auf Kernel < 5.12),
                    // übernimmt inotify – nur diese, auf ihr Dateisystem begrenzt, gleiche Verarbeitungskette
                    let failed: Vec<String> = src.marks.iter().filter(|m| !m.ok).map(|m| m.path.clone()).collect();
                    if !failed.is_empty() {
                        match tyrosd_source_inotify::InotifySource::new(&failed, proc.policy.clone(), true) {
                            Ok(isrc) => {
                                log(format!("Hybrid: inotify übernimmt {} ({} Watches), fanotify-Markierung dort nicht möglich", failed.join(", "), isrc.stats.watches));
                                let d = deb.clone();
                                let tx = rescan_tx.clone();
                                std::thread::Builder::new().name("inotify-hybrid".into()).spawn(move || {
                                    if let Err(e) = isrc.run(d, move || {
                                        let _ = tx.send("overflow");
                                    }) {
                                        log(format!("inotify (Hybrid) beendet: {e:#}"));
                                    }
                                })?;
                            }
                            Err(e) => log(format!("Hybrid: inotify für {} nicht möglich: {e:#}", failed.join(", "))),
                        }
                    }
                    let d = deb.clone();
                    let tx = rescan_tx.clone();
                    std::thread::Builder::new().name("fanotify".into()).spawn(move || {
                        if let Err(e) = src.run(d, move || {
                            let _ = tx.send("overflow");
                        }) {
                            log(format!("fanotify beendet: {e:#}"));
                        }
                    })?;
                }
                Err(e) if b == BackendChoice::Auto => log(format!("fanotify nicht verfügbar ({e:#}) → inotify")),
                Err(e) => return Err(e),
            }
        }
        // Probelauf „Schutz in Echtzeit“: Programmstarts aus /tmp, /dev/shm, Upload-Ordnern nur melden (nichts verhindern)
        match tyrosd_source_fanotify::exec::ExecWatch::new() {
            Ok(w) => {
                log(format!("Programmstarts (Probelauf Schutz): {}", w.marked.join(", ")));
                let d = deb.clone();
                std::thread::Builder::new().name("exec-watch".into()).spawn(move || {
                    if let Err(e) = w.run(d) {
                        log(format!("Programmstarts (Probelauf) beendet: {e:#}"));
                    }
                })?;
            }
            Err(e) => log(format!("Programmstarts (Probelauf Schutz) nicht verfügbar: {e:#}")),
        }
        if chosen == "none" && (b == BackendChoice::Auto || b == BackendChoice::Inotify) {
            let t = Instant::now();
            let src = tyrosd_source_inotify::InotifySource::new(&opts.roots, proc.policy.clone(), false)?;
            log(format!(
                "inotify: {} Watches in {:.1} s (Limit {} → {}, Fehler {}, ohne Watch wegen Obergrenze {})",
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
                    log(format!("inotify beendet: {e:#}"));
                }
            })?;
        }
        if chosen == "none" {
            log("kein Echtzeit-Backend – nur Abgleich-Scans");
        }
        if opts.start_scan {
            let _ = rescan_tx.send("start");
        }
        Ok(Monitor { backend: chosen, rescan_rx, rescan_tx, opts, proc })
    }

    /// Scan von außen anstoßen.
    #[allow(dead_code)]
    pub fn trigger(&self, reason: &'static str) {
        let _ = self.rescan_tx.send(reason);
    }

    /// Hauptschleife bis STOP. Danach Zustand dauerhaft sichern.
    pub fn run_until_stop(self) -> Result<()> {
        let mut last_scan = Instant::now() - Duration::from_secs(3600);
        let mut scans_done = 0u32;
        // Webroots nach Überlauf: frühester noch nicht nachgeprüfter Überlauf (Unix-Sekunden) und letzter Lauf
        let mut webroot_since: Option<i64> = None;
        let mut last_webroot = Instant::now() - Duration::from_secs(3600);
        let mut webroot_job: Option<WebrootRescan> = None;
        let started = Instant::now();
        loop {
            if STOP.load(Ordering::Relaxed) {
                // Zustand inkl. Echtzeit-Ereignissen sichern (Start-Scan danach findet nur echte Lücken)
                match tyrosd_source_scan::save_state(&self.proc, scans_done > 0 || self.proc.state.is_complete()) {
                    Ok(n) => log(format!("Zustand gespeichert ({n} B)")),
                    Err(e) => log(format!("Zustand nicht gespeichert: {e:#}")),
                }
                log(format!("Stop · Statistik {}", serde_json::to_string(&*self.proc.stats.lock().unwrap())?));
                return Ok(());
            }
            let reason = match self.rescan_rx.recv_timeout(Duration::from_millis(500)) {
                Ok(r) => r,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // Herabstufung eines heißen Ordners beendet: dort übersprungene Dateien per Nachscan nachholen
                    // (nur nach der ersten vollständigen Erfassung – ein Teil-Scan darf die Baseline nicht abschließen)
                    let due = if self.proc.state.is_complete() { self.proc.take_due_rescans() } else { Vec::new() };
                    let due: Vec<String> = due.into_iter().filter(|d| std::path::Path::new(d).is_dir()).collect();
                    if !due.is_empty() {
                        log(format!("Nachscan nach Herabstufung: {}", due.join(", ")));
                        let cfg = ScanConfig { roots: due, ..self.opts.scan.clone() };
                        match tyrosd_source_scan::scan(&cfg, &self.proc) {
                            Ok(r) => log(format!("Nachscan fertig: {}", serde_json::to_string(&r)?)),
                            Err(e) => log(format!("Nachscan-Fehler: {e:#}")),
                        }
                        continue;
                    }
                    // Webroots nach einem Überlauf nachprüfen – höchstens alle 10 min, deckt den Zeitraum seit dem ersten
                    // noch offenen Überlauf ab (die Standard-Orte deckt der Abgleich-Scan ab)
                    if webroot_job.is_none() {
                        if let Some(since) = webroot_since.filter(|_| last_webroot.elapsed() >= WEBROOT_RESCAN_EVERY) {
                            webroot_since = None;
                            webroot_job = Some(WebrootRescan::new(since - 120, crate::decoy::webroots()));
                            last_webroot = Instant::now() - WEBROOT_STEP_PAUSE;
                        }
                    }
                    // in Etappen: höchstens WEBROOT_STEP_BUDGET am Stück, dann WEBROOT_STEP_PAUSE Pause
                    if webroot_job.is_some() && last_webroot.elapsed() >= WEBROOT_STEP_PAUSE {
                        let job = webroot_job.as_mut().unwrap();
                        let done = job.step(&self.proc, WEBROOT_STEP_BUDGET);
                        last_webroot = Instant::now();
                        if done {
                            let (r, since) = (job.summary(), job.since());
                            webroot_job = None;
                            log(format!("Nachprüfung Webroots nach Überlauf: {r}"));
                            // Ergebnis an die Zentrale (wird an den offenen Überlauf-Alarm angehängt, kein eigener Alarm)
                            if let Some(sp) = REPORT_SPOOL.get() {
                                let _ = sp.push(tyrosd_core::now_ns(), tyrosd_proto::envelope::Body::Detection(tyrosd_proto::Detection {
                                    rule: "overflow_rescan".into(), severity: "info".into(), title: "Nachprüfung der Webroots nach Überlauf".into(),
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
                    log("Überlauf kurz nach dem Start – Webroots werden nicht nachgeprüft");
                } else {
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
                    webroot_since.get_or_insert(now);
                }
            }
            // Overflow-Rescans höchstens alle 30 s
            if reason == "overflow" && last_scan.elapsed() < Duration::from_secs(30) {
                continue;
            }
            last_scan = Instant::now();
            log(format!("Scan ({reason}) …"));
            match tyrosd_source_scan::scan(&self.opts.scan, &self.proc) {
                Ok(r) => {
                    scans_done += 1;
                    log(format!("Scan fertig: {}", serde_json::to_string(&r)?))
                }
                Err(e) => log(format!("Scan-Fehler: {e:#}")),
            }
        }
    }
}

/// Spool für Meldungen an die Zentrale (setzt main beim Start)
pub static REPORT_SPOOL: std::sync::OnceLock<Arc<tyrosd_transport::Spool>> = std::sync::OnceLock::new();

/// Webroots nach einem Überlauf höchstens so oft nachprüfen
const WEBROOT_RESCAN_EVERY: Duration = Duration::from_secs(600);
/// höchstens so viele geänderte Dateien je Nachprüfung weiterreichen
const WEBROOT_RESCAN_MAX_FILES: usize = 20_000;
/// eine Etappe der Nachprüfung höchstens so lange, danach Pause (Praxisfall: 2,5 Mio. Dateien, 133 s am Stück)
pub const WEBROOT_STEP_BUDGET: Duration = Duration::from_secs(45);
pub const WEBROOT_STEP_PAUSE: Duration = Duration::from_secs(60);
/// Überläufe so kurz nach dem Start (Neustart-Spitze, Start-Scan) lösen keine Nachprüfung der Webroots aus
pub const WEBROOT_START_GRACE: Duration = Duration::from_secs(180);

/// Nachprüfung der Webroots nach einem Überlauf: Dateien, die seit `since` geändert wurden (ctime – auch
/// Umbenennen/Rechte), gehen in die normale Verarbeitung (Prüfung, Webshell-/YARA-Prüfung). Nur Metadaten lesen; Inhalte
/// nur für geänderte Dateien. Läuft in Etappen (`step` mit Zeitbudget) und setzt am zuletzt geprüften Pfad fort.
/// Schließt die Lücke, wenn der Kernel bei Last Ereignisse verwirft und der Abgleich-Scan die Webroots außerhalb der
/// Standard-Orte nicht abdeckt.
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

    /// Eine Etappe; liefert true, wenn alle Webroots fertig sind.
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
                // fortsetzen: alles bis einschließlich Merkpunkt überspringen (Ordner ganz, wenn der Merkpunkt nicht darin liegt)
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
            "{} Webroots, {} Dateien geprüft, {} seit dem Überlauf geändert ({} ms in {} Etappe{})",
            self.roots.len(),
            self.seen,
            self.changed,
            self.ms,
            self.steps,
            if self.steps == 1 { "" } else { "n" }
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
            assert!(steps < 50, "kommt nicht voran");
        }
        assert!(steps >= 2, "in Etappen ({steps})");
        assert_eq!((r.seen, r.changed), (files, files), "jede Datei genau einmal");
        assert!(r.summary().contains("Etappen"));
        std::fs::remove_dir_all(&base).ok();
    }
}
