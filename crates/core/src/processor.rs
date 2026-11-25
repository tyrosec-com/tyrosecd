//! Processing of a (debounced) event: policy → read content →
//! hash → diff against base → patch verification → event.
//!
//! State (hashes, metadata, diff base) lives in `State` (embedded
//! database), not in RAM. Real-time monitoring and scan share this state.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::content;
use crate::diff;
use crate::event::{Backend, Event, FileMeta, Op};
use crate::hash::{self, Algo};
use crate::policy::{ContentMode, Policy};
use crate::procinfo::{self, ProcInfo};
use crate::redact;
use crate::sink::Sink;
#[cfg(test)]
use crate::sink::JsonlSink;
use crate::state::{hash_from_hex, Entry, State};

/// Temp directories in which short-lived files are common
pub fn is_temp_path(p: &str) -> bool {
    ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"].iter().any(|d| p.starts_with(d))
}

pub struct Processor {
    pub policy: Arc<Policy>,
    pub state: Arc<State>,
    pub sink: Box<dyn Sink>,
    pub algo: Algo,
    /// Write the (truncated) diff text into the event – spike only.
    pub emit_diff: bool,
    /// Apply the patch after creating it and check the hash (like the ingest).
    pub verify_patch: bool,
    pub stats: Mutex<Stats>,
    /// Event rate per directory (automatic downgrade, main plan 5)
    hot: Mutex<HashMap<String, Hot>>,
    /// downgraded directories → end of the downgrade; then rescan
    /// (catch up on skipped files)
    hot_rescan: Mutex<HashMap<String, Instant>>,
    /// Deploy window (marker file), optional
    pub deploy: Option<crate::deploy::DeployWindow>,
    /// Package update window for events without a process (inotify)
    pub pkg_window: crate::pkgwindow::PkgWindow,
}

struct Hot {
    window_start: Instant,
    count: u32,
    /// of these, in the current window: from the verified package manager (`ProcInfo::pkg`)
    /// or via the package update window
    pm: u32,
    pkg_window: u32,
    until: Option<Instant>,
    skipped: u64,
}

/// More events per minute in a directory → only process code files for `HOT_HOLD`.
pub const HOT_PER_MIN: u32 = 200;
pub const HOT_HOLD: Duration = Duration::from_secs(600);

enum HotState {
    Normal,
    Skip,
    /// (directory, events/min, package marker for the aggregate event)
    JustDowngraded(String, u32, Option<&'static str>),
}

/// Origin of a write access with respect to package management (determined as for individual events)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PkgOrigin {
    /// Process or ancestor is a verified package manager (executable, not the name)
    Pm,
    /// without a live process mapping, within the package update window in time (`PkgWindow::applies`)
    Window,
    None,
}

/// Files that are never downgraded (executable code, webshell/skimmer carriers).
/// Also PHP control files (`.user.ini` → auto_prepend_file), SSH keys and templates (Twig/Smarty/Latte
/// execute code) – otherwise a directory could be deliberately made “hot” to hide them.
/// Next.js build output (`…/.next/server/…`, `…/.next/static/…`) → root `…/.next`. A build replaces
/// thousands of files there at once (real case on developer servers: ≈ 70 % of all events). During a
/// build the whole root counts as *one* hot directory – code files are then only counted as well
/// (one aggregate report
/// per build, no rescan); outside of builds every change is checked individually as before.
pub fn build_root(path: &str) -> Option<String> {
    let i = path.find("/.next/")?;
    let rest = &path[i + 7..];
    (rest.starts_with("server/") || rest.starts_with("static/")).then(|| path[..i + 6].to_string())
}

pub fn is_code(path: &str) -> bool {
    let l = path.to_ascii_lowercase();
    const EXT: &[&str] = &[".php", ".phtml", ".phar", ".php5", ".php7", ".pht", ".inc", ".js", ".mjs", ".html", ".htm", ".sh", ".py", ".pl", ".rb", ".cgi", ".so", ".htaccess", ".service", ".timer",
        ".user.ini", "/php.ini", "/authorized_keys", "/authorized_keys2", ".twig", ".tpl", ".latte", ".blade.php", ".ejs", ".hbs", ".mustache", ".jinja", ".j2", ".erb", ".ctp", ".volt"];
    if EXT.iter().any(|e| l.ends_with(e)) {
        return true;
    }
    use std::os::unix::fs::PermissionsExt;
    std::fs::symlink_metadata(path).map(|m| m.permissions().mode() & 0o111 != 0).unwrap_or(false)
}

#[derive(Default, Debug, serde::Serialize)]
pub struct Stats {
    pub events: u64,
    pub diffs: u64,
    pub no_base: u64,
    pub verify_failed: u64,
    pub bytes_read: u64,
    pub cache_full: u64,
    pub hot_skipped: u64,
    /// short-lived temp files (created and gone right away), not reported
    pub temp_gone: u64,
}

pub struct Input {
    pub ts_ns: i64,
    pub first_ts_ns: i64,
    pub backend: Backend,
    pub op: Op,
    pub path: String,
    pub old_path: Option<String>,
    pub proc: Option<ProcInfo>,
    pub note: Option<String>,
    /// Do not report WRITE_NOCHANGE (scan: only timestamps changed)
    pub quiet_nochange: bool,
}

/// Content read from a file
struct Content {
    raw: [u8; 32],
    raw_hex: String,
    /// (hash, stored possibly masked version) – only for text in mode full/redacted
    stored: Option<([u8; 32], Vec<u8>)>,
    /// Masking changed something
    masked: bool,
}

fn hx(h: &[u8; 32]) -> String {
    hex::encode(h)
}

impl Processor {
    pub fn new(policy: Arc<Policy>, state: Arc<State>, sink: Box<dyn Sink>, algo: Algo) -> Processor {
        Processor { policy, state, sink, algo, emit_diff: false, verify_patch: true, stats: Mutex::new(Stats::default()), hot: Mutex::new(HashMap::new()), hot_rescan: Mutex::new(HashMap::new()), deploy: None, pkg_window: Default::default() }
    }

    /// Directories whose downgrade has expired and which should now be rescanned (once per downgrade).
    pub fn take_due_rescans(&self) -> Vec<String> {
        let now = Instant::now();
        let mut m = self.hot_rescan.lock().unwrap();
        let due: Vec<String> = m.iter().filter(|(_, u)| **u <= now).map(|(d, _)| d.clone()).collect();
        for d in &due {
            m.remove(d);
        }
        due
    }

    /// Remember the raw hash for the restore check (SHA-256 only, content-monitored files only)
    fn remember(&self, path: &str, mode: ContentMode, raw: &[u8; 32]) {
        if self.algo == Algo::Sha256 && mode >= ContentMode::Redacted {
            self.state.remember(path, raw);
        }
    }

    /// Record a baseline for a path, without an event (agent start).
    pub fn prime(&self, path: &str) {
        let mode = self.policy.mode_for(path);
        if mode < ContentMode::Hash {
            return;
        }
        let Some(meta) = FileMeta::from_path(path) else { return };
        if meta.mode & libc::S_IFMT == libc::S_IFLNK {
            // Symlinks: remember the target as “content”, otherwise every scan reports them again
            if let Some(t) = link_target(path) {
                self.state.put(path, Entry { hash: link_hash(&t), stored: None, meta });
            }
            return;
        }
        if meta.mode & libc::S_IFMT != libc::S_IFREG {
            return;
        }
        let Some(c) = self.read_content(path, mode, &meta) else { return };
        let stored = c.stored.as_ref().and_then(|(h, d)| {
            if self.state.blob_put(h, d) {
                Some(*h)
            } else {
                self.stats.lock().unwrap().cache_full += 1;
                None
            }
        });
        self.remember(path, mode, &c.raw);
        self.state.put(path, Entry { hash: c.raw, stored, meta });
    }

    fn hot_check(&self, path: &str, origin: PkgOrigin) -> HotState {
        let build = build_root(path);
        let dir = match (&build, path.rfind('/')) {
            (Some(b), _) => b.clone(),
            (None, Some(0)) => "/".to_string(),
            (None, Some(i)) => path[..i].to_string(),
            (None, None) => return HotState::Normal,
        };
        let now = Instant::now();
        let mut h = self.hot.lock().unwrap();
        if h.len() > 10_000 {
            h.retain(|_, v| v.until.is_some_and(|u| u > now));
        }
        let e = h.entry(dir.clone()).or_insert(Hot { window_start: now, count: 0, pm: 0, pkg_window: 0, until: None, skipped: 0 });
        if let Some(u) = e.until {
            if u > now {
                drop(h);
                if build.is_none() && is_code(path) {
                    return HotState::Normal;
                }
                self.stats.lock().unwrap().hot_skipped += 1;
                if let Some(e) = self.hot.lock().unwrap().get_mut(&dir) {
                    e.skipped += 1;
                }
                return HotState::Skip;
            }
            e.until = None;
            e.window_start = now;
            e.count = 0;
            e.pm = 0;
            e.pkg_window = 0;
        }
        if now.duration_since(e.window_start) > Duration::from_secs(60) {
            e.window_start = now;
            e.count = 0;
            e.pm = 0;
            e.pkg_window = 0;
        }
        e.count += 1;
        match origin {
            PkgOrigin::Pm => e.pm += 1,
            PkgOrigin::Window => e.pkg_window += 1,
            PkgOrigin::None => {}
        }
        if e.count > HOT_PER_MIN {
            e.until = Some(now + HOT_HOLD);
            let n = e.count;
            // Package marker only if **all** counted write accesses of the window came from package management
            // (a single foreign writer – e.g. a webshell writing in the middle of an apt run – removes it)
            let pkg = if e.pm == n {
                Some("pkg")
            } else if e.pm + e.pkg_window == n {
                Some("pkg,pkg_window")
            } else {
                None
            };
            drop(h);
            // not “/” (that would be a full scan; the periodic reconciliation covers it)
            // do not rescan build output (would re-report every newly built file individually)
            if dir != "/" && build.is_none() {
                let mut r = self.hot_rescan.lock().unwrap();
                if r.len() < 1000 {
                    r.insert(dir.clone(), now + HOT_HOLD);
                }
            }
            return HotState::JustDowngraded(dir, n, pkg);
        }
        HotState::Normal
    }

    /// Known state of a path.
    pub fn entry(&self, path: &str) -> Option<Entry> {
        self.state.get(path)
    }

    /// The path – or, for temporary names of package management (`x.dpkg-new`, rpm `x;1a2b3c4d`), its target –
    /// is known in the local
    /// state (for the package update window: under /lib/systemd only replacing known files counts)
    fn known_or_pkg_temp(&self, path: &str) -> bool {
        if !(path.starts_with("/lib/systemd/") || path.starts_with("/usr/lib/systemd/")) {
            return true; // only relevant there – saves the state lookup
        }
        self.state.get(path).is_some() || crate::pkgwindow::pkg_temp_target(path).is_some_and(|t| self.state.get(t).is_some())
    }

    /// Number of known paths.
    pub fn known(&self) -> u64 {
        self.state.count()
    }

    fn read_content(&self, path: &str, mode: ContentMode, meta: &FileMeta) -> Option<Content> {
        if mode >= ContentMode::Redacted && meta.size <= self.policy.diff_limit_bytes {
            // O_NOFOLLOW + fstat; inode must match the metadata just read (otherwise swapped → do not read)
            let (data, ino) = content::read_limited_ino(path, self.policy.diff_limit_bytes).ok()??;
            if ino != meta.ino {
                return None;
            }
            self.stats.lock().unwrap().bytes_read += data.len() as u64;
            let raw_hex = hash::hash_bytes(self.algo, &data);
            let raw = hash_from_hex(&raw_hex);
            if !content::is_text(&data) {
                return Some(Content { raw, raw_hex, stored: None, masked: false });
            }
            // Default “masked” for all uploaded texts (security review H6); “full” without masking only
            // if the local policy explicitly disables it (redact_full = false)
            let (stored, masked) = if mode == ContentMode::Redacted || self.policy.redact_full {
                let r = redact::redact_path(path, &data);
                let m = r != data;
                (r, m)
            } else {
                (data, false)
            };
            let sh = hash_from_hex(&hash::hash_bytes(self.algo, &stored));
            Some(Content { raw, raw_hex, stored: Some((sh, stored)), masked })
        } else if mode >= ContentMode::Hash {
            let (h, n, ino) = hash::hash_file_nofollow(self.algo, path).ok()?;
            if ino != meta.ino {
                return None;
            }
            self.stats.lock().unwrap().bytes_read += n;
            Some(Content { raw: hash_from_hex(&h), raw_hex: h, stored: None, masked: false })
        } else {
            None
        }
    }

    /// Returns true if an event was reported.
    pub fn process(&self, inp: Input) -> bool {
        if inp.op == Op::Exec {
            return self.exec(inp);
        }
        let mode = self.policy.mode_for(&inp.path);
        if mode == ContentMode::Ignore {
            return false;
        }
        // Device files, pipes, sockets have no content that could be monitored
        // (otherwise every “> /dev/null” would be a MODIFY)
        if is_special(&inp.path) {
            return false;
        }
        // Hot directories (sessions, caches): only code files in real time,
        // the rest comes via the next scan. The scan itself is never throttled.
        // Origin with respect to package management – the same check as for individual events (below), also for the
        // aggregate event
        let origin = if procinfo::is_package_manager(inp.proc.as_ref()) {
            PkgOrigin::Pm
        } else if self.pkg_window.applies(&inp.path, self.known_or_pkg_temp(&inp.path), inp.proc.as_ref()) {
            PkgOrigin::Window
        } else {
            PkgOrigin::None
        };
        if origin == PkgOrigin::Pm {
            self.pkg_window.saw_pm(); // keeps the package update window open (also for throttled events)
        }
        if inp.backend != Backend::Scan && inp.op != Op::Overflow {
            match self.hot_check(&inp.path, origin) {
                HotState::Normal => {}
                HotState::Skip => return false,
                HotState::JustDowngraded(dir, n, pkg) => {
                    let mut note = format!("hot_dir_downgraded,events_per_min={n},hold_s={}", HOT_HOLD.as_secs());
                    if dir.ends_with("/.next") {
                        note.push_str(",build_output");
                    }
                    if let Some(p) = pkg {
                        note.push(',');
                        note.push_str(p);
                    }
                    self.finish(Event {
                        ts_ns: crate::now_ns(),
                        first_ts_ns: inp.first_ts_ns,
                        backend: inp.backend,
                        op: Op::Overflow,
                        path: dir,
                        old_path: None,
                        pid: inp.proc.as_ref().map(|p| p.pid),
                        exe: inp.proc.as_ref().and_then(|p| p.exe.clone()),
                        comm: inp.proc.as_ref().and_then(|p| p.comm.clone()),
                        proc_chain: inp.proc.as_ref().map(|p| p.chain.clone()).unwrap_or_default(),
                        mode: Some("meta".into()),
                        base_hash: None,
                        new_hash: None,
                        diff_lines: None,
                        diff_bytes: None,
                        meta: None,
                        note: Some(note),
                        diff: None,
                        patch: None,
                        content: None,
                        stored_hash: None,
                    });
                    return true;
                }
            }
        }
        let mut ev = Event {
            ts_ns: crate::now_ns(),
            first_ts_ns: inp.first_ts_ns,
            backend: inp.backend,
            op: inp.op,
            path: inp.path.clone(),
            old_path: inp.old_path.clone(),
            pid: inp.proc.as_ref().map(|p| p.pid),
            exe: inp.proc.as_ref().and_then(|p| p.exe.clone()),
            comm: inp.proc.as_ref().and_then(|p| p.comm.clone()),
            proc_chain: inp.proc.as_ref().map(|p| p.chain.clone()).unwrap_or_default(),
            mode: Some(mode.as_str().to_string()),
            base_hash: None,
            new_hash: None,
            diff_lines: None,
            diff_bytes: None,
            meta: None,
            note: inp.note.clone(),
            diff: None,
            patch: None,
            content: None,
            stored_hash: None,
        };
        let mut notes: Vec<String> = ev.note.take().into_iter().collect();
        if inp.proc.as_ref().is_some_and(|p| p.gone) {
            notes.push("proc_gone".into());
        }
        if origin == PkgOrigin::Pm {
            // executable verified (root-owned package program), not just the name
            notes.push("pkg".into());
        } else if origin == PkgOrigin::Window || (inp.op == Op::Overflow && self.pkg_window.active()) {
            // without (complete) process mapping: temporal correlation with dpkg/rpm/apk activity – also with
            // fanotify, because short-lived dpkg helpers (mv, tzdata.postinst) have often already exited at evaluation time
            // and the rescan after a queue overflow has no process at all (test run: apt-get upgrade).
            // Tampered programs are still detected: comparison with the official package hashes (refcheck).
            // Since H5 only without a live process mapping, only for a real package manager, never for persistence paths.
            notes.push("pkg".into());
            notes.push("pkg_window".into());
        }
        if let Some(l) = self.deploy.as_ref().and_then(|d| d.label_for(&inp.path)) {
            notes.push(format!("deploy:{l}"));
        }
        let prev = self.state.get(&inp.path);

        let Some(meta) = FileMeta::from_path(&inp.path) else {
            // File does not exist (any more)
            // Short-lived temp files (mktemp, curl, package managers, databases): created and already gone, never
            // seen before – not a finding, just noise (real case: thousands per hour). If the process itself starts from
            // a temp directory, it is still reported.
            // likewise the deletion of a never-reported temp file
            if matches!(inp.op, Op::Create | Op::Modify | Op::Attrib | Op::Delete)
                && prev.is_none()
                && is_temp_path(&inp.path)
                && !inp.proc.as_ref().and_then(|p| p.exe.as_deref()).is_some_and(is_temp_path)
            {
                self.stats.lock().unwrap().temp_gone += 1;
                return false;
            }
            if inp.op != Op::Delete && inp.op != Op::Overflow {
                notes.push(format!("gone_after_{:?}", inp.op).to_lowercase());
            }
            if inp.op != Op::Overflow {
                ev.op = Op::Delete;
            }
            ev.base_hash = prev.as_ref().and_then(|p| p.stored.as_ref().map(hx));
            if prev.is_some() {
                self.state.remove(&inp.path);
            }
            ev.note = join(notes);
            self.finish(ev);
            return true;
        };
        if ev.op == Op::Delete {
            // File was deleted and recreated (temp+rename pattern)
            ev.op = Op::Modify;
            notes.push("recreated".into());
        }
        let is_reg = meta.mode & libc::S_IFMT == libc::S_IFREG;
        let is_link = meta.mode & libc::S_IFMT == libc::S_IFLNK;
        // Empty, non-executable new file in a temp directory (mktemp): neither report nor record. If it
        // gets content and persists, it arrives with the write as a new file; if it is deleted right away,
        // that is dropped too (real case: a monitoring cron job with mktemp + curl, ~30 000 reports a day).
        if ev.op == Op::Create
            && prev.is_none()
            && is_reg
            && meta.size == 0
            && meta.mode & 0o111 == 0
            && is_temp_path(&inp.path)
            && !inp.proc.as_ref().and_then(|p| p.exe.as_deref()).is_some_and(is_temp_path)
        {
            self.stats.lock().unwrap().temp_gone += 1;
            return false;
        }

        if is_link {
            if let Some(t) = link_target(&inp.path) {
                let h = link_hash(&t);
                let unchanged = prev.as_ref().is_some_and(|p| p.hash == h);
                if unchanged && matches!(ev.op, Op::Modify | Op::Create | Op::Rename) {
                    ev.op = Op::WriteNochange;
                }
                notes.push(format!("symlink -> {t}"));
                ev.new_hash = Some(hx(&h));
                self.state.put(&inp.path, Entry { hash: h, stored: None, meta: meta.clone() });
            }
        } else if is_reg && mode >= ContentMode::Hash {
            if let Some(c) = self.read_content(&inp.path, mode, &meta) {
                let unchanged = prev.as_ref().is_some_and(|p| p.hash == c.raw);
                if unchanged && matches!(ev.op, Op::Modify | Op::Create | Op::Rename) {
                    let meta_changed = prev.as_ref().is_some_and(|p| !same_attrs(&p.meta, &meta));
                    ev.op = if meta_changed { Op::Attrib } else { Op::WriteNochange };
                }
                let mut stored_hash = prev.as_ref().and_then(|p| p.stored);
                if let Some((sh, data)) = &c.stored {
                    let base = prev.as_ref().and_then(|p| p.stored);
                    ev.base_hash = base.as_ref().map(hx);
                    if base.as_ref() == Some(sh) && !unchanged && prev.is_some() {
                        // Only masked values (e.g. password) changed: report, without the value
                        notes.push("secret_value_changed".into());
                    }
                    if base.as_ref() != Some(sh) {
                        match base.and_then(|b| self.state.blob_get(&b)) {
                            Some(base_data) => {
                                let d = diff::make_patch(&base_data, data);
                                ev.diff_lines = Some(d.changed_lines);
                                ev.diff_bytes = Some(d.patch.len() as u32);
                                self.stats.lock().unwrap().diffs += 1;
                                if self.verify_patch {
                                    let ok = diff::apply_patch(&base_data, &d.patch)
                                        .map(|r| hash_from_hex(&hash::hash_bytes(self.algo, &r)) == *sh)
                                        .unwrap_or(false);
                                    if !ok {
                                        notes.push("patch_verify_failed".into());
                                        self.stats.lock().unwrap().verify_failed += 1;
                                    }
                                }
                                if self.emit_diff {
                                    ev.diff = Some(String::from_utf8_lossy(&d.patch).chars().take(4000).collect());
                                }
                                ev.patch = Some(d.patch);
                            }
                            None => {
                                notes.push("no_base".into());
                                self.stats.lock().unwrap().no_base += 1;
                                if self.emit_diff {
                                    ev.diff = Some(String::from_utf8_lossy(data).chars().take(4000).collect());
                                }
                                ev.content = Some(data.clone());
                            }
                        }
                        if self.state.blob_put(sh, data) {
                            stored_hash = Some(*sh);
                        } else {
                            // Budget exhausted: no base for the next diff
                            // (in the product: request the base from the central server)
                            notes.push("cache_full".into());
                            self.stats.lock().unwrap().cache_full += 1;
                            stored_hash = None;
                        }
                    }
                    if mode == ContentMode::Redacted || c.masked {
                        notes.push("redacted".into());
                    }
                    ev.stored_hash = Some(hx(sh));
                } else {
                    stored_hash = None;
                    if mode >= ContentMode::Redacted {
                        notes.push("binary_or_large".into());
                    }
                }
                ev.new_hash = Some(c.raw_hex.clone());
                self.remember(&inp.path, mode, &c.raw);
                self.state.put(&inp.path, Entry { hash: c.raw, stored: stored_hash, meta: meta.clone() });
            }
        } else if let Some(p) = &prev {
            if ev.op == Op::Modify && same_attrs(&p.meta, &meta) && p.meta.size == meta.size {
                ev.op = Op::WriteNochange;
            }
        }
        if meta.is_suid_sgid() {
            notes.push("suid_sgid".into());
        }
        if meta.caps.is_some() {
            notes.push("file_caps".into());
        }
        // without a verified package process or update window: compare a new/changed system file with the package
        // database
        // (e.g. only found by the periodic scan after an automatic update)
        if is_reg
            && matches!(ev.op, Op::Create | Op::Modify | Op::Rename)
            && !notes.iter().any(|n| n == "pkg")
            && crate::pkgverify::in_scope(&inp.path)
            && crate::pkgverify::from_package(&inp.path)
        {
            notes.push("pkg".into());
            notes.push("pkg_verified".into());
        }
        ev.meta = Some(meta);
        ev.note = join(notes);
        if ev.op == Op::WriteNochange && (inp.quiet_nochange || !crate::policy::Policy::nochange_relevant(&inp.path)) {
            return false; // state is updated, no event (only timestamps or a non-critical file)
        }
        self.finish(ev);
        true
    }

    /// Trial run “real-time protection”: report program start (with checksum of the executable), state stays
    /// untouched
    fn exec(&self, inp: Input) -> bool {
        const MAX_HASH: u64 = 64 << 20;
        let meta = FileMeta::from_path(&inp.path);
        let hash = meta
            .as_ref()
            .filter(|m| m.mode & libc::S_IFMT == libc::S_IFREG && m.size <= MAX_HASH)
            .and_then(|_| hash::hash_file_nofollow(Algo::Sha256, &inp.path).ok())
            .map(|(h, _, _)| h);
        // started by verified package management (dpkg-preconfigure runs tzdata.config from /tmp during
        // unattended-upgrades): mark it, real-time protection would never block that
        let note = if procinfo::is_package_manager(inp.proc.as_ref()) {
            Some(inp.note.map_or_else(|| "pkg".to_string(), |n| format!("{n},pkg")))
        } else {
            inp.note
        };
        self.finish(Event {
            ts_ns: inp.ts_ns,
            first_ts_ns: inp.first_ts_ns,
            backend: inp.backend,
            op: Op::Exec,
            path: inp.path,
            old_path: None,
            pid: inp.proc.as_ref().map(|p| p.pid),
            exe: inp.proc.as_ref().and_then(|p| p.exe.clone()),
            comm: inp.proc.as_ref().and_then(|p| p.comm.clone()),
            proc_chain: inp.proc.as_ref().map(|p| p.chain.clone()).unwrap_or_default(),
            mode: Some("meta".into()),
            base_hash: None,
            new_hash: hash,
            diff_lines: None,
            diff_bytes: None,
            meta,
            note,
            diff: None,
            patch: None,
            content: None,
            stored_hash: None,
        });
        true
    }

    fn finish(&self, ev: Event) {
        self.stats.lock().unwrap().events += 1;
        self.sink.emit(&ev);
    }
}

fn same_attrs(a: &FileMeta, b: &FileMeta) -> bool {
    a.mode == b.mode && a.uid == b.uid && a.gid == b.gid && a.caps == b.caps
}

fn join(v: Vec<String>) -> Option<String> {
    if v.is_empty() {
        None
    } else {
        Some(v.join(","))
    }
}

fn link_target(path: &str) -> Option<String> {
    std::fs::read_link(path).ok().map(|t| t.to_string_lossy().into_owned())
}

/// “Hash” of a symlink = hash of its target.
fn link_hash(target: &str) -> [u8; 32] {
    hash_from_hex(&hash::hash_bytes(Algo::Sha256, format!("link:{target}").as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(path: &str) -> Input {
        Input {
            ts_ns: 0,
            first_ts_ns: 0,
            backend: Backend::Fanotify,
            op: Op::Modify,
            path: path.into(),
            old_path: None,
            proc: None,
            note: None,
            quiet_nochange: false,
        }
    }

    #[test]
    fn hot_dir_is_downgraded_but_code_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let st = State::open(&dir.path().join("s.redb").to_string_lossy(), 4, 1 << 20).unwrap();
        let sink = JsonlSink::open(Some(&dir.path().join("e.jsonl").to_string_lossy())).unwrap();
        let p = Processor::new(Arc::new(Policy::default_policy()), st, Box::new(sink), Algo::Sha256);
        let mut emitted = 0;
        for i in 0..300 {
            if p.process(input(&format!("/srv/hot/sess_{i}"))) {
                emitted += 1;
            }
        }
        // 200 normal + 1 downgrade report, silent afterwards
        assert_eq!(emitted, HOT_PER_MIN as usize + 1);
        assert!(p.stats.lock().unwrap().hot_skipped >= 99);
        // Code file in the same directory is still processed
        assert!(p.process(input("/srv/hot/shell.php")));
        let log = std::fs::read_to_string(dir.path().join("e.jsonl")).unwrap();
        assert!(log.contains("hot_dir_downgraded"));
        // PHP control file, SSH keys and templates count as code
        for f in [".user.ini", "authorized_keys", "shop.twig", "header.tpl"] {
            assert!(p.process(input(&format!("/srv/hot/{f}"))), "{f}");
        }
        // Rescan of the directory is scheduled (due after the downgrade ends)
        assert!(p.take_due_rescans().is_empty());
        p.hot_rescan.lock().unwrap().values_mut().for_each(|u| *u = Instant::now());
        assert_eq!(p.take_due_rescans(), vec!["/srv/hot".to_string()]);
        assert!(p.take_due_rescans().is_empty(), "only once");
    }

    #[test]
    fn next_build_is_one_hot_dir_without_rescan() {
        assert_eq!(build_root("/users/www/app/.next/server/chunks/ssr/a.js").as_deref(), Some("/users/www/app/.next"));
        assert_eq!(build_root("/users/www/app/.next/static/chunks/b.js").as_deref(), Some("/users/www/app/.next"));
        assert_eq!(build_root("/users/www/app/.next/BUILD_ID"), None);
        assert_eq!(build_root("/users/www/app/public/x.js"), None);
        let dir = tempfile::tempdir().unwrap();
        let st = State::open(&dir.path().join("s.redb").to_string_lossy(), 4, 1 << 20).unwrap();
        let evs = Arc::new(Mutex::new(Vec::new()));
        let p = Processor::new(Arc::new(Policy::default_policy()), st, Box::new(Collect(evs.clone())), Algo::Sha256);
        // a build writes .js files (code) into many subdirectories
        let mut emitted = 0;
        for i in 0..600 {
            let sub = ["server/app", "server/chunks/ssr", "static/chunks", "static/css"][i % 4];
            if p.process(input(&format!("/srv/app/.next/{sub}/f{i}.js"))) {
                emitted += 1;
            }
        }
        assert_eq!(emitted, HOT_PER_MIN as usize + 1, "200 individually + 1 summary report, then silent – also for code");
        let evs = evs.lock().unwrap();
        let hot: Vec<_> = evs.iter().filter(|e| e.note.as_deref().is_some_and(|n| n.starts_with("hot_dir_downgraded"))).collect();
        assert_eq!(hot.len(), 1);
        assert_eq!(hot[0].path, "/srv/app/.next");
        assert!(hot[0].note.as_deref().unwrap().contains("build_output"));
        // no rescan of the build output
        p.hot_rescan.lock().unwrap().values_mut().for_each(|u| *u = Instant::now());
        assert!(p.take_due_rescans().is_empty());
        // Code outside the build output in the same project is still reported individually
        drop(evs);
        assert!(p.process(input("/srv/app/public/shell.php")));
    }

    struct Collect(Arc<Mutex<Vec<Event>>>);
    impl Sink for Collect {
        fn emit(&self, e: &Event) {
            self.0.lock().unwrap().push(e.clone());
        }
    }

    /// Aggregate event “hot directory” carries `pkg` only if all write accesses came from the **verified**
    /// package manager
    #[test]
    fn hot_dir_event_carries_verified_pkg_marker() {
        let proc = |name: &str, pkg: bool| ProcInfo { pid: 4242, exe: Some(format!("/usr/bin/{name}")), comm: Some(name.into()), chain: vec![name.into()], gone: false, pkg };
        let run = |writer: &dyn Fn(usize) -> Option<ProcInfo>| -> Option<String> {
            let dir = tempfile::tempdir().unwrap();
            let st = State::open(&dir.path().join("s.redb").to_string_lossy(), 4, 1 << 20).unwrap();
            let evs = Arc::new(Mutex::new(Vec::new()));
            let p = Processor::new(Arc::new(Policy::default_policy()), st, Box::new(Collect(evs.clone())), Algo::Sha256);
            for i in 0..(HOT_PER_MIN as usize + 5) {
                p.process(Input { proc: writer(i), ..input(&format!("/srv/hot/sess_{i}")) });
            }
            let evs = evs.lock().unwrap();
            let hot: Vec<_> = evs.iter().filter(|e| e.note.as_deref().is_some_and(|n| n.starts_with("hot_dir_downgraded"))).collect();
            assert_eq!(hot.len(), 1);
            hot[0].note.clone()
        };
        let has_pkg = |n: &Option<String>| n.as_deref().unwrap().split(',').any(|x| x == "pkg");
        // real (verified) dpkg
        let n = run(&|_| Some(proc("dpkg", true)));
        assert!(has_pkg(&n), "{n:?}");
        assert!(!n.as_deref().unwrap().contains("pkg_window"));
        // Webshell calls itself “dpkg” – the name alone does not count
        assert!(!has_pkg(&run(&|_| Some(proc("dpkg", false)))));
        // a foreign writer in the same window (last access, which triggers the downgrade) removes the marker
        assert!(!has_pkg(&run(&|i| Some(proc(if i == HOT_PER_MIN as usize { "php-fpm" } else { "dpkg" }, i != HOT_PER_MIN as usize)))));
        // … likewise in the middle
        assert!(!has_pkg(&run(&|i| Some(proc("dpkg", i != 17)))));
        // without a process and without a package update window: no marker
        assert!(!has_pkg(&run(&|_| None)));
    }

    /// Program start by verified package management carries `pkg` (trial run real-time protection)
    #[test]
    fn exec_by_package_manager_is_marked() {
        let dir = tempfile::tempdir().unwrap();
        let st = State::open(&dir.path().join("s.redb").to_string_lossy(), 4, 1 << 20).unwrap();
        let evs = Arc::new(Mutex::new(Vec::new()));
        let p = Processor::new(Arc::new(Policy::default_policy()), st, Box::new(Collect(evs.clone())), Algo::Sha256);
        let proc = |pkg: bool| ProcInfo { pid: 4243, exe: Some("/usr/bin/perl".into()), comm: Some("dpkg-preconfigu".into()),
            chain: vec!["dpkg-preconfigu".into(), "unattended-upgr".into()], gone: false, pkg };
        for pkg in [true, false] {
            p.process(Input { op: Op::Exec, proc: Some(proc(pkg)), note: Some("exec_shadow,exec_dir:/tmp".into()), ..input("/tmp/tzdata.config.x") });
        }
        let evs = evs.lock().unwrap();
        assert_eq!(evs[0].note.as_deref(), Some("exec_shadow,exec_dir:/tmp,pkg"));
        assert_eq!(evs[1].note.as_deref(), Some("exec_shadow,exec_dir:/tmp"), "name alone does not count");
    }

    #[test]
    fn full_text_is_masked_and_hash_remembered() {
        let dir = tempfile::tempdir().unwrap();
        let st = State::open(&dir.path().join("s.redb").to_string_lossy(), 4, 1 << 20).unwrap();
        let root = dir.path().join("app");
        std::fs::create_dir_all(&root).unwrap();
        let glob = format!("{}/**", root.display());
        let out = Arc::new(Mutex::new(Vec::new()));
        let p = Processor::new(Arc::new(Policy::new(&[(glob, ContentMode::Full)])), st.clone(), Box::new(Collect(out.clone())), Algo::Sha256);
        let f = root.join("config.yml");
        let raw = b"name: shop\napi_token: geheim-123 456\n";
        std::fs::write(&f, raw).unwrap();
        let path = f.to_string_lossy().into_owned();
        assert!(p.process(Input { op: Op::Create, ..input(&path) }));
        let ev = out.lock().unwrap().pop().unwrap();
        let c = String::from_utf8(ev.content.unwrap()).unwrap();
        assert!(!c.contains("geheim") && c.contains("name: shop"), "{c}");
        assert!(ev.note.unwrap_or_default().contains("redacted"));
        // Raw hash (not the masked one) is remembered for the restore
        let h = hash_from_hex(&hash::hash_bytes(Algo::Sha256, raw));
        assert!(st.seen_hash(&path, &h));
        // Symlink is never read as content
        let l = root.join("link.yml");
        std::os::unix::fs::symlink("/etc/hostname", &l).unwrap();
        assert!(p.process(Input { op: Op::Create, ..input(&l.to_string_lossy()) }));
        assert!(out.lock().unwrap().pop().unwrap().content.is_none());
    }
    #[test]
    fn short_lived_temp_files_not_reported() {
        assert!(is_temp_path("/tmp/tmp.abc123"));
        assert!(is_temp_path("/dev/shm/x"));
        assert!(!is_temp_path("/tmpfoo/x"));
        assert!(!is_temp_path("/var/www/tmp/x"));
        let dir = tempfile::tempdir().unwrap();
        let st = State::open(&dir.path().join("s.redb").to_string_lossy(), 4, 1 << 20).unwrap();
        let sink = JsonlSink::open(Some(&dir.path().join("e.jsonl").to_string_lossy())).unwrap();
        let p = Processor::new(Arc::new(Policy::default_policy()), st, Box::new(sink), Algo::Sha256);
        let mut i = input("/tmp/tyrosec-test-gone-0815");
        i.op = Op::Create;
        assert!(!p.process(i));
        assert_eq!(p.stats.lock().unwrap().temp_gone, 1);
        // outside of temp directories “created and gone again” remains a report
        let mut i = input("/var/www/tyrosec-test-gone-0815.php");
        i.op = Op::Create;
        assert!(p.process(i));
        // mktemp + curl: create empty file, write to it, delete it – nothing to report
        let tmp = tempfile::Builder::new().prefix("tmp.").tempfile_in("/tmp").unwrap();
        let path = tmp.path().to_string_lossy().into_owned();
        let mut c = input(&path);
        c.op = Op::Create;
        assert!(!p.process(c), "empty, not executable: do not report");
        std::fs::write(&path, b"<html>ok</html>").unwrap();
        drop(tmp); // deleted before the write is processed
        let mut m = input(&path);
        m.op = Op::Modify;
        assert!(!p.process(m), "never reported and already gone");
        let mut d = input(&path);
        d.op = Op::Delete;
        assert!(!p.process(d), "deletion of a never reported temp file");
        // executable empty file in /tmp stays visible
        let x = tempfile::Builder::new().prefix("tmp.").tempfile_in("/tmp").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(x.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut e = input(&x.path().to_string_lossy());
        e.op = Op::Create;
        assert!(p.process(e), "executable: report");
    }
}

/// Character/block device, FIFO or socket (does not follow symlinks; deleted paths → false).
pub fn is_special(path: &str) -> bool {
    use std::os::unix::fs::FileTypeExt;
    match std::fs::symlink_metadata(path) {
        Ok(m) => {
            let t = m.file_type();
            t.is_char_device() || t.is_block_device() || t.is_fifo() || t.is_socket()
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod special_tests {
    #[test]
    fn dev_null_is_special() {
        assert!(super::is_special("/dev/null"));
        assert!(!super::is_special("/etc/hostname"));
        assert!(!super::is_special("/does/not/exist"));
    }

}
