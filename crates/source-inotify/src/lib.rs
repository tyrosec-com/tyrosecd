//! inotify-Backend (Fallback für Kernel < 5.9 bzw. ohne fanotify-FID).
//! Ein Watch pro Verzeichnis, Nach-Scan neuer Verzeichnisse (Rennen beim
//! Anlegen), Overflow → Rückruf für gezielten Rescan. Keine Prozess-Zuordnung.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::sync::Arc;

use anyhow::{Context, Result};
use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use tyrosd_core::debounce::Debouncer;
use tyrosd_core::policy::{ContentMode, Policy};
use tyrosd_core::{Backend, Op, RawEvent};

pub struct Stats {
    pub watches: usize,
    pub limit_before: u64,
    pub limit_after: u64,
    pub add_errors: usize,
    /// Verzeichnisse ohne Watch (Obergrenze erreicht → nur Scan)
    pub capped: usize,
}

/// Obergrenze der Watches (je Watch ca. 1 KB Kernel-Speicher, nicht auslagerbar).
pub const MAX_WATCHES: usize = 131_072;

/// Sicherheitskritische Verzeichnisse zuerst überwachen, falls die Obergrenze greift.
fn priority(p: &str) -> u8 {
    const CRIT: &[&str] = &["/etc", "/root", "/var/spool/cron", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local", "/lib/systemd", "/usr/lib/systemd", "/tmp", "/var/tmp", "/dev/shm", "/boot"];
    if CRIT.iter().any(|c| p == *c || p.starts_with(&format!("{c}/"))) || p.contains("/.ssh") {
        0
    } else {
        1
    }
}

fn mask() -> WatchMask {
    WatchMask::MODIFY
        | WatchMask::CLOSE_WRITE
        | WatchMask::ATTRIB
        | WatchMask::CREATE
        | WatchMask::DELETE
        | WatchMask::MOVED_FROM
        | WatchMask::MOVED_TO
        | WatchMask::DELETE_SELF
        | WatchMask::DONT_FOLLOW
        | WatchMask::ONLYDIR
}

fn read_limit() -> u64 {
    std::fs::read_to_string("/proc/sys/fs/inotify/max_user_watches")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Verzeichnisse unter den Wurzeln zählen (für Limit-Anpassung).
fn dirs(roots: &[String], policy: &Policy, one_fs: bool) -> Vec<String> {
    let mut v = Vec::new();
    for r in roots {
        let mut it = walkdir::WalkDir::new(r).same_file_system(one_fs).follow_links(false).into_iter();
        while let Some(Ok(e)) = it.next() {
            if !e.file_type().is_dir() {
                continue;
            }
            let p = e.path().to_string_lossy().into_owned();
            if ignored_dir(policy, &p) {
                it.skip_current_dir();
                continue;
            }
            v.push(p);
        }
    }
    v
}

fn ignored_dir(policy: &Policy, p: &str) -> bool {
    policy.mode_for(&format!("{}/.x", p.trim_end_matches('/'))) == ContentMode::Ignore || nextcloud_data_root(p)
}

/// Datenordner einer Nextcloud (Markierung `.ocdata`): Nutzerdateien, kein Code, nicht direkt ausgeliefert – keine
/// Echtzeit-Watches (Praxisfall bei einer Installation: 73 000 Ordner, mehr als das Watch-Limit). Webroot und Apps der
/// Nextcloud bleiben überwacht; der Abgleich-Scan sieht den Ordner weiter.
fn nextcloud_data_root(p: &str) -> bool {
    std::path::Path::new(p).join(".ocdata").is_file()
}

pub struct InotifySource {
    ino: Inotify,
    wds: HashMap<WatchDescriptor, String>,
    policy: Arc<Policy>,
    pub stats: Stats,
}

impl InotifySource {
    pub fn new(roots: &[String], policy: Arc<Policy>, one_fs: bool) -> Result<InotifySource> {
        let ino = Inotify::init().context("inotify_init")?;
        let mut list = dirs(roots, &policy, one_fs);
        list.sort_by_key(|p| priority(p));
        let before = read_limit();
        let mut after = before;
        let need = (list.len().min(MAX_WATCHES) as u64) * 12 / 10 + 8192;
        if need > before {
            // Limit anheben (braucht root); dokumentiert und rückbaubar
            if std::fs::write("/proc/sys/fs/inotify/max_user_watches", need.to_string()).is_ok() {
                after = need;
            }
        }
        let mut s = InotifySource {
            ino,
            wds: HashMap::new(),
            policy,
            stats: Stats { watches: 0, limit_before: before, limit_after: after, add_errors: 0, capped: 0 },
        };
        for d in list {
            s.add(&d);
        }
        Ok(s)
    }

    fn add(&mut self, dir: &str) {
        if self.stats.watches >= MAX_WATCHES {
            self.stats.capped += 1;
            return;
        }
        match self.ino.watches().add(dir, mask()) {
            Ok(wd) => {
                if self.wds.insert(wd, dir.to_string()).is_none() {
                    self.stats.watches += 1;
                }
            }
            Err(_) => self.stats.add_errors += 1,
        }
    }

    /// Neues Verzeichnis: Watches rekursiv setzen und vorhandene Dateien
    /// melden (sie können vor dem Watch entstanden sein).
    fn add_tree(&mut self, dir: &str, deb: &Debouncer) {
        let mut it = walkdir::WalkDir::new(dir).follow_links(false).into_iter();
        while let Some(Ok(e)) = it.next() {
            let p = e.path().to_string_lossy().into_owned();
            if e.file_type().is_dir() {
                if ignored_dir(&self.policy, &p) {
                    it.skip_current_dir();
                    continue;
                }
                self.add(&p);
            } else if e.depth() > 0 {
                deb.push(raw(Op::Create, p, None, Some("inotify_rescan_new_dir".into())));
            }
        }
    }

    /// Ereignisschleife (blockiert). `on_overflow` wird bei Queue-Überlauf
    /// aufgerufen (Rescan anstoßen).
    pub fn run(mut self, deb: Arc<Debouncer>, on_overflow: impl Fn()) -> Result<()> {
        let mut buf = vec![0u8; 256 * 1024];
        let mut cookies: HashMap<u32, String> = HashMap::new();
        loop {
            let events: Vec<(WatchDescriptor, EventMask, u32, Option<std::ffi::OsString>)> = self
                .ino
                .read_events_blocking(&mut buf)?
                .map(|e| (e.wd, e.mask, e.cookie, e.name.map(OsStr::to_os_string)))
                .collect();
            for (wd, m, cookie, name) in events {
                if m.contains(EventMask::Q_OVERFLOW) {
                    deb.push(raw(Op::Overflow, String::new(), None, Some("inotify_queue_overflow".into())));
                    on_overflow();
                    continue;
                }
                let Some(dir) = self.wds.get(&wd).cloned() else { continue };
                if m.contains(EventMask::IGNORED) || m.contains(EventMask::DELETE_SELF) {
                    self.wds.remove(&wd);
                    continue;
                }
                let path = match &name {
                    Some(n) => format!("{}/{}", dir.trim_end_matches('/'), n.to_string_lossy()),
                    None => dir.clone(),
                };
                let is_dir = m.contains(EventMask::ISDIR);
                if is_dir {
                    if m.contains(EventMask::CREATE) || m.contains(EventMask::MOVED_TO) {
                        self.add_tree(&path, &deb);
                    }
                    continue;
                }
                if self.policy.mode_for(&path) == ContentMode::Ignore {
                    continue;
                }
                let op = if m.contains(EventMask::CREATE) {
                    Op::Create
                } else if m.contains(EventMask::DELETE) {
                    Op::Delete
                } else if m.contains(EventMask::MOVED_FROM) {
                    cookies.insert(cookie, path.clone());
                    if cookies.len() > 10_000 {
                        cookies.clear();
                    }
                    Op::Delete
                } else if m.contains(EventMask::MOVED_TO) {
                    let old = cookies.remove(&cookie);
                    deb.push(raw(Op::Rename, path, old, None));
                    continue;
                } else if m.contains(EventMask::ATTRIB) {
                    Op::Attrib
                } else {
                    Op::Modify
                };
                deb.push(raw(op, path, None, None));
            }
        }
    }
}

fn raw(op: Op, path: String, old_path: Option<String>, note: Option<String>) -> RawEvent {
    RawEvent { ts_ns: tyrosd_core::now_ns(), backend: Backend::Inotify, op, path, old_path, proc: None, note }
}
