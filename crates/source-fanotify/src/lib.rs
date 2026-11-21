//! fanotify-Backend: `FAN_MARK_FILESYSTEM` + `FAN_REPORT_DFID_NAME`
//! (Kernel ≥ 5.9). Pfade über `open_by_handle_at` + `/proc/self/fd`,
//! Prozess über die gelieferte PID + /proc (sofort gelesen).
//!
//! Braucht `CAP_SYS_ADMIN` (fanotify) und `CAP_DAC_READ_SEARCH`
//! (open_by_handle_at). Direkte Syscalls, damit es mit musl ohne
//! libc-Wrapper funktioniert.

use std::collections::HashMap;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use tyrosd_core::debounce::Debouncer;
use tyrosd_core::policy::{ContentMode, Policy};
use tyrosd_core::procinfo::{self, ProcInfo};
use tyrosd_core::{Backend, Op, RawEvent};

pub mod decoy;
pub mod exec;

// --- Konstanten aus <linux/fanotify.h> ---
const FAN_CLOEXEC: u32 = 0x0000_0001;
const FAN_CLASS_NOTIF: u32 = 0x0000_0000;
const FAN_UNLIMITED_QUEUE: u32 = 0x0000_0010;
const FAN_REPORT_DIR_FID: u32 = 0x0000_0400;
const FAN_REPORT_NAME: u32 = 0x0000_0800;
const FAN_REPORT_DFID_NAME: u32 = FAN_REPORT_DIR_FID | FAN_REPORT_NAME;

const FAN_MARK_ADD: u32 = 0x0000_0001;
const FAN_MARK_FILESYSTEM: u32 = 0x0000_0100;

const FAN_MODIFY: u64 = 0x0000_0002;
const FAN_ATTRIB: u64 = 0x0000_0004;
const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
const FAN_MOVED_FROM: u64 = 0x0000_0040;
const FAN_MOVED_TO: u64 = 0x0000_0080;
const FAN_CREATE: u64 = 0x0000_0100;
const FAN_DELETE: u64 = 0x0000_0200;
const FAN_Q_OVERFLOW: u64 = 0x0000_4000;
const FAN_ONDIR: u64 = 0x4000_0000;

const FAN_EVENT_INFO_TYPE_FID: u8 = 1;
const FAN_EVENT_INFO_TYPE_DFID_NAME: u8 = 2;
const FAN_EVENT_INFO_TYPE_DFID: u8 = 3;

const METADATA_LEN: usize = 24;
/// Obergrenze Pfad-Cache (Verzeichnis-Handles → Pfad). Praxisfall Desktop-Rechner: 792 000 Ordner, 1 Mio. Einträge à
/// ~190 B hätten die Speichergrenze des Dienstes (256 MB) gesprengt → kompakte Einträge (PathCache) und kleinere Grenzen.
const HANDLE_CACHE_MAX: usize = 400_000;
/// höchstens so viele Ordner beim Start vorab auflösen (wichtige Orte zuerst, siehe PREWARM_FIRST)
const PREWARM_MAX: usize = 200_000;
/// Diese Orte zuerst vorab auflösen: dort zählt die Zuordnung gelöschter Ordner (Webshells, Nachladen, Persistenz)
const PREWARM_FIRST: &[&str] = &["/etc", "/var/www", "/srv", "/root", "/tmp", "/var/tmp", "/dev/shm", "/opt", "/usr/local",
    "/var/spool/cron", "/usr/lib/systemd", "/lib/systemd"];
/// Ordnernamen, deren Inhalt nicht vorab aufgelöst wird (Caches, Pakete, Versionsverwaltung) – bei Ereignissen werden
/// sie trotzdem normal aufgelöst, nur nicht auf Vorrat
const PREWARM_SKIP: &[&str] = &[".cache", "node_modules", ".git", ".npm", ".cargo", ".rustup", ".mozilla", ".local",
    ".vscode-server", ".gradle", ".m2", "__pycache__", "snap", ".thumbnails", "Cache", "CacheStorage", "Code Cache"];

/// Ordner-Handle → Pfad, kompakt: 128-Bit-Prüfwert statt kopierter Kennung (spart Kennung + Vec-Kopf), Pfad ohne
/// Reserve-Kapazität. Wird die Grenze erreicht, beginnt der Cache neu (Pfade werden bei Bedarf wieder aufgelöst).
pub(crate) struct PathCache {
    map: HashMap<u128, Box<str>>,
    max: usize,
}

impl PathCache {
    pub(crate) fn new(max: usize) -> Self {
        PathCache { map: HashMap::new(), max }
    }

    pub(crate) fn key(fsid: [i32; 2], handle: &[u8]) -> u128 {
        use std::hash::{Hash, Hasher};
        let mut a = std::collections::hash_map::DefaultHasher::new();
        (0u8, fsid, handle).hash(&mut a);
        let mut b = std::collections::hash_map::DefaultHasher::new();
        (0x5au8, handle, fsid).hash(&mut b);
        ((a.finish() as u128) << 64) | b.finish() as u128
    }

    pub(crate) fn get(&self, k: u128) -> Option<&str> {
        self.map.get(&k).map(|s| &**s)
    }

    pub(crate) fn insert(&mut self, k: u128, path: &str) {
        if self.map.len() >= self.max {
            self.map.clear();
            self.map.shrink_to_fit();
        }
        self.map.insert(k, path.into());
    }

    pub(crate) fn clear(&mut self) {
        self.map.clear();
    }

    #[allow(dead_code)] // Tests, Statistik
    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }
}
const FANOTIFY_METADATA_VERSION: u8 = 3;

/// Dateisysteme, die markiert werden (Rest: nur Scan).
const FS_TYPES: &[&str] =
    &["ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "jfs", "reiserfs", "tmpfs", "overlay", "zfs", "bcachefs"];

#[derive(Debug, Clone)]
pub struct MountInfo {
    pub mount_point: String,
    pub fstype: String,
    pub dev: String,
}

/// /proc/self/mountinfo lesen.
pub fn mounts() -> Vec<MountInfo> {
    let s = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    s.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            let sep = f.iter().position(|x| *x == "-")?;
            Some(MountInfo {
                dev: f.get(2)?.to_string(),
                mount_point: unescape(f.get(4)?),
                fstype: f.get(sep + 1)?.to_string(),
            })
        })
        .collect()
}

fn unescape(s: &str) -> String {
    // mountinfo kodiert Leerzeichen etc. oktal (\040)
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() {
            if let Ok(v) = u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 4]).unwrap_or("x"), 8) {
                out.push(v);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn fanotify_init(flags: u32) -> std::io::Result<OwnedFd> {
    // SAFETY: Syscall ohne Zeiger.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_fanotify_init,
            flags as libc::c_long,
            (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as libc::c_long,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd ist frisch und gehört uns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

fn fanotify_mark(fd: i32, flags: u32, mask: u64, path: &str) -> std::io::Result<()> {
    let c = CString::new(path).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: c lebt bis nach dem Aufruf.
    let r = unsafe {
        libc::syscall(
            libc::SYS_fanotify_mark,
            fd as libc::c_long,
            flags as libc::c_long,
            mask as libc::c_long,
            libc::AT_FDCWD as libc::c_long,
            c.as_ptr(),
        )
    };
    if r < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Prüft, ob fanotify mit DFID_NAME verfügbar ist (Kernel ≥ 5.9, Rechte).
pub fn probe() -> Result<()> {
    let fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_REPORT_DFID_NAME)
        .context("fanotify_init(FAN_REPORT_DFID_NAME)")?;
    fanotify_mark(fd.as_raw_fd(), FAN_MARK_ADD | FAN_MARK_FILESYSTEM, FAN_CREATE | FAN_MODIFY, "/")
        .context("fanotify_mark(FAN_MARK_FILESYSTEM, /)")?;
    Ok(())
}

fn fsid_of(path: &str) -> Option<[i32; 2]> {
    let c = CString::new(path).ok()?;
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: gültiger Pfad und Puffer.
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    // SAFETY: fsid_t ist 2×int (8 Byte), Felder sind in libc privat.
    Some(unsafe { std::mem::transmute::<libc::fsid_t, [i32; 2]>(st.f_fsid) })
}

pub struct MarkResult {
    pub path: String,
    pub fstype: String,
    pub ok: bool,
    pub error: Option<String>,
}

pub struct FanotifySource {
    fd: OwnedFd,
    /// fsid → offenes Verzeichnis auf dem Dateisystem (für open_by_handle_at)
    mount_fds: HashMap<[i32; 2], OwnedFd>,
    roots: Vec<String>,
    policy: Arc<Policy>,
    handle_cache: PathCache,
    proc_cache: HashMap<i32, (Instant, ProcInfo)>,
    self_pid: i32,
    pub marks: Vec<MarkResult>,
    /// vorab aufgelöste Verzeichnisse
    pub prewarmed: usize,
    /// Ereignisse ohne auflösbaren Pfad
    pub unresolved: u64,
    /// Ereignisse aus Verzeichnissen, die in unserem Mount-Namespace nicht sichtbar sind (z. B. tmpfs eines Containers)
    pub foreign: u64,
}

impl FanotifySource {
    /// Kernel-Warteschlange für fanotify vergrößern (ab Kernel 5.13 als sysctl; Standard 16 384). Nur wenn die
    /// systemd-Unit /proc/sys/fs/fanotify beschreibbar macht (Neuinstallationen ab 0.5.3) – sonst bleibt der Standard.
    /// Liefert (vorher, nachher) oder None, wenn nicht möglich.
    pub fn raise_queue_limit(want: u64) -> Option<(u64, u64)> {
        let p = "/proc/sys/fs/fanotify/max_queued_events";
        let cur: u64 = std::fs::read_to_string(p).ok()?.trim().parse().ok()?;
        if cur >= want {
            return Some((cur, cur));
        }
        std::fs::write(p, want.to_string()).ok()?;
        let now: u64 = std::fs::read_to_string(p).ok()?.trim().parse().ok()?;
        Some((cur, now))
    }

    pub fn new(roots: &[String], policy: Arc<Policy>, unlimited_queue: bool) -> Result<FanotifySource> {
        let mut flags = FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_REPORT_DFID_NAME;
        if unlimited_queue {
            flags |= FAN_UNLIMITED_QUEUE;
        }
        let fd = fanotify_init(flags).context("fanotify_init")?;
        // FAN_MODIFY meldet jeden einzelnen write() – eine Sicherung, die eine große Datei schreibt, erzeugte so Tausende
        // Ereignisse und ließ die Warteschlange überlaufen (Praxisfall: 236 bzw. 166 Überläufe auf zwei Servern in
        // 7 Tagen). FAN_CLOSE_WRITE meldet die fertig geschriebene Datei einmal; dauerhaft offene Dateien (Datenbanken,
        // Protokolle – größtenteils ausgenommen) erscheinen erst beim Schließen.
        let mask = FAN_CLOSE_WRITE | FAN_ATTRIB | FAN_CREATE | FAN_DELETE | FAN_MOVED_FROM | FAN_MOVED_TO | FAN_ONDIR;
        let mut s = FanotifySource {
            fd,
            mount_fds: HashMap::new(),
            roots: roots.to_vec(),
            policy,
            handle_cache: PathCache::new(HANDLE_CACHE_MAX),
            proc_cache: HashMap::new(),
            self_pid: std::process::id() as i32,
            marks: Vec::new(),
            prewarmed: 0,
            unresolved: 0,
            foreign: 0,
        };
        let mut seen_dev = std::collections::HashSet::new();
        for m in mounts() {
            if !FS_TYPES.contains(&m.fstype.as_str()) {
                continue;
            }
            // nur Mounts, die eine Wurzel betreffen
            let relevant = roots.iter().any(|r| {
                m.mount_point.starts_with(r.as_str()) || r.starts_with(m.mount_point.as_str())
            });
            if !relevant || s.policy.mode_for(&format!("{}/.x", m.mount_point.trim_end_matches('/'))) == ContentMode::Ignore {
                continue;
            }
            let Some(fsid) = fsid_of(&m.mount_point) else { continue };
            if !seen_dev.insert((m.dev.clone(), fsid)) {
                continue; // Bind-Mount desselben Dateisystems
            }
            let r = fanotify_mark(s.fd.as_raw_fd(), FAN_MARK_ADD | FAN_MARK_FILESYSTEM, mask, &m.mount_point);
            if r.is_ok() && !s.mount_fds.contains_key(&fsid) {
                let c = CString::new(m.mount_point.clone()).unwrap();
                // SAFETY: gültiger Pfad
                let mfd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
                if mfd >= 0 {
                    // SAFETY: frischer fd
                    s.mount_fds.insert(fsid, unsafe { OwnedFd::from_raw_fd(mfd) });
                }
            }
            s.marks.push(MarkResult {
                path: m.mount_point.clone(),
                fstype: m.fstype.clone(),
                ok: r.is_ok(),
                error: r.err().map(|e| e.to_string()),
            });
        }
        if !s.marks.iter().any(|m| m.ok) {
            bail!("kein Dateisystem markiert");
        }
        s.prewarm();
        Ok(s)
    }

    /// Verzeichnis-Handles vorab auflösen (name_to_handle_at). Sonst lassen sich
    /// Ereignisse aus Verzeichnissen, die schon gelöscht sind, bevor wir sie
    /// lesen (`rm -rf` direkt nach dem Start), keinem Pfad mehr zuordnen.
    fn prewarm(&mut self) {
        use std::os::unix::fs::MetadataExt;
        let mut fsid_by_dev: HashMap<u64, [i32; 2]> = HashMap::new();
        let mut n = 0usize;
        // Durchgang 1: wichtige Orte (innerhalb der Wurzeln), Durchgang 2: der Rest der Wurzeln ohne diese Orte
        let first: Vec<String> = PREWARM_FIRST.iter().filter(|d| self.in_roots(d) && std::path::Path::new(d).is_dir()).map(|d| d.to_string()).collect();
        let passes: Vec<(Vec<String>, bool)> = vec![(first.clone(), false), (self.roots.clone(), true)];
        'outer: for (starts, skip_first) in passes {
          for r in &starts {
            let mut it = walkdir::WalkDir::new(r).follow_links(false).into_iter();
            while let Some(entry) = it.next() {
                let Ok(e) = entry else { continue };
                if !e.file_type().is_dir() {
                    continue;
                }
                let p = e.path().to_string_lossy().into_owned();
                if skip_first && first.contains(&p) {
                    it.skip_current_dir(); // schon in Durchgang 1
                    continue;
                }
                if e.depth() > 0 && e.file_name().to_str().is_some_and(|n| PREWARM_SKIP.contains(&n)) {
                    it.skip_current_dir();
                    continue;
                }
                if self.policy.mode_for(&format!("{}/.x", p.trim_end_matches('/'))) == ContentMode::Ignore {
                    it.skip_current_dir();
                    continue;
                }
                let Ok(md) = e.metadata() else { continue };
                let fsid = *fsid_by_dev.entry(md.dev()).or_insert_with(|| fsid_of(&p).unwrap_or([0, 0]));
                if !self.mount_fds.contains_key(&fsid) {
                    it.skip_current_dir(); // Dateisystem nicht markiert
                    continue;
                }
                if let Some(h) = name_to_handle(&p) {
                    self.handle_cache.insert(PathCache::key(fsid, &h), &p);
                    n += 1;
                    if n >= PREWARM_MAX {
                        break 'outer;
                    }
                }
            }
          }
        }
        self.prewarmed = n;
    }

    fn resolve(&mut self, fsid: [i32; 2], handle: &[u8]) -> Option<String> {
        let key = PathCache::key(fsid, handle);
        if let Some(p) = self.handle_cache.get(key) {
            return Some(p.to_string());
        }
        let mfd = self.mount_fds.get(&fsid)?.as_raw_fd();
        // file_handle mit 4-Byte-Ausrichtung kopieren
        let mut buf = vec![0u32; handle.len().div_ceil(4) + 1];
        // SAFETY: buf ist groß genug für handle.len() Bytes
        unsafe { std::ptr::copy_nonoverlapping(handle.as_ptr(), buf.as_mut_ptr() as *mut u8, handle.len()) };
        // SAFETY: buf enthält ein gültiges struct file_handle
        let fd = unsafe {
            libc::syscall(
                libc::SYS_open_by_handle_at,
                mfd as libc::c_long,
                buf.as_ptr(),
                (libc::O_PATH | libc::O_CLOEXEC) as libc::c_long,
            )
        };
        if fd < 0 {
            return None;
        }
        // SAFETY: frischer fd
        let owned = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        let p = std::fs::read_link(format!("/proc/self/fd/{}", owned.as_raw_fd())).ok()?;
        let mut p = p.to_string_lossy().into_owned();
        // Liegt das Verzeichnis außerhalb dessen, was unser Mount-Namespace sieht (Container-tmpfs, Mount nur im Namespace
        // eines Dienstes), liefert readlink einen Pfad relativ zur Wurzel jenes Dateisystems („/log.json“ statt des echten
        // Orts). Gegenprobe: Der Pfad muss bei uns auf genau dieses Objekt zeigen – sonst „fremd“ (leerer Pfad).
        if !p.ends_with(" (deleted)") && !same_object(owned.as_raw_fd(), &p) {
            p = String::new();
        }
        self.handle_cache.insert(key, &p);
        Some(p)
    }

    fn proc(&mut self, pid: i32) -> ProcInfo {
        if let Some((t, p)) = self.proc_cache.get(&pid) {
            if t.elapsed().as_millis() < 1000 {
                return p.clone();
            }
        }
        let p = procinfo::lookup(pid);
        if self.proc_cache.len() > 4096 {
            self.proc_cache.clear();
        }
        self.proc_cache.insert(pid, (Instant::now(), p.clone()));
        p
    }

    fn in_roots(&self, p: &str) -> bool {
        self.roots.iter().any(|r| r == "/" || p == r || p.starts_with(&format!("{}/", r.trim_end_matches('/'))))
    }

    /// Ereignisschleife (blockiert).
    pub fn run(mut self, deb: Arc<Debouncer>, on_overflow: impl Fn()) -> Result<()> {
        let mut buf = vec![0u8; 256 * 1024];
        let mut moved_from: Option<String> = None;
        let mut last_unresolved = Instant::now() - std::time::Duration::from_secs(5);
        loop {
            // SAFETY: buf ist gültig
            let n = unsafe { libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e.into());
            }
            let n = n as usize;
            let mut off = 0usize;
            while off + METADATA_LEN <= n {
                let ev = &buf[off..n];
                let event_len = u32::from_ne_bytes(ev[0..4].try_into().unwrap()) as usize;
                let vers = ev[4];
                let meta_len = u16::from_ne_bytes(ev[6..8].try_into().unwrap()) as usize;
                let mask = u64::from_ne_bytes(ev[8..16].try_into().unwrap());
                let efd = i32::from_ne_bytes(ev[16..20].try_into().unwrap());
                let pid = i32::from_ne_bytes(ev[20..24].try_into().unwrap());
                if event_len < METADATA_LEN || off + event_len > n || vers != FANOTIFY_METADATA_VERSION {
                    break;
                }
                if efd >= 0 {
                    // SAFETY: fd vom Kernel, wir schließen ihn
                    unsafe { libc::close(efd) };
                }
                if mask & FAN_Q_OVERFLOW != 0 {
                    deb.push(RawEvent {
                        ts_ns: tyrosd_core::now_ns(),
                        backend: Backend::Fanotify,
                        op: Op::Overflow,
                        path: String::new(),
                        old_path: None,
                        proc: None,
                        note: Some("fanotify_queue_overflow".into()),
                    });
                    on_overflow();
                    off += event_len;
                    continue;
                }
                // Info-Records parsen
                let mut path: Option<String> = None;
                let mut stale = false;
                let mut foreign = false;
                let mut i = meta_len;
                while i + 4 <= event_len {
                    let rec = &ev[i..event_len];
                    let itype = rec[0];
                    let ilen = u16::from_ne_bytes(rec[2..4].try_into().unwrap()) as usize;
                    if ilen < 4 || ilen > rec.len() {
                        break;
                    }
                    if matches!(itype, FAN_EVENT_INFO_TYPE_DFID_NAME | FAN_EVENT_INFO_TYPE_DFID | FAN_EVENT_INFO_TYPE_FID)
                        && path.is_none()
                        && ilen >= 20
                    {
                        let fsid = [
                            i32::from_ne_bytes(rec[4..8].try_into().unwrap()),
                            i32::from_ne_bytes(rec[8..12].try_into().unwrap()),
                        ];
                        let hbytes = u32::from_ne_bytes(rec[12..16].try_into().unwrap()) as usize;
                        let hend = 20 + hbytes;
                        if hend <= ilen {
                            let handle = &rec[12..hend];
                            let dir = self.resolve(fsid, handle);
                            let name = if itype == FAN_EVENT_INFO_TYPE_DFID_NAME {
                                let nb = &rec[hend..ilen];
                                let end = nb.iter().position(|b| *b == 0).unwrap_or(nb.len());
                                Some(String::from_utf8_lossy(&nb[..end]).into_owned())
                            } else {
                                None
                            };
                            match dir {
                                Some(d) if d.is_empty() => foreign = true,
                                Some(d) => {
                                    let d = d.strip_suffix(" (deleted)").map(|x| {
                                        stale = true;
                                        x.to_string()
                                    }).unwrap_or(d);
                                    path = Some(match name.as_deref() {
                                        Some(".") | None | Some("") => d,
                                        Some(nm) => format!("{}/{}", d.trim_end_matches('/'), nm),
                                    });
                                }
                                None => stale = true,
                            }
                        }
                    }
                    i += ilen;
                }
                off += event_len;
                if foreign {
                    self.foreign += 1;
                    continue;
                }

                let Some(path) = path else {
                    // Pfad nicht auflösbar (Verzeichnis schon gelöscht): nicht still
                    // verwerfen, sondern Abgleich-Scan anstoßen (höchstens 1×/s).
                    self.unresolved += 1;
                    if mask & (FAN_DELETE | FAN_MOVED_FROM | FAN_MODIFY | FAN_CREATE) != 0
                        && pid != self.self_pid
                        && last_unresolved.elapsed().as_millis() >= 1000
                    {
                        last_unresolved = Instant::now();
                        deb.push(RawEvent {
                            ts_ns: tyrosd_core::now_ns(),
                            backend: Backend::Fanotify,
                            op: Op::Overflow,
                            path: String::new(),
                            old_path: None,
                            proc: None,
                            note: Some(format!("unresolved_handle,total={}", self.unresolved)),
                        });
                        on_overflow();
                    }
                    continue;
                };
                if pid == self.self_pid || !self.in_roots(&path) {
                    continue;
                }
                let is_dir = mask & FAN_ONDIR != 0;
                if is_dir {
                    // Verzeichnis-Umbenennung → Pfad-Cache ungültig. Bei DELETE den
                    // Cache NICHT leeren: Ereignisse aus dem gelöschten Verzeichnis
                    // stehen evtl. noch in der Queue und brauchen den alten Pfad (T19).
                    if mask & (FAN_MOVED_FROM | FAN_MOVED_TO) != 0 {
                        self.handle_cache.clear();
                    }
                    continue;
                }
                if self.policy.mode_for(&path) == ContentMode::Ignore {
                    continue;
                }
                let proc = Some(self.proc(pid));
                let note = if stale { Some("stale_dir_handle".to_string()) } else { None };
                let (op, old) = if mask & FAN_CREATE != 0 {
                    (Op::Create, None)
                } else if mask & FAN_DELETE != 0 {
                    (Op::Delete, None)
                } else if mask & FAN_MOVED_FROM != 0 {
                    moved_from = Some(path.clone());
                    (Op::Delete, None)
                } else if mask & FAN_MOVED_TO != 0 {
                    (Op::Rename, moved_from.take())
                } else if mask & (FAN_MODIFY | FAN_CLOSE_WRITE) != 0 {
                    (Op::Modify, None)
                } else if mask & FAN_ATTRIB != 0 {
                    (Op::Attrib, None)
                } else {
                    continue;
                };
                deb.push(RawEvent { ts_ns: tyrosd_core::now_ns(), backend: Backend::Fanotify, op, path, old_path: old, proc, note });
            }
        }
    }
}

/// Zeigt `path` in unserem Namespace auf dasselbe Objekt wie `fd` (Gerät + Inode)?
fn same_object(fd: i32, path: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: st wird von fstat gefüllt, fd ist gültig (O_PATH erlaubt fstat)
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return true; // im Zweifel behalten
    }
    match std::fs::symlink_metadata(path) {
        Ok(m) => m.dev() == st.st_dev as u64 && m.ino() == st.st_ino as u64,
        Err(_) => false,
    }
}

/// Datei-Handle eines Pfads (gleiches Format wie in den fanotify-Info-Records:
/// handle_bytes, handle_type, f_handle).
fn name_to_handle(path: &str) -> Option<Vec<u8>> {
    const MAX_HANDLE_SZ: u32 = 128;
    let c = CString::new(path).ok()?;
    let mut buf = vec![0u32; (8 + MAX_HANDLE_SZ as usize) / 4];
    buf[0] = MAX_HANDLE_SZ;
    let mut mount_id: libc::c_int = 0;
    // SAFETY: buf ist groß genug (struct file_handle + 128 Byte), Zeiger gültig.
    let r = unsafe {
        libc::syscall(
            libc::SYS_name_to_handle_at,
            libc::AT_FDCWD as libc::c_long,
            c.as_ptr(),
            buf.as_mut_ptr(),
            &mut mount_id as *mut libc::c_int,
            0 as libc::c_long,
        )
    };
    if r != 0 {
        return None;
    }
    let hb = (buf[0] as usize).min(MAX_HANDLE_SZ as usize);
    // SAFETY: buf enthält mindestens 8 + hb Bytes
    let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, 8 + hb) };
    Some(bytes.to_vec())
}

#[cfg(test)]
mod path_cache_tests {
    use super::PathCache;

    #[test]
    fn keys_differ_and_cache_is_bounded() {
        let a = PathCache::key([1, 2], &[8, 0, 0, 0, 1, 0, 0, 0, 7, 7, 7, 7]);
        let b = PathCache::key([1, 3], &[8, 0, 0, 0, 1, 0, 0, 0, 7, 7, 7, 7]);
        let c = PathCache::key([1, 2], &[8, 0, 0, 0, 1, 0, 0, 0, 7, 7, 7, 8]);
        assert!(a != b && a != c && b != c);
        let mut pc = PathCache::new(3);
        pc.insert(a, "/var/www");
        assert_eq!(pc.get(a), Some("/var/www"));
        pc.insert(b, "/etc");
        pc.insert(c, "/tmp");
        assert_eq!(pc.len(), 3);
        pc.insert(PathCache::key([9, 9], &[1]), "/srv"); // Grenze erreicht → neu beginnen
        assert_eq!(pc.len(), 1);
        assert_eq!(pc.get(a), None);
    }
}

#[cfg(test)]
mod path_cache_mem {
    use super::PathCache;
    use std::collections::HashMap;

    fn rss_kb() -> usize {
        std::fs::read_to_string("/proc/self/status").unwrap().lines()
            .find(|l| l.starts_with("VmRSS")).unwrap().split_whitespace().nth(1).unwrap().parse().unwrap()
    }

    /// Speichervergleich alt (Vec-Schlüssel + String) gegen PathCache: `cargo test -- --ignored --nocapture mem_compare`
    #[test]
    #[ignore]
    fn mem_compare() {
        let n = 400_000;
        let path = |i: usize| format!("/home/cheops/.config/some-application/profile-{i:07}/storage/default/idb");
        let q0 = rss_kb();
        let mut pc = PathCache::new(n + 1);
        for i in 0..n {
            pc.insert(PathCache::key([1, 2], &(i as u64).to_ne_bytes()), &path(i));
        }
        let q1 = rss_kb();
        let r0 = rss_kb();
        let mut old: HashMap<Vec<u8>, String> = HashMap::new();
        for i in 0..n {
            let mut k = vec![1u8; 8];
            k.extend_from_slice(&[8, 0, 0, 0, 1, 0, 0, 0]);
            k.extend_from_slice(&(i as u64).to_ne_bytes());
            let mut p = path(i);
            p.reserve(8); // wie read_link/format!: oft Reserve-Kapazität
            old.insert(k, p);
        }
        let r1 = rss_kb();
        println!("alt: {} MB, neu: {} MB (je {} Einträge)", (r1 - r0) / 1024, (q1 - q0) / 1024, n);
        assert!(pc.get(PathCache::key([1, 2], &0u64.to_ne_bytes())).is_some() && !old.is_empty());
    }
}
