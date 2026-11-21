//! Probelauf „Schutz in Echtzeit“ (18.11.2026): Programmstarts aus Orten, an denen ein scharfer Schutz sie verhindern
//! würde (/tmp, /var/tmp, /dev/shm, Upload-Ordner von Websites). Es wird **nichts verhindert** – nur gemeldet, damit wir
//! sehen, was dort im Alltag legitim startet, bevor jemals etwas blockiert wird.
//!
//! Eigene fanotify-Gruppe nur mit `FAN_OPEN_EXEC` (reine Benachrichtigung, keine Berechtigungsabfrage): Ein Hänger oder
//! Überlauf hier berührt weder den Datei-Wächter noch startende Programme. Überläufe werden nur gezählt.

use std::collections::HashMap;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use tyrosd_core::debounce::Debouncer;
use tyrosd_core::procinfo;
use tyrosd_core::{Backend, Op, RawEvent};

use super::*;

const FAN_OPEN_EXEC: u64 = 0x0000_1000;
/// Dieselbe Datei höchstens alle 10 Minuten melden
const REPEAT: Duration = Duration::from_secs(600);

/// Verzeichnisse, deren Dateisysteme markiert werden
const DIRS: &[&str] = &["/tmp", "/var/tmp", "/dev/shm", "/var/www", "/srv", "/home"];

/// Würde ein scharfer Schutz den Start dieser Datei verhindern? → Ort (für die Anzeige)
pub fn exec_place(path: &str) -> Option<&'static str> {
    const TMP: &[(&str, &str)] = &[("/tmp/", "/tmp"), ("/var/tmp/", "/var/tmp"), ("/dev/shm/", "/dev/shm")];
    if let Some((_, l)) = TMP.iter().find(|(d, _)| path.starts_with(d)) {
        return Some(l);
    }
    const UPLOADS: &[(&str, &str)] = &[
        ("/wp-content/uploads/", "Upload-Ordner (WordPress)"),
        ("/pub/media/", "Upload-Ordner (Magento)"),
        ("/public/media/", "Upload-Ordner (Shopware)"),
        ("/storage/app/public/", "Upload-Ordner (Laravel)"),
        ("/sites/default/files/", "Upload-Ordner (Drupal)"),
        ("/fileadmin/", "Upload-Ordner (TYPO3)"),
        ("/uploads/", "Upload-Ordner"),
    ];
    UPLOADS.iter().find(|(d, _)| path.contains(d)).map(|(_, l)| *l)
}

pub struct ExecWatch {
    fd: OwnedFd,
    mount_fds: HashMap<[i32; 2], OwnedFd>,
    cache: PathCache,
    seen: HashMap<String, Instant>,
    self_pid: i32,
    /// markierte Dateisysteme (Einhängepunkte)
    pub marked: Vec<String>,
    pub overflows: u64,
}

impl ExecWatch {
    pub fn new() -> Result<ExecWatch> {
        let fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_REPORT_DFID_NAME)?;
        let mut w = ExecWatch {
            fd,
            mount_fds: HashMap::new(),
            cache: PathCache::new(50_000),
            seen: HashMap::new(),
            self_pid: std::process::id() as i32,
            marked: Vec::new(),
            overflows: 0,
        };
        let mounts = mounts();
        for dir in DIRS {
            if !std::path::Path::new(dir).is_dir() {
                continue;
            }
            let Some(fsid) = fsid_of(dir) else { continue };
            if w.mount_fds.contains_key(&fsid) {
                continue;
            }
            // Einhängepunkt des Verzeichnisses (längster passender Präfix)
            let Some(m) = mounts
                .iter()
                .filter(|m| FS_TYPES.contains(&m.fstype.as_str()))
                .filter(|m| m.mount_point == "/" || dir == &m.mount_point || dir.starts_with(&format!("{}/", m.mount_point.trim_end_matches('/'))))
                .max_by_key(|m| m.mount_point.len())
            else {
                continue;
            };
            if fsid_of(&m.mount_point) != Some(fsid) {
                continue;
            }
            if fanotify_mark(w.fd.as_raw_fd(), FAN_MARK_ADD | FAN_MARK_FILESYSTEM, FAN_OPEN_EXEC, &m.mount_point).is_err() {
                continue; // z. B. Kernel ohne FAN_OPEN_EXEC (< 5.0) oder tmpfs ohne Datei-Handles (< 5.13)
            }
            let c = CString::new(m.mount_point.clone()).unwrap();
            // SAFETY: gültiger Pfad
            let mfd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
            if mfd >= 0 {
                // SAFETY: frischer fd
                w.mount_fds.insert(fsid, unsafe { OwnedFd::from_raw_fd(mfd) });
                w.marked.push(m.mount_point.clone());
            }
        }
        if w.marked.is_empty() {
            bail!("kein Dateisystem für Programmstarts markierbar");
        }
        Ok(w)
    }

    fn resolve(&mut self, fsid: [i32; 2], handle: &[u8]) -> Option<String> {
        let key = PathCache::key(fsid, handle);
        if let Some(p) = self.cache.get(key) {
            return Some(p.to_string());
        }
        let mfd = self.mount_fds.get(&fsid)?.as_raw_fd();
        let mut buf = vec![0u32; handle.len().div_ceil(4) + 1];
        // SAFETY: buf ist groß genug für handle.len() Bytes
        unsafe { std::ptr::copy_nonoverlapping(handle.as_ptr(), buf.as_mut_ptr() as *mut u8, handle.len()) };
        // SAFETY: buf enthält ein gültiges struct file_handle
        let fd = unsafe {
            libc::syscall(libc::SYS_open_by_handle_at, mfd as libc::c_long, buf.as_ptr(), (libc::O_PATH | libc::O_CLOEXEC) as libc::c_long)
        };
        if fd < 0 {
            return None;
        }
        // SAFETY: frischer fd
        let owned = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        let p = std::fs::read_link(format!("/proc/self/fd/{}", owned.as_raw_fd())).ok()?.to_string_lossy().into_owned();
        // außerhalb unseres Mount-Namespaces (Container) → leer, wie im Datei-Wächter
        let p = if !p.ends_with(" (deleted)") && !same_object(owned.as_raw_fd(), &p) { String::new() } else { p };
        self.cache.insert(key, &p);
        Some(p)
    }

    /// Ereignisschleife (blockiert)
    pub fn run(mut self, deb: Arc<Debouncer>) -> Result<()> {
        let mut buf = vec![0u8; 64 * 1024];
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
                off += event_len;
                if mask & FAN_Q_OVERFLOW != 0 {
                    self.overflows += 1;
                    continue;
                }
                if mask & FAN_OPEN_EXEC == 0 || mask & FAN_ONDIR != 0 || pid == self.self_pid {
                    continue;
                }
                let mut path: Option<String> = None;
                let mut i = meta_len;
                while i + 4 <= event_len {
                    let rec = &ev[i..event_len];
                    let itype = rec[0];
                    let ilen = u16::from_ne_bytes(rec[2..4].try_into().unwrap()) as usize;
                    if ilen < 4 || ilen > rec.len() {
                        break;
                    }
                    if itype == FAN_EVENT_INFO_TYPE_DFID_NAME && path.is_none() && ilen >= 20 {
                        let fsid = [i32::from_ne_bytes(rec[4..8].try_into().unwrap()), i32::from_ne_bytes(rec[8..12].try_into().unwrap())];
                        let hbytes = u32::from_ne_bytes(rec[12..16].try_into().unwrap()) as usize;
                        let hend = 20 + hbytes;
                        if hend <= ilen {
                            let nb = &rec[hend..ilen];
                            let end = nb.iter().position(|b| *b == 0).unwrap_or(nb.len());
                            let name = String::from_utf8_lossy(&nb[..end]).into_owned();
                            if let Some(d) = self.resolve(fsid, &rec[12..hend]).filter(|d| !d.is_empty()) {
                                let d = d.strip_suffix(" (deleted)").unwrap_or(&d).to_string();
                                path = Some(format!("{}/{}", d.trim_end_matches('/'), name));
                            }
                        }
                    }
                    i += ilen;
                }
                let Some(path) = path else { continue };
                let Some(place) = exec_place(&path) else { continue };
                let now = Instant::now();
                if self.seen.get(&path).is_some_and(|t| now.duration_since(*t) < REPEAT) {
                    continue;
                }
                if self.seen.len() > 10_000 {
                    self.seen.retain(|_, t| now.duration_since(*t) < REPEAT);
                }
                self.seen.insert(path.clone(), now);
                deb.push(RawEvent {
                    ts_ns: tyrosd_core::now_ns(),
                    backend: Backend::Fanotify,
                    op: Op::Exec,
                    path,
                    old_path: None,
                    proc: Some(procinfo::lookup(pid)),
                    note: Some(format!("exec_shadow,exec_dir:{place}")),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::exec_place;

    #[test]
    fn places() {
        assert_eq!(exec_place("/tmp/.x/kworker"), Some("/tmp"));
        assert_eq!(exec_place("/dev/shm/a"), Some("/dev/shm"));
        assert_eq!(exec_place("/var/www/site/wp-content/uploads/2026/11/x"), Some("Upload-Ordner (WordPress)"));
        assert_eq!(exec_place("/usr/bin/php"), None);
        assert_eq!(exec_place("/var/www/site/vendor/bin/phpunit"), None);
        assert_eq!(exec_place("/tmpfoo/x"), None);
    }
}
