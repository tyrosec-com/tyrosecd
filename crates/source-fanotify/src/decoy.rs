//! Köder-Dateien (Plan „Köder-Zugangsdaten“, 18.11.2026): meldet, wenn ein Prozess eine Köder-Datei **öffnet**.
//! Eine Köder-Datei enthält falsche Zugangsdaten und wird von niemandem gebraucht – wer sie liest, sucht auf dem Server
//! nach Zugangsdaten (Einbruch) oder ist ein Sicherungs-/Prüfprogramm (wird vom Aufrufer eingeordnet).
//!
//! Eigene fanotify-Gruppe mit **Inode-Markierungen nur auf den Köder-Dateien** – kostet nichts, berührt den
//! Datei-Wächter nicht.
//!
//! Ab 0.4.16 als Berechtigungs-Abfrage (`FAN_OPEN_PERM`): Der öffnende Prozess wartet, bis der Agent geantwortet hat –
//! so ist er beim Nachschlagen von Name und Prozesskette garantiert noch da (vorher fehlte er bei kurzlebigen
//! Programmen wie `cat`). Die Antwort ist **immer „erlauben“**; nichts wird verhindert. Endet der Agent, gibt der
//! Kernel wartende Zugriffe selbst frei. Ohne Kernel-Unterstützung (CONFIG_FANOTIFY_ACCESS_PERMISSIONS) wie bisher als
//! reine Benachrichtigung (`FAN_OPEN`).

use std::os::fd::{AsRawFd, OwnedFd};
use std::time::{Duration, Instant};

use anyhow::Result;

use super::{fanotify_init, fanotify_mark, FAN_CLASS_NOTIF, FAN_CLOEXEC, FAN_MARK_ADD, FAN_Q_OVERFLOW, FANOTIFY_METADATA_VERSION, METADATA_LEN};

const FAN_OPEN: u64 = 0x0000_0020;
const FAN_OPEN_PERM: u64 = 0x0001_0000;
const FAN_CLASS_CONTENT: u32 = 0x0000_0004;
const FAN_ALLOW: u32 = 0x01;
/// dieselbe Datei durch denselben Prozess höchstens einmal je Minute melden
const REPEAT: Duration = Duration::from_secs(60);

pub struct DecoyWatch {
    fd: OwnedFd,
    self_pid: i32,
    /// Berechtigungs-Abfrage (Prozess wartet) statt reiner Benachrichtigung
    perm: bool,
}

impl DecoyWatch {
    pub fn new() -> Result<DecoyWatch> {
        let self_pid = std::process::id() as i32;
        if let Ok(fd) = fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT) {
            return Ok(DecoyWatch { fd, self_pid, perm: true });
        }
        let fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_NOTIF)?;
        Ok(DecoyWatch { fd, self_pid, perm: false })
    }

    pub fn permission_mode(&self) -> bool {
        self.perm
    }

    /// Köder-Datei beobachten (Inode-Markierung auf Öffnen)
    pub fn watch(&self, path: &str) -> std::io::Result<()> {
        if self.perm {
            match fanotify_mark(self.fd.as_raw_fd(), FAN_MARK_ADD, FAN_OPEN_PERM, path) {
                Ok(()) => return Ok(()),
                // Kernel ohne Berechtigungs-Ereignisse: dann eben als Benachrichtigung in derselben Gruppe
                Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {}
                Err(e) => return Err(e),
            }
        }
        fanotify_mark(self.fd.as_raw_fd(), FAN_MARK_ADD, FAN_OPEN, path)
    }

    fn allow(&self, efd: i32) {
        // struct fanotify_response { __s32 fd; __u32 response; }
        let mut b = [0u8; 8];
        b[..4].copy_from_slice(&efd.to_ne_bytes());
        b[4..].copy_from_slice(&FAN_ALLOW.to_ne_bytes());
        // SAFETY: Puffer gültig, fd der Gruppe gültig
        unsafe { libc::write(self.fd.as_raw_fd(), b.as_ptr() as *const libc::c_void, b.len()) };
    }

    /// Ereignisschleife (blockiert): `emit(pfad, pid)` je Öffnen durch einen fremden Prozess. Bei Berechtigungs-
    /// Ereignissen wird `emit` aufgerufen, **bevor** der Zugriff freigegeben wird (Prozess lebt noch).
    pub fn run(&self, emit: impl Fn(String, i32)) -> Result<()> {
        let mut buf = vec![0u8; 16 * 1024];
        let mut seen: std::collections::HashMap<(String, i32), Instant> = std::collections::HashMap::new();
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
                let mask = u64::from_ne_bytes(ev[8..16].try_into().unwrap());
                let efd = i32::from_ne_bytes(ev[16..20].try_into().unwrap());
                let pid = i32::from_ne_bytes(ev[20..24].try_into().unwrap());
                if event_len < METADATA_LEN || off + event_len > n || vers != FANOTIFY_METADATA_VERSION {
                    break;
                }
                off += event_len;
                let path = if efd >= 0 { std::fs::read_link(format!("/proc/self/fd/{efd}")).ok().map(|p| p.to_string_lossy().into_owned()) } else { None };
                let opened = mask & (FAN_OPEN | FAN_OPEN_PERM) != 0 && mask & FAN_Q_OVERFLOW == 0;
                if opened && pid != self.self_pid {
                    if let Some(path) = path {
                        let now = Instant::now();
                        let k = (path.clone(), pid);
                        if !seen.get(&k).is_some_and(|t| now.duration_since(*t) < REPEAT) {
                            if seen.len() > 1000 {
                                seen.retain(|_, t| now.duration_since(*t) < REPEAT);
                            }
                            seen.insert(k, now);
                            emit(path, pid);
                        }
                    }
                }
                if efd >= 0 {
                    if mask & FAN_OPEN_PERM != 0 {
                        self.allow(efd); // immer erlauben – auch bei eigenem Prozess und Wiederholungen
                    }
                    // SAFETY: fd vom Kernel, wir schließen ihn
                    unsafe { libc::close(efd) };
                }
            }
        }
    }
}
