//! Dateien unter einer fremden Wurzel lesen (Container: `/proc/<pid>/root`, nspawn-/LXC-Wurzeln).
//!
//! Der Inhalt einer Container-Wurzel gehört dem Container (bei User-Namespaces auch einem unprivilegierten Benutzer).
//! Pfadbasiertes Lesen (`/proc/<pid>/root/etc/hostname`) folgt absoluten Symlinks im Container auf den **Host**
//! (`/etc/hostname → /etc/shadow`) und öffnet Geräte/FIFOs (`→ /dev/zero` → Speicher voll, Agent aus). Deshalb:
//! - `openat2` relativ zu einem Deskriptor der Wurzel mit `RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS`: Symlinks und
//!   `..` werden innerhalb der Wurzel aufgelöst, `/proc/self/…`-Sprünge sind verboten
//! - erst `O_PATH` öffnen, per `fstat` prüfen (nur reguläre Dateien bzw. Verzeichnisse), dann über den Deskriptor lesen
//!   – kein Öffnen von Geräten/FIFOs, kein Wettlauf zwischen Prüfung und Lesen
//! - feste Größengrenzen je Datei
//! - ohne `openat2` (Kernel < 5.6, `ENOSYS`) wird **nicht** auf unsicheres Öffnen zurückgefallen: die Wurzel wird dann
//!   gar nicht gelesen (`FsRoot::contained` schlägt fehl)
//!
//! `FsRoot::Host` liest wie bisher pfadbasiert unter einem Präfix (eigenes System, Test-Wurzeln), mit denselben
//! Prüfungen auf Dateityp und Größe.

use std::ffi::CString;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

/// Kleine Konfigurationsdateien (os-release, hostname, Header von Plugins …)
pub const SMALL: u64 = 1 << 20;
/// Paketdatenbanken (dpkg status, apk installed, .list-Dateien, rpmdb)
pub const PKG_DB: u64 = 256 << 20;

// Linux-UAPI (linux/openat2.h); Systemaufruf-Nummer 437 ist auf allen Architekturen gleich (seit 5.6).
const SYS_OPENAT2: libc::c_long = 437;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_IN_ROOT: u64 = 0x10;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// Wurzel, unter der gelesen wird
pub enum FsRoot {
    /// eigenes System bzw. Test-Wurzel: Pfad = Präfix + relativer Pfad
    Host(String),
    /// fremde Wurzel (Container): nur über `openat2` relativ zu diesem Deskriptor
    Contained { fd: OwnedFd, path: String },
}

/// Art eines Eintrags (ohne Symlinks zu folgen)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Other,
}

fn rel_cstr(rel: &str) -> io::Result<CString> {
    let r = rel.trim_start_matches('/');
    CString::new(if r.is_empty() { "." } else { r }).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn openat2(dir: &OwnedFd, rel: &str, flags: i32) -> io::Result<OwnedFd> {
    let p = rel_cstr(rel)?;
    // openat2 ist streng: zu O_PATH sind nur O_DIRECTORY/O_NOFOLLOW/O_CLOEXEC erlaubt (sonst EINVAL)
    let extra = if flags & libc::O_PATH != 0 { libc::O_CLOEXEC } else { libc::O_CLOEXEC | libc::O_NOCTTY };
    let how = OpenHow { flags: (flags | extra) as u64, mode: 0, resolve: RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS };
    // SAFETY: gültige Zeiger auf p/how für die Dauer des Aufrufs; Ergebnis ist ein neuer Deskriptor oder -1
    let r = unsafe { libc::syscall(SYS_OPENAT2, dir.as_raw_fd(), p.as_ptr(), &how as *const OpenHow, std::mem::size_of::<OpenHow>()) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: r ist ein eben geöffneter, uns gehörender Deskriptor
    Ok(unsafe { OwnedFd::from_raw_fd(r as i32) })
}

fn fstat(fd: &OwnedFd) -> io::Result<libc::stat> {
    // SAFETY: st wird vom Kern gefüllt
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}

fn kind_of(mode: u32) -> Kind {
    match mode & libc::S_IFMT {
        libc::S_IFREG => Kind::File,
        libc::S_IFDIR => Kind::Dir,
        _ => Kind::Other,
    }
}

/// Deskriptor (O_PATH) über /proc/self/fd neu zum Lesen öffnen – gleicher Inode, keine erneute Pfadauflösung
fn reopen(fd: &OwnedFd, flags: i32) -> io::Result<std::fs::File> {
    let p = CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap();
    // SAFETY: gültiger C-String
    let r = unsafe { libc::open(p.as_ptr(), flags | libc::O_CLOEXEC | libc::O_NOCTTY) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: r ist ein eben geöffneter, uns gehörender Deskriptor
    Ok(std::fs::File::from(unsafe { OwnedFd::from_raw_fd(r) }))
}

fn read_capped(mut f: impl Read, size: u64, limit: u64) -> Option<Vec<u8>> {
    if size > limit {
        return None;
    }
    let mut v = Vec::with_capacity(size.min(limit) as usize);
    f.by_ref().take(limit + 1).read_to_end(&mut v).ok()?;
    (v.len() as u64 <= limit).then_some(v)
}

impl FsRoot {
    pub fn host(prefix: &str) -> FsRoot {
        FsRoot::Host(prefix.trim_end_matches('/').to_string())
    }

    /// Fremde Wurzel öffnen. Fehler (auch: Kernel ohne `openat2`) → die Wurzel wird nicht gelesen.
    pub fn contained(path: &str) -> io::Result<FsRoot> {
        let c = CString::new(std::path::Path::new(path).as_os_str().as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // die Wurzel selbst (z. B. der Magic-Link /proc/<pid>/root) wird bewusst normal aufgelöst
        // SAFETY: gültiger C-String
        let r = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: eben geöffneter Deskriptor
        let fd = unsafe { OwnedFd::from_raw_fd(r) };
        // openat2 vorhanden? (ENOSYS auf Kerneln < 5.6, EPERM/ENOSYS unter manchen seccomp-Filtern)
        openat2(&fd, ".", libc::O_PATH | libc::O_DIRECTORY)?;
        Ok(FsRoot::Contained { fd, path: path.trim_end_matches('/').to_string() })
    }

    /// Wird `openat2` vom Kernel unterstützt?
    pub fn openat2_supported() -> bool {
        FsRoot::contained("/").is_ok()
    }

    /// Anzeigepfad (Präfix bzw. Wurzelpfad + relativer Pfad) – nur zum Melden, nie zum Öffnen fremder Wurzeln
    pub fn display(&self, rel: &str) -> String {
        let pre = match self {
            FsRoot::Host(p) => p.as_str(),
            FsRoot::Contained { path, .. } => path.as_str(),
        };
        format!("{pre}/{}", rel.trim_start_matches('/'))
    }

    pub fn is_contained(&self) -> bool {
        matches!(self, FsRoot::Contained { .. })
    }

    /// Ist dies das echte Wurzelverzeichnis des Hosts (Präfix leer)?
    pub fn is_host_root(&self) -> bool {
        matches!(self, FsRoot::Host(p) if p.is_empty())
    }

    /// Art des Ziels (Symlinks werden – innerhalb der Wurzel – aufgelöst); `None`, wenn nicht vorhanden
    pub fn kind(&self, rel: &str) -> Option<Kind> {
        match self {
            FsRoot::Host(_) => std::fs::metadata(self.display(rel)).ok().map(|m| kind_of(m.mode())),
            FsRoot::Contained { fd, .. } => {
                let f = openat2(fd, rel, libc::O_PATH).ok()?;
                Some(kind_of(fstat(&f).ok()?.st_mode))
            }
        }
    }

    pub fn is_dir(&self, rel: &str) -> bool {
        self.kind(rel) == Some(Kind::Dir)
    }

    pub fn exists(&self, rel: &str) -> bool {
        self.kind(rel).is_some()
    }

    /// Reguläre Datei lesen, höchstens `limit` Bytes (größere Dateien: `None`, nicht gekürzt)
    pub fn read(&self, rel: &str, limit: u64) -> Option<Vec<u8>> {
        match self {
            FsRoot::Host(_) => {
                // O_NONBLOCK: eine FIFO blockiert das Öffnen nicht; danach Typprüfung am offenen Deskriptor
                use std::os::unix::fs::OpenOptionsExt;
                let f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY).open(self.display(rel)).ok()?;
                let m = f.metadata().ok()?;
                if !m.is_file() {
                    return None;
                }
                read_capped(f, m.len(), limit)
            }
            FsRoot::Contained { fd, .. } => {
                let p = openat2(fd, rel, libc::O_PATH).ok()?;
                let st = fstat(&p).ok()?;
                if kind_of(st.st_mode) != Kind::File || st.st_size as u64 > limit {
                    return None;
                }
                let f = reopen(&p, libc::O_RDONLY).ok()?;
                read_capped(f, st.st_size as u64, limit)
            }
        }
    }

    /// Anfang einer regulären Datei (höchstens `n` Bytes, auch bei größeren Dateien)
    pub fn read_head(&self, rel: &str, n: u64) -> Option<Vec<u8>> {
        let f = match self {
            FsRoot::Host(_) => {
                use std::os::unix::fs::OpenOptionsExt;
                let f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY).open(self.display(rel)).ok()?;
                if !f.metadata().ok()?.is_file() {
                    return None;
                }
                f
            }
            FsRoot::Contained { fd, .. } => {
                let p = openat2(fd, rel, libc::O_PATH).ok()?;
                if kind_of(fstat(&p).ok()?.st_mode) != Kind::File {
                    return None;
                }
                reopen(&p, libc::O_RDONLY).ok()?
            }
        };
        let mut v = Vec::new();
        f.take(n).read_to_end(&mut v).ok()?;
        Some(v)
    }

    /// wie `read`, als Text (ungültiges UTF-8 ersetzt)
    pub fn read_string(&self, rel: &str, limit: u64) -> Option<String> {
        self.read(rel, limit).map(|v| String::from_utf8(v).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()))
    }

    /// Einträge eines Verzeichnisses: (Name, Art ohne Symlinks zu folgen), höchstens `max`
    pub fn read_dir(&self, rel: &str, max: usize) -> Vec<(String, Kind)> {
        let conv = |e: std::fs::DirEntry| {
            let k = match e.file_type() {
                Ok(t) if t.is_file() => Kind::File,
                Ok(t) if t.is_dir() => Kind::Dir,
                _ => Kind::Other,
            };
            (e.file_name().to_string_lossy().into_owned(), k)
        };
        match self {
            FsRoot::Host(_) => std::fs::read_dir(self.display(rel)).map(|rd| rd.flatten().take(max).map(conv).collect()).unwrap_or_default(),
            FsRoot::Contained { fd, .. } => {
                let Ok(d) = openat2(fd, rel, libc::O_RDONLY | libc::O_DIRECTORY) else { return Vec::new() };
                // /proc/self/fd/N zeigt auf genau dieses (bereits sicher geöffnete) Verzeichnis
                let out = std::fs::read_dir(format!("/proc/self/fd/{}", d.as_raw_fd())).map(|rd| rd.flatten().take(max).map(conv).collect()).unwrap_or_default();
                drop(d);
                out
            }
        }
    }

    /// Verzeichnisbaum ab `rel` durchlaufen (ohne Symlinks zu folgen, Tiefe ≤ `max_depth`); `f(relativer Pfad, Art)`
    /// liefert `false`, um ein Verzeichnis nicht zu betreten. Höchstens `max` Einträge insgesamt.
    pub fn walk(&self, rel: &str, max_depth: usize, max: usize, f: &mut dyn FnMut(&str, Kind) -> bool) {
        let mut stack = vec![(rel.trim_end_matches('/').to_string(), 0usize)];
        let mut n = 0;
        while let Some((dir, depth)) = stack.pop() {
            for (name, k) in self.read_dir(if dir.is_empty() { "/" } else { &dir }, max) {
                n += 1;
                if n > max {
                    return;
                }
                let p = format!("{dir}/{name}");
                let enter = f(&p, k);
                if k == Kind::Dir && enter && depth + 1 < max_depth {
                    stack.push((p, depth + 1));
                }
            }
        }
    }
}

/// Höchstens `max` Zeichen, ohne Steuerzeichen (Namen/Hostnamen aus fremden Wurzeln für die Zentrale)
pub fn cap_name(s: &str, max: usize) -> String {
    s.trim().chars().filter(|c| !c.is_control()).take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn contained_reads_stay_inside_root() {
        if !FsRoot::openat2_supported() {
            eprintln!("openat2 nicht verfügbar – Test übersprungen");
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let host = d.path().join("host");
        let root = d.path().join("ct");
        std::fs::create_dir_all(host.join("etc")).unwrap();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::create_dir_all(root.join("usr/lib")).unwrap();
        std::fs::write(host.join("etc/secret"), "HOST-SECRET").unwrap();
        std::fs::write(root.join("usr/lib/os-release"), "ID=debian\n").unwrap();
        // relativer und absoluter Symlink im Container (absolut = Container-Wurzel, nicht Host)
        symlink("../usr/lib/os-release", root.join("etc/os-release")).unwrap();
        symlink("/usr/lib/os-release", root.join("etc/abs")).unwrap();
        // Ausbruchsversuche
        symlink(host.join("etc/secret"), root.join("etc/hostname")).unwrap();
        symlink("../../host/etc/secret", root.join("etc/dotdot")).unwrap();
        symlink("/proc/self/root/etc/passwd", root.join("etc/magic")).unwrap();
        symlink("/dev/zero", root.join("etc/zero")).unwrap();
        std::fs::write(root.join("etc/big"), vec![b'x'; (SMALL + 1) as usize]).unwrap();
        let fifo = CString::new(root.join("etc/fifo").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);

        let fs = FsRoot::contained(&root.to_string_lossy()).unwrap();
        assert_eq!(fs.read_string("/etc/os-release", SMALL).as_deref(), Some("ID=debian\n"));
        assert_eq!(fs.read_string("/etc/abs", SMALL).as_deref(), Some("ID=debian\n"));
        assert_eq!(fs.read("/etc/hostname", SMALL), None, "absoluter Symlink auf den Host");
        assert_eq!(fs.read("/etc/dotdot", SMALL), None, ".. über die Wurzel hinaus");
        assert_eq!(fs.read("/../../host/etc/secret", SMALL), None);
        assert_eq!(fs.read("/etc/magic", SMALL), None, "Magic-Link");
        assert_eq!(fs.read("/etc/zero", SMALL), None, "Gerät");
        assert_eq!(fs.read("/etc/fifo", SMALL), None, "FIFO darf nicht blockieren");
        assert_eq!(fs.read("/etc/big", SMALL), None, "zu groß");
        assert!(fs.read("/etc/big", SMALL + 1).is_some());
        assert!(fs.is_dir("/etc") && !fs.is_dir("/etc/os-release") && fs.exists("/etc/os-release"));
        let mut names: Vec<_> = fs.read_dir("/etc", 100).into_iter().map(|(n, _)| n).collect();
        names.sort();
        assert!(names.contains(&"os-release".to_string()) && names.contains(&"fifo".to_string()));
        // Wurzel als Symlink-Ziel über Verzeichnisse
        symlink("/", root.join("loop")).unwrap();
        assert_eq!(fs.read_string("/loop/loop/usr/lib/os-release", SMALL).as_deref(), Some("ID=debian\n"));
        let mut seen = Vec::new();
        fs.walk("/usr", 5, 100, &mut |p, k| {
            seen.push((p.to_string(), k));
            true
        });
        assert_eq!(seen, vec![("/usr/lib".to_string(), Kind::Dir), ("/usr/lib/os-release".to_string(), Kind::File)]);
    }

    #[test]
    fn host_reads_check_type_and_size() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("etc")).unwrap();
        std::fs::write(d.path().join("etc/a"), "x").unwrap();
        let fifo = CString::new(d.path().join("etc/fifo").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        let fs = FsRoot::host(&d.path().to_string_lossy());
        assert_eq!(fs.read_string("/etc/a", 10).as_deref(), Some("x"));
        assert_eq!(fs.read("/etc/a", 0), None);
        assert_eq!(fs.read("/etc/fifo", 10), None);
        assert_eq!(fs.read("/etc/missing", 10), None);
    }

    #[test]
    fn names_are_capped() {
        assert_eq!(cap_name(&"a".repeat(300), 64).len(), 64);
        assert_eq!(cap_name(" web\n1\u{1b}[31m ", 64), "web1[31m");
    }
}
