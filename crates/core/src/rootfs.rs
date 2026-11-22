//! Reading files under a foreign root (containers: `/proc/<pid>/root`, nspawn/LXC roots).
//!
//! The content of a container root belongs to the container (with user namespaces also to an unprivileged user).
//! Path-based reading (`/proc/<pid>/root/etc/hostname`) follows absolute symlinks in the container onto the **host**
//! (`/etc/hostname → /etc/shadow`) and opens devices/FIFOs (`→ /dev/zero` → memory full, agent dead). Therefore:
//! - `openat2` relative to a descriptor of the root with `RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS`: symlinks and
//!   `..` are resolved within the root, `/proc/self/…` jumps are forbidden
//! - open with `O_PATH` first, check via `fstat` (only regular files or directories), then read via the descriptor
//!   – no opening of devices/FIFOs, no race between check and read
//! - fixed size limits per file
//! - without `openat2` (kernel < 5.6, `ENOSYS`) there is **no** fallback to unsafe opening: the root is then
//!   not read at all (`FsRoot::contained` fails)
//!
//! `FsRoot::Host` reads path-based under a prefix as before (own system, test roots), with the same
//! checks on file type and size.

use std::ffi::CString;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

/// Small configuration files (os-release, hostname, plugin headers …)
pub const SMALL: u64 = 1 << 20;
/// Package databases (dpkg status, apk installed, .list files, rpmdb)
pub const PKG_DB: u64 = 256 << 20;

// Linux UAPI (linux/openat2.h); syscall number 437 is the same on all architectures (since 5.6).
const SYS_OPENAT2: libc::c_long = 437;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_IN_ROOT: u64 = 0x10;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// Root under which reading happens
pub enum FsRoot {
    /// own system or test root: path = prefix + relative path
    Host(String),
    /// foreign root (container): only via `openat2` relative to this descriptor
    Contained { fd: OwnedFd, path: String },
}

/// Kind of an entry (without following symlinks)
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
    // openat2 is strict: with O_PATH only O_DIRECTORY/O_NOFOLLOW/O_CLOEXEC are allowed (otherwise EINVAL)
    let extra = if flags & libc::O_PATH != 0 { libc::O_CLOEXEC } else { libc::O_CLOEXEC | libc::O_NOCTTY };
    let how = OpenHow { flags: (flags | extra) as u64, mode: 0, resolve: RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS };
    // SAFETY: valid pointers to p/how for the duration of the call; result is a new descriptor or -1
    let r = unsafe { libc::syscall(SYS_OPENAT2, dir.as_raw_fd(), p.as_ptr(), &how as *const OpenHow, std::mem::size_of::<OpenHow>()) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: r is a just-opened descriptor that we own
    Ok(unsafe { OwnedFd::from_raw_fd(r as i32) })
}

fn fstat(fd: &OwnedFd) -> io::Result<libc::stat> {
    // SAFETY: st is filled by the kernel
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

/// Reopen a descriptor (O_PATH) for reading via /proc/self/fd – same inode, no new path resolution
fn reopen(fd: &OwnedFd, flags: i32) -> io::Result<std::fs::File> {
    let p = CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap();
    // SAFETY: valid C string
    let r = unsafe { libc::open(p.as_ptr(), flags | libc::O_CLOEXEC | libc::O_NOCTTY) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: r is a just-opened descriptor that we own
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

    /// Open a foreign root. Errors (also: kernel without `openat2`) → the root is not read.
    pub fn contained(path: &str) -> io::Result<FsRoot> {
        let c = CString::new(std::path::Path::new(path).as_os_str().as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // the root itself (e.g. the magic link /proc/<pid>/root) is deliberately resolved normally
        // SAFETY: valid C string
        let r = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: just-opened descriptor
        let fd = unsafe { OwnedFd::from_raw_fd(r) };
        // openat2 available? (ENOSYS on kernels < 5.6, EPERM/ENOSYS under some seccomp filters)
        openat2(&fd, ".", libc::O_PATH | libc::O_DIRECTORY)?;
        Ok(FsRoot::Contained { fd, path: path.trim_end_matches('/').to_string() })
    }

    /// Is `openat2` supported by the kernel?
    pub fn openat2_supported() -> bool {
        FsRoot::contained("/").is_ok()
    }

    /// Display path (prefix or root path + relative path) – only for reporting, never for opening foreign roots
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

    /// Is this the real root directory of the host (empty prefix)?
    pub fn is_host_root(&self) -> bool {
        matches!(self, FsRoot::Host(p) if p.is_empty())
    }

    /// Kind of the target (symlinks are resolved – within the root); `None` if it does not exist
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

    /// Read a regular file, at most `limit` bytes (larger files: `None`, not truncated)
    pub fn read(&self, rel: &str, limit: u64) -> Option<Vec<u8>> {
        match self {
            FsRoot::Host(_) => {
                // O_NONBLOCK: a FIFO does not block the open; then type check on the open descriptor
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

    /// Start of a regular file (at most `n` bytes, also for larger files)
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

    /// like `read`, as text (invalid UTF-8 replaced)
    pub fn read_string(&self, rel: &str, limit: u64) -> Option<String> {
        self.read(rel, limit).map(|v| String::from_utf8(v).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()))
    }

    /// Entries of a directory: (name, kind without following symlinks), at most `max`
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
                // /proc/self/fd/N points to exactly this (already safely opened) directory
                let out = std::fs::read_dir(format!("/proc/self/fd/{}", d.as_raw_fd())).map(|rd| rd.flatten().take(max).map(conv).collect()).unwrap_or_default();
                drop(d);
                out
            }
        }
    }

    /// Walk the directory tree from `rel` (without following symlinks, depth ≤ `max_depth`); `f(relative path, kind)`
    /// returns `false` to not enter a directory. At most `max` entries in total.
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

/// At most `max` characters, without control characters (names/host names from foreign roots for the central server)
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
            eprintln!("openat2 not available – test skipped");
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
        // relative and absolute symlink in the container (absolute = container root, not host)
        symlink("../usr/lib/os-release", root.join("etc/os-release")).unwrap();
        symlink("/usr/lib/os-release", root.join("etc/abs")).unwrap();
        // Escape attempts
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
        assert_eq!(fs.read("/etc/hostname", SMALL), None, "absolute symlink to the host");
        assert_eq!(fs.read("/etc/dotdot", SMALL), None, ".. beyond the root");
        assert_eq!(fs.read("/../../host/etc/secret", SMALL), None);
        assert_eq!(fs.read("/etc/magic", SMALL), None, "Magic-Link");
        assert_eq!(fs.read("/etc/zero", SMALL), None, "device");
        assert_eq!(fs.read("/etc/fifo", SMALL), None, "FIFO must not block");
        assert_eq!(fs.read("/etc/big", SMALL), None, "too large");
        assert!(fs.read("/etc/big", SMALL + 1).is_some());
        assert!(fs.is_dir("/etc") && !fs.is_dir("/etc/os-release") && fs.exists("/etc/os-release"));
        let mut names: Vec<_> = fs.read_dir("/etc", 100).into_iter().map(|(n, _)| n).collect();
        names.sort();
        assert!(names.contains(&"os-release".to_string()) && names.contains(&"fifo".to_string()));
        // Root as symlink target via directories
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
