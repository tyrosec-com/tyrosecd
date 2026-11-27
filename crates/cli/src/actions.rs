//! Actions from the central server (actions plan): restore a file, quarantine, block/unblock an IP.
//!
//! Security: the agent only executes kinds that are enabled **locally** in `agent.toml` (`actions = [...]`) –
//! via `tyrosecd actions enable`. Fixed list, no arbitrary commands; strict path and IP validation.
//!
//! Restore/quarantine (security review K1/K2):
//! - path normalized (no empty, `.` or `..` components), the **resolved** path is checked against a block list
//!   (own files, cron, ld.so, systemd, sudoers, accounts, .ssh, /usr, /root …),
//! - only content is restored whose SHA-256 the agent itself has seen before for exactly this path
//!   (local state) – a compromised central server cannot inject new content,
//! - file access only via descriptors: folders opened without symlinks (O_NOFOLLOW per path component), temp file with
//!   random name (O_CREAT|O_EXCL|O_NOFOLLOW), fchown/fchmod, renameat or unlinkat relative to the folder.
use std::ffi::CString;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use std::sync::Mutex;

use sha2::{Digest, Sha256};
use tyrosd_core::state::{ActionRun, State};
use tyrosd_proto as pb;

pub const KINDS: [&str; 5] = ["restore", "quarantine", "block_ip", "decoy", "harden"];
/// Enabled by `tyrosecd actions enable` without a list – hardening changes configuration files and must be named
/// explicitly (`tyrosecd actions enable harden`)
pub const DEFAULT_KINDS: [&str; 4] = ["restore", "quarantine", "block_ip", "decoy"];
const MAX_RESTORE: usize = 32 << 20;
/// largest file that is copied into quarantine
const MAX_QUARANTINE: u64 = 16 << 20;

/// Folders (including their contents) in which nothing is restored or moved into quarantine.
/// Additionally all locations from which root executes files or reads commands as
/// configuration (logrotate scripts, MOTD, sysctl, bash completion, NetworkManager/ifupdown/DHCP/PPP hooks,
/// package manager maintainer scripts, anacron/incron, rsyslog omprog, fail2ban actions, kernel/initramfs hooks,
/// certificate trust stores …).
const DENY_DIRS: &[&str] = &[
    "/opt/tyrosecd", "/etc/tyrosecd", "/var/lib/tyrosecd", "/var/lib/tyrosd", "/var/spool/cron", "/var/spool/at", "/var/spool/anacron",
    "/var/spool/incron", "/etc/systemd", "/lib/systemd", "/usr/lib/systemd", "/var/lib/systemd", "/etc/pam.d", "/etc/security", "/etc/ssh",
    "/etc/profile.d", "/etc/init.d", "/etc/init", "/etc/modprobe.d", "/etc/modules-load.d", "/etc/udev", "/etc/apt", "/etc/yum.repos.d",
    "/etc/yum", "/etc/dnf", "/etc/zypp", "/etc/pacman.d", "/etc/apk", "/etc/dpkg", "/var/lib/dpkg", "/var/lib/rpm", "/etc/logrotate.d",
    "/etc/update-motd.d", "/etc/sysctl.d", "/etc/bash_completion.d", "/etc/NetworkManager", "/etc/network", "/etc/networkd-dispatcher",
    "/etc/dhcp", "/etc/ppp", "/etc/sysconfig", "/etc/xdg", "/etc/X11", "/etc/kernel", "/etc/initramfs-tools", "/etc/dracut.conf.d",
    "/etc/grub.d", "/etc/default", "/etc/binfmt.d", "/etc/tmpfiles.d", "/etc/environment.d", "/etc/rsyslog.d", "/etc/syslog-ng", "/etc/audit",
    "/etc/fail2ban", "/etc/needrestart", "/etc/acpi", "/etc/pm", "/etc/polkit-1", "/etc/sudo.conf", "/etc/doas.conf", "/etc/doas.d",
    "/etc/selinux", "/etc/apparmor.d", "/etc/skel", "/etc/supervisor", "/etc/monit", "/etc/docker", "/etc/containerd", "/etc/containers",
    "/etc/ssl", "/etc/pki", "/etc/ca-certificates", "/etc/incron.d",
    "/root", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/boot", "/proc", "/sys", "/dev", "/run",
];
/// Name prefixes (files and folders): /etc/cron*, /etc/ld.so.*, /etc/sudoers*, account files incl. backups, rc scripts …
const DENY_PREFIX: &[&str] = &[
    "/etc/cron", "/etc/anacrontab", "/etc/ld.so.", "/etc/sudoers", "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/subuid",
    "/etc/subgid", "/usr/local/bin/tyrosecd", "/etc/profile", "/etc/bash", "/etc/zsh", "/etc/csh", "/etc/environment", "/etc/rc", "/etc/inittab",
    "/etc/logrotate.conf", "/etc/sysctl.conf", "/etc/modules", "/etc/rsyslog.conf", "/etc/at.", "/etc/incron", "/etc/gitconfig",
    "/etc/login.defs", "/etc/securetty", "/etc/shells", "/etc/nsswitch.conf", "/etc/hosts", "/etc/resolv.conf", "/etc/fstab", "/etc/crypttab",
    "/etc/ca-certificates.conf",
];
/// additionally off-limits for quarantine (system files – removing them could cripple the server)
const NO_QUARANTINE: [&str; 10] = ["/etc/", "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/libexec/", "/lib/", "/lib64/", "/usr/share/"];

/// systemd drop-in for restore/quarantine. The base unit hardens the service (ProtectSystem=strict,
/// ProtectHome=read-only, without CAP_CHOWN/CAP_FOWNER) – so restoring into the webroot fails with EROFS.
/// Only `tyrosecd actions enable|disable|refresh` (local, root, outside the service)
/// writes this file; the service itself cannot modify /etc/systemd (ProtectSystem=strict, block list) –
/// so a compromised central server can neither disable the hardening nor extend the write permission.
pub const DROPIN: &str = "/etc/systemd/system/tyrosecd.service.d/actions.conf";

/// Path allowed in `ReadWritePaths=`: absolute, normalized, without whitespace/control characters, quotes,
/// `\` and `%` (systemd specifiers), not "/" and not in the block list
pub fn dropin_path_ok(p: &str) -> bool {
    p != "/"
        && clean_path(p).is_ok()
        && !p.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '\'' | '\\' | '%' | ';'))
        && !denied(p, false)
        // also no folder that contains blocked areas (/etc, /var, /var/lib …)
        && !DENY_DIRS.iter().chain(DENY_PREFIX).any(|d| d.starts_with(&format!("{p}/")))
}

/// Content of the drop-in for the enabled actions – `None` if no file is needed (neither restore nor
/// quarantine). `paths`: webroots (and other locally specified folders) in which restoring is allowed.
pub fn dropin_content(kinds: &[String], paths: &[String]) -> Result<Option<String>, String> {
    let restore = kinds.iter().any(|k| k == "restore");
    let quarantine = kinds.iter().any(|k| k == "quarantine");
    // Decoys: create new files in webroots – the same write permission as restore (webroots only)
    let decoy = kinds.iter().any(|k| k == "decoy");
    // Hardening: changes wp-config.php / .htaccess inside the webroots – same write permission (webroots only)
    let harden = kinds.iter().any(|k| k == "harden");
    if !restore && !quarantine && !decoy && !harden {
        return Ok(None);
    }
    let mut rw: Vec<String> = Vec::new();
    for p in paths {
        let p = p.trim_end_matches('/');
        if !dropin_path_ok(p) {
            return Err(format!("Folder {p} cannot be allowed (system area or invalid path)"));
        }
        rw.push(p.to_string());
    }
    if quarantine {
        // typical malware drop locations (/dev/shm is writable under ProtectSystem anyway)
        rw.extend(["/tmp".to_string(), "/var/tmp".to_string()]);
    }
    rw.sort();
    rw.dedup();
    let mut s = String::from(
        "# Written by \"tyrosecd actions enable|disable|refresh\" – only locally as root, never by the central server.\n\
         # Gives the agent write permission ONLY for the following folders (restore/quarantine) and the capabilities\n\
         # to set owner/mode of the restored file. The rest of the unit's hardening remains.\n[Service]\n",
    );
    if !rw.is_empty() {
        // "-": missing folders do not prevent startup
        s.push_str("ReadWritePaths=");
        s.push_str(&rw.iter().map(|p| format!("-{p}")).collect::<Vec<_>>().join(" "));
        s.push('\n');
    }
    // multiple CapabilityBoundingSet lines are merged by systemd (OR)
    s.push_str("CapabilityBoundingSet=CAP_CHOWN CAP_FOWNER\n");
    Ok(Some(s))
}

/// Write or remove the drop-in, then `systemctl daemon-reload` (and restart the service if requested).
/// Runs only via the local command line. `dropin` is `DROPIN` in production.
pub fn write_dropin(dropin: &str, kinds: &[String], paths: &[String], restart: bool) -> Result<String, String> {
    let content = dropin_content(kinds, paths)?;
    let target = Path::new(dropin);
    let changed = match &content {
        Some(c) => {
            if std::fs::read_to_string(target).ok().as_deref() == Some(c.as_str()) {
                false
            } else {
                let dir = target.parent().ok_or("invalid drop-in path")?;
                std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
                let tmp = dir.join(format!(".actions.conf.{}", random_hex()));
                let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o644).custom_flags(libc::O_NOFOLLOW).open(&tmp)
                    .map_err(|e| format!("{}: {e}", tmp.display()))?;
                f.write_all(c.as_bytes()).and_then(|_| f.sync_all()).map_err(|e| e.to_string())?;
                std::fs::rename(&tmp, target).map_err(|e| { let _ = std::fs::remove_file(&tmp); format!("{dropin}: {e}") })?;
                true
            }
        }
        None => match std::fs::remove_file(target) {
            Ok(()) => {
                if let Some(d) = target.parent() {
                    let _ = std::fs::remove_dir(d); // only if empty
                }
                true
            }
            Err(_) => false,
        },
    };
    if changed && dropin == DROPIN && Path::new("/run/systemd/system").is_dir() {
        let _ = Command::new("systemctl").arg("daemon-reload").status();
        if restart {
            let _ = Command::new("systemctl").args(["try-restart", "tyrosecd"]).status();
        }
    }
    Ok(match (&content, changed) {
        (Some(_), true) => format!("Write permission for actions set up: {dropin}"),
        (Some(_), false) => format!("Write permission for actions unchanged: {dropin}"),
        (None, true) => format!("Write permission for actions removed: {dropin}"),
        (None, false) => "no write permission needed".to_string(),
    })
}

/// Enabled actions freshly from the configuration (changes via CLI take effect without a restart)
pub fn enabled(config: &str) -> Vec<String> {
    tyrosd_transport::config::AgentConfig::load(config)
        .map(|c| c.actions.into_iter().filter(|a| KINDS.contains(&a.as_str())).collect())
        .unwrap_or_default()
}

/// Check the path syntactically → (folder, file name)
fn clean_path(p: &str) -> Result<(String, String), String> {
    if !p.starts_with('/') || p.contains('\0') || p.len() > 4000 {
        return Err("invalid path".into());
    }
    let parts: Vec<&str> = p[1..].split('/').collect();
    if parts.iter().any(|c| c.is_empty() || *c == "." || *c == "..") {
        return Err("invalid path".into());
    }
    let name = parts.last().unwrap().to_string();
    let dir = format!("/{}", parts[..parts.len() - 1].join("/"));
    Ok((dir, name))
}

/// Container file systems under a host path that `container::container_path` (only writable layers and
/// container roots) does not know: (prefix, suffix after the name) – merged views and containerd snapshots
const CONTAINER_VIEWS: &[(&str, &str)] = &[
    ("/var/lib/docker/overlay2/", "/merged"),
    ("/var/lib/containers/storage/overlay/", "/merged"),
    ("/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/", "/fs"),
];

/// `/proc/<pid>/root/x`, `/proc/<pid>/task/<tid>/root/x` → `/x`
fn proc_root_inner(p: &str) -> Option<String> {
    let rest = p.strip_prefix("/proc/")?;
    let (pid, mut after) = rest.split_once('/')?;
    if !(pid.bytes().all(|c| c.is_ascii_digit()) || pid == "self" || pid == "thread-self") {
        return None;
    }
    if let Some(t) = after.strip_prefix("task/") {
        after = t.split_once('/')?.1;
    }
    let inner = after.strip_prefix("root")?;
    match inner {
        "" => Some("/".into()),
        i if i.starts_with('/') => Some(i.to_string()),
        _ => None,
    }
}

/// Path inside the container if `p` lies in a container file system (`/proc/<pid>/root/…`, nspawn/LXC/Incus roots,
/// Docker/Podman writable layers and views, containerd snapshots)
fn container_inner(p: &str) -> Option<String> {
    if let Some(i) = proc_root_inner(p) {
        return Some(i);
    }
    if let Some(c) = tyrosd_core::container::container_path(p) {
        return Some(c.rel.to_string());
    }
    for (prefix, suffix) in CONTAINER_VIEWS {
        let Some(rest) = p.strip_prefix(prefix) else { continue };
        let (_, after) = rest.split_once('/')?;
        let tail = format!("/{after}");
        return match tail.strip_prefix(suffix)? {
            "" => Some("/".into()),
            i if i.starts_with('/') => Some(i.to_string()),
            _ => None,
        };
    }
    None
}

fn denied_plain(p: &str, quarantine: bool) -> bool {
    if quarantine && p.starts_with("/dev/shm/") {
        return false; // typical malware drop location – quarantine allowed
    }
    DENY_DIRS.iter().any(|d| p == *d || p.starts_with(&format!("{d}/")))
        || DENY_PREFIX.iter().any(|d| p.starts_with(d))
        || p.split('/').any(|c| c == ".ssh")
}

/// `check` on the path and – for container paths – on the **effective** path inside the container (up to 4 levels
/// nested; deeper → rejected)
fn any_view(p: &str, check: impl Fn(&str) -> bool) -> bool {
    let mut cur = p.to_string();
    for _ in 0..5 {
        if check(&cur) {
            return true;
        }
        match container_inner(&cur) {
            Some(inner) if inner != cur => cur = inner,
            _ => return false,
        }
    }
    true
}

/// Path in a blocked area? (`p` is normalized). The effective path inside the container also
/// counts – `/var/lib/machines/web/etc/cron.d/x` is the same for the container as `/etc/cron.d/x` on the host.
fn denied(p: &str, quarantine: bool) -> bool {
    any_view(p, |x| denied_plain(x, quarantine))
}

/// System folders from which nothing is moved into quarantine – also on the effective path
fn no_quarantine(p: &str) -> bool {
    any_view(p, |x| NO_QUARANTINE.iter().any(|d| x.starts_with(d)))
}

fn cstr(s: &str) -> Result<CString, String> {
    CString::new(s).map_err(|_| "invalid path".to_string())
}

fn os_err(what: &str) -> String {
    format!("{what}: {}", std::io::Error::last_os_error())
}

/// Open a folder component by component without following a symlink (O_NOFOLLOW per path component)
fn open_dir_nofollow(dir: &str) -> Result<OwnedFd, String> {
    // SAFETY: valid C string, return value checked
    let root = unsafe { libc::open(c"/".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if root < 0 {
        return Err(os_err("Opening folder"));
    }
    let mut fd = unsafe { OwnedFd::from_raw_fd(root) };
    for part in dir.split('/').filter(|c| !c.is_empty()) {
        let c = cstr(part)?;
        // SAFETY: fd and c valid
        let n = unsafe { libc::openat(fd.as_raw_fd(), c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if n < 0 {
            return Err(format!("Folder {dir} cannot be opened safely (symbolic link or missing): {}", std::io::Error::last_os_error()));
        }
        fd = unsafe { OwnedFd::from_raw_fd(n) };
    }
    Ok(fd)
}

/// Normalize, resolve the parent folder, block list on the **resolved** path → (folder fd, name, resolved path)
/// for decoys: same as restore (block list, parent folder without symlinks)
pub(crate) fn resolve_pub(p: &str) -> Result<(OwnedFd, String, String), String> {
    resolve(p, false)
}

fn resolve(p: &str, quarantine: bool) -> Result<(OwnedFd, String, String), String> {
    let (dir, name) = clean_path(p)?;
    if denied(p, quarantine) {
        return Err("Path in a protected system area".into());
    }
    let real_dir = std::fs::canonicalize(&dir).map_err(|_| format!("Folder {dir} does not exist"))?;
    let real_dir = real_dir.to_string_lossy().into_owned();
    let resolved = if real_dir == "/" { format!("/{name}") } else { format!("{real_dir}/{name}") };
    if denied(&resolved, quarantine) {
        return Err(format!("Path in a protected system area (resolved: {resolved})"));
    }
    let fd = open_dir_nofollow(&real_dir)?;
    Ok((fd, name, resolved))
}

fn fstatat(dir: &OwnedFd, name: &str) -> Result<Option<libc::stat>, String> {
    let c = cstr(name)?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: pointer valid
    let r = unsafe { libc::fstatat(dir.as_raw_fd(), c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    if r == 0 {
        Ok(Some(st))
    } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        Ok(None)
    } else {
        Err(os_err("Checking target"))
    }
}

fn fstat(fd: &impl AsRawFd) -> Result<libc::stat, String> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: pointer valid
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(os_err("fstat"));
    }
    Ok(st)
}

fn random_hex() -> String {
    let mut b = [0u8; 12];
    let ok = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).is_ok();
    if !ok {
        // Fallback; protection against takeover comes from O_EXCL|O_NOFOLLOW, not from the randomness of the name
        b[..8].copy_from_slice(&((tyrosd_core::now_ns() as u64) ^ ((std::process::id() as u64) << 32)).to_le_bytes());
    }
    hex(&b)
}

fn is_type(st: &libc::stat, t: libc::mode_t) -> bool {
    st.st_mode & libc::S_IFMT == t
}

/// Execute an action → (ok, message)
/// Permission that an action kind requires
fn needed(kind: &str) -> &str {
    match kind {
        "unblock_ip" => "block_ip",
        "decoy_place" | "decoy_remove" => "decoy",
        "harden_apply" | "harden_undo" => "harden",
        k => k,
    }
}

pub fn execute(a: &pb::Action, allowed: &[String], data_dir: &str, central_host: &str, state: &State) -> (bool, String) {
    let need = needed(&a.kind);
    if !allowed.iter().any(|x| x == need) {
        return (false, format!("Action “{need}” is not enabled on this server (sudo tyrosecd actions enable)"));
    }
    let r = match a.kind.as_str() {
        "restore" => restore(a, state),
        "quarantine" => quarantine(&a.path, data_dir),
        "block_ip" => block_ip(&a.ip, a.duration_s, data_dir, central_host),
        "unblock_ip" => unblock_ip(&a.ip, data_dir),
        "decoy_place" => crate::decoy::place(a, data_dir, &crate::decoy::webroots()),
        "decoy_remove" => crate::decoy::remove(a, data_dir),
        "harden_apply" => crate::harden::apply(a, data_dir, &crate::decoy::webroots()),
        "harden_undo" => crate::harden::undo(a, data_dir),
        k => Err(format!("unknown action {k}")),
    };
    match r {
        Ok(m) => (true, m),
        Err(e) => (false, e),
    }
}

/// Execute an action at most once (security review: repetition of the same ID by the central server, lost
/// response, restart). The ID is durably recorded as running **before** execution.
/// → `None`: already running (report nothing, the result follows), otherwise (ok, message) to report.
pub fn execute_once(a: &pb::Action, allowed: &[String], data_dir: &str, central_host: &str, state: &State) -> Option<(bool, String)> {
    let need = needed(&a.kind);
    if !allowed.iter().any(|x| x == need) {
        // do not record: after local enabling, the central server may send the same action again
        return Some(execute(a, allowed, data_dir, central_host, state));
    }
    {
        // Lock across check + record, so that "currently running" and "interrupted" can be reliably distinguished
        let mut running = RUNNING.lock().unwrap_or_else(|e| e.into_inner());
        match state.action_begin(a.id, tyrosd_core::now_ns()) {
            Ok(None) => {
                running.insert(a.id);
            }
            Ok(Some(ActionRun::Running { .. })) if running.contains(&a.id) => return None,
            Ok(Some(ActionRun::Running { .. })) => {
                return Some((false, "already executed (interrupted by a restart, result unknown) – not repeated".into()))
            }
            Ok(Some(ActionRun::Done { ok, message, .. })) => return Some((ok, format!("already executed: {message}"))),
            // without a reliable record, better not execute
            Err(e) => return Some((false, format!("Action not executed: state not writable ({e:#})"))),
        }
    }
    let (ok, message) = execute(a, allowed, data_dir, central_host, state);
    let _ = state.action_finish(a.id, tyrosd_core::now_ns(), ok, &message);
    RUNNING.lock().unwrap_or_else(|e| e.into_inner()).remove(&a.id);
    Some((ok, message))
}

/// action IDs currently running in this process
static RUNNING: Mutex<std::collections::BTreeSet<u64>> = Mutex::new(std::collections::BTreeSet::new());

fn restore(a: &pb::Action, state: &State) -> Result<String, String> {
    let (dir, name, resolved) = resolve(&a.path, false)?;
    if resolved != a.path {
        return Err(format!("Path contains symbolic links (resolved: {resolved}) – not restored"));
    }
    let content = zstd::bulk::decompress(&a.content_zstd, MAX_RESTORE).map_err(|_| "Content not readable".to_string())?;
    let sha: [u8; 32] = Sha256::digest(&content).into();
    if sha.as_slice() != a.content_hash.as_slice() {
        return Err("Content checksum does not match".into());
    }
    if !state.seen_hash(&a.path, &sha) {
        return Err("Content does not match any version the agent itself has seen for this file – restore refused".into());
    }
    let (mode, uid, gid) = match fstatat(&dir, &name)? {
        Some(st) if is_type(&st, libc::S_IFLNK) => return Err("Target is a symbolic link".into()),
        Some(st) if !is_type(&st, libc::S_IFREG) => return Err("Target is not a regular file".into()),
        // mode is kept, but never SUID/SGID/sticky
        Some(st) => (st.st_mode & 0o777, st.st_uid, st.st_gid),
        None => {
            // deleted file: create anew, without SUID/SGID, owner same as the folder (e.g. www-data). Mode is never
            // taken from the central server: the locally last seen mode, otherwise 0644 – the
            // central server can only restrict it.
            let ds = fstat(&dir)?;
            let local = state.get(&a.path).map(|e| e.meta.mode);
            (restore_mode(local, a.mode) as libc::mode_t, ds.st_uid, ds.st_gid)
        }
    };
    let tmp = format!(".tyrosec-restore-{}", random_hex());
    let ctmp = cstr(&tmp)?;
    // SAFETY: dir and ctmp valid
    let raw = unsafe { libc::openat(dir.as_raw_fd(), ctmp.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600 as libc::c_uint) };
    if raw < 0 {
        return Err(os_err("Write failed"));
    }
    let mut f = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(raw) });
    let fin = (|| -> Result<(), String> {
        f.write_all(&content).map_err(|e| format!("Write failed: {e}"))?;
        // SAFETY: fd valid
        if unsafe { libc::fchown(f.as_raw_fd(), uid, gid) } != 0 {
            return Err(os_err("Replace failed (owner)"));
        }
        if unsafe { libc::fchmod(f.as_raw_fd(), mode) } != 0 {
            return Err(os_err("Replace failed (permissions)"));
        }
        f.sync_all().map_err(|e| format!("Replace failed: {e}"))?;
        let cname = cstr(&name)?;
        if unsafe { libc::renameat(dir.as_raw_fd(), ctmp.as_ptr(), dir.as_raw_fd(), cname.as_ptr()) } != 0 {
            return Err(os_err("Replace failed"));
        }
        Ok(())
    })();
    if let Err(e) = fin {
        // SAFETY: dir and ctmp valid
        unsafe { libc::unlinkat(dir.as_raw_fd(), ctmp.as_ptr(), 0) };
        return Err(e);
    }
    Ok(format!("{} restored ({} bytes)", a.path, content.len()))
}

/// Mode for a newly created (deleted) file: the locally last seen mode (otherwise 0644), never SUID/SGID/sticky,
/// never world-writable. The central server (`server`, 0 = not specified) can only **remove** bits, never add them.
fn restore_mode(local: Option<u32>, server: u32) -> u32 {
    let base = local.map(|m| m & 0o777).unwrap_or(0o644) & !0o002;
    if server > 0 { base & server } else { base }
}

fn quarantine(p: &str, data_dir: &str) -> Result<String, String> {
    let (dir, name, resolved) = resolve(p, true)?;
    if no_quarantine(&resolved) {
        return Err("System files are not moved to quarantine – please check manually".into());
    }
    let cname = cstr(&name)?;
    // SAFETY: dir and cname valid
    let raw = unsafe { libc::openat(dir.as_raw_fd(), cname.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if raw < 0 {
        return Err(match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ENOENT) => "File does not exist (anymore)".to_string(),
            Some(libc::ELOOP) => "symbolic link – not moved".to_string(),
            _ => os_err("Read failed"),
        });
    }
    let f = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(raw) });
    let st = fstat(&f)?;
    if !is_type(&st, libc::S_IFREG) {
        return Err("not a regular file".into());
    }
    if st.st_size as u64 > MAX_QUARANTINE {
        return Err(format!("File too large for quarantine ({} MB, limit {} MB) – please check manually", st.st_size >> 20, MAX_QUARANTINE >> 20));
    }
    let mut data = Vec::new();
    (&f).take(MAX_QUARANTINE + 1).read_to_end(&mut data).map_err(|e| format!("Read failed: {e}"))?;
    if data.len() as u64 > MAX_QUARANTINE {
        return Err("File too large for quarantine".into());
    }
    let hash = hex(&Sha256::digest(&data));
    let qdir = Path::new(data_dir).join("quarantine");
    std::fs::create_dir_all(&qdir).map_err(|e| e.to_string())?;
    let _ = std::fs::set_permissions(&qdir, std::fs::Permissions::from_mode(0o700));
    let safe: String = resolved.trim_start_matches('/').chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' }).take(120).collect();
    let target = qdir.join(format!("{}-{}-{safe}", tyrosd_core::now_ns() / 1_000_000_000, &random_hex()[..8]));
    let write_new = |path: &Path, bytes: &[u8]| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(path)?;
        f.write_all(bytes)?;
        f.sync_all()
    };
    write_new(&target, &data).map_err(|e| format!("Copy failed: {e}"))?;
    let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o000));
    let meta = serde_json::json!({ "path": resolved, "mode": st.st_mode & 0o7777, "uid": st.st_uid, "gid": st.st_gid, "size": st.st_size, "sha256": hash, "ts": tyrosd_core::now_ns() / 1_000_000_000 });
    let _ = write_new(&target.with_extension("json"), meta.to_string().as_bytes());
    // Removal: Linux has no "delete the name only if it points to inode X". Therefore the name is first atomically
    // moved to a random name in the same folder (pinned during resolution), and only then is it checked *what* was
    // moved: only if it is the copied file is it deleted, otherwise it is renamed back. The remaining gap
    // (random name swapped between check and deletion) requires write permission on the folder – with that, the
    // person concerned could remove the name themselves anyway; nothing is ever deleted outside this folder, never by
    // following a symlink, and never a folder.
    let tmp = format!(".tyrosec-q-{}", &random_hex()[..12]);
    let ctmp = cstr(&tmp)?;
    if renameat_noreplace(&dir, &cname, &ctmp) != 0 {
        return Err(format!("Removal failed (copy is in {}): {}", target.display(), std::io::Error::last_os_error()));
    }
    match fstatat(&dir, &tmp)? {
        Some(now) if now.st_ino == st.st_ino && now.st_dev == st.st_dev && is_type(&now, libc::S_IFREG) => {}
        _ => {
            let _ = renameat_noreplace(&dir, &ctmp, &cname);
            return Err(format!("File was replaced in the meantime – not removed (copy is in {})", target.display()));
        }
    }
    // SAFETY: dir and ctmp valid
    if unsafe { libc::unlinkat(dir.as_raw_fd(), ctmp.as_ptr(), 0) } != 0 {
        let _ = renameat_noreplace(&dir, &ctmp, &cname);
        return Err(format!("Removal failed (copy is in {}): {}", target.display(), std::io::Error::last_os_error()));
    }
    Ok(format!("Quarantined: {} (SHA-256 {}…)", target.display(), &hash[..16]))
}

/// `renameat2(RENAME_NOREPLACE)` in the same folder (never overwrites an existing name); 0 = success
fn renameat_noreplace(dir: &OwnedFd, from: &std::ffi::CStr, to: &std::ffi::CStr) -> libc::c_long {
    const RENAME_NOREPLACE: libc::c_uint = 1;
    // SAFETY: valid folder descriptor and NUL-terminated names; direct system call (musl does not provide renameat2
    // in all versions)
    unsafe { libc::syscall(libc::SYS_renameat2, dir.as_raw_fd(), from.as_ptr(), dir.as_raw_fd(), to.as_ptr(), RENAME_NOREPLACE) }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// IPv4-mapped IPv6 address (::ffff:a.b.c.d) → IPv4 (otherwise it would bypass the private network check and
/// end up ineffective in the IPv6 set)
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// Never block: private/local networks and the central server itself (otherwise the agent cuts itself off)
fn blockable(ip: &IpAddr, central_host: &str) -> Result<(), String> {
    let ip = &canonical(*ip);
    let private = match ip {
        IpAddr::V4(v) => v.is_private() || v.is_loopback() || v.is_link_local() || v.is_unspecified() || v.is_broadcast() || v.is_multicast()
            || v.octets()[0] == 100 && (64..128).contains(&v.octets()[1]),
        IpAddr::V6(v) => v.is_loopback() || v.is_unspecified() || v.is_multicast() || (v.segments()[0] & 0xfe00) == 0xfc00 || (v.segments()[0] & 0xffc0) == 0xfe80,
    };
    if private {
        return Err("private or local addresses are not blocked".into());
    }
    use std::net::ToSocketAddrs;
    if let Ok(addrs) = (central_host, 443).to_socket_addrs() {
        if addrs.into_iter().any(|a| canonical(a.ip()) == *ip) {
            return Err("the address of the central server is not blocked".into());
        }
    }
    Ok(())
}

fn have(cmd: &str) -> bool {
    ["/usr/sbin/", "/sbin/", "/usr/bin/", "/bin/"].iter().any(|d| Path::new(&format!("{d}{cmd}")).exists())
}

fn run(cmd: &str, args: &[&str]) -> Result<(), String> {
    let o = Command::new(cmd).args(args).output().map_err(|e| format!("{cmd}: {e}"))?;
    if o.status.success() {
        Ok(())
    } else {
        Err(format!("{cmd}: {}", String::from_utf8_lossy(&o.stderr).trim()))
    }
}

/// nftables table with sets (built-in expiry); creates table/chain/rules once
fn nft_ready() -> Result<(), String> {
    run("nft", &["add", "table", "inet", "tyrosec"])?;
    run("nft", &["add", "set", "inet", "tyrosec", "block4", "{ type ipv4_addr; flags timeout; }"])?;
    run("nft", &["add", "set", "inet", "tyrosec", "block6", "{ type ipv6_addr; flags timeout; }"])?;
    run("nft", &["add", "chain", "inet", "tyrosec", "input", "{ type filter hook input priority -5; policy accept; }"])?;
    let o = Command::new("nft").args(["list", "chain", "inet", "tyrosec", "input"]).output().map_err(|e| e.to_string())?;
    if !String::from_utf8_lossy(&o.stdout).contains("@block4") {
        run("nft", &["add", "rule", "inet", "tyrosec", "input", "ip", "saddr", "@block4", "drop"])?;
        run("nft", &["add", "rule", "inet", "tyrosec", "input", "ip6", "saddr", "@block6", "drop"])?;
    }
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct Block {
    ip: String,
    until: i64, // 0 = permanent
}

fn blocks_file(data_dir: &str) -> PathBuf {
    Path::new(data_dir).join("blocks.json")
}
fn load_blocks(data_dir: &str) -> Vec<Block> {
    std::fs::read(blocks_file(data_dir)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}
/// blocks.json is modified by actions (separate threads per heartbeat) and by maintenance – only one at a time
static BLOCKS_LOCK: Mutex<()> = Mutex::new(());

fn save_blocks(data_dir: &str, b: &[Block]) {
    // replace atomically (temp file with random name, O_EXCL|O_NOFOLLOW)
    let tmp = Path::new(data_dir).join(format!(".blocks-{}.tmp", random_hex()));
    let ok = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .and_then(|mut f| f.write_all(&serde_json::to_vec(b).unwrap_or_default()).and_then(|_| f.sync_all()))
        .and_then(|_| std::fs::rename(&tmp, blocks_file(data_dir)));
    if ok.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
}
fn now_s() -> i64 {
    tyrosd_core::now_ns() / 1_000_000_000
}

fn apply_block(ip: &IpAddr, secs: u32) -> Result<&'static str, String> {
    let s = ip.to_string();
    if have("nft") {
        nft_ready()?;
        let set = if ip.is_ipv4() { "block4" } else { "block6" };
        let el = if secs > 0 { format!("{{ {s} timeout {secs}s }}") } else { format!("{{ {s} }}") };
        let _ = run("nft", &["delete", "element", "inet", "tyrosec", set, &format!("{{ {s} }}")]);
        run("nft", &["add", "element", "inet", "tyrosec", set, &el])?;
        return Ok("nftables");
    }
    let tool = if ip.is_ipv4() { "iptables" } else { "ip6tables" };
    if !have(tool) {
        return Err("neither nftables nor iptables available".into());
    }
    if run(tool, &["-C", "INPUT", "-s", &s, "-j", "DROP", "-m", "comment", "--comment", "tyrosec"]).is_err() {
        run(tool, &["-I", "INPUT", "-s", &s, "-j", "DROP", "-m", "comment", "--comment", "tyrosec"])?;
    }
    Ok("iptables")
}

fn remove_block(ip: &IpAddr) {
    let s = ip.to_string();
    if have("nft") {
        let set = if ip.is_ipv4() { "block4" } else { "block6" };
        let _ = run("nft", &["delete", "element", "inet", "tyrosec", set, &format!("{{ {s} }}")]);
    }
    let tool = if ip.is_ipv4() { "iptables" } else { "ip6tables" };
    if have(tool) {
        while run(tool, &["-D", "INPUT", "-s", &s, "-j", "DROP", "-m", "comment", "--comment", "tyrosec"]).is_ok() {}
    }
}

fn block_ip(ip: &str, secs: u32, data_dir: &str, central_host: &str) -> Result<String, String> {
    let addr = canonical(ip.trim().parse().map_err(|_| "not a valid IP address".to_string())?);
    blockable(&addr, central_host)?;
    let _g = BLOCKS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let how = apply_block(&addr, secs)?;
    let mut b: Vec<Block> = load_blocks(data_dir).into_iter().filter(|x| x.ip != addr.to_string()).collect();
    b.push(Block { ip: addr.to_string(), until: if secs > 0 { now_s() + secs as i64 } else { 0 } });
    save_blocks(data_dir, &b);
    Ok(format!("{addr} blocked ({how}{})", if secs > 0 { format!(", {} h", (secs + 1800) / 3600) } else { ", permanent".into() }))
}

fn unblock_ip(ip: &str, data_dir: &str) -> Result<String, String> {
    let addr = canonical(ip.trim().parse().map_err(|_| "not a valid IP address".to_string())?);
    let _g = BLOCKS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    remove_block(&addr);
    let b: Vec<Block> = load_blocks(data_dir).into_iter().filter(|x| x.ip != addr.to_string()).collect();
    save_blocks(data_dir, &b);
    Ok(format!("{addr} unblocked"))
}

/// At startup restore blocks (empty after a reboot) and remove expired ones (iptables has no expiry)
pub fn maintain_blocks(data_dir: &str, reapply: bool) {
    let _g = BLOCKS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let now = now_s();
    let mut keep = Vec::new();
    for b in load_blocks(data_dir) {
        let Ok(ip) = b.ip.parse::<IpAddr>() else { continue };
        if b.until > 0 && b.until <= now {
            remove_block(&ip);
            continue;
        }
        if reapply {
            let _ = apply_block(&ip, if b.until > 0 { (b.until - now) as u32 } else { 0 });
        }
        keep.push(b);
    }
    save_blocks(data_dir, &keep);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn state(dir: &Path) -> std::sync::Arc<State> {
        State::open(&dir.join("s.redb").to_string_lossy(), 4, 1 << 20).unwrap()
    }

    fn sha(b: &[u8]) -> [u8; 32] {
        Sha256::digest(b).into()
    }

    #[test]
    fn paths_and_ips_are_checked() {
        assert!(clean_path("/var/www/x/../etc/passwd").is_err());
        assert!(clean_path("relative").is_err());
        assert!(clean_path("//etc/passwd").is_err()); // an empty path component no longer bypasses the block list
        assert!(clean_path("/var/www//x.php").is_err());
        assert!(clean_path("/var/www/./x.php").is_err());
        assert!(clean_path("/var/www/").is_err());
        assert_eq!(clean_path("/var/www/shop/index.php").unwrap(), ("/var/www/shop".to_string(), "index.php".to_string()));
        for p in [
            "/proc/1/mem", "/opt/tyrosecd/bin/tyrosecd", "/usr/local/bin/tyrosecd", "/etc/tyrosecd/agent.toml", "/var/lib/tyrosecd/agent.key",
            "/etc/cron.d/x", "/etc/crontab", "/var/spool/cron/crontabs/root", "/etc/ld.so.preload", "/etc/systemd/system/x.service",
            "/lib/systemd/system/x.service", "/usr/lib/systemd/system/x.service", "/etc/sudoers", "/etc/sudoers.d/x", "/etc/passwd", "/etc/shadow",
            "/etc/group", "/etc/gshadow", "/root/x", "/home/a/.ssh/authorized_keys", "/var/www/.ssh/authorized_keys", "/usr/bin/ls", "/bin/sh", "/sbin/x",
            "/lib/x.so", "/lib64/x.so", "/boot/vmlinuz", "/sys/x", "/dev/sda", "/run/x",
        ] {
            assert!(denied(p, false), "{p}");
            assert!(denied(p, true), "{p}");
        }
        assert!(!denied("/dev/shm/x", true));
        assert!(denied("/dev/shm/x", false));
        assert!(!denied("/var/www/shop/index.php", false));
        assert!(!denied("/home/a/public_html/index.php", false));
        // root execution paths
        for p in [
            "/etc/logrotate.d/nginx", "/etc/logrotate.conf", "/etc/update-motd.d/00-header", "/etc/sysctl.d/99-x.conf", "/etc/sysctl.conf",
            "/etc/bash_completion.d/x", "/usr/share/bash-completion/completions/x", "/etc/NetworkManager/dispatcher.d/x", "/var/lib/dpkg/info/x.postinst",
            "/etc/anacrontab", "/var/spool/anacron/cron.daily", "/etc/rc.local", "/etc/rc2.d/S01x", "/etc/network/if-up.d/x", "/etc/dhcp/dhclient-exit-hooks.d/x",
            "/etc/fail2ban/action.d/x.conf", "/etc/rsyslog.d/x.conf", "/etc/kernel/postinst.d/x", "/etc/apt/apt.conf.d/99x", "/etc/dpkg/dpkg.cfg.d/x",
            "/etc/gitconfig", "/etc/environment", "/etc/bash.bashrc", "/etc/ssl/certs/ca-certificates.crt", "/etc/default/grub", "/etc/modules",
        ] {
            assert!(denied(p, false), "{p}");
        }
        // effective path inside the container: same block list
        for p in [
            "/var/lib/machines/web/etc/cron.d/x", "/var/lib/machines/web/etc/systemd/system/x.service", "/var/lib/lxc/c1/rootfs/etc/sudoers",
            "/var/lib/docker/overlay2/3f2a9c1b7d4e/diff/etc/ld.so.preload", "/var/lib/docker/overlay2/3f2a9c1b7d4e/merged/root/.bashrc",
            "/var/lib/containers/storage/overlay/abc/merged/etc/profile.d/x.sh", "/var/lib/docker/overlay2/abc/merged/usr/bin/ls",
            "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/12/fs/etc/crontab", "/var/lib/machines/web/home/a/.ssh/authorized_keys",
            // container inside a container
            "/var/lib/machines/host2/var/lib/lxc/c/rootfs/etc/logrotate.d/x",
        ] {
            assert!(denied(p, false), "{p}");
            assert!(denied(p, true), "{p}");
        }
        assert_eq!(proc_root_inner("/proc/123/root/etc/cron.d/x").as_deref(), Some("/etc/cron.d/x"));
        assert_eq!(proc_root_inner("/proc/123/task/124/root/etc").as_deref(), Some("/etc"));
        assert_eq!(proc_root_inner("/proc/123/rootx"), None);
        assert_eq!(container_inner("/var/lib/docker/overlay2/abc/merged/var/www/x.php").as_deref(), Some("/var/www/x.php"));
        assert_eq!(container_inner("/var/lib/docker/overlay2/abc/mergedx/var/www/x.php"), None);
        // webroots inside the container remain allowed
        assert!(!denied("/var/lib/machines/web/var/www/shop/index.php", false));
        assert!(!denied("/var/lib/docker/overlay2/abc/merged/var/www/html/index.php", false));
        assert!(!no_quarantine("/var/lib/machines/web/var/www/shop/x.php"));
        assert!(no_quarantine("/var/lib/machines/web/etc/hostname"));
        assert!(no_quarantine("/var/lib/lxc/c1/rootfs/usr/bin/x"));
        for ip in ["10.0.0.1", "192.168.1.5", "127.0.0.1", "100.64.0.1", "::1", "fd00::1", "fe80::1"] {
            assert!(blockable(&ip.parse().unwrap(), "localhost").is_err(), "{ip}");
        }
        assert!(blockable(&"91.92.93.20".parse().unwrap(), "localhost").is_ok());
        // IPv4-mapped IPv6 addresses count like the IPv4 address
        for ip in ["::ffff:10.0.0.1", "::ffff:192.168.1.5", "::ffff:127.0.0.1", "::ffff:100.64.0.1", "::ffff:169.254.1.1", "::ffff:0.0.0.0"] {
            assert!(blockable(&ip.parse().unwrap(), "localhost").is_err(), "{ip}");
        }
        assert!(blockable(&"::ffff:91.92.93.20".parse().unwrap(), "localhost").is_ok());
        assert_eq!(canonical("::ffff:91.92.93.20".parse().unwrap()), "91.92.93.20".parse::<IpAddr>().unwrap());
        assert_eq!(canonical("2001:db8::1".parse().unwrap()), "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn dropin_only_for_local_actions() {
        let k = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(dropin_content(&k(&[]), &k(&["/var/www"])).unwrap(), None);
        assert_eq!(dropin_content(&k(&["block_ip"]), &k(&["/var/www"])).unwrap(), None);
        let c = dropin_content(&k(&["restore"]), &k(&["/var/www/", "/home/a/public_html"])).unwrap().unwrap();
        assert!(c.contains("\nReadWritePaths=-/home/a/public_html -/var/www\n"), "{c}");
        assert!(c.contains("\nCapabilityBoundingSet=CAP_CHOWN CAP_FOWNER\n"), "{c}");
        assert!(!c.contains("/tmp"));
        let q = dropin_content(&k(&["quarantine"]), &[]).unwrap().unwrap();
        assert!(q.contains("ReadWritePaths=-/tmp -/var/tmp\n"), "{q}");
        // system areas, "/" and paths with systemd special characters are never allowed
        for bad in ["/", "/etc", "/var", "/var/lib", "/etc/cron.d", "/usr/share/nginx/html", "/var/www/a b", "/var/www/%h", "/var/www/x\nExecStartPre=/bin/sh", "relative", "/var/www/../etc"] {
            assert!(dropin_content(&k(&["restore"]), &k(&[bad])).is_err(), "{bad:?}");
        }
        // write and remove again (test path, no systemctl)
        let d = std::env::temp_dir().join(format!("act-dropin-{}", std::process::id()));
        let f = d.join("tyrosecd.service.d/actions.conf");
        let fs = f.to_string_lossy().into_owned();
        assert!(write_dropin(&fs, &k(&["restore"]), &k(&["/var/www"]), false).unwrap().contains("set up"));
        assert_eq!(std::fs::metadata(&f).unwrap().mode() & 0o777, 0o644);
        assert!(write_dropin(&fs, &k(&["restore"]), &k(&["/var/www"]), false).unwrap().contains("unchanged"));
        assert!(write_dropin(&fs, &k(&["block_ip"]), &k(&["/var/www"]), false).unwrap().contains("removed"));
        assert!(!f.exists());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn mode_never_from_server() {
        assert_eq!(restore_mode(None, 0), 0o644);
        assert_eq!(restore_mode(None, 0o4777), 0o644); // central server cannot add anything
        assert_eq!(restore_mode(None, 0o600), 0o600); // … only restrict
        assert_eq!(restore_mode(Some(0o100755), 0), 0o755);
        assert_eq!(restore_mode(Some(0o100777), 0o777), 0o775); // never world-writable
        assert_eq!(restore_mode(Some(0o104755), 0), 0o755); // never SUID
    }

    #[test]
    fn same_action_runs_only_once() {
        let dir = std::env::temp_dir().join(format!("act-once-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let st = state(&dir);
        let allowed: Vec<String> = KINDS.iter().map(|s| s.to_string()).collect();
        let f = dir.join("evil.php");
        std::fs::write(&f, "<?php system($_GET['c']);").unwrap();
        let q = dir.join("q");
        let a = pb::Action { id: 4711, kind: "quarantine".into(), path: f.to_string_lossy().into(), ..Default::default() };
        let (ok, msg) = execute_once(&a, &allowed, q.to_str().unwrap(), "localhost", &st).unwrap();
        assert!(ok, "{msg}");
        // file is back (e.g. recreated by the attacker) – the same ID must not do anything anymore
        std::fs::write(&f, "new").unwrap();
        let (ok2, msg2) = execute_once(&a, &allowed, q.to_str().unwrap(), "localhost", &st).unwrap();
        assert!(ok2 && msg2.starts_with("already executed") && msg2.contains(&msg), "{msg2}");
        assert!(f.exists());
        assert_eq!(std::fs::read_dir(q.join("quarantine")).unwrap().count(), 2);
        // interrupted by a restart (recorded, but not running in this process) → not repeated
        st.action_begin(4712, tyrosd_core::now_ns()).unwrap();
        let (ok, msg) = execute_once(&pb::Action { id: 4712, ..a.clone() }, &allowed, q.to_str().unwrap(), "localhost", &st).unwrap();
        assert!(!ok && msg.contains("interrupted"), "{msg}");
        assert!(f.exists());
        // currently running (other thread) → report nothing
        RUNNING.lock().unwrap().insert(4713);
        st.action_begin(4713, tyrosd_core::now_ns()).unwrap();
        assert!(execute_once(&pb::Action { id: 4713, ..a.clone() }, &allowed, q.to_str().unwrap(), "localhost", &st).is_none());
        RUNNING.lock().unwrap().remove(&4713);
        // not enabled → not recorded, possible after enabling
        let (ok, _) = execute_once(&pb::Action { id: 4714, ..a.clone() }, &[], q.to_str().unwrap(), "localhost", &st).unwrap();
        assert!(!ok);
        let (ok, msg) = execute_once(&pb::Action { id: 4714, ..a }, &allowed, q.to_str().unwrap(), "localhost", &st).unwrap();
        assert!(ok && !msg.starts_with("already"), "{msg}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn not_enabled_is_refused() {
        let d = std::env::temp_dir().join(format!("act-ne-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let st = state(&d);
        let a = pb::Action { id: 1, kind: "quarantine".into(), path: "/tmp/x".into(), ..Default::default() };
        let (ok, msg) = execute(&a, &[], "/tmp", "localhost", &st);
        assert!(!ok && msg.contains("not enabled"));
        let (ok, msg) = execute(&pb::Action { kind: "unblock_ip".into(), ..a.clone() }, &["restore".into()], "/tmp", "localhost", &st);
        assert!(!ok && msg.contains("block_ip"));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn restore_and_quarantine_roundtrip() {
        let dir = std::env::temp_dir().join(format!("act-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let st = state(&dir);
        let f = dir.join("index.php");
        std::fs::write(&f, "<?php eval($_POST['x']);").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o640)).unwrap();
        let good = b"<?php echo 'ok';\n";
        let path: String = f.to_string_lossy().into();
        let allowed: Vec<String> = KINDS.iter().map(|s| s.to_string()).collect();
        let a = pb::Action {
            id: 1, kind: "restore".into(), path: path.clone(),
            content_zstd: zstd::encode_all(&good[..], 1).unwrap(), content_hash: sha(good).to_vec(), ..Default::default()
        };
        // version the agent has never seen (e.g. from a compromised central server) → rejected
        let (ok, msg) = execute(&a, &allowed, "/tmp", "localhost", &st);
        assert!(!ok && msg.contains("any version"), "{msg}");
        // … seen for a different path does not count
        st.remember(&format!("{}/other.php", dir.display()), &sha(good));
        assert!(!execute(&a, &allowed, "/tmp", "localhost", &st).0);
        st.remember(&path, &sha(good));
        let (ok, msg) = execute(&a, &allowed, "/tmp", "localhost", &st);
        assert!(ok, "{msg}");
        assert_eq!(std::fs::read(&f).unwrap(), good);
        assert_eq!(std::fs::metadata(&f).unwrap().mode() & 0o777, 0o640); // mode is kept
        assert!(std::fs::read_dir(&dir).unwrap().flatten().all(|e| !e.file_name().to_string_lossy().starts_with(".tyrosec-restore-")));
        // wrong checksum → nothing changed
        let bad = pb::Action { content_hash: vec![0; 32], ..a.clone() };
        assert!(!execute(&bad, &allowed, "/tmp", "localhost", &st).0);
        // quarantine: removed from its location, copy with mode 000 + metadata
        let q = dir.join("q");
        let (ok, msg) = execute(&pb::Action { kind: "quarantine".into(), ..a.clone() }, &allowed, q.to_str().unwrap(), "localhost", &st);
        assert!(ok, "{msg}");
        assert!(!f.exists());
        let files: Vec<_> = std::fs::read_dir(q.join("quarantine")).unwrap().flatten().collect();
        assert_eq!(files.len(), 2);
        assert!(!execute(&pb::Action { kind: "quarantine".into(), path: "/etc/passwd".into(), ..a.clone() }, &allowed, "/tmp", "localhost", &st).0);
        // restore a deleted file: mode from the central server (SUID, world-writable) is not adopted
        let (ok, msg) = execute(&pb::Action { id: 7, mode: 0o4777, ..a }, &allowed, "/tmp", "localhost", &st);
        assert!(ok, "{msg}");
        assert_eq!(std::fs::metadata(&f).unwrap().mode() & 0o7777, 0o644);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn symlinks_are_refused() {
        let dir = std::env::temp_dir().join(format!("act-ln-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let st = state(&dir);
        let allowed: Vec<String> = KINDS.iter().map(|s| s.to_string()).collect();
        let victim = dir.join("victim.txt");
        std::fs::write(&victim, "unchanged").unwrap();
        let good = b"new";
        // target is a symlink → no writing through the link
        let link = dir.join("link.php");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        let lp: String = link.to_string_lossy().into();
        st.remember(&lp, &sha(good));
        let a = pb::Action { id: 1, kind: "restore".into(), path: lp.clone(), content_zstd: zstd::encode_all(&good[..], 1).unwrap(), content_hash: sha(good).to_vec(), ..Default::default() };
        let (ok, msg) = execute(&a, &allowed, "/tmp", "localhost", &st);
        assert!(!ok && msg.contains("symbolic link"), "{msg}");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "unchanged");
        // quarantine of a symlink → rejected, target remains
        let (ok, msg) = execute(&pb::Action { kind: "quarantine".into(), ..a.clone() }, &allowed, dir.join("q").to_str().unwrap(), "localhost", &st);
        assert!(!ok && msg.contains("symbolic link"), "{msg}");
        assert!(victim.exists() && link.exists());
        // folder via symlink (e.g. to /etc) → the resolved path counts
        let sub = dir.join("etc-link");
        std::os::unix::fs::symlink("/etc", &sub).unwrap();
        let p = format!("{}/cron.d/evil", sub.display());
        st.remember(&p, &sha(good));
        let (ok, msg) = execute(&pb::Action { path: p, ..a.clone() }, &allowed, "/tmp", "localhost", &st);
        assert!(!ok && msg.contains("protected"), "{msg}");
        // harmless folder via symlink: path differs from the state → rejected
        let real = dir.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let via = dir.join("via");
        std::os::unix::fs::symlink(&real, &via).unwrap();
        let p = format!("{}/x.php", via.display());
        st.remember(&p, &sha(good));
        let (ok, msg) = execute(&pb::Action { path: p, ..a }, &allowed, "/tmp", "localhost", &st);
        assert!(!ok && msg.contains("symbolic links"), "{msg}");
        assert!(!real.join("x.php").exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}
