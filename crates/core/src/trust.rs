//! Shared "known benign" context for all process and command rules (false-positive early detection plan, F1).
//! Instead of separate exception lists per rule, detection (detect) and check ask the same functions –
//! so legitimate software (package management, a mounted AppImage) does not trigger several rules one after another.
//!
//! Security review H4: trust is never granted by name alone (every process sets `comm` itself, a
//! symlink `/tmp/dpkg → /bin/bash` is called "dpkg"). A package management process only counts if
//! - the name is **exactly** in the list (comm is truncated to 15 characters: "unattended-upgr", "update-initramf"),
//! - the process runs as root,
//! - `/proc/<pid>/exe` is a root-owned file, not writable by group/others, under /usr/bin, /usr/sbin,
//!   /bin, /sbin, /usr/lib, /usr/libexec or /usr/share,
//! - and the program name matches the file – for scripts (dracut, update-initramfs, unattended-upgrade …)
//!   `exe` is the interpreter; then the script (first argument) must itself be such a system file with a matching
//!   name.

use std::os::unix::fs::MetadataExt;

/// Package management/installers: whatever they start is part of an update (e.g. apt-key → base64 -d).
/// Exact comm names (max. 15 characters). The agent itself is deliberately no longer listed here – `own_descendant`
/// applies to it.
pub const INSTALLERS: &[&str] = &["dpkg", "apt", "apt-get", "apt-key", "unattended-upgr", "rpm", "dnf", "dnf5", "yum", "snapd", "packagekitd", "needrestart", "apt-check", "update-notifier",
    "update-initramf", "mkinitramfs", "dracut", "dracut-install", "mkdumprd", "kdumpctl", "mkinitcpio", "dpkg-trigger", "dpkg-deb", "dpkg-preconfigu", "debconf", "zypper", "apk", "pacman"];

/// Package managers in the narrow sense (file changes count as a package update, note "pkg")
pub const PACKAGE_MANAGERS: &[&str] =
    &["dpkg", "apt", "apt-get", "unattended-upgr", "rpm", "dnf", "dnf5", "yum", "apk", "pacman", "zypper", "packagekitd",
      // initramfs build (kernel updates, kdump at boot; test run on Rocky 9): writes copies of system programs to /var/tmp
      "dracut", "dracut-install", "mkdumprd", "kdumpctl", "mkinitramfs", "update-initramf", "mkinitcpio"];

/// Directories trusted package programs come from
const TRUSTED_DIRS: &[&str] = &["/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/libexec/", "/usr/share/"];

fn base(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// comm (max. 15 characters) matches the file name
fn comm_matches(comm: &str, file: &str) -> bool {
    let b = base(file).as_bytes();
    comm.as_bytes() == b || (b.len() > 15 && comm.as_bytes() == &b[..15])
}

fn is_interpreter(file: &str) -> bool {
    let b = base(file);
    matches!(b, "sh" | "bash" | "dash") || b.starts_with("python") || b.starts_with("perl")
}

/// Root-owned regular file, not writable by group/others, in a system directory (path without symlinks)
pub fn trusted_file(path: &str) -> bool {
    if path.ends_with(" (deleted)") || path.contains("/../") || path.contains("/./") || !TRUSTED_DIRS.iter().any(|d| path.starts_with(d)) {
        return false;
    }
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0)
}

/// effective UID of a process (from /proc/<pid>/status)
pub fn proc_euid(pid: i32) -> Option<u32> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    s.lines().find_map(|l| l.strip_prefix("Uid:")).and_then(|l| l.split_whitespace().nth(1)).and_then(|u| u.parse().ok())
}

/// Environment variables through which foreign code gets into an (otherwise verified) program – preloading libraries,
/// search paths for modules/libraries, interpreter startup options, shell startup scripts
/// (`LD_PRELOAD=/tmp/x.so dpkg …` would otherwise have counted as package management).
/// Variables whose content is **code** (interpreter options, startup scripts, shell options): non-empty → no trust
const CODE_ENV: &[&str] = &["PYTHONSTARTUP", "PYTHONINSPECT", "PERL5OPT", "PERL5DB", "RUBYOPT", "NODE_OPTIONS", "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"];

/// Variables with **path lists** (search paths, preloaded libraries): harmless if every entry is an absolute,
/// existing path that, including all parent directories, is owned by root and not writable by group/others
/// (e.g. an Oracle client with `LD_LIBRARY_PATH=/usr/lib/oracle/…` in /etc/environment – otherwise false alarms on
/// every update). (name, separators) – ld.so also splits LD_PRELOAD/LD_AUDIT on spaces.
const PATH_ENV: &[(&str, &[char])] = &[
    ("LD_PRELOAD", &[':', ' ']), ("LD_AUDIT", &[':', ' ']), ("LD_LIBRARY_PATH", &[':']), ("GCONV_PATH", &[':']), ("PYTHONPATH", &[':']),
    ("PYTHONHOME", &[':']), ("PERL5LIB", &[':']), ("PERLLIB", &[':']), ("RUBYLIB", &[':']), ("NODE_PATH", &[':']),
];

/// Path and all parent directories up to / are owned by root; directories/files not writable by group/others
/// (symlinks: owner only – their permissions are meaningless)
fn root_chain(p: &std::path::Path) -> bool {
    p.ancestors().all(|a| {
        std::fs::symlink_metadata(a).is_ok_and(|m| m.uid() == 0 && (m.file_type().is_symlink() || m.mode() & 0o022 == 0))
    })
}

/// A path list entry is harmless: absolute, exists, and both the given path (not followed) and the resolved
/// target, including their parent directories, lie in root-owned directories not writable by others.
/// Empty (= current directory) or relative → not harmless.
pub fn safe_path_entry(e: &str) -> bool {
    if !e.starts_with('/') || e.split('/').any(|c| c == "..") {
        return false;
    }
    let p = std::path::Path::new(e);
    let Ok(real) = std::fs::canonicalize(p) else { return false };
    root_chain(p) && root_chain(&real)
}

/// First suspicious variable in an environment (`/proc/<pid>/environ`, NUL-separated) – empty values do not count.
/// Exported bash functions (`BASH_FUNC_name%%`) override commands in scripts and always count.
pub fn unsafe_env(environ: &[u8]) -> Option<String> {
    unsafe_env_with(environ, &safe_path_entry)
}

fn unsafe_env_with(environ: &[u8], path_ok: &dyn Fn(&str) -> bool) -> Option<String> {
    environ.split(|b| *b == 0).find_map(|kv| {
        let i = kv.iter().position(|b| *b == b'=')?;
        let (k, v) = (&kv[..i], &kv[i + 1..]);
        let k = String::from_utf8_lossy(k);
        let bad = if k.starts_with("BASH_FUNC_") {
            true
        } else if v.is_empty() {
            false
        } else if CODE_ENV.contains(&k.as_ref()) {
            true
        } else if let Some((_, seps)) = PATH_ENV.iter().find(|(n, _)| *n == k) {
            // every entry must be harmless; empty entries ("a::b", ":a") = current directory
            match std::str::from_utf8(v) {
                Ok(s) => s.split(|c| seps.contains(&c)).any(|e| !path_ok(e)),
                Err(_) => true,
            }
        } else {
            false
        };
        bad.then(|| k.into_owned())
    })
}

/// Shebang line `#!/path [argument]` → (interpreter, optional argument as the kernel passes it: rest of the line)
fn parse_shebang(line: &str) -> Option<(String, Option<String>)> {
    let rest = line.strip_prefix("#!")?.trim_matches(|c: char| c == ' ' || c == '\t' || c == '\r');
    let (interp, arg) = match rest.find([' ', '\t']) {
        Some(i) => (&rest[..i], Some(rest[i..].trim_matches([' ', '\t']).to_string()).filter(|a| !a.is_empty())),
        None => (rest, None),
    };
    (!interp.is_empty()).then(|| (interp.to_string(), arg))
}

/// Index of the script in an interpreter's command line – **only in shebang form**:
/// `[interp, script, …]` or `[interp, <exactly the argument from the script's shebang line>, script, …]`.
/// This way `python3 -c …`, `python3 -mmodule script`, `perl -e …`, `sh -c …` never count as the script.
/// `first_line(arg)` returns the file's first line (or None), `canon(path)` the resolved path.
/// The shebang line's interpreter must be the running program `exe` (`/usr/bin/env name` → `name*`).
fn shebang_index(args: &[String], exe: &str, first_line: &dyn Fn(&str) -> Option<String>, canon: &dyn Fn(&str) -> Option<String>) -> Option<usize> {
    let (idx, flag) = match args.get(1) {
        Some(a) if !a.is_empty() && !a.starts_with('-') => (1, None),
        Some(a) if a.starts_with('-') && args.get(2).is_some_and(|s| !s.is_empty() && !s.starts_with('-')) => (2, Some(a.as_str())),
        _ => return None,
    };
    let (interp, sarg) = parse_shebang(&first_line(&args[idx])?)?;
    let via_env = base(&interp) == "env";
    if let Some(f) = flag {
        // an option before the script only if it comes verbatim from the shebang line (not with env: there the
        // argument is the program name)
        if via_env || sarg.as_deref() != Some(f) {
            return None;
        }
    }
    let matches = if via_env {
        sarg.as_deref().is_some_and(|name| !name.contains(['/', ' ']) && !name.starts_with('-') && base(exe).starts_with(name))
    } else {
        canon(&interp).as_deref() == Some(exe)
    };
    matches.then_some(idx)
}

/// Is `pid` with the name `comm` really a package program of the system? (see module description)
pub fn verified_program(pid: i32, comm: &str) -> bool {
    if proc_euid(pid) != Some(0) {
        return false;
    }
    let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe")) else { return false };
    let exe = exe.to_string_lossy().into_owned();
    if !trusted_file(&exe) {
        return false;
    }
    // the file actually executed (not just the name behind it) must also be owned by root
    if !std::fs::metadata(format!("/proc/{pid}/exe")).is_ok_and(|m| m.uid() == 0 && m.mode() & 0o022 == 0) {
        return false;
    }
    // no preloaded libraries, foreign module paths or interpreter options from the environment
    // (not readable → no trust)
    match std::fs::read(format!("/proc/{pid}/environ")) {
        Ok(env) if unsafe_env(&env).is_none() => {}
        _ => return false,
    }
    if comm_matches(comm, &exe) {
        return true;
    }
    if !is_interpreter(&exe) {
        return false;
    }
    // script in shebang form: the script itself must be a system file with a matching name
    let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else { return false };
    let args: Vec<String> = cmdline.split(|b| *b == 0).map(|a| String::from_utf8_lossy(a).into_owned()).collect();
    let resolve = |a: &str| -> Option<String> {
        let full = if a.starts_with('/') { std::path::PathBuf::from(a) } else { std::path::Path::new(&format!("/proc/{pid}/cwd")).join(a) };
        std::fs::canonicalize(full).ok().map(|p| p.to_string_lossy().into_owned())
    };
    let first_line = |a: &str| -> Option<String> {
        let real = resolve(a)?;
        if !trusted_file(&real) {
            return None;
        }
        let mut buf = [0u8; 256];
        let n = std::io::Read::read(&mut std::fs::File::open(&real).ok()?, &mut buf).ok()?;
        let line = buf[..n].split(|b| *b == b'\n').next()?;
        Some(String::from_utf8_lossy(line).into_owned())
    };
    let canon = |p: &str| std::fs::canonicalize(p).ok().map(|p| p.to_string_lossy().into_owned());
    let Some(i) = shebang_index(&args, &exe, &first_line, &canon) else { return false };
    let Some(real) = resolve(&args[i]) else { return false };
    trusted_file(&real) && comm_matches(comm, &real)
}

/// The process or an ancestor (up to `depth`) is a verified program from `names`
pub fn verified_ancestor(pid: i32, depth: usize, names: &[&str]) -> bool {
    let mut cur = pid;
    for _ in 0..depth {
        let Some(c) = std::fs::read_to_string(format!("/proc/{cur}/comm")).ok().map(|s| s.trim_end().to_string()) else { return false };
        if names.contains(&c.as_str()) && verified_program(cur, &c) {
            return true;
        }
        match crate::procinfo::ppid(cur) {
            Some(p) if p > 1 => cur = p,
            _ => return false,
        }
    }
    false
}

/// Does the process run under (verified) package management?
pub fn installer_ancestor(pid: i32, depth: usize) -> bool {
    verified_ancestor(pid, depth, INSTALLERS)
}

/// The process is the agent itself or was started by it (nft, journalctl, dpkg --verify …)
pub fn own_descendant(pid: i32, depth: usize) -> bool {
    let me = std::process::id() as i32;
    let mut cur = pid;
    for _ in 0..depth {
        if cur == me {
            return true;
        }
        match crate::procinfo::ppid(cur) {
            Some(p) if p > 1 => cur = p,
            _ => return false,
        }
    }
    false
}

/// Mount point of an AppImage for the path (`/tmp/.mount_XXXX`), if the path lies inside it
fn appimage_root(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/tmp/.mount_")?;
    let end = rest.find('/').map(|i| i + "/tmp/.mount_".len()).unwrap_or(path.len());
    Some(&path[..end])
}

/// The path lies in a really mounted AppImage (FUSE mount under /tmp/.mount_*).
/// The name alone is not enough – otherwise an attacker could simply name a directory that way. In addition the mount
/// must be owned by root or by the same user as the process (`proc_uid`; without a known process only root mounts).
/// Service accounts are allowed (Collabora in Nextcloud runs as www-data) – anyone with www-data rights can start
/// directly from the webroot anyway; there is no network/mining exception for AppImages.
pub fn appimage_with(path: &str, mounts: &str, proc_uid: Option<u32>) -> bool {
    let Some(root) = appimage_root(path) else { return false };
    mounts.lines().any(|l| {
        let mut f = l.split_whitespace();
        let (_, mp, fs, opts) = (f.next(), f.next(), f.next().unwrap_or(""), f.next().unwrap_or(""));
        if mp != Some(root) || !fs.starts_with("fuse") {
            return false;
        }
        let owner = opts.split(',').find_map(|o| o.strip_prefix("user_id=")).and_then(|u| u.parse::<u32>().ok());
        match owner {
            Some(0) => true,
            Some(u) => proc_uid == Some(u),
            None => false,
        }
    })
}

/// Mounted AppImage; the user of process `pid` (if known) matches the mount
pub fn appimage_for(path: &str, pid: Option<i32>) -> bool {
    if !path.starts_with("/tmp/.mount_") {
        return false;
    }
    let uid = pid.and_then(|p| std::fs::metadata(format!("/proc/{p}")).ok()).map(|m| m.uid());
    appimage_with(path, &mounts_of(pid), uid)
}

/// Mounts as seen by the process: services with PrivateTmp (e.g. Apache → Collabora) have their own
/// mount namespace; their AppImage mount is not in the agent's /proc/mounts (real case on a server).
fn mounts_of(pid: Option<i32>) -> String {
    pid.and_then(|p| std::fs::read_to_string(format!("/proc/{p}/mounts")).ok())
        .unwrap_or_else(|| std::fs::read_to_string("/proc/mounts").unwrap_or_default())
}

/// Command line without paths of mounted AppImages (so patterns like "/tmp/.x" do not match them)
pub fn strip_appimages(cmdline: &str, pid: Option<i32>) -> String {
    if !cmdline.contains("/tmp/.mount_") {
        return cmdline.to_string();
    }
    let mounts = mounts_of(pid);
    let uid = pid.and_then(|p| std::fs::metadata(format!("/proc/{p}")).ok()).map(|m| m.uid());
    strip_appimages_with(cmdline, &mounts, uid)
}

pub fn strip_appimages_with(cmdline: &str, mounts: &str, proc_uid: Option<u32>) -> String {
    let mut out = cmdline.to_string();
    let mut from = 0;
    while let Some(i) = out[from..].find("/tmp/.mount_").map(|i| i + from) {
        let end = out[i..].find(|c: char| c.is_whitespace() || c == '=' || c == ':').map(|e| i + e).unwrap_or(out.len());
        let tok = out[i..end].to_string();
        if appimage_with(&tok, mounts, proc_uid) {
            let root = appimage_root(&tok).unwrap().to_string();
            out.replace_range(i..i + root.len(), "/appimage");
            from = i + "/appimage".len();
        } else {
            from = i + 1;
        }
    }
    out
}

/// Reason why a process counts as known benign – or None. Only package management (verified via the program);
/// deliberately not AppImages – there is no AppImage exception for network/mining rules.
pub fn benign(pid: i32) -> Option<&'static str> {
    if installer_ancestor(pid, 16) {
        return Some("runs under package management");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOUNTS: &str = "/dev/md2 / ext4 rw 0 0\nCollabora /tmp/.mount_CollabjIprLa fuse.Collabora ro,nosuid,user_id=0,group_id=0 0 0\n\
        App /tmp/.mount_UserApp fuse.App ro,nosuid,user_id=1000,group_id=1000 0 0\nWww /tmp/.mount_WwwApp fuse.App ro,user_id=33,group_id=33 0 0\n";

    #[test]
    fn appimage_needs_real_fuse_mount() {
        assert!(appimage_with("/tmp/.mount_CollabjIprLa/usr/bin/coolwsd", MOUNTS, None));
        assert!(!appimage_with("/tmp/.mount_Fake123/usr/bin/x", MOUNTS, None)); // only the name → suspicious stays suspicious
        assert!(!appimage_with("/tmp/.x/kworker", MOUNTS, None));
        assert!(!appimage_with("/tmp/.mount_CollabjIprLaX/evil", MOUNTS, None)); // similar name, different directory
    }

    #[test]
    fn appimage_owner_must_fit() {
        // user mount only for the same user
        assert!(appimage_with("/tmp/.mount_UserApp/bin/x", MOUNTS, Some(1000)));
        assert!(!appimage_with("/tmp/.mount_UserApp/bin/x", MOUNTS, Some(1001)));
        assert!(!appimage_with("/tmp/.mount_UserApp/bin/x", MOUNTS, None));
        // service account (www-data, UID 33) cannot disguise itself
        assert!(appimage_with("/tmp/.mount_WwwApp/bin/x", MOUNTS, Some(33))); // Collabora as www-data
        assert!(!appimage_with("/tmp/.mount_WwwApp/bin/x", MOUNTS, Some(1000))); // different user
    }

    #[test]
    fn strip_only_mounted() {
        let c = "coolwsd --config-file=/tmp/.mount_CollabjIprLa/etc/coolwsd/coolwsd.xml --x=/tmp/.mount_Fake/a";
        assert_eq!(strip_appimages_with(c, MOUNTS, None), "coolwsd --config-file=/appimage/etc/coolwsd/coolwsd.xml --x=/tmp/.mount_Fake/a");
    }

    #[test]
    fn names_are_exact() {
        assert!(comm_matches("dpkg", "/usr/bin/dpkg"));
        assert!(!comm_matches("dpkg", "/usr/bin/dpkg-evil"));
        assert!(comm_matches("unattended-upgr", "/usr/bin/unattended-upgrade"));
        assert!(comm_matches("update-initramf", "/usr/sbin/update-initramfs"));
        assert!(!comm_matches("apt", "/usr/bin/apt-get"));
        assert!(!INSTALLERS.contains(&"tyrosecd"));
        assert!(!INSTALLERS.iter().any(|n| n.len() > 15), "comm is at most 15 characters long");
    }

    #[test]
    fn trusted_files_only_in_system_dirs() {
        assert!(!trusted_file("/tmp/dpkg"));
        assert!(!trusted_file("/usr/bin/../../tmp/dpkg"));
        assert!(!trusted_file("/usr/bin/dpkg (deleted)"));
        assert!(!trusted_file("/home/a/usr/bin/dpkg"));
        // /bin/sh exists on every test system (root-owned)
        let sh = std::fs::canonicalize("/bin/sh").unwrap().to_string_lossy().into_owned();
        if std::fs::metadata(&sh).map(|m| m.uid() == 0).unwrap_or(false) {
            assert!(trusted_file(&sh), "{sh}");
        }
    }

    #[test]
    fn renamed_shell_is_not_a_package_manager() {
        // symlink "dpkg" → /bin/sh: comm is dpkg, but the program is the shell and the argument is not a system script
        let d = tempfile::tempdir().unwrap();
        let link = d.path().join("dpkg");
        std::os::unix::fs::symlink("/bin/sh", &link).unwrap();
        let mut child = std::process::Command::new(&link).args(["-c", "sleep 5; true"]).spawn().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));
        let pid = child.id() as i32;
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
        assert_eq!(comm.trim(), "dpkg");
        assert!(!verified_program(pid, "dpkg"));
        assert!(!installer_ancestor(pid, 4));
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn dangerous_environment() {
        assert_eq!(unsafe_env(b"PATH=/usr/bin\0LANG=C\0DEBIAN_FRONTEND=noninteractive\0"), None);
        for v in ["LD_PRELOAD=/tmp/x.so", "LD_LIBRARY_PATH=/tmp", "LD_AUDIT=/tmp/a.so", "PYTHONPATH=/tmp", "PYTHONSTARTUP=/tmp/s.py", "PERL5LIB=/tmp",
            "PERL5OPT=-Mevil", "RUBYOPT=-revil", "RUBYLIB=/tmp", "NODE_OPTIONS=--require /tmp/x.js", "BASH_ENV=/tmp/x", "ENV=/tmp/x", "GCONV_PATH=/tmp",
            "BASH_FUNC_dpkg%%=() { evil; }", "SHELLOPTS=xtrace"] {
            let e = format!("PATH=/usr/bin\0{v}\0HOME=/root\0");
            assert!(unsafe_env(e.as_bytes()).is_some(), "{v}");
        }
        // set to empty is harmless; similar names do not count
        assert_eq!(unsafe_env(b"LD_PRELOAD=\0MY_ENV=1\0ENVIRONMENT=prod\0"), None);
    }

    #[test]
    fn path_lists_in_root_dirs_are_ok() {
        // root-owned system directories (exist on every test system) → harmless
        let usr_lib = std::fs::canonicalize("/usr/lib").unwrap().to_string_lossy().into_owned();
        if !root_chain(std::path::Path::new(&usr_lib)) {
            return; // unusual test system
        }
        assert!(safe_path_entry(&usr_lib));
        assert!(safe_path_entry("/usr/lib")); // also via a symlinked parent directory (/lib → usr/lib with merged-usr)
        for v in [format!("LD_LIBRARY_PATH={usr_lib}:/usr"), format!("PYTHONPATH={usr_lib}"), format!("PERL5LIB=/usr:{usr_lib}"),
            "PYTHONHOME=/usr:/usr".to_string(), "NODE_PATH=/usr/lib".to_string()] {
            assert_eq!(unsafe_env(format!("PATH=/usr/bin\0{v}\0").as_bytes()), None, "{v}");
        }
        // preloaded library from a root-owned directory (a file that surely exists), also separated by spaces
        let sh = std::fs::canonicalize("/bin/sh").unwrap().to_string_lossy().into_owned();
        if root_chain(std::path::Path::new(&sh)) {
            assert_eq!(unsafe_env(format!("LD_PRELOAD={sh} {sh}:{sh}\0").as_bytes()), None);
        }
        // /tmp (writable by everyone), relative, empty (= current directory), nonexistent, ".."
        for e in ["/tmp", "lib", "./lib", "", "/nonexistent/lib", "/usr/../tmp"] {
            assert!(!safe_path_entry(e), "{e:?}");
        }
        for v in ["LD_LIBRARY_PATH=/usr/lib:/tmp", "LD_LIBRARY_PATH=/usr/lib:", "LD_LIBRARY_PATH=:/usr/lib", "LD_LIBRARY_PATH=/usr/lib::/usr",
            "PYTHONPATH=lib", "LD_PRELOAD=/tmp/x.so"] {
            assert!(unsafe_env(format!("{v}\0").as_bytes()).is_some(), "{v}");
        }
        // directory in /tmp and symlink to /tmp → not harmless
        let d = tempfile::tempdir().unwrap();
        assert!(!safe_path_entry(&d.path().to_string_lossy()));
        let link = d.path().join("lib");
        std::os::unix::fs::symlink("/tmp", &link).unwrap();
        assert!(!safe_path_entry(&link.to_string_lossy()));
        // code variables stay strict, even with "harmless" content
        for v in ["PYTHONSTARTUP=/usr/lib", "PERL5OPT=-w", "RUBYOPT=-W0", "NODE_OPTIONS=--max-old-space-size=100", "BASH_ENV=/usr/lib", "ENV=/usr/lib",
            "SHELLOPTS=braceexpand", "BASHOPTS=checkwinsize", "PYTHONINSPECT=1", "PERL5DB=x"] {
            assert!(unsafe_env(format!("{v}\0").as_bytes()).is_some(), "{v}");
        }
        // the check function is asked per entry
        assert_eq!(unsafe_env_with(b"LD_LIBRARY_PATH=/a:/b\0", &|e: &str| e == "/a" || e == "/b"), None);
        assert!(unsafe_env_with(b"LD_LIBRARY_PATH=/a:/c\0", &|e: &str| e == "/a" || e == "/b").is_some());
    }

    #[test]
    fn shebang_form_only() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let lines = |p: &str| -> Option<String> {
            match p {
                "/usr/bin/unattended-upgrade" => Some("#!/usr/bin/python3".into()),
                "/usr/bin/dnf" => Some("#!/usr/bin/python3 -s".into()),
                "/usr/bin/dracut" => Some("#!/bin/bash -p".into()),
                "/usr/sbin/update-initramfs" => Some("#!/bin/sh".into()),
                "/usr/bin/apt-check" => Some("#!/usr/bin/env python3".into()),
                "/usr/bin/plain" => Some("no shebang".into()),
                _ => None,
            }
        };
        let canon = |p: &str| -> Option<String> {
            Some(match p {
                "/usr/bin/python3" => "/usr/bin/python3.12".into(),
                "/bin/bash" => "/usr/bin/bash".into(),
                "/bin/sh" => "/usr/bin/dash".into(),
                o => o.to_string(),
            })
        };
        let py = "/usr/bin/python3.12";
        assert_eq!(shebang_index(&a(&["/usr/bin/python3", "/usr/bin/unattended-upgrade", "--dry-run"]), py, &lines, &canon), Some(1));
        assert_eq!(shebang_index(&a(&["/usr/bin/python3", "-s", "/usr/bin/dnf", "upgrade"]), py, &lines, &canon), Some(2));
        assert_eq!(shebang_index(&a(&["/bin/bash", "-p", "/usr/bin/dracut", "-f"]), "/usr/bin/bash", &lines, &canon), Some(2));
        assert_eq!(shebang_index(&a(&["/bin/sh", "/usr/sbin/update-initramfs", "-u"]), "/usr/bin/dash", &lines, &canon), Some(1));
        assert_eq!(shebang_index(&a(&["python3", "/usr/bin/apt-check"]), py, &lines, &canon), Some(1));
        // inline code and foreign options before the script
        assert_eq!(shebang_index(&a(&["python3", "-c", "import os", "/usr/bin/unattended-upgrade"]), py, &lines, &canon), None);
        assert_eq!(shebang_index(&a(&["python3", "-mevil", "/usr/bin/unattended-upgrade"]), py, &lines, &canon), None);
        assert_eq!(shebang_index(&a(&["python3", "-s", "/usr/bin/unattended-upgrade"]), py, &lines, &canon), None); // -s is not in its shebang
        assert_eq!(shebang_index(&a(&["perl", "-e", "system('x')", "/usr/sbin/needrestart"]), "/usr/bin/perl", &lines, &canon), None);
        assert_eq!(shebang_index(&a(&["sh", "-c", "evil", "/usr/sbin/update-initramfs"]), "/usr/bin/dash", &lines, &canon), None);
        assert_eq!(shebang_index(&a(&["sh", "-c", "/usr/sbin/update-initramfs"]), "/usr/bin/dash", &lines, &canon), None);
        assert_eq!(shebang_index(&a(&["python3"]), py, &lines, &canon), None);
        // script without shebang, or written for a different interpreter
        assert_eq!(shebang_index(&a(&["sh", "/usr/bin/plain"]), "/usr/bin/dash", &lines, &canon), None);
        assert_eq!(shebang_index(&a(&["/bin/bash", "/usr/bin/unattended-upgrade"]), "/usr/bin/bash", &lines, &canon), None);
        assert_eq!(shebang_index(&a(&["perl", "/usr/bin/apt-check"]), "/usr/bin/perl", &lines, &canon), None);
        assert_eq!(parse_shebang("#! /usr/bin/perl -w \r"), Some(("/usr/bin/perl".into(), Some("-w".into()))));
        assert_eq!(parse_shebang("#!/usr/bin/env -S python3 -E"), Some(("/usr/bin/env".into(), Some("-S python3 -E".into()))));
    }

    #[test]
    fn preloaded_program_is_not_trusted() {
        // only meaningful as root (verified_program requires euid 0)
        if proc_euid(std::process::id() as i32) != Some(0) {
            return;
        }
        let Ok(sleep) = std::fs::canonicalize("/bin/sleep") else { return };
        if !trusted_file(&sleep.to_string_lossy()) {
            return;
        }
        let mut plain = std::process::Command::new(&sleep).arg("5").env_clear().env("PATH", "/usr/bin:/bin").spawn().unwrap();
        let mut pre = std::process::Command::new(&sleep).arg("5").env_clear().env("LD_PRELOAD", "/nonexistent/x.so").spawn().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(verified_program(plain.id() as i32, "sleep"));
        assert!(!verified_program(pre.id() as i32, "sleep"));
        for c in [&mut plain, &mut pre] {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    #[test]
    fn own_children_are_known() {
        let mut child = std::process::Command::new("sleep").arg("5").spawn().unwrap();
        assert!(own_descendant(child.id() as i32, 4));
        assert!(own_descendant(std::process::id() as i32, 1));
        let _ = child.kill();
        let _ = child.wait();
        assert!(!own_descendant(1, 4));
    }
}
