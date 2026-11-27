//! Package E 5.2 (plan 2026-11-27): optional hardening on request – never by default, never automatically.
//!
//! Runs only with all three keys: enabled locally (`sudo tyrosecd actions enable harden` – not part of "enable all"),
//! allowed per server in the central server, and a person (admin) clicked "Apply" with preview and password.
//!
//! Fixed list of recipes, no free commands, no content from the central server: the agent builds the change itself.
//! Only files inside the web roots (first step: `wp-config.php`, `.htaccess` in `wp-content/uploads`), never web
//! server main configuration, php.ini or systemd. Every change:
//! 1. backup of the original (data directory, `harden/<action id>.json`),
//! 2. new content written via descriptors (temp file + rename, owner and mode kept),
//! 3. check: `php -l` of the new PHP file and/or HTTP request of the home page (and of an uploaded image) – same
//!    result as before,
//! 4. check failed → original restored immediately,
//! 5. "Undo" restores the backup – only if the file was not changed since.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::process::Command;

use sha2::{Digest, Sha256};
use tyrosd_proto as pb;

/// Recipes the agent knows (the central server can only pick one of them)
pub const RECIPES: &[&str] = &["wp_disallow_file_edit", "wp_uploads_noexec"];
const MAX_FILE: usize = 1 << 20;
const MARK_BEGIN: &str = "# BEGIN tyrosec harden (undo in the tyrosec control center)";
const MARK_END: &str = "# END tyrosec harden";
const WP_LINE: &str = "define( 'DISALLOW_FILE_EDIT', true ); // added by tyrosec (harden) – undo in the control center";

/// The change a recipe makes to the current content (None = file does not exist yet) → new content
pub fn change(recipe: &str, current: Option<&str>) -> Result<String, String> {
    match recipe {
        "wp_disallow_file_edit" => {
            let cur = current.ok_or("wp-config.php not found")?;
            if !cur.trim_start().starts_with("<?php") {
                return Err("wp-config.php does not start with <?php – not changed".into());
            }
            if cur.contains("DISALLOW_FILE_EDIT") || cur.contains("DISALLOW_FILE_MODS") {
                return Err("DISALLOW_FILE_EDIT/DISALLOW_FILE_MODS already appears in wp-config.php – please check manually".into());
            }
            // above "That's all, stop editing!", else above the line that loads wp-settings.php
            let lines: Vec<&str> = cur.split_inclusive('\n').collect();
            let at = lines
                .iter()
                .position(|l| l.contains("That's all, stop editing") || l.contains("That’s all, stop editing"))
                .or_else(|| lines.iter().position(|l| l.contains("wp-settings.php") && l.contains("require")))
                .ok_or("No suitable place found in wp-config.php (\"That's all, stop editing!\" or require wp-settings.php) – not changed")?;
            let mut out = String::with_capacity(cur.len() + WP_LINE.len() + 2);
            for (i, l) in lines.iter().enumerate() {
                if i == at {
                    out.push_str(WP_LINE);
                    out.push('\n');
                }
                out.push_str(l);
            }
            Ok(out)
        }
        "wp_uploads_noexec" => {
            let block = format!("{MARK_BEGIN}\n<FilesMatch \"\\.(php|php[0-9]|phtml|phar|pht)$\">\n  Require all denied\n</FilesMatch>\n{MARK_END}\n");
            match current {
                Some(c) if c.contains(MARK_BEGIN) => Err("tyrosec hardening is already present in this .htaccess".into()),
                Some(c) => Ok(if c.is_empty() || c.ends_with('\n') { format!("{c}{block}") } else { format!("{c}\n{block}") }),
                None => Ok(block),
            }
        }
        r => Err(format!("unknown hardening {r}")),
    }
}

/// Target file allowed for this recipe? (name, inside a web root)
fn target_ok(recipe: &str, resolved: &str, webroots: &[String]) -> Result<(), String> {
    let inside = webroots.iter().any(|w| resolved.starts_with(&format!("{}/", w.trim_end_matches('/'))));
    if !inside {
        return Err("File is not inside a web root – not changed".into());
    }
    let ok = match recipe {
        "wp_disallow_file_edit" => resolved.ends_with("/wp-config.php"),
        "wp_uploads_noexec" => resolved.ends_with("/wp-content/uploads/.htaccess"),
        _ => false,
    };
    ok.then_some(()).ok_or_else(|| "File does not match the hardening".into())
}

fn apache_serves() -> bool {
    let dirs = ["/etc/apache2", "/etc/httpd"].iter().any(|d| Path::new(d).is_dir());
    let running = std::fs::read_dir("/proc").map(|rd| {
        rd.flatten().take(5000).any(|e| std::fs::read_to_string(e.path().join("comm")).is_ok_and(|c| matches!(c.trim(), "apache2" | "httpd" | "litespeed" | "lshttpd")))
    });
    dirs && running.unwrap_or(false)
}

fn sha(b: &[u8]) -> String {
    Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

fn php_bin() -> Option<String> {
    for p in ["/usr/bin/php", "/usr/local/bin/php"] {
        if Path::new(p).is_file() {
            return Some(p.into());
        }
    }
    let mut v: Vec<String> = std::fs::read_dir("/usr/bin").ok()?.flatten().filter_map(|e| e.file_name().to_str().map(String::from)).filter(|n| n.starts_with("php") && n[3..].chars().all(|c| c.is_ascii_digit() || c == '.') && n.len() > 3).collect();
    v.sort();
    v.pop().map(|n| format!("/usr/bin/{n}"))
}

/// `php -l` of a file → Some(true/false), None = no PHP command line on the server
fn php_lint(path: &str) -> Option<bool> {
    let php = php_bin()?;
    Command::new(php).args(["-n", "-l", path]).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().ok().map(|s| s.success())
}

/// Home page of the website a file belongs to (domain from the web server configuration)
fn site_url(resolved: &str) -> Option<String> {
    let sites = tyrosd_source_weblog::docroots();
    let (_, names) = sites.iter().filter(|(r, n)| !n.is_empty() && resolved.starts_with(&format!("{}/", r.trim_end_matches('/')))).max_by_key(|(r, _)| r.len())?;
    let name = names.split(',').next()?.trim();
    (!name.is_empty()).then(|| format!("https://{name}/"))
}

/// Status of a GET request (None = not reachable)
fn http_status(url: &str) -> Option<u16> {
    tyrosd_check::wordpress::status_of(url)
}

/// An uploaded image (to check that uploads still work after the .htaccess change) → URL
fn sample_upload(uploads: &Path, home: &str) -> Option<String> {
    let mut stack = vec![uploads.to_path_buf()];
    let mut n = 0;
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).ok()?.flatten() {
            n += 1;
            if n > 2000 {
                return None;
            }
            let p = e.path();
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                stack.push(p);
            } else if p.extension().and_then(|x| x.to_str()).is_some_and(|x| matches!(x.to_ascii_lowercase().as_str(), "jpg" | "jpeg" | "png" | "gif" | "webp")) {
                let rel = p.strip_prefix(uploads).ok()?.to_string_lossy().into_owned();
                return Some(format!("{home}wp-content/uploads/{rel}"));
            }
        }
    }
    None
}

/// Write `content` to `name` in the folder (temp file + rename; owner/mode as given). Never follows symlinks.
fn write_file(dir: &OwnedFd, name: &str, content: &[u8], mode: u32, uid: u32, gid: u32) -> Result<(), String> {
    let tmp = std::ffi::CString::new(format!(".tyrosec-harden-{}", tyrosd_core::now_ns())).map_err(|_| "invalid name")?;
    let cname = std::ffi::CString::new(name).map_err(|_| "invalid name")?;
    // SAFETY: valid fd and C strings
    let raw = unsafe { libc::openat(dir.as_raw_fd(), tmp.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600 as libc::c_uint) };
    if raw < 0 {
        return Err(format!("Write failed: {}", std::io::Error::last_os_error()));
    }
    let mut f = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(raw) });
    let r = (|| -> Result<(), String> {
        f.write_all(content).map_err(|e| format!("Write failed: {e}"))?;
        // SAFETY: fd valid
        if unsafe { libc::fchown(f.as_raw_fd(), uid, gid) } != 0 || unsafe { libc::fchmod(f.as_raw_fd(), (mode & 0o777) as libc::mode_t) } != 0 {
            return Err(format!("Write failed (owner/permissions): {}", std::io::Error::last_os_error()));
        }
        f.sync_all().map_err(|e| format!("Write failed: {e}"))?;
        if unsafe { libc::renameat(dir.as_raw_fd(), tmp.as_ptr(), dir.as_raw_fd(), cname.as_ptr()) } != 0 {
            return Err(format!("Replace failed: {}", std::io::Error::last_os_error()));
        }
        Ok(())
    })();
    if r.is_err() {
        unsafe { libc::unlinkat(dir.as_raw_fd(), tmp.as_ptr(), 0) };
    }
    r
}

fn unlink(dir: &OwnedFd, name: &str) -> Result<(), String> {
    let cname = std::ffi::CString::new(name).map_err(|_| "invalid name")?;
    // SAFETY: valid fd and C string
    if unsafe { libc::unlinkat(dir.as_raw_fd(), cname.as_ptr(), 0) } != 0 {
        return Err(format!("Removal failed: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Current file: (content, mode, uid, gid) or None (does not exist). Regular files only, no symlinks.
fn read_current(dir: &OwnedFd, name: &str) -> Result<Option<(Vec<u8>, u32, u32, u32)>, String> {
    let cname = std::ffi::CString::new(name).map_err(|_| "invalid name")?;
    // SAFETY: valid fd and C string
    let raw = unsafe { libc::openat(dir.as_raw_fd(), cname.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if raw < 0 {
        return match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ENOENT) => Ok(None),
            Some(libc::ELOOP) => Err("Target is a symbolic link – not changed".into()),
            _ => Err(format!("Read failed: {}", std::io::Error::last_os_error())),
        };
    }
    let f = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(raw) });
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fd and pointer valid
    if unsafe { libc::fstat(f.as_raw_fd(), &mut st) } != 0 || st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err("Target is not a regular file".into());
    }
    let mut data = Vec::new();
    (&f).take(MAX_FILE as u64 + 1).read_to_end(&mut data).map_err(|e| format!("Read failed: {e}"))?;
    if data.len() > MAX_FILE {
        return Err("File too large – not changed".into());
    }
    Ok(Some((data, st.st_mode & 0o777, st.st_uid, st.st_gid)))
}

fn backup_path(data_dir: &str, id: u64) -> std::path::PathBuf {
    Path::new(data_dir).join("harden").join(format!("{id}.json"))
}

/// Apply a hardening (action `harden_apply`, params `{"recipe": …}`, path = target file)
pub fn apply(a: &pb::Action, data_dir: &str, webroots: &[String]) -> Result<String, String> {
    let p: serde_json::Value = serde_json::from_str(&a.params).unwrap_or_default();
    let recipe = p["recipe"].as_str().unwrap_or("");
    if !RECIPES.contains(&recipe) {
        return Err(format!("unknown hardening {recipe}"));
    }
    let (dir, name, resolved) = crate::actions::resolve_pub(&a.path)?;
    if resolved != a.path {
        return Err(format!("Path contains symbolic links (resolved: {resolved}) – not changed"));
    }
    target_ok(recipe, &resolved, webroots)?;
    if recipe == "wp_uploads_noexec" && !apache_serves() {
        return Err("No Apache/LiteSpeed running – a .htaccess has no effect here. For nginx use the snippet from the finding.".into());
    }
    let cur = read_current(&dir, &name)?;
    let cur_text = match &cur {
        Some((b, ..)) => Some(String::from_utf8(b.clone()).map_err(|_| "File is not valid UTF-8 – not changed".to_string())?),
        None => None,
    };
    let new = change(recipe, cur_text.as_deref())?;
    let (mode, uid, gid) = match &cur {
        Some((_, m, u, g)) => (*m & !0o002, *u, *g),
        None => {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: fd and pointer valid
            if unsafe { libc::fstat(dir.as_raw_fd(), &mut st) } != 0 {
                return Err("Folder not readable".into());
            }
            (0o644, st.st_uid, st.st_gid)
        }
    };
    // checks before: home page (and an uploaded image)
    let home = site_url(&resolved);
    let before_home = home.as_deref().and_then(http_status);
    let uploads = Path::new(&resolved).parent().map(|d| d.to_path_buf());
    let img = if recipe == "wp_uploads_noexec" { home.as_deref().and_then(|h| uploads.as_deref().and_then(|u| sample_upload(u, h))) } else { None };
    let before_img = img.as_deref().and_then(http_status);
    if recipe == "wp_uploads_noexec" && before_home.is_none() {
        return Err("The website could not be reached for the check before the change – not changed (without a check there is no automatic rollback)".into());
    }
    // backup first (durable), then change
    let bp = backup_path(data_dir, a.id);
    std::fs::create_dir_all(bp.parent().unwrap()).map_err(|e| e.to_string())?;
    let _ = std::fs::set_permissions(bp.parent().unwrap(), std::os::unix::fs::PermissionsExt::from_mode(0o700));
    let backup = serde_json::json!({
        "path": resolved, "recipe": recipe, "existed": cur.is_some(), "mode": mode, "uid": uid, "gid": gid,
        "original": cur_text, "after_sha256": sha(new.as_bytes()), "ts": tyrosd_core::now_ns() / 1_000_000_000,
    });
    {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&bp).map_err(|e| format!("Backup failed: {e}"))?;
        f.write_all(backup.to_string().as_bytes()).and_then(|_| f.sync_all()).map_err(|e| format!("Backup failed: {e}"))?;
    }
    write_file(&dir, &name, new.as_bytes(), mode, uid, gid)?;
    // checks after
    let mut problems = Vec::new();
    let mut checked = Vec::new();
    if resolved.ends_with(".php") {
        match php_lint(&resolved) {
            Some(true) => checked.push("php -l ok"),
            Some(false) => problems.push("php -l reports a syntax error".to_string()),
            None => {}
        }
    }
    if let (Some(url), Some(b)) = (home.as_deref(), before_home) {
        std::thread::sleep(std::time::Duration::from_secs(2));
        match http_status(url) {
            Some(s) if s / 100 == b / 100 && s < 500 => checked.push("home page unchanged"),
            s => problems.push(format!("home page answers {} instead of {b}", s.map(|x| x.to_string()).unwrap_or_else(|| "nothing".into()))),
        }
    }
    if let (Some(url), Some(200)) = (img.as_deref(), before_img) {
        match http_status(url) {
            Some(200) => checked.push("uploaded images still load"),
            s => problems.push(format!("uploaded image answers {} instead of 200", s.map(|x| x.to_string()).unwrap_or_else(|| "nothing".into()))),
        }
    }
    if checked.is_empty() && problems.is_empty() {
        problems.push("no check possible (no PHP command line, website not reachable)".into());
    }
    if !problems.is_empty() {
        let back = match &cur {
            Some((b, ..)) => write_file(&dir, &name, b, mode, uid, gid),
            None => unlink(&dir, &name),
        };
        let _ = std::fs::remove_file(&bp);
        return Err(match back {
            Ok(()) => format!("Check after the change failed ({}) – original restored, nothing changed", problems.join("; ")),
            Err(e) => format!("Check after the change failed ({}) and restoring failed: {e} – backup kept", problems.join("; ")),
        });
    }
    Ok(format!("Hardening {recipe} applied to {resolved} ({}) – backup #{}", checked.join(", "), a.id))
}

/// Undo a hardening (action `harden_undo`, params `{"of": <id of the apply action>}`)
pub fn undo(a: &pb::Action, data_dir: &str) -> Result<String, String> {
    let p: serde_json::Value = serde_json::from_str(&a.params).unwrap_or_default();
    let of = p["of"].as_u64().ok_or("missing reference to the hardening")?;
    let bp = backup_path(data_dir, of);
    let b: serde_json::Value = std::fs::read_to_string(&bp).ok().and_then(|s| serde_json::from_str(&s).ok()).ok_or("No backup for this hardening on the server")?;
    let path = b["path"].as_str().ok_or("backup damaged")?;
    let (dir, name, resolved) = crate::actions::resolve_pub(path)?;
    if resolved != path {
        return Err("Path contains symbolic links now – not changed".into());
    }
    let cur = read_current(&dir, &name)?;
    match &cur {
        Some((data, ..)) if sha(data) == b["after_sha256"].as_str().unwrap_or("") => {}
        Some(_) => return Err("The file was changed after the hardening – undo manually (the original is in the backup on the server)".into()),
        None => return Err("The file no longer exists – nothing to undo".into()),
    }
    let (mode, uid, gid) = (b["mode"].as_u64().unwrap_or(0o644) as u32, b["uid"].as_u64().unwrap_or(0) as u32, b["gid"].as_u64().unwrap_or(0) as u32);
    if b["existed"].as_bool() == Some(true) {
        let orig = b["original"].as_str().ok_or("backup damaged")?;
        write_file(&dir, &name, orig.as_bytes(), mode, uid, gid)?;
    } else {
        unlink(&dir, &name)?;
    }
    let _ = std::fs::rename(&bp, bp.with_extension("undone"));
    Ok(format!("Hardening undone: {path} is back to the state before #{of}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wp_config_change() {
        let cfg = "<?php\ndefine('DB_NAME', 'x');\n/* That's all, stop editing! Happy publishing. */\nrequire_once ABSPATH . 'wp-settings.php';\n";
        let n = change("wp_disallow_file_edit", Some(cfg)).unwrap();
        assert!(n.contains(&format!("{WP_LINE}\n/* That's all")));
        assert_eq!(n.replace(&format!("{WP_LINE}\n"), ""), cfg, "only one line added");
        // without the marker: above require wp-settings.php
        let n = change("wp_disallow_file_edit", Some("<?php\n$x=1;\nrequire_once(ABSPATH . 'wp-settings.php');\n")).unwrap();
        assert!(n.contains(&format!("{WP_LINE}\nrequire_once(")));
        assert!(change("wp_disallow_file_edit", Some("<?php\ndefine('DISALLOW_FILE_EDIT', false);\n/* That's all, stop editing! */")).is_err());
        assert!(change("wp_disallow_file_edit", Some("<?php\n$x=1;\n")).is_err(), "no place found");
        assert!(change("wp_disallow_file_edit", None).is_err());
    }

    #[test]
    fn uploads_htaccess_change() {
        let n = change("wp_uploads_noexec", None).unwrap();
        assert!(n.starts_with(MARK_BEGIN) && n.contains("Require all denied") && n.ends_with(&format!("{MARK_END}\n")));
        let n2 = change("wp_uploads_noexec", Some("Options -Indexes")).unwrap();
        assert!(n2.starts_with("Options -Indexes\n# BEGIN tyrosec"));
        assert!(change("wp_uploads_noexec", Some(&n)).is_err(), "not twice");
        assert!(change("rm_rf", None).is_err());
    }

    #[test]
    fn targets() {
        let roots = vec!["/var/www/site".to_string()];
        assert!(target_ok("wp_disallow_file_edit", "/var/www/site/wp-config.php", &roots).is_ok());
        assert!(target_ok("wp_disallow_file_edit", "/var/www/site/index.php", &roots).is_err());
        assert!(target_ok("wp_disallow_file_edit", "/etc/wp-config.php", &roots).is_err());
        assert!(target_ok("wp_uploads_noexec", "/var/www/site/wp-content/uploads/.htaccess", &roots).is_ok());
        assert!(target_ok("wp_uploads_noexec", "/var/www/site/.htaccess", &roots).is_err());
    }

    #[test]
    fn apply_and_undo_roundtrip_without_web_checks() {
        // the file-level flow: change, backup, undo (web/php checks are skipped when not available → apply refuses)
        let dir = std::env::temp_dir().join(format!("tyrosd-harden-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("www/wp-content/uploads")).unwrap();
        let roots = vec![dir.join("www").to_string_lossy().into_owned()];
        let target = dir.join("www/wp-content/uploads/.htaccess").to_string_lossy().into_owned();
        let a = pb::Action { id: 77, kind: "harden_apply".into(), path: target.clone(), params: r#"{"recipe":"wp_uploads_noexec"}"#.into(), ..Default::default() };
        let r = apply(&a, dir.to_str().unwrap(), &roots);
        // no Apache / no website in the test environment: refused before any change, nothing written
        assert!(r.is_err(), "{r:?}");
        assert!(!Path::new(&target).exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn failed_check_restores_original_and_undo_needs_unchanged_file() {
        let dir = std::env::temp_dir().join(format!("tyrosd-harden2-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("www")).unwrap();
        let roots = vec![dir.join("www").to_string_lossy().into_owned()];
        let cfg = dir.join("www/wp-config.php");
        let orig = "<?php\n$x = 1;\n/* That's all, stop editing! */\n";
        std::fs::write(&cfg, orig).unwrap();
        let path = cfg.to_string_lossy().into_owned();
        let a = pb::Action { id: 78, kind: "harden_apply".into(), path: path.clone(), params: r#"{"recipe":"wp_disallow_file_edit"}"#.into(), ..Default::default() };
        let dd = dir.to_string_lossy().into_owned();
        match apply(&a, &dd, &roots) {
            // test environment with a PHP command line: lint passes → applied; then undo brings back the original
            Ok(_) => {
                assert!(std::fs::read_to_string(&cfg).unwrap().contains("DISALLOW_FILE_EDIT"));
                let u = pb::Action { id: 79, kind: "harden_undo".into(), params: r#"{"of":78}"#.into(), ..Default::default() };
                undo(&u, &dd).unwrap();
                assert_eq!(std::fs::read_to_string(&cfg).unwrap(), orig);
            }
            // no PHP, no website: no check possible → original restored, backup removed
            Err(e) => {
                assert!(e.contains("original restored"), "{e}");
                assert_eq!(std::fs::read_to_string(&cfg).unwrap(), orig);
                assert!(!backup_path(&dd, 78).exists());
            }
        }
        // undo refuses when the file was changed after the hardening
        let changed = change("wp_disallow_file_edit", Some(orig)).unwrap();
        std::fs::create_dir_all(dir.join("harden")).unwrap();
        std::fs::write(backup_path(&dd, 80), serde_json::json!({ "path": path, "existed": true, "mode": 0o644, "uid": 0, "gid": 0, "original": orig, "after_sha256": sha(changed.as_bytes()) }).to_string()).unwrap();
        std::fs::write(&cfg, format!("{changed}// edited later\n")).unwrap();
        let u = pb::Action { id: 81, kind: "harden_undo".into(), params: r#"{"of":80}"#.into(), ..Default::default() };
        assert!(undo(&u, &dd).unwrap_err().contains("changed after"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
