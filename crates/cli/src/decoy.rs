//! Decoy credentials.
//!
//! The central server sends only **values** (user, password, secret address) – the agent builds the file content
//! itself from fixed templates. A compromised central server therefore cannot write code (e.g. PHP) into a webroot:
//! - only **new** files (O_CREAT|O_EXCL|O_NOFOLLOW), never overwrite,
//! - only in detected webroots, never in system areas (same block list as restore),
//! - file name as specified, never with executable extensions (.php, .phtml, .phar, .cgi, .sh, .htaccess …) – not
//!   even as an intermediate extension ("x.php.bak" would be executed by Apache with AddHandler),
//! - values strictly validated (user/password letters/digits only, address only https?://host/path), at most 4 KB,
//! - mode 0640, owner same as the folder; removal only for files the agent itself created as decoys.
//!
//! Detection: opening the file (fanotify, `DecoyWatch`), request to the secret address (access log, `source-weblog`),
//! SSH login attempt with the decoy user (the central server matches logins).
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tyrosd_proto as pb;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Service {
    /// ssh | web | postgresql | mysql
    #[serde(rename = "type")]
    pub kind: String,
    /// web: wordpress | shopware | generic
    #[serde(default)]
    pub flavor: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub url: String,
    pub user: String,
    pub password: String,
    /// Database: port and name (phase 2)
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub db: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PlaceParams {
    pub id: u64,
    /// env | txt
    pub format: String,
    pub services: Vec<Service>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Entry {
    pub id: u64,
    pub path: String,
    pub sha256: String,
    /// secret addresses (path part) for access-log detection
    #[serde(default)]
    pub url_paths: Vec<String>,
}

const MAX_SIZE: usize = 4096;
const MAX_DECOYS: usize = 50;
/// Extensions/name parts that a web server could execute or read as configuration – never in the file name
const FORBIDDEN_PARTS: &[&str] = &[
    "php", "phtml", "phar", "php3", "php4", "php5", "php7", "php8", "pht", "phps", "cgi", "pl", "py", "sh", "bash", "rb", "js", "mjs", "html",
    "htm", "shtml", "xhtml", "asp", "aspx", "jsp", "jspx", "svg", "htaccess", "htpasswd", "user", "ini", "so", "exe",
];
/// allowed last extensions (backup/note files)
const ALLOWED_ENDINGS: &[&str] = &["bak", "old", "backup", "txt", "save", "orig", "copy", "env"];

static WATCH: OnceLock<Arc<tyrosd_source_fanotify::decoy::DecoyWatch>> = OnceLock::new();
static REGISTRY_LOCK: Mutex<()> = Mutex::new(());

fn registry_path(data_dir: &str) -> String {
    format!("{}/decoys.json", data_dir.trim_end_matches('/'))
}

pub fn load(data_dir: &str) -> Vec<Entry> {
    std::fs::read_to_string(registry_path(data_dir)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn save(data_dir: &str, list: &[Entry]) -> Result<(), String> {
    let p = registry_path(data_dir);
    let tmp = format!("{p}.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(list).unwrap_or_default()).map_err(|e| format!("Decoy registry: {e}"))?;
    std::fs::rename(&tmp, &p).map_err(|e| format!("Decoy registry: {e}"))
}

/// Bring detection up to date: secret addresses/file names to the access-log analysis, watch files
pub fn apply(data_dir: &str) {
    let list = load(data_dir);
    let mut web = Vec::new();
    for e in &list {
        let file_name = e.path.rsplit('/').next().unwrap_or("").to_string();
        if e.url_paths.is_empty() {
            web.push(tyrosd_source_weblog::DecoyWeb { id: e.id, url_path: String::new(), file_name });
        } else {
            for u in &e.url_paths {
                web.push(tyrosd_source_weblog::DecoyWeb { id: e.id, url_path: u.clone(), file_name: file_name.clone() });
            }
        }
        if let Some(w) = WATCH.get() {
            let _ = w.watch(&e.path);
        }
    }
    tyrosd_source_weblog::set_decoys(web);
}

/// Start watching the decoy files (once at agent startup); `emit(id, path, pid)` per open
pub fn start_watch(data_dir: &str, emit: impl Fn(u64, String, i32) + Send + 'static) -> Result<(), String> {
    let w = Arc::new(tyrosd_source_fanotify::decoy::DecoyWatch::new().map_err(|e| format!("{e:#}"))?);
    let _ = WATCH.set(w.clone());
    apply(data_dir);
    let dd = data_dir.to_string();
    std::thread::Builder::new()
        .name("decoy-watch".into())
        .spawn(move || {
            let _ = w.run(|path, pid| {
                let id = load(&dd).iter().find(|e| e.path == path).map(|e| e.id).unwrap_or(0);
                emit(id, path, pid);
            });
        })
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Webroots for decoys (and the write permission): default locations plus `root`/`DocumentRoot` from the web server
/// configuration (e.g. /users/www/app/public), only existing folders outside system areas,
/// nested ones merged
pub fn webroots() -> Vec<String> {
    let mut v: Vec<String> = tyrosd_check::default_webroots("/");
    v.extend(tyrosd_source_weblog::docroots().into_iter().map(|(root, _)| root));
    let mut v: Vec<String> = v
        .into_iter()
        .map(|p| p.trim_end_matches('/').to_string())
        .filter(|p| !p.is_empty() && std::path::Path::new(p).is_dir() && crate::actions::dropin_path_ok(p))
        .collect();
    v.sort();
    v.dedup();
    let copy = v.clone();
    v.retain(|a| !copy.iter().any(|b| b != a && a.starts_with(&format!("{b}/"))));
    v.truncate(100);
    v
}

fn ok_value(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn ok_host(s: &str) -> bool {
    (1..=253).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
}

/// secret address: http(s)://host[:port]/path – path only [A-Za-z0-9/_.-], with at least 6 random characters in the path
pub fn url_path(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    let (host, path) = rest.split_once('/')?;
    if !ok_host(host) || url.len() > 200 {
        return None;
    }
    let path = format!("/{path}");
    let ok = path.len() >= 8
        && path.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'.' | b'-'))
        && !path.contains("..")
        && !path.contains("//");
    ok.then_some(path)
}

/// File name: letters/digits/._-, never with executable parts, last extension from the allow list
pub fn ok_file_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 64 || name.starts_with("..") || !name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')) {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    let parts: Vec<&str> = lower.split('.').filter(|p| !p.is_empty()).collect();
    if parts.len() < 2 && !lower.starts_with('.') {
        return false;
    }
    if parts.iter().skip(1).any(|p| FORBIDDEN_PARTS.contains(p)) || parts.first().is_some_and(|p| FORBIDDEN_PARTS.contains(p) && lower.starts_with('.')) {
        return false;
    }
    if lower.contains("authorized_keys") || lower.contains("htaccess") || lower.contains("user.ini") {
        return false;
    }
    parts.last().is_some_and(|e| ALLOWED_ENDINGS.contains(e))
}

fn valid_service(s: &Service) -> Result<(), String> {
    if !ok_value(&s.user, 3, 40) || !ok_value(&s.password, 12, 64) {
        return Err("Decoy values invalid (user/password)".into());
    }
    match s.kind.as_str() {
        "ssh" => {
            if !ok_host(&s.host) {
                return Err("Decoy values invalid (host)".into());
            }
        }
        "web" => {
            if !matches!(s.flavor.as_str(), "wordpress" | "shopware" | "generic") || url_path(&s.url).is_none() {
                return Err("Decoy values invalid (address)".into());
            }
        }
        "postgresql" | "mysql" => {
            if !ok_host(&s.host) || s.port == 0 || !ok_value(&s.db, 1, 40) {
                return Err("Decoy values invalid (database)".into());
            }
        }
        k => return Err(format!("unknown decoy type {k}")),
    }
    Ok(())
}

/// File content from fixed templates (labels in English – looks natural on any server)
pub fn render(format: &str, services: &[Service]) -> Result<String, String> {
    if services.is_empty() || services.len() > 6 {
        return Err("Decoy without services".into());
    }
    for s in services {
        valid_service(s)?;
    }
    let mut out = String::new();
    match format {
        "env" => {
            out.push_str("# credentials backup – do not commit\n");
            for s in services {
                // Databases: common variable names (libpq or Docker images)
                if s.kind == "postgresql" {
                    out.push_str(&format!("\nPGHOST={}\nPGPORT={}\nPGDATABASE={}\nPGUSER={}\nPGPASSWORD={}\n", s.host, s.port, s.db, s.user, s.password));
                    continue;
                }
                if s.kind == "mysql" {
                    out.push_str(&format!("\nMYSQL_HOST={}\nMYSQL_PORT={}\nMYSQL_DATABASE={}\nMYSQL_USER={}\nMYSQL_PASSWORD={}\n", s.host, s.port, s.db, s.user, s.password));
                    continue;
                }
                let (pre, url_key) = match (s.kind.as_str(), s.flavor.as_str()) {
                    ("ssh", _) => ("SSH", ""),
                    (_, "wordpress") => ("WP_ADMIN", "URL"),
                    (_, "shopware") => ("SHOPWARE_ADMIN", "URL"),
                    _ => ("ADMIN", "URL"),
                };
                out.push('\n');
                if s.kind == "ssh" {
                    out.push_str(&format!("{pre}_HOST={}\n", s.host));
                } else {
                    out.push_str(&format!("{pre}_{url_key}={}\n", s.url));
                }
                out.push_str(&format!("{pre}_USER={}\n{pre}_PASSWORD={}\n", s.user, s.password));
            }
        }
        "txt" => {
            out.push_str("Access data (backup) - keep private\n");
            for s in services {
                if matches!(s.kind.as_str(), "postgresql" | "mysql") {
                    let title = if s.kind == "postgresql" { "PostgreSQL" } else { "MySQL" };
                    out.push_str(&format!("\n{title}\n  Host:     {}:{}\n  Database: {}\n  User:     {}\n  Password: {}\n", s.host, s.port, s.db, s.user, s.password));
                    continue;
                }
                let title = match (s.kind.as_str(), s.flavor.as_str()) {
                    ("ssh", _) => "SSH",
                    (_, "wordpress") => "WordPress admin",
                    (_, "shopware") => "Shopware admin",
                    _ => "Admin login",
                };
                out.push_str(&format!("\n{title}\n"));
                if s.kind == "ssh" {
                    out.push_str(&format!("  Host:     {}\n", s.host));
                } else {
                    out.push_str(&format!("  URL:      {}\n", s.url));
                }
                out.push_str(&format!("  User:     {}\n  Password: {}\n", s.user, s.password));
            }
        }
        f => return Err(format!("unknown format {f}")),
    }
    if out.len() > MAX_SIZE {
        return Err("Decoy file too large".into());
    }
    Ok(out)
}

fn cstr(s: &str) -> Result<std::ffi::CString, String> {
    std::ffi::CString::new(s).map_err(|_| "invalid path".to_string())
}

/// Place a decoy (action `decoy_place`): path in `a.path`, values in `a.params`
pub fn place(a: &pb::Action, data_dir: &str, webroots: &[String]) -> Result<String, String> {
    let p: PlaceParams = serde_json::from_str(&a.params).map_err(|_| "Decoy parameters unreadable".to_string())?;
    let content = render(&p.format, &p.services)?;
    let (dir, name, resolved) = crate::actions::resolve_pub(&a.path)?;
    if resolved != a.path {
        return Err(format!("Path contains symbolic links (resolved: {resolved})"));
    }
    if !ok_file_name(&name) {
        return Err(format!("File name “{name}” is not allowed for decoys"));
    }
    if !webroots.iter().any(|w| resolved.starts_with(&format!("{}/", w.trim_end_matches('/')))) {
        return Err("Decoys only inside a detected web root".into());
    }
    let _g = REGISTRY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut list = load(data_dir);
    if list.len() >= MAX_DECOYS {
        return Err("too many decoys on this server".into());
    }
    if list.iter().any(|e| e.id == p.id || e.path == resolved) {
        return Err("Decoy already exists".into());
    }
    let ds = {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: pointer valid
        if unsafe { libc::fstat(dir.as_raw_fd(), &mut st) } != 0 {
            return Err("Folder cannot be checked".into());
        }
        st
    };
    let cname = cstr(&name)?;
    // SAFETY: dir and cname valid; O_EXCL: never overwrite an existing file
    let raw = unsafe {
        libc::openat(dir.as_raw_fd(), cname.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o640 as libc::c_uint)
    };
    if raw < 0 {
        let e = std::io::Error::last_os_error();
        return Err(if e.raw_os_error() == Some(libc::EEXIST) { "File already exists – decoy not created".into() } else { format!("Creating decoy: {e}") });
    }
    // SAFETY: fresh fd
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut f = std::fs::File::from(fd);
    let written = f.write_all(content.as_bytes()).and_then(|_| f.sync_all());
    // Owner same as the folder (e.g. www-data), so the file looks inconspicuous
    // SAFETY: fd valid
    unsafe {
        libc::fchown(f.as_raw_fd(), ds.st_uid, ds.st_gid);
        libc::fchmod(f.as_raw_fd(), 0o640);
    }
    if let Err(e) = written {
        // SAFETY: dir and cname valid
        unsafe { libc::unlinkat(dir.as_raw_fd(), cname.as_ptr(), 0) };
        return Err(format!("Writing decoy: {e}"));
    }
    let sha: String = Sha256::digest(content.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    let url_paths = p.services.iter().filter_map(|s| url_path(&s.url)).collect();
    list.push(Entry { id: p.id, path: resolved.clone(), sha256: sha.clone(), url_paths });
    save(data_dir, &list)?;
    drop(_g);
    apply(data_dir);
    Ok(format!("Decoy created: {resolved} (SHA-256 {})", &sha[..16]))
}

/// Remove a decoy (action `decoy_remove`): only files the agent itself created as decoys
pub fn remove(a: &pb::Action, data_dir: &str) -> Result<String, String> {
    #[derive(Deserialize)]
    struct P {
        id: u64,
    }
    let p: P = serde_json::from_str(&a.params).map_err(|_| "Decoy parameters unreadable".to_string())?;
    let _g = REGISTRY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut list = load(data_dir);
    let Some(pos) = list.iter().position(|e| e.id == p.id) else {
        return Ok("Decoy was not present (anymore)".into());
    };
    let e = list[pos].clone();
    let msg = match crate::actions::resolve_pub(&e.path) {
        Ok((dir, name, resolved)) if resolved == e.path => {
            let cname = cstr(&name)?;
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: pointer valid
            let exists = unsafe { libc::fstatat(dir.as_raw_fd(), cname.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } == 0;
            if exists && st.st_mode & libc::S_IFMT == libc::S_IFREG {
                // SAFETY: dir and cname valid
                if unsafe { libc::unlinkat(dir.as_raw_fd(), cname.as_ptr(), 0) } != 0 {
                    return Err(format!("Removing decoy: {}", std::io::Error::last_os_error()));
                }
                format!("Decoy removed: {}", e.path)
            } else {
                format!("Decoy file was already missing: {}", e.path)
            }
        }
        _ => format!("Decoy file no longer safely reachable, only removed from the registry: {}", e.path),
    };
    list.remove(pos);
    save(data_dir, &list)?;
    drop(_g);
    apply(data_dir);
    Ok(msg)
}

/// Programs that routinely read files (backup, virus scanners) – opening only as a notice
pub fn routine_reader(comm: &str) -> bool {
    const R: &[&str] = &[
        "rsync", "borg", "restic", "tar", "gzip", "zstd", "duplicity", "rclone", "rdiff-backup", "bacula-fd", "bareos-fd", "duply", "kopia",
        "clamscan", "clamd", "freshclam", "maldet", "imunify", "imunify-service", "ai-bolit", "bitninja", "rkhunter", "chkrootkit", "aide",
        "tripwire", "pmm-ras", "pkgacct", "updatedb", "mlocate", "plocate", "cp", "dsync", "backup-manager", "lsyncd",
    ];
    R.iter().any(|r| comm == *r || comm.starts_with(&format!("{r}-")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn web(url: &str) -> Service {
        Service { kind: "web".into(), flavor: "wordpress".into(), host: String::new(), url: url.into(), user: "wpadmin_x7f3".into(), password: "Kq7vX2mP9sLr4tWz".into(), port: 0, db: String::new() } // guard:ok test data
    }

    #[test]
    fn file_names() {
        for ok in [".env.backup", ".env.old", "credentials.txt", "wp-config.bak", "access-notes.txt", "db.env", "zugang.save"] {
            assert!(ok_file_name(ok), "{ok}");
        }
        for bad in ["x.php", "x.php.bak", "wp-config.php.bak", ".htaccess", ".user.ini", "a.phtml.old", "run.sh", "x", "../x.txt", "a b.txt", "authorized_keys.bak", "x.html.bak", "shell.cgi.txt"] {
            assert!(!ok_file_name(bad), "{bad}");
        }
    }

    #[test]
    fn values_and_urls() {
        assert_eq!(url_path("https://shop.example/admin-backup-7f3a9c/").as_deref(), Some("/admin-backup-7f3a9c/"));
        assert!(url_path("https://shop.example/<script>").is_none());
        assert!(url_path("https://shop.example/a").is_none()); // too short
        assert!(url_path("javascript:alert(1)").is_none());
        assert!(render("env", &[Service { password: "kurz".into(), ..web("https://s.example/admin-backup-7f3a9c/") }]).is_err());
        assert!(render("env", &[Service { user: "x\n<?php".into(), ..web("https://s.example/admin-backup-7f3a9c/") }]).is_err());
    }

    #[test]
    fn templates_contain_values_and_no_code() {
        let s = vec![
            Service { kind: "ssh".into(), flavor: String::new(), host: "203.0.113.5".into(), url: String::new(), user: "svc_backup_x7f3".into(), password: "Tq8wN3vB6yHc2kLp".into(), port: 0, db: String::new() }, // guard:ok test data
            web("https://shop.example/admin-backup-7f3a9c/"),
        ];
        let env = render("env", &s).unwrap();
        assert!(env.contains("SSH_USER=svc_backup_x7f3") && env.contains("WP_ADMIN_URL=https://shop.example/admin-backup-7f3a9c/"));
        let txt = render("txt", &s).unwrap();
        assert!(txt.contains("WordPress admin") && txt.contains("Password: Tq8wN3vB6yHc2kLp"));
        assert!(!env.contains("<?") && !txt.contains("<?"));
    }

    #[test]
    fn database_templates() {
        let s = vec![
            Service { kind: "postgresql".into(), flavor: String::new(), host: "127.0.0.1".into(), url: String::new(), user: "report_ro_x7f3".into(), password: "Tq8wN3vB6yHc2kLp".into(), port: 5432, db: "shop_backup".into() }, // guard:ok test data
            Service { kind: "mysql".into(), flavor: String::new(), host: "127.0.0.1".into(), url: String::new(), user: "backup_x7f3".into(), password: "Kq7vX2mP9sLr4tWz".into(), port: 3306, db: "shop".into() }, // guard:ok test data
        ];
        let env = render("env", &s).unwrap();
        assert!(env.contains("PGUSER=report_ro_x7f3\nPGPASSWORD=Tq8wN3vB6yHc2kLp") && env.contains("MYSQL_DATABASE=shop\nMYSQL_USER=backup_x7f3"));
        let txt = render("txt", &s).unwrap();
        assert!(txt.contains("PostgreSQL\n  Host:     127.0.0.1:5432\n  Database: shop_backup"));
        assert!(render("env", &[Service { db: "x;drop".into(), ..s[0].clone() }]).is_err());
        assert!(render("env", &[Service { port: 0, ..s[0].clone() }]).is_err());
    }

    #[test]
    fn routine_readers() {
        assert!(routine_reader("rsync") && routine_reader("clamscan") && !routine_reader("bash") && !routine_reader("php-fpm8.3"));
    }
}
