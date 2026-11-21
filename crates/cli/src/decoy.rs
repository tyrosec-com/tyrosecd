//! Köder-Zugangsdaten.
//!
//! Die Zentrale schickt nur **Werte** (Benutzer, Passwort, geheime Adresse) – den Datei-Inhalt baut der Agent selbst
//! aus festen Vorlagen. Eine übernommene Zentrale kann so keinen Code (z. B. PHP) in einen Webroot schreiben:
//! - nur **neue** Dateien (O_CREAT|O_EXCL|O_NOFOLLOW), nie überschreiben,
//! - nur in erkannten Webroots, nie in Systembereichen (Sperrliste wie Wiederherstellen),
//! - Dateiname nach Vorgabe, nie mit ausführbaren Endungen (.php, .phtml, .phar, .cgi, .sh, .htaccess …) – auch nicht
//!   als Zwischenendung („x.php.bak“ würde Apache mit AddHandler ausführen),
//! - Werte streng geprüft (Benutzer/Passwort nur Buchstaben/Ziffern, Adresse nur https?://host/pfad), höchstens 4 KB,
//! - Rechte 0640, Eigentümer wie der Ordner; Entfernen nur für Dateien, die der Agent selbst als Köder angelegt hat.
//!
//! Erkennung: Öffnen der Datei (fanotify, `DecoyWatch`), Aufruf der geheimen Adresse (Access-Log, `source-weblog`),
//! SSH-Anmeldeversuch mit dem Köder-Benutzer (Zentrale gleicht Anmeldungen ab).
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
    /// Datenbank: Port und Name (Phase 2)
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
    /// geheime Adressen (Pfadteil) für die Access-Log-Erkennung
    #[serde(default)]
    pub url_paths: Vec<String>,
}

const MAX_SIZE: usize = 4096;
const MAX_DECOYS: usize = 50;
/// Endungen/Namensteile, die ein Webserver ausführen oder als Konfiguration lesen könnte – nie im Dateinamen
const FORBIDDEN_PARTS: &[&str] = &[
    "php", "phtml", "phar", "php3", "php4", "php5", "php7", "php8", "pht", "phps", "cgi", "pl", "py", "sh", "bash", "rb", "js", "mjs", "html",
    "htm", "shtml", "xhtml", "asp", "aspx", "jsp", "jspx", "svg", "htaccess", "htpasswd", "user", "ini", "so", "exe",
];
/// erlaubte letzte Endungen (Sicherungs-/Notizdateien)
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
    std::fs::write(&tmp, serde_json::to_vec_pretty(list).unwrap_or_default()).map_err(|e| format!("Köder-Verzeichnis: {e}"))?;
    std::fs::rename(&tmp, &p).map_err(|e| format!("Köder-Verzeichnis: {e}"))
}

/// Erkennung auf den aktuellen Stand bringen: geheime Adressen/Dateinamen an die Access-Log-Auswertung, Dateien beobachten
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

/// Beobachtung der Köder-Dateien starten (einmal beim Start des Agenten); `emit(id, pfad, pid)` je Öffnen
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

/// Webroots für Köder (und die Schreibfreigabe): Standard-Orte plus `root`/`DocumentRoot` aus der Webserver-
/// Konfiguration (z. B. /users/www/app/public), nur vorhandene Ordner außerhalb von Systembereichen,
/// verschachtelte zusammengefasst
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

/// geheime Adresse: http(s)://host[:port]/pfad – Pfad nur [A-Za-z0-9/_.-], mit mindestens 6 Zeichen Zufall im Pfad
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

/// Dateiname: Buchstaben/Ziffern/._-, nie mit ausführbaren Teilen, letzte Endung aus der Erlaubtliste
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
        return Err("Köder-Werte ungültig (Benutzer/Passwort)".into());
    }
    match s.kind.as_str() {
        "ssh" => {
            if !ok_host(&s.host) {
                return Err("Köder-Werte ungültig (Host)".into());
            }
        }
        "web" => {
            if !matches!(s.flavor.as_str(), "wordpress" | "shopware" | "generic") || url_path(&s.url).is_none() {
                return Err("Köder-Werte ungültig (Adresse)".into());
            }
        }
        "postgresql" | "mysql" => {
            if !ok_host(&s.host) || s.port == 0 || !ok_value(&s.db, 1, 40) {
                return Err("Köder-Werte ungültig (Datenbank)".into());
            }
        }
        k => return Err(format!("unbekannte Köder-Art {k}")),
    }
    Ok(())
}

/// Datei-Inhalt aus festen Vorlagen (Bezeichnungen englisch – wirkt auf jedem Server natürlich)
pub fn render(format: &str, services: &[Service]) -> Result<String, String> {
    if services.is_empty() || services.len() > 6 {
        return Err("Köder ohne Dienste".into());
    }
    for s in services {
        valid_service(s)?;
    }
    let mut out = String::new();
    match format {
        "env" => {
            out.push_str("# credentials backup – do not commit\n");
            for s in services {
                // Datenbanken: übliche Variablennamen (libpq bzw. Docker-Images)
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
        f => return Err(format!("unbekanntes Format {f}")),
    }
    if out.len() > MAX_SIZE {
        return Err("Köder-Datei zu groß".into());
    }
    Ok(out)
}

fn cstr(s: &str) -> Result<std::ffi::CString, String> {
    std::ffi::CString::new(s).map_err(|_| "ungültiger Pfad".to_string())
}

/// Köder anlegen (Aktion `decoy_place`): Pfad in `a.path`, Werte in `a.params`
pub fn place(a: &pb::Action, data_dir: &str, webroots: &[String]) -> Result<String, String> {
    let p: PlaceParams = serde_json::from_str(&a.params).map_err(|_| "Köder-Parameter unlesbar".to_string())?;
    let content = render(&p.format, &p.services)?;
    let (dir, name, resolved) = crate::actions::resolve_pub(&a.path)?;
    if resolved != a.path {
        return Err(format!("Pfad enthält symbolische Links (aufgelöst: {resolved})"));
    }
    if !ok_file_name(&name) {
        return Err(format!("Dateiname „{name}“ ist für Köder nicht erlaubt"));
    }
    if !webroots.iter().any(|w| resolved.starts_with(&format!("{}/", w.trim_end_matches('/')))) {
        return Err("Köder nur innerhalb eines erkannten Webroots".into());
    }
    let _g = REGISTRY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut list = load(data_dir);
    if list.len() >= MAX_DECOYS {
        return Err("zu viele Köder auf diesem Server".into());
    }
    if list.iter().any(|e| e.id == p.id || e.path == resolved) {
        return Err("Köder existiert bereits".into());
    }
    let ds = {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: Zeiger gültig
        if unsafe { libc::fstat(dir.as_raw_fd(), &mut st) } != 0 {
            return Err("Ordner nicht prüfbar".into());
        }
        st
    };
    let cname = cstr(&name)?;
    // SAFETY: dir und cname gültig; O_EXCL: nie eine vorhandene Datei überschreiben
    let raw = unsafe {
        libc::openat(dir.as_raw_fd(), cname.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o640 as libc::c_uint)
    };
    if raw < 0 {
        let e = std::io::Error::last_os_error();
        return Err(if e.raw_os_error() == Some(libc::EEXIST) { "Datei existiert bereits – Köder nicht angelegt".into() } else { format!("Köder anlegen: {e}") });
    }
    // SAFETY: frischer fd
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut f = std::fs::File::from(fd);
    let written = f.write_all(content.as_bytes()).and_then(|_| f.sync_all());
    // Eigentümer wie der Ordner (z. B. www-data), damit die Datei unauffällig wirkt
    // SAFETY: fd gültig
    unsafe {
        libc::fchown(f.as_raw_fd(), ds.st_uid, ds.st_gid);
        libc::fchmod(f.as_raw_fd(), 0o640);
    }
    if let Err(e) = written {
        // SAFETY: dir und cname gültig
        unsafe { libc::unlinkat(dir.as_raw_fd(), cname.as_ptr(), 0) };
        return Err(format!("Köder schreiben: {e}"));
    }
    let sha: String = Sha256::digest(content.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    let url_paths = p.services.iter().filter_map(|s| url_path(&s.url)).collect();
    list.push(Entry { id: p.id, path: resolved.clone(), sha256: sha.clone(), url_paths });
    save(data_dir, &list)?;
    drop(_g);
    apply(data_dir);
    Ok(format!("Köder angelegt: {resolved} (SHA-256 {})", &sha[..16]))
}

/// Köder entfernen (Aktion `decoy_remove`): nur Dateien, die der Agent selbst als Köder angelegt hat
pub fn remove(a: &pb::Action, data_dir: &str) -> Result<String, String> {
    #[derive(Deserialize)]
    struct P {
        id: u64,
    }
    let p: P = serde_json::from_str(&a.params).map_err(|_| "Köder-Parameter unlesbar".to_string())?;
    let _g = REGISTRY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut list = load(data_dir);
    let Some(pos) = list.iter().position(|e| e.id == p.id) else {
        return Ok("Köder war nicht (mehr) vorhanden".into());
    };
    let e = list[pos].clone();
    let msg = match crate::actions::resolve_pub(&e.path) {
        Ok((dir, name, resolved)) if resolved == e.path => {
            let cname = cstr(&name)?;
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: Zeiger gültig
            let exists = unsafe { libc::fstatat(dir.as_raw_fd(), cname.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } == 0;
            if exists && st.st_mode & libc::S_IFMT == libc::S_IFREG {
                // SAFETY: dir und cname gültig
                if unsafe { libc::unlinkat(dir.as_raw_fd(), cname.as_ptr(), 0) } != 0 {
                    return Err(format!("Köder entfernen: {}", std::io::Error::last_os_error()));
                }
                format!("Köder entfernt: {}", e.path)
            } else {
                format!("Köder-Datei fehlte bereits: {}", e.path)
            }
        }
        _ => format!("Köder-Datei nicht mehr sicher erreichbar, nur aus dem Verzeichnis entfernt: {}", e.path),
    };
    list.remove(pos);
    save(data_dir, &list)?;
    drop(_g);
    apply(data_dir);
    Ok(msg)
}

/// Programme, die Dateien routinemäßig lesen (Sicherung, Virenscanner) – Öffnen nur als Hinweis
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
        Service { kind: "web".into(), flavor: "wordpress".into(), host: String::new(), url: url.into(), user: "wpadmin_x7f3".into(), password: "Kq7vX2mP9sLr4tWz".into(), port: 0, db: String::new() } // guard:ok Testdaten
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
        assert!(url_path("https://shop.example/a").is_none()); // zu kurz
        assert!(url_path("javascript:alert(1)").is_none());
        assert!(render("env", &[Service { password: "kurz".into(), ..web("https://s.example/admin-backup-7f3a9c/") }]).is_err());
        assert!(render("env", &[Service { user: "x\n<?php".into(), ..web("https://s.example/admin-backup-7f3a9c/") }]).is_err());
    }

    #[test]
    fn templates_contain_values_and_no_code() {
        let s = vec![
            Service { kind: "ssh".into(), flavor: String::new(), host: "203.0.113.5".into(), url: String::new(), user: "svc_backup_x7f3".into(), password: "Tq8wN3vB6yHc2kLp".into(), port: 0, db: String::new() }, // guard:ok Testdaten
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
            Service { kind: "postgresql".into(), flavor: String::new(), host: "127.0.0.1".into(), url: String::new(), user: "report_ro_x7f3".into(), password: "Tq8wN3vB6yHc2kLp".into(), port: 5432, db: "shop_backup".into() }, // guard:ok Testdaten
            Service { kind: "mysql".into(), flavor: String::new(), host: "127.0.0.1".into(), url: String::new(), user: "backup_x7f3".into(), password: "Kq7vX2mP9sLr4tWz".into(), port: 3306, db: "shop".into() }, // guard:ok Testdaten
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
