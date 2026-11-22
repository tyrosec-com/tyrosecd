//! Access logs of nginx and Apache (plan C2, round 3).
//!
//! The agent analyzes the logs itself and reports only findings – no full logs (data volume,
//! visitor IPs). Detected are:
//! - **Request to a newly created PHP file** (from file monitoring of the last 7 days) → a webshell is being used
//! - **POST to PHP in upload directories**
//! - **Sensitive file served** (200 on `.env`, `.git/`, database dumps, backups, phpinfo …)
//! - **WordPress logins**: failed attempts aggregated per IP, success individually → "brute force → login" chain on server
//!
//! Formats: combined / common, optionally with a leading `vhost:port` (vhost_combined).
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use regex::Regex;
use tyrosd_proto::{Detection, LoginEvent};

fn now_s() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Decoys (plan "decoy credentials"): secret address and file name per decoy, set by the agent at startup and after
/// every creation/removal. The secret address is only in the decoy file – whoever requests it has read the file.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DecoyWeb {
    pub id: u64,
    /// e.g. "/admin-backup-7f3a/" (always with a random part), empty = no secret address
    pub url_path: String,
    /// file name of the decoy file (retrieval via the web = scanner, not an intrusion)
    pub file_name: String,
}

static DECOYS: std::sync::RwLock<Vec<DecoyWeb>> = std::sync::RwLock::new(Vec::new());

pub fn set_decoys(v: Vec<DecoyWeb>) {
    *DECOYS.write().unwrap_or_else(|e| e.into_inner()) = v;
}

/// Hit of a request on a decoy: (decoy, true = secret address, false = decoy file retrieved)
pub fn decoy_hit(path: &str) -> Option<(DecoyWeb, bool)> {
    let list = DECOYS.read().unwrap_or_else(|e| e.into_inner());
    for d in list.iter() {
        let u = d.url_path.trim_end_matches('/');
        if u.len() >= 8 && (path == u || path.starts_with(&format!("{u}/")) || path.starts_with(&format!("{u}?"))) {
            return Some((d.clone(), true));
        }
    }
    for d in list.iter() {
        if !d.file_name.is_empty() && path.rsplit('/').next() == Some(d.file_name.as_str()) {
            return Some((d.clone(), false));
        }
    }
    None
}

/// A request from the access log.
#[derive(Debug, Clone, PartialEq)]
pub struct Req {
    pub vhost: String,
    pub ip: String,
    pub method: String,
    pub path: String,
    pub query: String,
    pub status: u16,
    pub size: u64,
    pub ua: String,
}

fn re_line() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"^(?:(\S+):\d+ )?(\S+) \S+ \S+ \[[^\]]+\] "([A-Z]{3,10}) (\S+)(?: [^"]*)?" (\d{3}) (\d+|-)(?: "[^"]*" "([^"]*)")?"#).unwrap()
    })
}

/// URL decoding (%xx), invalid sequences are left as they are.
fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            // %00 is left as is (a null character breaks database/JSON and is an attack pattern anyway)
            if let Some(v) = s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok()).filter(|v| *v != 0) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_line(line: &str) -> Option<Req> {
    let c = re_line().captures(line)?;
    let target = &c[4];
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    Some(Req {
        vhost: c.get(1).map(|m| m.as_str().to_string()).unwrap_or_default(),
        ip: c[2].to_string(),
        method: c[3].to_string(),
        path: url_decode(path),
        query: query.chars().take(200).collect(),
        status: c[5].parse().ok()?,
        size: c[6].parse().unwrap_or(0),
        ua: c.get(7).map(|m| m.as_str().chars().take(160).collect()).unwrap_or_default(),
    })
}

fn is_php(p: &str) -> bool {
    let l = p.to_ascii_lowercase();
    [".php", ".phtml", ".phar", ".php5", ".php7", ".pht"].iter().any(|e| l.ends_with(e))
}

/// Files that should never be served publicly (status 200 with content = data leak).
pub fn sensitive(path: &str) -> Option<&'static str> {
    let l = path.to_ascii_lowercase();
    let name = l.rsplit('/').next().unwrap_or("");
    if name == ".env" || name.starts_with(".env.") {
        return Some("Environment file with credentials (.env)");
    }
    if l.contains("/.git/") || l.ends_with("/.git") {
        return Some("Git directory (source code, credentials)");
    }
    if l.contains("/.svn/") || name == ".htpasswd" || name == ".htaccess.bak" {
        return Some("Version control or password file");
    }
    if [".sql", ".sql.gz", ".sql.zip", ".sql.bz2", ".dump"].iter().any(|e| name.ends_with(e)) {
        return Some("Database dump");
    }
    if ["wp-config", "config", "configuration", "env.php", "settings.php", "localsettings.php", "parameters"].iter().any(|b| name.starts_with(b))
        && [".bak", ".old", ".orig", ".save", ".swp", "~", ".txt", ".backup", ".1"].iter().any(|e| name.ends_with(e))
    {
        return Some("Backup copy of a configuration file");
    }
    if ["backup.zip", "backup.tar.gz", "backup.tgz", "site.zip", "www.zip", "htdocs.zip", "public_html.zip", "backup.sql"].contains(&name) {
        return Some("Full backup");
    }
    if ["phpinfo.php", "info.php", "php_info.php"].contains(&name) {
        return Some("phpinfo() (server details)");
    }
    if l == "/server-status" || l == "/server-info" {
        return Some("Apache status page");
    }
    None
}

fn in_upload_dir(p: &str) -> bool {
    let l = p.to_ascii_lowercase();
    ["/uploads/", "/upload/", "/images/", "/media/", "/files/", "/tmp/", "/cache/", "/assets/"].iter().any(|d| l.contains(d))
}

/// Newly created PHP files from file monitoring (path → (time, creating process)), 7 days.
#[derive(Default)]
pub struct RecentPhp {
    files: Mutex<HashMap<String, (i64, String)>>,
}

impl RecentPhp {
    pub const KEEP_S: i64 = 7 * 86400;

    /// Record a file event (only created/renamed PHP files in web directories)
    pub fn note(&self, path: &str, comm: &str) {
        if !is_php(path) || !(path.starts_with("/var/www/") || path.starts_with("/srv/") || path.starts_with("/home/")) {
            return;
        }
        let mut f = self.files.lock().unwrap();
        if f.len() >= 20_000 {
            let cut = now_s() - Self::KEEP_S;
            f.retain(|_, (t, _)| *t > cut);
            if f.len() >= 20_000 {
                return; // e.g. large deploys without a marker – limit memory
            }
        }
        f.insert(path.to_string(), (now_s(), comm.to_string()));
    }

    /// Does the URL path (end of the file path) match a newly created file?
    pub fn find(&self, url_path: &str) -> Option<(String, i64, String)> {
        if !is_php(url_path) || url_path.len() < 5 {
            return None;
        }
        let cut = now_s() - Self::KEEP_S;
        let f = self.files.lock().unwrap();
        f.iter()
            .filter(|(p, (t, _))| *t > cut && p.ends_with(url_path))
            .max_by_key(|(_, (t, _))| *t)
            .map(|(p, (t, c))| (p.clone(), *t, c.clone()))
    }

    pub fn save(&self, path: &str) {
        let cut = now_s() - Self::KEEP_S;
        let f = self.files.lock().unwrap();
        let v: Vec<_> = f.iter().filter(|(_, (t, _))| *t > cut).map(|(p, (t, c))| serde_json::json!([p, t, c])).collect();
        let _ = std::fs::write(path, serde_json::Value::Array(v).to_string());
    }

    pub fn load(&self, path: &str) {
        let Ok(s) = std::fs::read_to_string(path) else { return };
        let Ok(serde_json::Value::Array(v)) = serde_json::from_str(&s) else { return };
        let mut f = self.files.lock().unwrap();
        for e in v {
            if let (Some(p), Some(t), Some(c)) = (e[0].as_str(), e[1].as_i64(), e[2].as_str()) {
                f.insert(p.to_string(), (t, c.to_string()));
            }
        }
    }
}

/// Result of evaluating a line.
#[derive(Debug)]
pub enum Out {
    Detect(Detection),
    Login(LoginEvent),
}

/// Evaluation across all logs (failed attempts per IP, deduplication, limiting).
pub struct Analyzer {
    recent: Arc<RecentPhp>,
    /// Webroots from the web server configuration; empty = unknown (then no check is done)
    pub roots: Vec<String>,
    /// Webroot → domain(s) from `server_name`/`ServerName` or the Plesk directory name
    pub sites: HashMap<String, String>,
    logins: tyrosd_source_auth::Aggregator,
    seen: HashMap<String, Instant>,
    budget: (Instant, u32),
    /// Probing by scanners (IP → (count, path → count)), reported every 10 min as statistics
    probes: HashMap<String, (u32, HashMap<String, u32>)>,
    probes_since: Instant,
    /// Apache modules for /server-status and /server-info loaded? (status, info)
    pub handlers: (bool, bool),
    /// per website: sizes of the fallback page served with 200 for non-existent addresses
    fallback: HashMap<String, Vec<u64>>,
    /// Sizes of 302 responses to requests other than the login, per website/log ("redirects everything", e.g. plugins
    /// that hide wp-login.php – real case: a website answers everything with 302 → /)
    redirects: HashMap<String, Vec<u64>>,
}

/// Does Apache load mod_status / mod_info? Without an Apache configuration (e.g. nginx only) neither page exists.
pub fn apache_handlers() -> (bool, bool) {
    let mut h = (false, false);
    for d in ["/etc/apache2/mods-enabled", "/etc/httpd/conf.modules.d", "/etc/httpd/conf", "/etc/httpd/conf.d"] {
        let Ok(rd) = std::fs::read_dir(d) else { continue };
        for e in rd.flatten() {
            let s = std::fs::read_to_string(e.path()).unwrap_or_default();
            for l in s.lines().map(str::trim).filter(|l| !l.starts_with('#')) {
                h.0 |= l.contains("LoadModule status_module");
                h.1 |= l.contains("LoadModule info_module");
            }
        }
    }
    h
}

/// Typical scanner targets that do not count as "sensitive file served" (admin tools, exploits of well-known software)
pub fn scanner_path(path: &str) -> bool {
    let l = path.to_ascii_lowercase();
    ["phpmyadmin", "/pma/", "/adminer", "/vendor/phpunit", "/cgi-bin/", "/boaform", "/actuator", "/hnap1", "/.aws", "/.ssh", "/.docker",
        "/wp-admin/setup-config.php", "/wp-config", "/config.json", "/.vscode", "/.idea", "/telescope", "/_ignition", "/solr/", "/owa/",
        "/autodiscover", "/geoserver", "/console", "/manager/html", "/shell", "/eval-stdin", "/.well-known/security.txt.bak"]
        .iter()
        .any(|p| l.contains(p))
}

fn web_process(comm: &str) -> bool {
    comm.starts_with("php") || matches!(comm, "apache2" | "httpd" | "nginx" | "lsphp" | "frankenphp" | "www-data")
}

impl Analyzer {
    pub const MAX_PER_MIN: u32 = 60;

    pub fn new(recent: Arc<RecentPhp>) -> Self {
        Analyzer { recent, probes: HashMap::new(), probes_since: Instant::now(), handlers: apache_handlers(), fallback: HashMap::new(), redirects: HashMap::new(), roots: Vec::new(), sites: HashMap::new(), logins: tyrosd_source_auth::Aggregator::new(Duration::from_secs(300)), seen: HashMap::new(), budget: (Instant::now(), 0) }
    }

    fn once(&mut self, key: &str) -> bool {
        // the same report at most once per hour; at most MAX_PER_MIN reports per minute
        if self.seen.get(key).is_some_and(|t| t.elapsed() < Duration::from_secs(3600)) {
            return false;
        }
        if self.budget.0.elapsed() >= Duration::from_secs(60) {
            self.budget = (Instant::now(), 0);
        }
        if self.budget.1 >= Self::MAX_PER_MIN {
            return false;
        }
        self.budget.1 += 1;
        if self.seen.len() > 10_000 {
            self.seen.retain(|_, t| t.elapsed() < Duration::from_secs(3600));
        }
        self.seen.insert(key.to_string(), Instant::now());
        true
    }

    /// Domain for the longest matching webroot of a file
    fn site_for(&self, file: &str) -> Option<String> {
        self.sites
            .iter()
            .filter(|(root, _)| file.starts_with(&format!("{root}/")))
            .max_by_key(|(root, _)| root.len())
            .map(|(_, n)| n.clone())
    }

    /// Take over webroots and domains (from `docroots()`)
    pub fn set_sites(&mut self, sites: Vec<(String, String)>) {
        self.roots = sites.iter().map(|(r, _)| r.clone()).collect();
        self.roots.dedup();
        self.sites = sites.into_iter().filter(|(_, n)| !n.is_empty()).collect();
    }

    fn detection(rule: &str, severity: &str, title: &str, detail: String, key: String) -> Out {
        Out::Detect(Detection { rule: rule.into(), severity: severity.into(), title: title.into(), detail, key, ..Default::default() })
    }

    pub fn feed(&mut self, r: &Req, log: &str) -> Vec<Out> {
        let mut out = Vec::new();
        let ok = (200..300).contains(&r.status);
        let site = if r.vhost.is_empty() { String::new() } else { format!(" on {}", r.vhost) };
        let who = format!("{} {} {}{site} → {} ({})", r.ip, r.method, r.path, r.status, log);

        // 0. Decoy: secret address requested (credentials from the decoy file used) or decoy file retrieved
        if let Some((d, secret)) = decoy_hit(&r.path) {
            if self.once(&format!("decoy|{}|{}|{secret}", d.id, r.ip)) {
                out.push(if secret {
                    Self::detection("decoy_url", "critical", "Decoy address requested: credentials from the decoy file used",
                        format!("{who}
Decoy #{}", d.id), format!("decoy:{}", d.id))
                } else {
                    Self::detection("decoy_fetched", "low", "Decoy file fetched via the web (scanner)",
                        format!("{who}
Decoy #{}", d.id), format!("decoy:{}", d.id))
                });
            }
            return out;
        }

        // 1. a newly created PHP file is requested
        if ok {
            if let Some((file, t, comm)) = self.recent.find(&r.path) {
                if self.once(&format!("new_php|{file}|{}", r.ip)) {
                    let by_web = web_process(&comm);
                    let age_h = (now_s() - t) / 3600;
                    out.push(Self::detection(
                        "web_new_php_accessed",
                        if by_web { "critical" } else { "high" },
                        "Newly created PHP file is being requested (web shell?)",
                        format!("{who}\nFile {file}, created {age_h} h ago{}", if comm.is_empty() { String::new() } else { format!(" by {comm}") }),
                        format!("{file}|{}", r.ip),
                    ));
                }
            }
        }
        // 2. POST to PHP in upload/media directories
        if r.method == "POST" && ok && is_php(&r.path) && in_upload_dir(&r.path) && self.once(&format!("post_upload|{}|{}", r.path, r.ip)) {
            out.push(Self::detection("web_post_php_upload_dir", "high", "POST to a PHP file in the upload folder", who.clone(), format!("{}|{}", r.path, r.ip)));
        }
        // 3. sensitive file served – only if it really exists on disk. Many applications
        //    (WordPress, Laravel, shops) serve the home page with 200 for every unknown address;
        //    that is not a data leak.
        if r.status == 200 && r.size > 0 && matches!(r.method.as_str(), "GET" | "HEAD" | "POST") {
            if let Some(what) = sensitive(&r.path) {
                // status pages only if the module is loaded and the response is not the website's usual
                // fallback page (apps behind a proxy answer every address with their home page)
                let handler = match r.path.as_str() {
                    "/server-status" => self.handlers.0,
                    "/server-info" => self.handlers.1,
                    _ => false,
                } && !self.is_fallback(r);
                let file = if handler || self.roots.is_empty() { None } else { locate(&self.roots, &r.path) };
                let real = handler || file.is_some();
                if !real && !self.roots.is_empty() {
                    self.note_fallback(r);
                    self.probe(r); // not a real data leak: statistics only
                }
                if (real || self.roots.is_empty()) && self.once(&format!("sensitive|{}|{}", r.vhost, r.path)) {
                    let mut d = format!("{what}\n");
                    // website: from the log (vhost_combined), otherwise from the configuration for the file's webroot
                    let site = if !r.vhost.is_empty() {
                        Some(r.vhost.clone())
                    } else {
                        file.as_ref().and_then(|(f, _)| self.site_for(f)).map(|n| format!("{n} (according to the web server configuration)"))
                    };
                    if let Some(s) = &site {
                        d.push_str(&format!("Website: {s}\n"));
                    }
                    match &file {
                        Some((f, sz)) => {
                            let dir = f.rsplit_once('/').map(|(d, _)| d).filter(|d| !d.is_empty()).unwrap_or("/");
                            d.push_str(&format!("File on the server: {f} ({sz} bytes)\nDirectory: {dir}\n"));
                        }
                        None if !handler => d.push_str("File on the server: not checked (web root unknown)\n"),
                        None => {}
                    }
                    d.push_str(&format!("Request: {} {} → {}, {} bytes served\n", r.method, r.path, r.status, r.size));
                    d.push_str(&format!("From: {}\nLog: {log}", r.ip));
                    out.push(Self::detection(
                        "web_sensitive_file_served",
                        if real { "high" } else { "medium" },
                        "Sensitive file served publicly",
                        d,
                        format!("{}|{}", r.vhost, r.path),
                    ));
                }
            }
        }
        // Probing: scanner paths and non-existent PHP files (4xx) count only for the statistics
        if (400..500).contains(&r.status) && sensitive(&r.path).is_none() && (scanner_path(&r.path) || (r.status == 404 && is_php(&r.path))) {
            self.probe(r);
        } else if (400..500).contains(&r.status) && sensitive(&r.path).is_some() {
            self.probe(r);
        }
        // 4. WordPress login: POST wp-login.php → 302 = success, 200 = wrong password; xmlrpc = attempt.
        // Exception: the website also redirects other requests with an equally sized 302 response – then the login's 302
        // is not a login but the general redirect (counts as an attempt). WordPress itself redirects with an empty body
        // after a successful login.
        let lp = r.path.to_ascii_lowercase();
        let wp_login = lp.ends_with("/wp-login.php") && r.method == "POST" && (r.query.is_empty() || r.query.contains("action=login"));
        let xmlrpc = lp.ends_with("/xmlrpc.php") && r.method == "POST";
        let site_key = if r.vhost.is_empty() { log.to_string() } else { r.vhost.clone() };
        if r.status == 302 && !wp_login && !lp.contains("/wp-admin") && r.size > 0 {
            if self.redirects.len() < 500 || self.redirects.contains_key(&site_key) {
                let v = self.redirects.entry(site_key.clone()).or_default();
                if !v.iter().any(|s| s.abs_diff(r.size) <= 64) {
                    if v.len() >= 8 {
                        v.remove(0);
                    }
                    v.push(r.size);
                }
            }
        }
        if wp_login || xmlrpc {
            let generic = r.size > 0 && self.redirects.get(&site_key).is_some_and(|v| v.iter().any(|s| s.abs_diff(r.size) <= 64));
            let success = wp_login && r.status == 302 && !generic;
            let e = LoginEvent {
                service: "wordpress".into(),
                success,
                user: if r.vhost.is_empty() { "?".into() } else { r.vhost.clone() },
                ip: r.ip.clone(),
                method: if xmlrpc { "xmlrpc".into() } else { "password".into() },
                count: 1,
                first_ts_ns: now_s() * 1_000_000_000,
                ..Default::default()
            };
            if success || (wp_login && (r.status == 200 || r.status == 302)) || xmlrpc {
                out.extend(self.logins.push(e).into_iter().map(Out::Login));
            }
        }
        out
    }

    fn note_fallback(&mut self, r: &Req) {
        if self.fallback.len() >= 500 && !self.fallback.contains_key(&r.vhost) {
            return;
        }
        let v = self.fallback.entry(r.vhost.clone()).or_default();
        if !v.iter().any(|s| s.abs_diff(r.size) <= 64) {
            if v.len() >= 8 {
                v.remove(0);
            }
            v.push(r.size);
        }
    }

    /// Response size matches this website's fallback page (±64 bytes, e.g. changing CSRF token)
    fn is_fallback(&self, r: &Req) -> bool {
        self.fallback.get(&r.vhost).is_some_and(|v| v.iter().any(|s| s.abs_diff(r.size) <= 64))
    }

    fn probe(&mut self, r: &Req) {
        if self.probes.len() >= 5000 && !self.probes.contains_key(&r.ip) {
            return; // limit memory
        }
        let e = self.probes.entry(r.ip.clone()).or_default();
        e.0 += 1;
        if e.1.len() < 20 || e.1.contains_key(&r.path) {
            *e.1.entry(r.path.chars().take(120).collect()).or_default() += 1;
        }
    }

    /// Statistics of the last 10 minutes (severity "info": the server does not raise an alarm from it)
    fn probe_stats(&mut self, force: bool) -> Option<Out> {
        if self.probes.is_empty() || (!force && self.probes_since.elapsed() < Duration::from_secs(600)) {
            return None;
        }
        let window = self.probes_since.elapsed().as_secs();
        self.probes_since = Instant::now();
        let mut ips: Vec<(String, (u32, HashMap<String, u32>))> = std::mem::take(&mut self.probes).into_iter().collect();
        let total: u32 = ips.iter().map(|(_, (n, _))| n).sum();
        ips.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));
        let list: Vec<serde_json::Value> = ips
            .into_iter()
            .take(200)
            .map(|(ip, (n, paths))| {
                let mut p: Vec<(String, u32)> = paths.into_iter().collect();
                p.sort_by(|a, b| b.1.cmp(&a.1));
                serde_json::json!({ "ip": ip, "n": n, "paths": p.into_iter().take(8).map(|(k, v)| serde_json::json!([k, v])).collect::<Vec<_>>() })
            })
            .collect();
        let detail = serde_json::json!({ "window_s": window, "total": total, "ips": list }).to_string();
        Some(Self::detection("web_probes", "info", "Scanner probing", detail, format!("probes|{}", now_s())))
    }

    pub fn flush(&mut self, force: bool) -> Vec<Out> {
        let mut out: Vec<Out> = self.logins.flush(force).into_iter().map(Out::Login).collect();
        out.extend(self.probe_stats(force));
        out
    }
}

/// Look up a URL path in the webroots → (file path, size). Only real files, no "..".
pub fn locate(roots: &[String], url_path: &str) -> Option<(String, u64)> {
    let rel = url_path.trim_start_matches('/');
    if rel.is_empty() || rel.split('/').any(|c| c == ".." || c == ".") {
        return None;
    }
    roots.iter().find_map(|r| {
        let p = std::path::Path::new(r).join(rel);
        let m = std::fs::metadata(&p).ok()?;
        (m.is_file() || m.is_dir()).then(|| (p.to_string_lossy().into_owned(), if m.is_file() { m.len() } else { 0 }))
    })
}

/// Webroots with domain(s) from nginx/Apache configuration and panel default paths → [(webroot, domains)].
pub fn docroots() -> Vec<(String, String)> {
    let mut files = Vec::new();
    for d in ["/etc/nginx/sites-enabled", "/etc/nginx/conf.d", "/etc/apache2/sites-enabled", "/etc/httpd/conf.d", "/etc/httpd/sites-enabled"] {
        if let Ok(rd) = std::fs::read_dir(d) {
            files.extend(rd.flatten().map(|e| e.path()));
        }
    }
    files.extend(["/etc/nginx/nginx.conf", "/etc/httpd/conf/httpd.conf", "/etc/apache2/apache2.conf"].map(std::path::PathBuf::from));
    let mut out: Vec<(String, String)> = Vec::new();
    for f in files.iter().take(500) {
        let Ok(s) = std::fs::read_to_string(f) else { continue };
        out.extend(parse_sites(&s));
    }
    // Plesk: /var/www/vhosts/<domain>/httpdocs
    if let Ok(rd) = std::fs::read_dir("/var/www/vhosts") {
        for d in rd.flatten() {
            let dom = d.file_name().to_string_lossy().into_owned();
            out.push((d.path().join("httpdocs").to_string_lossy().into_owned(), if dom.contains('.') { dom } else { String::new() }));
        }
    }
    out.push(("/var/www/html".into(), String::new()));
    out.retain(|(p, _)| std::path::Path::new(p).is_dir());
    // the same webroot several times: prefer the entry with a domain
    out.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.len().cmp(&a.1.len())));
    out.dedup_by(|a, b| a.0 == b.0);
    out.truncate(500);
    out
}

/// Only the webroots (for tests and simple callers)
pub fn parse_roots(conf: &str) -> Vec<String> {
    parse_sites(conf).into_iter().map(|(r, _)| r).collect()
}

/// Per `server { … }` (nginx) or `<VirtualHost>` (Apache): `root`/`DocumentRoot` with `server_name`/`ServerName`/`ServerAlias`.
/// Paths with variables and placeholder names (`_`, `localhost`) are skipped.
pub fn parse_sites(conf: &str) -> Vec<(String, String)> {
    fn flush(roots: &mut Vec<String>, names: &mut Vec<String>, out: &mut Vec<(String, String)>) {
        let n = names.join(", ");
        out.extend(roots.drain(..).map(|r| (r, n.clone())));
        names.clear();
    }
    let (mut out, mut roots, mut names) = (Vec::new(), Vec::new(), Vec::new());
    for l in conf.lines() {
        let l = l.trim();
        if l.starts_with('#') {
            continue;
        }
        if l.starts_with("server {") || l == "server{" || l.starts_with("<VirtualHost") {
            flush(&mut roots, &mut names, &mut out);
            continue;
        }
        let clean = |v: &str| v.trim().trim_end_matches(';').trim().trim_matches('"').trim_matches('\'').trim_end_matches('/').to_string();
        if let Some(v) = l.strip_prefix("root ").or_else(|| l.strip_prefix("DocumentRoot ")) {
            let v = clean(v);
            if v.starts_with('/') && !v.contains('$') && !v.contains('%') {
                roots.push(v);
            }
        } else if let Some(v) = l.strip_prefix("server_name ").or_else(|| l.strip_prefix("ServerName ")).or_else(|| l.strip_prefix("ServerAlias ")) {
            for n in clean(v).split_whitespace() {
                let n = n.trim_matches('"').split(':').next().unwrap_or("");
                if n.contains('.') && !n.contains('$') && !names.iter().any(|x| x == n) && names.len() < 4 {
                    names.push(n.to_string());
                }
            }
        }
    }
    flush(&mut roots, &mut names, &mut out);
    out
}

/// Find access logs: default paths of the distributions and common panels.
pub fn discover() -> Vec<String> {
    let mut out = Vec::new();
    let mut add_dir = |dir: &str, pred: &dyn Fn(&str) -> bool| {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if pred(&n) && e.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    out.push(format!("{dir}/{n}"));
                }
            }
        }
    };
    let access = |n: &str| n.contains("access") && (n.ends_with(".log") || n.ends_with("access_log") || n.ends_with("_log"));
    add_dir("/var/log/nginx", &access);
    add_dir("/var/log/apache2", &access);
    add_dir("/var/log/httpd", &access);
    // Plesk: /var/www/vhosts/system/<domain>/logs/access_log, access_ssl_log
    if let Ok(rd) = std::fs::read_dir("/var/www/vhosts/system") {
        for d in rd.flatten() {
            let dir = format!("/var/www/vhosts/system/{}/logs", d.file_name().to_string_lossy());
            add_dir(&dir, &|n: &str| n == "access_log" || n == "access_ssl_log" || n == "proxy_access_log" || n == "proxy_access_ssl_log");
        }
    }
    // ISPConfig: /var/log/ispconfig/httpd/<domain>/access.log
    if let Ok(rd) = std::fs::read_dir("/var/log/ispconfig/httpd") {
        for d in rd.flatten() {
            add_dir(&format!("/var/log/ispconfig/httpd/{}", d.file_name().to_string_lossy()), &|n: &str| n == "access.log");
        }
    }
    out.sort();
    out.dedup();
    out.truncate(200);
    out
}

/// A monitored log file (follows log rotation via inode change and truncation).
struct Tail {
    path: String,
    file: std::fs::File,
    ino: u64,
    pending: Vec<u8>,
}

/// Open a log file safely: regular files only (no FIFOs/devices – a FIFO would make the analysis hang), non-
/// blocking; if the file is in a directory writable by others than root (e.g. per-website logs or a
/// log directory owned by the web server user), a symlink as the last path component is not followed – otherwise
/// that user could replace `access.log` with a link to a root file. Symlinks created by the admin in
/// root-owned directories remain allowed.
fn open_log(path: &str) -> Option<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let dir = std::path::Path::new(path).parent()?;
    let dm = std::fs::metadata(dir).ok()?;
    let untrusted = dm.uid() != 0 || dm.mode() & 0o022 != 0;
    let mut flags = libc::O_NONBLOCK;
    if untrusted {
        flags |= libc::O_NOFOLLOW;
    }
    let file = std::fs::OpenOptions::new().read(true).custom_flags(flags).open(path).ok()?;
    file.metadata().ok().filter(|m| m.is_file())?;
    Some(file)
}

impl Tail {
    fn open(path: &str) -> Option<Tail> {
        use std::os::unix::fs::MetadataExt;
        let mut file = open_log(path)?;
        file.seek(SeekFrom::End(0)).ok()?;
        let ino = file.metadata().ok()?.ino();
        Some(Tail { path: path.to_string(), file, ino, pending: Vec::new() })
    }

    /// New complete lines (at most 4 MB per call, so that one file does not block everything)
    fn lines(&mut self) -> Vec<String> {
        use std::os::unix::fs::MetadataExt;
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0;
        while total < 4 << 20 {
            match self.file.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    self.pending.extend_from_slice(&buf[..n]);
                    total += n;
                }
            }
        }
        if total == 0 {
            if let Ok(m) = std::fs::metadata(&self.path) {
                if m.ino() != self.ino || m.len() < self.file.stream_position().unwrap_or(0) {
                    if let Some(nf) = open_log(&self.path) {
                        self.file = nf; // rotated: new file from the start
                        self.ino = m.ino();
                        self.pending.clear();
                    }
                }
            }
        }
        let mut out = Vec::new();
        while let Some(i) = self.pending.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=i).collect();
            if line.len() <= 16 * 1024 {
                out.push(String::from_utf8_lossy(&line).trim_end().to_string());
            }
        }
        if self.pending.len() > 64 * 1024 {
            self.pending.clear(); // discard an overlong line without a line break
        }
        out
    }
}

/// Analyze logs until `stop`; `emit` receives findings and login events.
pub fn run(stop: Arc<AtomicBool>, recent: Arc<RecentPhp>, emit: impl Fn(Out)) {
    let mut az = Analyzer::new(recent);
    let mut tails: HashMap<String, Tail> = HashMap::new();
    let mut last_discover = Instant::now() - Duration::from_secs(3600);
    while !stop.load(Ordering::Relaxed) {
        if last_discover.elapsed() >= Duration::from_secs(300) {
            az.set_sites(docroots());
            let found = discover();
            tails.retain(|p, _| found.contains(p));
            for p in found {
                if !tails.contains_key(&p) {
                    if let Some(t) = Tail::open(&p) {
                        tails.insert(p, t);
                    }
                }
            }
            last_discover = Instant::now();
        }
        let mut busy = false;
        for (path, t) in tails.iter_mut() {
            let log = path.rsplit('/').take(2).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("/");
            for line in t.lines() {
                busy = true;
                if let Some(r) = parse_line(&line) {
                    for o in az.feed(&r, &log) {
                        emit(o);
                    }
                }
            }
        }
        for o in az.flush(false) {
            emit(o);
        }
        if !busy {
            std::thread::sleep(Duration::from_millis(1000));
        }
    }
    for o in az.flush(true) {
        emit(o);
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn decoy_secret_url_and_file_fetch() {
        set_decoys(vec![DecoyWeb { id: 7, url_path: "/admin-backup-7f3a9c/".into(), file_name: ".env.backup".into() }]);
        let mut az = Analyzer::new(std::sync::Arc::new(RecentPhp::default()));
        let req = |path: &str| Req { vhost: "shop.example".into(), ip: "203.0.113.9".into(), method: "GET".into(), path: path.into(), query: String::new(), status: 404, size: 10, ua: String::new() };
        let out = az.feed(&req("/admin-backup-7f3a9c/login"), "nginx/access.log");
        assert!(matches!(&out[..], [Out::Detect(d)] if d.rule == "decoy_url" && d.severity == "critical" && d.key == "decoy:7"));
        let out = az.feed(&req("/.env.backup"), "nginx/access.log");
        assert!(matches!(&out[..], [Out::Detect(d)] if d.rule == "decoy_fetched"));
        // similar but different path: no hit
        assert!(decoy_hit("/admin-backup-7f3a9").is_none());
        set_decoys(Vec::new());
    }

    use super::*;

    const COMBINED: &str = r#"203.0.113.9 - - [15/Nov/2026:10:00:00 +0100] "GET /wp-content/uploads/2026/11/x.php?cmd=id HTTP/1.1" 200 512 "-" "curl/8.0""#;

    #[test]
    fn parses_formats() {
        let r = parse_line(COMBINED).unwrap();
        assert_eq!((r.ip.as_str(), r.method.as_str(), r.path.as_str(), r.query.as_str(), r.status, r.size), ("203.0.113.9", "GET", "/wp-content/uploads/2026/11/x.php", "cmd=id", 200, 512));
        assert_eq!(r.ua, "curl/8.0");
        let v = parse_line(r#"shop.example:443 2001:db8::7 - - [15/Nov/2026:10:00:00 +0100] "POST /wp-login.php HTTP/2.0" 302 0 "https://shop.example/wp-login.php" "Mozilla""#).unwrap();
        assert_eq!((v.vhost.as_str(), v.ip.as_str(), v.status), ("shop.example", "2001:db8::7", 302));
        let c = parse_line(r#"198.51.100.1 - - [15/Nov/2026:10:00:00 +0100] "GET /a%20b.php HTTP/1.0" 404 -"#).unwrap();
        assert_eq!((c.path.as_str(), c.size), ("/a b.php", 0));
        assert!(parse_line("broken").is_none());
        assert!(parse_line(r#"1.2.3.4 - - [x] "\x16\x03\x01" 400 0 "-" "-""#).is_none()); // TLS on an HTTP port
    }

    #[test]
    fn probes_become_statistics_not_alerts() {
        let root = std::env::temp_dir().join(format!("wp-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let mut a = Analyzer::new(Arc::new(RecentPhp::default()));
        a.set_sites(vec![(root.to_string_lossy().into_owned(), String::new())]);
        for p in ["/.env", "/phpmyadmin/index.php", "/does-not-exist.php", "/.git/config"] {
            let st = if p == "/.env" { 200 } else { 404 };
            let r = parse_line(&format!(r#"91.92.93.20 - - [15/Nov/2026:10:00:00 +0100] "GET {p} HTTP/1.1" {st} 900 "-" "x""#)).unwrap();
            assert!(a.feed(&r, "l").is_empty(), "{p}");
        }
        let ok = parse_line(r#"91.92.93.20 - - [15/Nov/2026:10:00:00 +0100] "GET /index.php HTTP/1.1" 200 900 "-" "x""#).unwrap();
        assert!(a.feed(&ok, "l").is_empty());
        let out = a.flush(true);
        let Some(Out::Detect(d)) = out.first() else { panic!("no statistics") };
        assert_eq!((d.rule.as_str(), d.severity.as_str()), ("web_probes", "info"));
        let v: serde_json::Value = serde_json::from_str(&d.detail).unwrap();
        assert_eq!((v["total"].as_u64(), v["ips"][0]["ip"].as_str(), v["ips"][0]["n"].as_u64()), (Some(4), Some("91.92.93.20"), Some(4)));
        assert!(a.flush(true).is_empty()); // reset
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn roots_from_config() {
        let c = "server {\n  server_name shop.example www.shop.example _;\n  root /var/www/shop/public;\n  location / { root $doc; }\n}\n\
                 <VirtualHost *:80>\n  ServerName blog.example:80\n  DocumentRoot \"/srv/blog/\"\n</VirtualHost>\nserver {\n  root /var/www/html;\n}";
        assert_eq!(parse_roots(c), vec!["/var/www/shop/public", "/srv/blog", "/var/www/html"]);
        assert_eq!(
            parse_sites(c),
            vec![
                ("/var/www/shop/public".to_string(), "shop.example, www.shop.example".to_string()),
                ("/srv/blog".to_string(), "blog.example".to_string()),
                ("/var/www/html".to_string(), String::new()),
            ]
        );
    }

    #[test]
    fn sensitive_files() {
        for p in ["/.env", "/.git/config", "/backup.sql.gz", "/wp-config.php.bak", "/wp-config.php~", "/app/etc/env.php.old", "/phpinfo.php", "/server-status"] {
            assert!(sensitive(p).is_some(), "{p}");
        }
        for p in ["/index.php", "/wp-config.php", "/environment.html", "/blog/.envelope", "/test.php"] {
            assert!(sensitive(p).is_none(), "{p}");
        }
    }

    #[test]
    fn webshell_access_and_dedupe() {
        let recent = Arc::new(RecentPhp::default());
        recent.note("/var/www/blog/wp-content/uploads/2026/11/x.php", "php-fpm8.2");
        recent.note("/var/www/blog/readme.txt", "vim"); // not a PHP file
        let mut a = Analyzer::new(recent.clone());
        let r = parse_line(COMBINED).unwrap();
        let out = a.feed(&r, "nginx/access.log");
        let d: Vec<_> = out.iter().filter_map(|o| if let Out::Detect(d) = o { Some(d) } else { None }).collect();
        assert_eq!(d.len(), 1);
        assert_eq!((d[0].rule.as_str(), d[0].severity.as_str()), ("web_new_php_accessed", "critical")); // by the web server
        assert!(d[0].detail.contains("/var/www/blog/wp-content/uploads/2026/11/x.php"));
        assert!(a.feed(&r, "nginx/access.log").is_empty()); // same IP + file: once per hour
        // 404 on the same file: nothing
        let mut r404 = r.clone();
        r404.status = 404;
        r404.ip = "198.51.100.2".into();
        assert!(a.feed(&r404, "x").is_empty());
    }

    #[test]
    fn status_pages_only_with_module_and_not_fallback() {
        let root = std::env::temp_dir().join(format!("si-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let line = |p: &str, sz: u32| parse_line(&format!(r#"91.92.93.30 - - [16/Nov/2026:14:52:38 +0100] "GET {p} HTTP/1.1" 200 {sz} "-" "x""#)).unwrap();
        // Real case: mod_info not loaded, app behind a proxy serves its page everywhere
        let mut a = Analyzer::new(Arc::new(RecentPhp::default()));
        a.roots = vec![root.to_string_lossy().into_owned()];
        a.handlers = (true, false);
        assert!(a.feed(&line("/server-info", 2779), "l").is_empty());
        // mod_status loaded, but the response is as large as the fallback page before (/sendgrid.env)
        assert!(a.feed(&line("/sendgrid.env", 2776), "l").is_empty());
        assert!(a.feed(&line("/server-status", 2779), "l").is_empty());
        // real status page: module loaded, different size → alarm
        let mut b = Analyzer::new(Arc::new(RecentPhp::default()));
        b.roots = a.roots.clone();
        b.handlers = (true, true);
        assert!(matches!(&b.feed(&line("/server-status", 9120), "l")[..], [Out::Detect(d)] if d.severity == "high"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn post_to_upload_and_sensitive() {
        let mut a = Analyzer::new(Arc::new(RecentPhp::default()));
        let p = parse_line(r#"203.0.113.9 - - [15/Nov/2026:10:00:00 +0100] "POST /images/cache/a.php HTTP/1.1" 200 33 "-" "x""#).unwrap();
        assert!(matches!(&a.feed(&p, "l")[..], [Out::Detect(d)] if d.rule == "web_post_php_upload_dir"));
        let e = parse_line(r#"203.0.113.9 - - [15/Nov/2026:10:00:00 +0100] "GET /.env HTTP/1.1" 200 900 "-" "x""#).unwrap();
        // webroot unknown: report, but only "medium"
        assert!(matches!(&a.feed(&e, "l")[..], [Out::Detect(d)] if d.rule == "web_sensitive_file_served" && d.severity == "medium"));
        // webroot known: only if the file exists, then with path
        let root = std::env::temp_dir().join(format!("wr-{}", std::process::id()));
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join(".git/config"), "[core]").unwrap();
        let mut b = Analyzer::new(Arc::new(RecentPhp::default()));
        b.roots = vec![root.to_string_lossy().into_owned()];
        assert!(b.feed(&e, "l").is_empty()); // .env does not exist → home page as fallback, no alarm
        let g = parse_line(r#"203.0.113.9 - - [15/Nov/2026:10:00:00 +0100] "GET /.git/config HTTP/1.1" 200 6 "-" "x""#).unwrap();
        let out = b.feed(&g, "nginx/access.log");
        assert!(matches!(&out[..], [Out::Detect(d)] if d.severity == "high" && d.detail.contains("/.git/config (6 bytes)")));
        // domain from the configuration + directory in the evidence
        let mut c = Analyzer::new(Arc::new(RecentPhp::default()));
        c.set_sites(vec![(root.to_string_lossy().into_owned(), "shop.example".into())]);
        let out = c.feed(&g, "nginx/access.log");
        let Out::Detect(d) = &out[0] else { panic!() };
        assert!(d.detail.contains("Website: shop.example (according to the web server configuration)\n"), "{}", d.detail);
        assert!(d.detail.contains(&format!("Directory: {}/.git\n", root.to_string_lossy())), "{}", d.detail);
        let t = parse_line(r#"203.0.113.9 - - [15/Nov/2026:10:00:00 +0100] "GET /../etc/passwd.sql HTTP/1.1" 200 6 "-" "x""#).unwrap();
        assert!(b.feed(&t, "l").is_empty());
        std::fs::remove_dir_all(&root).ok();
        let e404 = parse_line(r#"203.0.113.9 - - [15/Nov/2026:10:00:00 +0100] "GET /.git/config HTTP/1.1" 404 900 "-" "x""#).unwrap();
        assert!(a.feed(&e404, "l").is_empty());
    }

    #[test]
    fn wordpress_logins_aggregate_and_flush_before_success() {
        let mut a = Analyzer::new(Arc::new(RecentPhp::default()));
        let fail = parse_line(r#"shop.example:443 203.0.113.9 - - [15/Nov/2026:10:00:00 +0100] "POST /wp-login.php HTTP/1.1" 200 4000 "-" "x""#).unwrap();
        for _ in 0..30 {
            assert!(a.feed(&fail, "l").is_empty());
        }
        let ok = parse_line(r#"shop.example:443 203.0.113.9 - - [15/Nov/2026:10:01:00 +0100] "POST /wp-login.php HTTP/1.1" 302 0 "-" "x""#).unwrap();
        let out = a.feed(&ok, "l");
        let l: Vec<_> = out.iter().filter_map(|o| if let Out::Login(l) = o { Some(l) } else { None }).collect();
        assert_eq!(l.len(), 2);
        assert_eq!((l[0].success, l[0].count, l[0].service.as_str()), (false, 30, "wordpress"));
        assert!(l[1].success && l[1].user == "shop.example");
        // website redirects everything the same way (302, ~5450 bytes): a 302 on wp-login.php is then not a success
        let mut b = Analyzer::new(Arc::new(RecentPhp::default()));
        let x = parse_line(r#"91.92.93.9 - - [21/Nov/2026:01:49:09 +0100] "POST /xmlrpc.php HTTP/1.1" 302 5451 "-" "x""#).unwrap();
        let w = parse_line(r#"91.92.93.9 - - [21/Nov/2026:01:49:10 +0100] "POST /wp-login.php HTTP/1.1" 302 5450 "-" "x""#).unwrap();
        b.feed(&x, "www_at_access.log");
        b.feed(&w, "www_at_access.log");
        let l: Vec<_> = b.flush(true).into_iter().filter_map(|o| if let Out::Login(l) = o { Some(l) } else { None }).collect();
        assert!(!l.is_empty() && l.iter().all(|l| !l.success), "{l:?}");
        // GET on wp-login.php (form) does not count
        let get = parse_line(r#"203.0.113.9 - - [15/Nov/2026:10:00:00 +0100] "GET /wp-login.php HTTP/1.1" 200 4000 "-" "x""#).unwrap();
        assert!(a.feed(&get, "l").is_empty() && a.flush(true).is_empty());
    }

    #[test]
    fn log_open_refuses_fifo_and_symlinks_in_writable_dirs() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("weblog-open-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap(); // writable by everyone
        let real = dir.join("real.log");
        std::fs::write(&real, "x\n").unwrap();
        assert!(open_log(real.to_str().unwrap()).is_some(), "regular file");
        let secret = std::env::temp_dir().join(format!("weblog-secret-{}", std::process::id()));
        std::fs::write(&secret, "secret\n").unwrap();
        let link = dir.join("access.log");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        assert!(open_log(link.to_str().unwrap()).is_none(), "symlink in a writable directory");
        let fifo = dir.join("fifo.log");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        assert!(open_log(fifo.to_str().unwrap()).is_none(), "FIFO does not block and is rejected");
        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_file(&secret).ok();
    }

    #[test]
    fn tail_follows_rotation() {
        let dir = std::env::temp_dir().join(format!("weblog-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("access.log");
        std::fs::write(&p, "old\n").unwrap();
        let mut t = Tail::open(p.to_str().unwrap()).unwrap();
        use std::io::Write;
        std::fs::OpenOptions::new().append(true).open(&p).unwrap().write_all(b"one\ntw").unwrap();
        assert_eq!(t.lines(), vec!["one"]);
        std::fs::OpenOptions::new().append(true).open(&p).unwrap().write_all(b"o\n\xff\xfe broken\n").unwrap();
        assert_eq!(t.lines().len(), 2);
        std::fs::rename(&p, dir.join("access.log.1")).unwrap();
        std::fs::write(&p, "new\n").unwrap();
        assert!(t.lines().is_empty()); // detects rotation …
        assert_eq!(t.lines(), vec!["new"]); // … and reads the new file from the start
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recent_php_persistence() {
        let r = RecentPhp::default();
        r.note("/var/www/a/x.php", "php-fpm");
        r.note("/etc/x.php", "vim"); // not a web directory
        let f = std::env::temp_dir().join(format!("recent-{}.json", std::process::id()));
        r.save(f.to_str().unwrap());
        let r2 = RecentPhp::default();
        r2.load(f.to_str().unwrap());
        assert!(r2.find("/x.php").is_some());
        assert!(r2.find("/etc/x.php").is_none());
        let _ = std::fs::remove_file(f);
    }
}
