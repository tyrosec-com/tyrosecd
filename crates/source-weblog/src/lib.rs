//! Access-Logs von nginx und Apache (Plan C2, Runde 3).
//!
//! Der Agent wertet die Logs selbst aus und meldet nur Befunde – keine ganzen Logs (Datenmenge,
//! Besucher-IPs). Erkannt werden:
//! - **Aufruf einer neu angelegten PHP-Datei** (aus der Dateiüberwachung der letzten 7 Tage) → Webshell wird benutzt
//! - **POST auf PHP in Upload-Ordnern**
//! - **Sensible Datei ausgeliefert** (200 auf `.env`, `.git/`, Datenbank-Dumps, Backups, phpinfo …)
//! - **WordPress-Logins**: Fehlversuche je IP zusammengefasst, Erfolg einzeln → Kette „Brute-Force → Login“ in der Zentrale
//!
//! Formate: combined / common, optional mit vorangestelltem `vhost:port` (vhost_combined).
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

/// Köder (Plan „Köder-Zugangsdaten“): geheime Adresse und Dateiname je Köder, gesetzt vom Agenten beim Start und nach
/// jedem Anlegen/Entfernen. Die geheime Adresse steht nur in der Köder-Datei – wer sie aufruft, hat die Datei gelesen.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DecoyWeb {
    pub id: u64,
    /// z. B. „/admin-backup-7f3a/“ (immer mit zufälligem Teil), leer = keine geheime Adresse
    pub url_path: String,
    /// Dateiname der Köder-Datei (Abruf über das Web = Scanner, kein Einbruch)
    pub file_name: String,
}

static DECOYS: std::sync::RwLock<Vec<DecoyWeb>> = std::sync::RwLock::new(Vec::new());

pub fn set_decoys(v: Vec<DecoyWeb>) {
    *DECOYS.write().unwrap_or_else(|e| e.into_inner()) = v;
}

/// Treffer einer Anfrage auf einen Köder: (Köder, true = geheime Adresse, false = Köder-Datei abgerufen)
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

/// Eine Anfrage aus dem Access-Log.
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

/// URL-Dekodierung (%xx), ungültige Folgen bleiben stehen.
fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            // %00 bleibt stehen (Null-Zeichen bricht Datenbank/JSON und ist ohnehin ein Angriffsmuster)
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

/// Dateien, die nie öffentlich ausgeliefert werden sollten (Status 200 mit Inhalt = Datenleck).
pub fn sensitive(path: &str) -> Option<&'static str> {
    let l = path.to_ascii_lowercase();
    let name = l.rsplit('/').next().unwrap_or("");
    if name == ".env" || name.starts_with(".env.") {
        return Some("Umgebungsdatei mit Zugangsdaten (.env)");
    }
    if l.contains("/.git/") || l.ends_with("/.git") {
        return Some("Git-Verzeichnis (Quellcode, Zugangsdaten)");
    }
    if l.contains("/.svn/") || name == ".htpasswd" || name == ".htaccess.bak" {
        return Some("Versionsverwaltung bzw. Passwortdatei");
    }
    if [".sql", ".sql.gz", ".sql.zip", ".sql.bz2", ".dump"].iter().any(|e| name.ends_with(e)) {
        return Some("Datenbank-Dump");
    }
    if ["wp-config", "config", "configuration", "env.php", "settings.php", "localsettings.php", "parameters"].iter().any(|b| name.starts_with(b))
        && [".bak", ".old", ".orig", ".save", ".swp", "~", ".txt", ".backup", ".1"].iter().any(|e| name.ends_with(e))
    {
        return Some("Sicherungskopie einer Konfigurationsdatei");
    }
    if ["backup.zip", "backup.tar.gz", "backup.tgz", "site.zip", "www.zip", "htdocs.zip", "public_html.zip", "backup.sql"].contains(&name) {
        return Some("Komplett-Sicherung");
    }
    if ["phpinfo.php", "info.php", "php_info.php"].contains(&name) {
        return Some("phpinfo() (Serverdetails)");
    }
    if l == "/server-status" || l == "/server-info" {
        return Some("Apache-Statusseite");
    }
    None
}

fn in_upload_dir(p: &str) -> bool {
    let l = p.to_ascii_lowercase();
    ["/uploads/", "/upload/", "/images/", "/media/", "/files/", "/tmp/", "/cache/", "/assets/"].iter().any(|d| l.contains(d))
}

/// Neu angelegte PHP-Dateien aus der Dateiüberwachung (Pfad → (Zeitpunkt, anlegender Prozess)), 7 Tage.
#[derive(Default)]
pub struct RecentPhp {
    files: Mutex<HashMap<String, (i64, String)>>,
}

impl RecentPhp {
    pub const KEEP_S: i64 = 7 * 86400;

    /// Datei-Ereignis aufnehmen (nur angelegte/umbenannte PHP-Dateien in Web-Verzeichnissen)
    pub fn note(&self, path: &str, comm: &str) {
        if !is_php(path) || !(path.starts_with("/var/www/") || path.starts_with("/srv/") || path.starts_with("/home/")) {
            return;
        }
        let mut f = self.files.lock().unwrap();
        if f.len() >= 20_000 {
            let cut = now_s() - Self::KEEP_S;
            f.retain(|_, (t, _)| *t > cut);
            if f.len() >= 20_000 {
                return; // z. B. große Deploys ohne Markierung – Speicher begrenzen
            }
        }
        f.insert(path.to_string(), (now_s(), comm.to_string()));
    }

    /// Passt der URL-Pfad (Ende des Dateipfads) zu einer neu angelegten Datei?
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

/// Ergebnis der Auswertung einer Zeile.
#[derive(Debug)]
pub enum Out {
    Detect(Detection),
    Login(LoginEvent),
}

/// Auswertung über alle Logs hinweg (Fehlversuche je IP, Entdopplung, Begrenzung).
pub struct Analyzer {
    recent: Arc<RecentPhp>,
    /// Webroots aus der Webserver-Konfiguration; leer = unbekannt (dann wird nicht geprüft)
    pub roots: Vec<String>,
    /// Webroot → Domain(s) aus `server_name`/`ServerName` bzw. Plesk-Ordnername
    pub sites: HashMap<String, String>,
    logins: tyrosd_source_auth::Aggregator,
    seen: HashMap<String, Instant>,
    budget: (Instant, u32),
    /// Abklopfen durch Scanner (IP → (Anzahl, Pfad → Anzahl)), alle 10 min als Statistik gemeldet
    probes: HashMap<String, (u32, HashMap<String, u32>)>,
    probes_since: Instant,
    /// Apache-Module für /server-status und /server-info geladen? (status, info)
    pub handlers: (bool, bool),
    /// je Website: Größen der Ersatzseite, die für nicht vorhandene Adressen mit 200 ausgeliefert wird
    fallback: HashMap<String, Vec<u64>>,
    /// Größen von 302-Antworten auf andere Anfragen als den Login, je Website/Log („leitet alles um“, z. B. Plugins,
    /// die wp-login.php verbergen – Praxisfall: eine Website antwortet auf alles mit 302 → /)
    redirects: HashMap<String, Vec<u64>>,
}

/// Lädt Apache mod_status / mod_info? Ohne Apache-Konfiguration (z. B. nur nginx) gibt es beide Seiten nicht.
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

/// Typische Scanner-Ziele, die nicht als „sensibel ausgeliefert“ zählen (Admin-Tools, Exploits bekannter Software)
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
        // dieselbe Meldung höchstens einmal je Stunde; höchstens MAX_PER_MIN Meldungen je Minute
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

    /// Domain zum längsten passenden Webroot einer Datei
    fn site_for(&self, file: &str) -> Option<String> {
        self.sites
            .iter()
            .filter(|(root, _)| file.starts_with(&format!("{root}/")))
            .max_by_key(|(root, _)| root.len())
            .map(|(_, n)| n.clone())
    }

    /// Webroots und Domains übernehmen (aus `docroots()`)
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
        let site = if r.vhost.is_empty() { String::new() } else { format!(" auf {}", r.vhost) };
        let who = format!("{} {} {}{site} → {} ({})", r.ip, r.method, r.path, r.status, log);

        // 0. Köder: geheime Adresse aufgerufen (Zugangsdaten aus der Köder-Datei benutzt) bzw. Köder-Datei abgerufen
        if let Some((d, secret)) = decoy_hit(&r.path) {
            if self.once(&format!("decoy|{}|{}|{secret}", d.id, r.ip)) {
                out.push(if secret {
                    Self::detection("decoy_url", "critical", "Köder-Adresse aufgerufen: Zugangsdaten aus der Köder-Datei benutzt",
                        format!("{who}
Köder #{}", d.id), format!("decoy:{}", d.id))
                } else {
                    Self::detection("decoy_fetched", "low", "Köder-Datei über das Web abgerufen (Scanner)",
                        format!("{who}
Köder #{}", d.id), format!("decoy:{}", d.id))
                });
            }
            return out;
        }

        // 1. neu angelegte PHP-Datei wird aufgerufen
        if ok {
            if let Some((file, t, comm)) = self.recent.find(&r.path) {
                if self.once(&format!("new_php|{file}|{}", r.ip)) {
                    let by_web = web_process(&comm);
                    let age_h = (now_s() - t) / 3600;
                    out.push(Self::detection(
                        "web_new_php_accessed",
                        if by_web { "critical" } else { "high" },
                        "Neu angelegte PHP-Datei wird aufgerufen (Webshell?)",
                        format!("{who}\nDatei {file}, angelegt vor {age_h} h{}", if comm.is_empty() { String::new() } else { format!(" von {comm}") }),
                        format!("{file}|{}", r.ip),
                    ));
                }
            }
        }
        // 2. POST auf PHP in Upload-/Medien-Ordnern
        if r.method == "POST" && ok && is_php(&r.path) && in_upload_dir(&r.path) && self.once(&format!("post_upload|{}|{}", r.path, r.ip)) {
            out.push(Self::detection("web_post_php_upload_dir", "high", "POST auf PHP-Datei im Upload-Ordner", who.clone(), format!("{}|{}", r.path, r.ip)));
        }
        // 3. sensible Datei ausgeliefert – nur wenn sie wirklich auf der Platte liegt. Viele Anwendungen
        //    (WordPress, Laravel, Shops) liefern für jede unbekannte Adresse die Startseite mit 200 aus;
        //    das ist kein Datenleck.
        if r.status == 200 && r.size > 0 && matches!(r.method.as_str(), "GET" | "HEAD" | "POST") {
            if let Some(what) = sensitive(&r.path) {
                // Statusseiten nur, wenn das Modul geladen ist und die Antwort nicht die übliche Ersatzseite
                // der Website ist (Apps hinter Proxy beantworten jede Adresse mit ihrer Startseite)
                let handler = match r.path.as_str() {
                    "/server-status" => self.handlers.0,
                    "/server-info" => self.handlers.1,
                    _ => false,
                } && !self.is_fallback(r);
                let file = if handler || self.roots.is_empty() { None } else { locate(&self.roots, &r.path) };
                let real = handler || file.is_some();
                if !real && !self.roots.is_empty() {
                    self.note_fallback(r);
                    self.probe(r); // kein echtes Datenleck: nur Statistik
                }
                if (real || self.roots.is_empty()) && self.once(&format!("sensitive|{}|{}", r.vhost, r.path)) {
                    let mut d = format!("{what}\n");
                    // Website: aus dem Log (vhost_combined), sonst aus der Konfiguration zum Webroot der Datei
                    let site = if !r.vhost.is_empty() {
                        Some(r.vhost.clone())
                    } else {
                        file.as_ref().and_then(|(f, _)| self.site_for(f)).map(|n| format!("{n} (laut Webserver-Konfiguration)"))
                    };
                    if let Some(s) = &site {
                        d.push_str(&format!("Website: {s}\n"));
                    }
                    match &file {
                        Some((f, sz)) => {
                            let dir = f.rsplit_once('/').map(|(d, _)| d).filter(|d| !d.is_empty()).unwrap_or("/");
                            d.push_str(&format!("Datei auf dem Server: {f} ({sz} Bytes)\nVerzeichnis: {dir}\n"));
                        }
                        None if !handler => d.push_str("Datei auf dem Server: nicht geprüft (Webroot unbekannt)\n"),
                        None => {}
                    }
                    d.push_str(&format!("Anfrage: {} {} → {}, {} Bytes ausgeliefert\n", r.method, r.path, r.status, r.size));
                    d.push_str(&format!("Von: {}\nLog: {log}", r.ip));
                    out.push(Self::detection(
                        "web_sensitive_file_served",
                        if real { "high" } else { "medium" },
                        "Sensible Datei öffentlich ausgeliefert",
                        d,
                        format!("{}|{}", r.vhost, r.path),
                    ));
                }
            }
        }
        // Abklopfen: Scanner-Pfade und nicht vorhandene PHP-Dateien (4xx) zählen nur für die Statistik
        if (400..500).contains(&r.status) && sensitive(&r.path).is_none() && (scanner_path(&r.path) || (r.status == 404 && is_php(&r.path))) {
            self.probe(r);
        } else if (400..500).contains(&r.status) && sensitive(&r.path).is_some() {
            self.probe(r);
        }
        // 4. WordPress-Login: POST wp-login.php → 302 = Erfolg, 200 = falsches Passwort; xmlrpc = Versuch.
        // Ausnahme: Die Website leitet auch andere Anfragen mit einer gleich großen 302-Antwort um – dann ist das 302 des
        // Logins keine Anmeldung, sondern die allgemeine Umleitung (zählt als Versuch). WordPress selbst leitet nach
        // erfolgreicher Anmeldung mit leerem Inhalt um.
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

    /// Antwortgröße entspricht der Ersatzseite dieser Website (±64 Bytes, z. B. wechselnder CSRF-Token)
    fn is_fallback(&self, r: &Req) -> bool {
        self.fallback.get(&r.vhost).is_some_and(|v| v.iter().any(|s| s.abs_diff(r.size) <= 64))
    }

    fn probe(&mut self, r: &Req) {
        if self.probes.len() >= 5000 && !self.probes.contains_key(&r.ip) {
            return; // Speicher begrenzen
        }
        let e = self.probes.entry(r.ip.clone()).or_default();
        e.0 += 1;
        if e.1.len() < 20 || e.1.contains_key(&r.path) {
            *e.1.entry(r.path.chars().take(120).collect()).or_default() += 1;
        }
    }

    /// Statistik der letzten 10 Minuten (Schwere „info“: die Zentrale macht keinen Alarm daraus)
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
        Some(Self::detection("web_probes", "info", "Abklopfen durch Scanner", detail, format!("probes|{}", now_s())))
    }

    pub fn flush(&mut self, force: bool) -> Vec<Out> {
        let mut out: Vec<Out> = self.logins.flush(force).into_iter().map(Out::Login).collect();
        out.extend(self.probe_stats(force));
        out
    }
}

/// URL-Pfad in den Webroots suchen → (Dateipfad, Größe). Nur echte Dateien, kein „..“.
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

/// Webroots mit Domain(s) aus nginx-/Apache-Konfiguration und Panel-Standardpfaden → [(Webroot, Domains)].
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
    // gleicher Webroot mehrfach: Eintrag mit Domain bevorzugen
    out.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.len().cmp(&a.1.len())));
    out.dedup_by(|a, b| a.0 == b.0);
    out.truncate(500);
    out
}

/// Nur die Webroots (für Tests und einfache Aufrufer)
pub fn parse_roots(conf: &str) -> Vec<String> {
    parse_sites(conf).into_iter().map(|(r, _)| r).collect()
}

/// Je `server { … }` (nginx) bzw. `<VirtualHost>` (Apache): `root`/`DocumentRoot` mit `server_name`/`ServerName`/`ServerAlias`.
/// Pfade mit Variablen und Platzhalter-Namen (`_`, `localhost`) werden übergangen.
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

/// Access-Logs finden: Standardpfade der Distributionen und gängiger Panels.
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

/// Eine überwachte Logdatei (folgt Logrotation über Inode-Wechsel und Kürzung).
struct Tail {
    path: String,
    file: std::fs::File,
    ino: u64,
    pending: Vec<u8>,
}

impl Tail {
    fn open(path: &str) -> Option<Tail> {
        use std::os::unix::fs::MetadataExt;
        let mut file = std::fs::File::open(path).ok()?;
        file.seek(SeekFrom::End(0)).ok()?;
        let ino = file.metadata().ok()?.ino();
        Some(Tail { path: path.to_string(), file, ino, pending: Vec::new() })
    }

    /// Neue vollständige Zeilen (höchstens 4 MB je Aufruf, damit eine Datei nicht alles blockiert)
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
                    if let Ok(nf) = std::fs::File::open(&self.path) {
                        self.file = nf; // rotiert: neue Datei von vorn
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
            self.pending.clear(); // überlange Zeile ohne Umbruch verwerfen
        }
        out
    }
}

/// Logs auswerten bis `stop`; `emit` erhält Befunde und Login-Ereignisse.
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
        // ähnlicher, aber anderer Pfad: kein Treffer
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
        assert!(parse_line("kaputt").is_none());
        assert!(parse_line(r#"1.2.3.4 - - [x] "\x16\x03\x01" 400 0 "-" "-""#).is_none()); // TLS auf HTTP-Port
    }

    #[test]
    fn probes_become_statistics_not_alerts() {
        let root = std::env::temp_dir().join(format!("wp-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let mut a = Analyzer::new(Arc::new(RecentPhp::default()));
        a.set_sites(vec![(root.to_string_lossy().into_owned(), String::new())]);
        for p in ["/.env", "/phpmyadmin/index.php", "/gibtsnicht.php", "/.git/config"] {
            let st = if p == "/.env" { 200 } else { 404 };
            let r = parse_line(&format!(r#"91.92.93.20 - - [15/Nov/2026:10:00:00 +0100] "GET {p} HTTP/1.1" {st} 900 "-" "x""#)).unwrap();
            assert!(a.feed(&r, "l").is_empty(), "{p}");
        }
        let ok = parse_line(r#"91.92.93.20 - - [15/Nov/2026:10:00:00 +0100] "GET /index.php HTTP/1.1" 200 900 "-" "x""#).unwrap();
        assert!(a.feed(&ok, "l").is_empty());
        let out = a.flush(true);
        let Some(Out::Detect(d)) = out.first() else { panic!("keine Statistik") };
        assert_eq!((d.rule.as_str(), d.severity.as_str()), ("web_probes", "info"));
        let v: serde_json::Value = serde_json::from_str(&d.detail).unwrap();
        assert_eq!((v["total"].as_u64(), v["ips"][0]["ip"].as_str(), v["ips"][0]["n"].as_u64()), (Some(4), Some("91.92.93.20"), Some(4)));
        assert!(a.flush(true).is_empty()); // zurückgesetzt
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
        recent.note("/var/www/blog/readme.txt", "vim"); // keine PHP-Datei
        let mut a = Analyzer::new(recent.clone());
        let r = parse_line(COMBINED).unwrap();
        let out = a.feed(&r, "nginx/access.log");
        let d: Vec<_> = out.iter().filter_map(|o| if let Out::Detect(d) = o { Some(d) } else { None }).collect();
        assert_eq!(d.len(), 1);
        assert_eq!((d[0].rule.as_str(), d[0].severity.as_str()), ("web_new_php_accessed", "critical")); // vom Webserver angelegt
        assert!(d[0].detail.contains("/var/www/blog/wp-content/uploads/2026/11/x.php"));
        assert!(a.feed(&r, "nginx/access.log").is_empty()); // gleiche IP + Datei: einmal je Stunde
        // 404 auf dieselbe Datei: nichts
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
        // Praxisfall: mod_info nicht geladen, App hinter Proxy liefert überall ihre Seite
        let mut a = Analyzer::new(Arc::new(RecentPhp::default()));
        a.roots = vec![root.to_string_lossy().into_owned()];
        a.handlers = (true, false);
        assert!(a.feed(&line("/server-info", 2779), "l").is_empty());
        // mod_status geladen, aber Antwort so groß wie die Ersatzseite zuvor (/sendgrid.env)
        assert!(a.feed(&line("/sendgrid.env", 2776), "l").is_empty());
        assert!(a.feed(&line("/server-status", 2779), "l").is_empty());
        // echte Statusseite: Modul geladen, andere Größe → Alarm
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
        // Webroot unbekannt: melden, aber nur „mittel“
        assert!(matches!(&a.feed(&e, "l")[..], [Out::Detect(d)] if d.rule == "web_sensitive_file_served" && d.severity == "medium"));
        // Webroot bekannt: nur wenn die Datei existiert, dann mit Pfad
        let root = std::env::temp_dir().join(format!("wr-{}", std::process::id()));
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join(".git/config"), "[core]").unwrap();
        let mut b = Analyzer::new(Arc::new(RecentPhp::default()));
        b.roots = vec![root.to_string_lossy().into_owned()];
        assert!(b.feed(&e, "l").is_empty()); // .env gibt es nicht → Startseite als Fallback, kein Alarm
        let g = parse_line(r#"203.0.113.9 - - [15/Nov/2026:10:00:00 +0100] "GET /.git/config HTTP/1.1" 200 6 "-" "x""#).unwrap();
        let out = b.feed(&g, "nginx/access.log");
        assert!(matches!(&out[..], [Out::Detect(d)] if d.severity == "high" && d.detail.contains("/.git/config (6 Bytes)")));
        // Domain aus der Konfiguration + Verzeichnis im Beleg
        let mut c = Analyzer::new(Arc::new(RecentPhp::default()));
        c.set_sites(vec![(root.to_string_lossy().into_owned(), "shop.example".into())]);
        let out = c.feed(&g, "nginx/access.log");
        let Out::Detect(d) = &out[0] else { panic!() };
        assert!(d.detail.contains("Website: shop.example (laut Webserver-Konfiguration)\n"), "{}", d.detail);
        assert!(d.detail.contains(&format!("Verzeichnis: {}/.git\n", root.to_string_lossy())), "{}", d.detail);
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
        // Website leitet alles gleich um (302, ~5450 Bytes): 302 auf wp-login.php ist dann kein Erfolg
        let mut b = Analyzer::new(Arc::new(RecentPhp::default()));
        let x = parse_line(r#"91.92.93.9 - - [21/Nov/2026:01:49:09 +0100] "POST /xmlrpc.php HTTP/1.1" 302 5451 "-" "x""#).unwrap();
        let w = parse_line(r#"91.92.93.9 - - [21/Nov/2026:01:49:10 +0100] "POST /wp-login.php HTTP/1.1" 302 5450 "-" "x""#).unwrap();
        b.feed(&x, "www_at_access.log");
        b.feed(&w, "www_at_access.log");
        let l: Vec<_> = b.flush(true).into_iter().filter_map(|o| if let Out::Login(l) = o { Some(l) } else { None }).collect();
        assert!(!l.is_empty() && l.iter().all(|l| !l.success), "{l:?}");
        // GET auf wp-login.php (Formular) zählt nicht
        let get = parse_line(r#"203.0.113.9 - - [15/Nov/2026:10:00:00 +0100] "GET /wp-login.php HTTP/1.1" 200 4000 "-" "x""#).unwrap();
        assert!(a.feed(&get, "l").is_empty() && a.flush(true).is_empty());
    }

    #[test]
    fn tail_follows_rotation() {
        let dir = std::env::temp_dir().join(format!("weblog-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("access.log");
        std::fs::write(&p, "alt\n").unwrap();
        let mut t = Tail::open(p.to_str().unwrap()).unwrap();
        use std::io::Write;
        std::fs::OpenOptions::new().append(true).open(&p).unwrap().write_all(b"eins\nzw").unwrap();
        assert_eq!(t.lines(), vec!["eins"]);
        std::fs::OpenOptions::new().append(true).open(&p).unwrap().write_all(b"ei\n\xff\xfe kaputt\n").unwrap();
        assert_eq!(t.lines().len(), 2);
        std::fs::rename(&p, dir.join("access.log.1")).unwrap();
        std::fs::write(&p, "neu\n").unwrap();
        assert!(t.lines().is_empty()); // erkennt Rotation …
        assert_eq!(t.lines(), vec!["neu"]); // … und liest die neue Datei von vorn
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recent_php_persistence() {
        let r = RecentPhp::default();
        r.note("/var/www/a/x.php", "php-fpm");
        r.note("/etc/x.php", "vim"); // kein Web-Verzeichnis
        let f = std::env::temp_dir().join(format!("recent-{}.json", std::process::id()));
        r.save(f.to_str().unwrap());
        let r2 = RecentPhp::default();
        r2.load(f.to_str().unwrap());
        assert!(r2.find("/x.php").is_some());
        assert!(r2.find("/etc/x.php").is_none());
        let _ = std::fs::remove_file(f);
    }
}
