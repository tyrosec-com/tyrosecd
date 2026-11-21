//! SSH-Anmeldungen (Hauptplan 22, Phase 1).
//!
//! Quellen, ohne zusätzliche Software:
//! - systemd-Journal über `journalctl -f -o json` (vorhanden auf systemd-Systemen)
//! - sonst `/var/log/auth.log` (Debian/Ubuntu) bzw. `/var/log/secure` (RHEL); dort ist das Programmfeld
//!   fälschbar (`logger -t sshd[…]`) – Anmeldungen von dort sind immer `service` = „ssh_unverified“; Zeilen,
//!   deren PID einem fremden Prozess gehört (`SshdCheck`), werden verworfen
//!
//! Erfolgreiche Logins werden sofort gemeldet; Fehlversuche je Quell-IP in
//! Fenstern (Standard 5 min) zusammengefasst – Brute-Force-Wellen sind
//! Dauerzustand und kein Einzelalarm wert (24.9).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use regex::Regex;
use tyrosd_proto::LoginEvent;

pub mod db;

fn now_ns() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as i64).unwrap_or(0)
}

// Sicherheitsprüfung H1: Ausdrücke am Anfang und Ende verankert; der Benutzername ist gierig (`.+`), damit IP und Port
// immer vom **rechten** Ende kommen – ein Benutzer „x from 203.0.113.7 port 1“ kann die Quell-IP nicht fälschen.
fn re_ok() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"^Accepted (\S+) for (.+) from (\S+) port (\d+)(?: ssh2)?(?:: (\S+) (\S+))?$").unwrap()
    })
}
fn re_fail() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^Failed (\S+) for (invalid user )?(.+) from (\S+) port (\d+)(?: ssh2)?(?:: (\S+) (\S+))?$").unwrap())
}
fn re_invalid() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^Invalid user (.*) from (\S+)(?: port (\d+))?$").unwrap())
}

/// Nur echte IP-Adressen (sonst ist die Zeile kein sshd-Format, z. B. Hostname bei UseDNS)
fn ip(s: &str) -> Option<String> {
    s.parse::<std::net::IpAddr>().ok().map(|a| a.to_string())
}

/// Dienstname für alle Anmeldungen aus auth.log/secure (Programmfeld und PID fälschbar, siehe `auth_log_line`).
/// Die Zentrale zählt solche Fehlversuche nicht für automatische Sperren/Bedrohungslisten.
pub const SERVICE_UNVERIFIED: &str = "ssh_unverified";

fn skip_token(s: &str) -> Option<&str> {
    let s = s.trim_start_matches(' ');
    let end = s.find(' ')?;
    (end > 0).then(|| &s[end..])
}

/// Zeile aus auth.log/secure → (PID, Nachricht), nur wenn das **Programmfeld** sshd bzw. sshd-session ist:
/// „Nov 16 10:00:00 host sshd[123]: …“ oder „2026-11-16T10:00:00.1+01:00 host sshd[123]: …“ (verankert – ein
/// „sshd[1]:“ irgendwo in einer fremden Nachricht zählt nicht).
/// Hinweis: In Logdateien kann `logger -t 'sshd[123]'` das Programmfeld fälschen – deshalb prüft `run` zusätzlich
/// den Prozess (`SshdCheck`); das Journal (mit _COMM/_UID) ist die verlässliche Quelle und wird bevorzugt.
pub fn syslog_entry(line: &str) -> Option<(u32, &str)> {
    let mut rest = line;
    // Zeitstempel: RFC 3339 (ein Feld) oder klassisch „Mon dd hh:mm:ss“ (drei Felder)
    let fields = if line.starts_with(|c: char| c.is_ascii_digit()) { 1 } else { 3 };
    for _ in 0..fields + 1 {
        rest = skip_token(rest)?; // … und der Hostname
    }
    let rest = rest.trim_start_matches(' ');
    let rest = rest.strip_prefix("sshd[").or_else(|| rest.strip_prefix("sshd-session["))?;
    let close = rest.find("]: ")?;
    let pid = &rest[..close];
    if pid.is_empty() || pid.len() > 10 || !pid.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((pid.parse().ok()?, &rest[close + 3..]))
}

/// wie `syslog_entry`, nur die Nachricht
pub fn syslog_message(line: &str) -> Option<&str> {
    syslog_entry(line).map(|(_, m)| m)
}

/// Ergebnis der Prozessprüfung für eine auth.log-Zeile
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// PID gehört beim Lesen zu einem sshd-Programm von root, Prozess läuft als uid 0
    Sshd,
    /// PID läuft nicht mehr (oder nicht prüfbar, z. B. Zombie) – Zeile zählt, aber als unbestätigt
    Gone,
    /// PID gehört einem anderen Programm/Benutzer – gefälschte Zeile (`logger -t sshd[…]`), verworfen
    Foreign,
}

/// Prüft die PID einer auth.log-Zeile über /proc (Wurzeln für Tests einstellbar).
pub struct SshdCheck {
    pub proc_root: std::path::PathBuf,
    pub fs_root: std::path::PathBuf,
}

/// erlaubte Orte der sshd-Programme (Debian/Ubuntu, RHEL/Fedora; OpenSSH ≥ 9.8 mit sshd-session)
const SSHD_DIRS: [&str; 3] = ["/usr/sbin", "/usr/lib/openssh", "/usr/libexec/openssh"];

impl Default for SshdCheck {
    fn default() -> Self {
        SshdCheck { proc_root: "/proc".into(), fs_root: "/".into() }
    }
}

impl SshdCheck {
    pub fn check(&self, pid: u32) -> Origin {
        use std::os::unix::fs::MetadataExt;
        if pid == 0 {
            return Origin::Foreign;
        }
        let dir = self.proc_root.join(pid.to_string());
        let Ok(status) = std::fs::read_to_string(dir.join("status")) else {
            return Origin::Gone;
        };
        // reale und effektive uid müssen 0 sein
        let root = status
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .map(|u| u.split_whitespace().take(2).collect::<Vec<_>>())
            .is_some_and(|u| u.len() == 2 && u.iter().all(|x| *x == "0"));
        if !root {
            return Origin::Foreign;
        }
        let Ok(exe) = std::fs::read_link(dir.join("exe")) else {
            return Origin::Gone; // Zombie/beendet während der Prüfung
        };
        let exe = exe.to_string_lossy().into_owned();
        if exe.ends_with(" (deleted)") {
            return Origin::Gone; // Programm nach Update ersetzt – nicht mehr prüfbar
        }
        let p = std::path::Path::new(&exe);
        let name_ok = matches!(p.file_name().and_then(|n| n.to_str()), Some("sshd" | "sshd-session"));
        let dir_ok = p.parent().and_then(|d| d.to_str()).is_some_and(|d| SSHD_DIRS.contains(&d));
        if !name_ok || !dir_ok {
            return Origin::Foreign;
        }
        // Programm gehört root und ist nur für root schreibbar (sonst könnte es jeder ersetzen)
        match std::fs::symlink_metadata(self.fs_root.join(exe.trim_start_matches('/'))) {
            Ok(m) if m.file_type().is_file() && m.uid() == 0 && m.mode() & 0o022 == 0 => Origin::Sshd,
            _ => Origin::Foreign,
        }
    }
}

/// Eintrag aus `journalctl -o json`: nur vom echten sshd (vom Journal gesetzte Felder _COMM und _UID, nicht fälschbar
/// wie SYSLOG_IDENTIFIER per `logger -t sshd`)
pub fn journal_message(v: &serde_json::Value) -> Option<&str> {
    let comm = v.get("_COMM").and_then(|c| c.as_str())?;
    let uid = v.get("_UID").and_then(|u| u.as_str())?;
    if !matches!(comm, "sshd" | "sshd-session") || uid != "0" {
        return None;
    }
    v.get("MESSAGE").and_then(|m| m.as_str())
}

/// Eine Logzeile auswerten.
pub fn parse_line(msg: &str) -> Option<LoginEvent> {
    let msg = msg.trim_end();
    if let Some(c) = re_ok().captures(msg) {
        return Some(LoginEvent {
            service: "ssh".into(),
            success: true,
            method: c[1].to_string(),
            user: c[2].to_string(),
            ip: ip(&c[3])?,
            port: c[4].parse().unwrap_or(0),
            key_type: c.get(5).map(|m| m.as_str().to_string()).unwrap_or_default(),
            key_fp: c.get(6).map(|m| m.as_str().to_string()).unwrap_or_default(),
            count: 1,
            invalid_user: false,
            first_ts_ns: now_ns(),
        });
    }
    if let Some(c) = re_fail().captures(msg) {
        return Some(LoginEvent {
            service: "ssh".into(),
            success: false,
            method: c[1].to_string(),
            invalid_user: c.get(2).is_some(),
            user: c[3].to_string(),
            ip: ip(&c[4])?,
            port: c[5].parse().unwrap_or(0),
            count: 1,
            first_ts_ns: now_ns(),
            ..Default::default()
        });
    }
    if let Some(c) = re_invalid().captures(msg) {
        return Some(LoginEvent {
            service: "ssh".into(),
            success: false,
            method: "none".into(),
            invalid_user: true,
            user: c[1].to_string(),
            ip: ip(&c[2])?,
            port: c.get(3).and_then(|m| m.as_str().parse().ok()).unwrap_or(0),
            count: 1,
            first_ts_ns: now_ns(),
            ..Default::default()
        });
    }
    None
}

/// Fasst Fehlversuche je IP zusammen.
pub struct Aggregator {
    window: Duration,
    fails: HashMap<String, (Instant, LoginEvent)>,
}

impl Aggregator {
    pub fn new(window: Duration) -> Self {
        Aggregator { window, fails: HashMap::new() }
    }

    /// Ereignis aufnehmen; liefert sofort zu sendende Ereignisse.
    pub fn push(&mut self, e: LoginEvent) -> Vec<LoginEvent> {
        if e.success {
            // vorherige Fehlversuche derselben IP zuerst melden (Kontext für „Erfolg nach Brute-Force“)
            let mut out: Vec<LoginEvent> = [e.service.as_str(), SERVICE_UNVERIFIED, "ssh"]
                .iter()
                .filter_map(|s| self.fails.remove(&format!("{s}|{}", e.ip)).map(|(_, f)| f))
                .collect();
            out.push(e);
            return out;
        }
        // bestätigte und unbestätigte Fehlversuche getrennt (sonst färbte ein gefälschter Eintrag echte ein und umgekehrt)
        let key = format!("{}|{}", e.service, e.ip);
        let entry = self.fails.entry(key).or_insert_with(|| (Instant::now(), LoginEvent { count: 0, ..e.clone() }));
        entry.1.count += 1;
        entry.1.invalid_user |= e.invalid_user;
        if entry.1.user != e.user {
            entry.1.user = "*".into(); // verschiedene Benutzernamen (typisch für Scanner)
        }
        Vec::new()
    }

    /// Abgelaufene Fenster ausgeben.
    pub fn flush(&mut self, force: bool) -> Vec<LoginEvent> {
        let w = self.window;
        let keys: Vec<String> = self.fails.iter().filter(|(_, (t, _))| force || t.elapsed() >= w).map(|(k, _)| k.clone()).collect();
        keys.into_iter().filter_map(|k| self.fails.remove(&k).map(|(_, e)| e)).collect()
    }
}

/// auth.log-Zeile → Anmeldung, **immer** mit `service` = `SERVICE_UNVERIFIED` („ssh_unverified“), ab Agent 0.4.10:
/// Die PID im Programmfeld ist frei wählbar – `logger -t 'sshd[<PID des sshd-Masters>]'`
/// trifft einen dauerhaft laufenden, echten sshd. Die Prozessprüfung sortiert deshalb nur offensichtlich gefälschte
/// Zeilen aus (PID gehört einem anderen Programm/Benutzer → verworfen), bestätigt aber nichts. Bestätigte Anmeldungen
/// kommen nur aus dem Journal (_COMM/_UID).
pub fn auth_log_line(check: &SshdCheck, line: &str) -> Option<LoginEvent> {
    let (pid, msg) = syslog_entry(line)?;
    let mut e = parse_line(msg)?; // erst parsen: /proc nur für echte Anmeldezeilen
    if check.check(pid) == Origin::Foreign {
        return None;
    }
    e.service = SERVICE_UNVERIFIED.into();
    Some(e)
}

/// Liest Anmeldungen und ruft `emit` für jedes zu sendende Ereignis auf.
/// Blockiert bis `stop`.
pub fn run(stop: Arc<AtomicBool>, emit: impl Fn(LoginEvent) + Send + 'static) {
    let has_journal = std::path::Path::new("/run/systemd/journal").exists() && which("journalctl");
    // Anmeldungen: aus dem Journal bestätigt (_COMM/_UID), aus auth.log immer unbestätigt (`auth_log_line`)
    let (tx, rx) = std::sync::mpsc::channel::<LoginEvent>();
    if has_journal {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let child = Command::new("journalctl")
                // Feldfilter auf vom Journal selbst gesetzte Felder: gleiche Felder = ODER, verschiedene = UND
                .args(["-f", "-n", "0", "-o", "json", "_COMM=sshd", "_COMM=sshd-session", "_UID=0"])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn();
            let Ok(mut child) = child else { return };
            let out = child.stdout.take().unwrap();
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                    if let Some(m) = journal_message(&v) {
                        if let Some(e) = parse_line(m) {
                            if tx.send(e).is_err() {
                                break;
                            }
                        }
                    }
                }
            }
            let _ = child.kill();
        });
    } else if let Some(path) = ["/var/log/auth.log", "/var/log/secure"].into_iter().find(|p| std::path::Path::new(p).exists()) {
        let tx = tx.clone();
        let stop = stop.clone();
        let check = SshdCheck::default();
        std::thread::spawn(move || tail(path, &stop, |l| match auth_log_line(&check, &l) {
            Some(e) => tx.send(e).is_ok(),
            None => true,
        }));
    }
    // Datenbanken (Köder-Benutzer, Plan Köder Phase 2): Journal der DB-Units und übliche Protokolldateien
    if has_journal {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let child = Command::new("journalctl")
                .args(["-f", "-n", "0", "-o", "json", "-u", "postgresql*", "-u", "mariadb*", "-u", "mysql*"])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn();
            let Ok(mut child) = child else { return };
            let out = child.stdout.take().unwrap();
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
                let Some(svc) = v.get("_SYSTEMD_UNIT").and_then(|u| u.as_str()).and_then(db::service_of_unit) else { continue };
                if let Some(e) = v.get("MESSAGE").and_then(|m| m.as_str()).and_then(|m| db::parse_line(svc, m)) {
                    if tx.send(e).is_err() {
                        break;
                    }
                }
            }
            let _ = child.kill();
        });
    }
    for (path, svc) in db::log_files() {
        let tx = tx.clone();
        let stop = stop.clone();
        std::thread::spawn(move || tail(&path, &stop, |l| match db::parse_line(svc, &l) {
            Some(e) => tx.send(e).is_ok(),
            None => true,
        }));
    }
    drop(tx);
    let mut agg = Aggregator::new(Duration::from_secs(300));
    // Datenbank-Fehlanmeldungen einzeln (Benutzername zählt), je Dienst und Benutzer höchstens einmal je Minute
    let mut db_seen: HashMap<String, Instant> = HashMap::new();
    loop {
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(e) if matches!(e.service.as_str(), "postgresql" | "mysql") => {
                let k = format!("{}|{}", e.service, e.user);
                if !db_seen.get(&k).is_some_and(|t| t.elapsed() < Duration::from_secs(60)) {
                    if db_seen.len() > 1000 {
                        db_seen.retain(|_, t| t.elapsed() < Duration::from_secs(60));
                    }
                    db_seen.insert(k, Instant::now());
                    emit(e);
                }
            }
            Ok(e) => {
                for x in agg.push(e) {
                    emit(x);
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => {
                // keine Quelle: nur warten
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        let stopping = stop.load(Ordering::Relaxed);
        for x in agg.flush(stopping) {
            emit(x);
        }
        if stopping {
            return;
        }
    }
}

fn which(bin: &str) -> bool {
    std::env::var("PATH")
        .unwrap_or_else(|_| "/usr/sbin:/usr/bin:/sbin:/bin".into())
        .split(':')
        .any(|d| std::path::Path::new(d).join(bin).is_file())
}

/// `tail -F`: folgt der Datei auch über Logrotation (Inode-Wechsel).
fn tail(path: &str, stop: &AtomicBool, mut f: impl FnMut(String) -> bool) {
    use std::os::unix::fs::MetadataExt;
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let _ = file.seek(SeekFrom::End(0));
    let mut ino = file.metadata().map(|m| m.ino()).unwrap_or(0);
    let mut buf = String::new();
    let mut pending = String::new();
    while !stop.load(Ordering::Relaxed) {
        buf.clear();
        let n = file.read_to_string(&mut buf).unwrap_or(0);
        if n > 0 {
            pending.push_str(&buf);
            while let Some(i) = pending.find('\n') {
                let line: String = pending.drain(..=i).collect();
                if !f(line.trim_end().to_string()) {
                    return;
                }
            }
            continue;
        }
        std::thread::sleep(Duration::from_millis(500));
        if let Ok(m) = std::fs::metadata(path) {
            if m.ino() != ino || m.len() < file.stream_position().unwrap_or(0) {
                if let Ok(nf) = std::fs::File::open(path) {
                    file = nf;
                    ino = m.ino();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_openssh() {
        let e = parse_line("Accepted publickey for root from 203.0.113.5 port 51234 ssh2: ED25519 SHA256:abcDEF123").unwrap();
        assert!(e.success);
        assert_eq!((e.user.as_str(), e.ip.as_str(), e.method.as_str()), ("root", "203.0.113.5", "publickey"));
        assert_eq!(e.key_fp, "SHA256:abcDEF123");
        let e = parse_line("Accepted password for deploy from 2001:db8::1 port 2222 ssh2").unwrap();
        assert_eq!((e.method.as_str(), e.ip.as_str()), ("password", "2001:db8::1"));
        let e = parse_line("Failed password for invalid user admin from 198.51.100.7 port 4000 ssh2").unwrap();
        assert!(!e.success && e.invalid_user && e.user == "admin");
        let e = parse_line("Invalid user oracle from 198.51.100.8 port 5000").unwrap();
        assert!(e.invalid_user && e.user == "oracle");
        assert!(parse_line("Connection closed by 1.2.3.4 port 22").is_none());
    }

    #[test]
    fn username_cannot_spoof_ip() {
        // Angreifer wählt den Benutzernamen „x from 203.0.113.7 port 1“ – maßgeblich ist die IP am Zeilenende
        let e = parse_line("Invalid user x from 203.0.113.7 port 1 from 198.51.100.9 port 40000").unwrap();
        assert_eq!(e.ip, "198.51.100.9");
        assert_eq!(e.user, "x from 203.0.113.7 port 1");
        let e = parse_line("Failed password for invalid user x from 203.0.113.7 port 1 ssh2 from 198.51.100.9 port 40001 ssh2").unwrap();
        assert_eq!((e.ip.as_str(), e.port), ("198.51.100.9", 40001));
        let e = parse_line("Failed publickey for root from 198.51.100.9 port 40002 ssh2: RSA SHA256:abc").unwrap();
        assert_eq!(e.ip, "198.51.100.9");
        // Text nach dem sshd-Format (z. B. angehängt) oder davor → keine Anmeldung
        assert!(parse_line("Accepted password for root from 203.0.113.7 port 22 ssh2 trailing junk here").is_none());
        assert!(parse_line("evil: Accepted password for root from 203.0.113.7 port 22 ssh2").is_none());
        assert!(parse_line("Failed password for root from not-an-ip port 22 ssh2").is_none());
    }

    #[test]
    fn only_real_sshd_sources() {
        let j = |comm: &str, uid: &str| serde_json::json!({"_COMM": comm, "_UID": uid, "SYSLOG_IDENTIFIER": "sshd", "MESSAGE": "Accepted password for root from 203.0.113.7 port 22 ssh2"});
        assert!(journal_message(&j("sshd", "0")).is_some());
        assert!(journal_message(&j("sshd-session", "0")).is_some());
        // logger -t sshd: _COMM=logger
        assert!(journal_message(&j("logger", "0")).is_none());
        // Programm namens „sshd“ eines normalen Benutzers
        assert!(journal_message(&j("sshd", "33")).is_none());
        assert!(journal_message(&serde_json::json!({"MESSAGE": "Accepted password for root from 1.2.3.4 port 1 ssh2"})).is_none());
        // Logdatei
        assert_eq!(
            syslog_message("Nov 16 10:00:00 web1 sshd[1234]: Accepted publickey for root from 203.0.113.5 port 51234 ssh2"),
            Some("Accepted publickey for root from 203.0.113.5 port 51234 ssh2")
        );
        assert!(syslog_message("Nov 16 10:00:00 web1 cron[1]: Accepted password for root from 1.2.3.4 port 1 ssh2").is_none());
        assert!(syslog_message("Nov 16 10:00:00 web1 sshd[x]: Accepted password for root from 1.2.3.4 port 1 ssh2").is_none());
    }

    #[test]
    fn syslog_program_field_is_anchored() {
        assert_eq!(syslog_entry("Nov  6 10:00:00 web1 sshd[77]: Failed password for root from 1.2.3.4 port 1 ssh2").map(|x| x.0), Some(77));
        assert_eq!(
            syslog_entry("2026-11-16T10:00:00.123456+01:00 web1 sshd-session[1234]: Accepted publickey for root from 203.0.113.5 port 5 ssh2"),
            Some((1234, "Accepted publickey for root from 203.0.113.5 port 5 ssh2"))
        );
        // „sshd[…]:“ nur als Teil einer fremden Nachricht
        assert!(syslog_entry("Nov 16 10:00:00 web1 cron[1]: x sshd[1]: Accepted password for root from 1.2.3.4 port 1 ssh2").is_none());
        assert!(syslog_entry("Nov 16 10:00:00 web1 evilsshd[1]: Accepted password for root from 1.2.3.4 port 1 ssh2").is_none());
        assert!(syslog_entry("Nov 16 10:00:00 web1 sshd[]: Accepted password for root from 1.2.3.4 port 1 ssh2").is_none());
        assert!(syslog_entry("sshd[1]: Accepted password for root from 1.2.3.4 port 1 ssh2").is_none());
    }

    /// Falsches /proc (pid, Uid-Werte, Ziel von exe) und Dateisystem (Programm, Rechte)
    fn fake_root(name: &str, procs: &[(u32, &str, &str)], bins: &[(&str, u32)]) -> (SshdCheck, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("auth-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        for (pid, uid, exe) in procs {
            let d = base.join("proc").join(pid.to_string());
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("status"), format!("Name:{t}sshd\nPid:{t}{pid}\nUid:{t}{uid}\nGid:{t}0\t0\t0\t0\n", t = '\t')).unwrap();
            std::os::unix::fs::symlink(exe, d.join("exe")).unwrap();
        }
        for (bin, mode) in bins {
            let p = base.join("fs").join(bin.trim_start_matches('/'));
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, "ELF").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(*mode)).unwrap();
        }
        (SshdCheck { proc_root: base.join("proc"), fs_root: base.join("fs") }, base)
    }

    #[test]
    fn auth_log_lines_need_real_sshd_process() {
        use std::os::unix::fs::MetadataExt;
        let (c, base) = fake_root(
            "proc",
            &[
                (100, "0\t0\t0\t0", "/usr/sbin/sshd"),
                (101, "0\t0\t0\t0", "/usr/lib/openssh/sshd-session"),
                (200, "1000\t1000\t1000\t1000", "/usr/sbin/sshd"), // Prozess eines Benutzers
                (201, "1000\t0\t0\t0", "/usr/sbin/sshd"),           // nur effektiv root
                (300, "0\t0\t0\t0", "/usr/bin/logger"),
                (301, "0\t0\t0\t0", "/tmp/sshd"),
                (302, "0\t0\t0\t0", "/usr/sbin/sshd-session"), // Programm für alle schreibbar
                (303, "0\t0\t0\t0", "/usr/sbin/sshd (deleted)"),
            ],
            &[("/usr/sbin/sshd", 0o755), ("/usr/lib/openssh/sshd-session", 0o755), ("/usr/sbin/sshd-session", 0o777), ("/tmp/sshd", 0o755), ("/usr/bin/logger", 0o755)],
        );
        let root_owned = std::fs::metadata(base.join("fs/usr/sbin/sshd")).unwrap().uid() == 0;
        if root_owned {
            assert_eq!(c.check(100), Origin::Sshd);
            assert_eq!(c.check(101), Origin::Sshd);
        }
        assert_eq!(c.check(200), Origin::Foreign);
        assert_eq!(c.check(201), Origin::Foreign);
        assert_eq!(c.check(300), Origin::Foreign);
        assert_eq!(c.check(301), Origin::Foreign);
        assert_eq!(c.check(302), Origin::Foreign);
        assert_eq!(c.check(303), Origin::Gone);
        assert_eq!(c.check(999), Origin::Gone);
        assert_eq!(c.check(0), Origin::Foreign);

        let line = |pid: u32| format!("Nov 16 10:00:00 web1 sshd[{pid}]: Failed password for root from 198.51.100.7 port 4000 ssh2");
        if root_owned {
            // auch die PID eines echten, laufenden sshd bestätigt nichts (logger -t 'sshd[<Master-PID>]')
            for pid in [100, 101] {
                assert_eq!(auth_log_line(&c, &line(pid)).unwrap().service, SERVICE_UNVERIFIED);
            }
        }
        // logger -t 'sshd[300]' eines Benutzers bzw. fremdes Programm → verworfen
        assert!(auth_log_line(&c, &line(200)).is_none());
        assert!(auth_log_line(&c, &line(300)).is_none());
        // PID schon weg → angenommen, aber unbestätigt
        let e = auth_log_line(&c, &line(999)).unwrap();
        assert_eq!((e.service.as_str(), e.ip.as_str()), (SERVICE_UNVERIFIED, "198.51.100.7"));
        // keine Anmeldezeile → gar nicht erst geprüft
        assert!(auth_log_line(&c, "Nov 16 10:00:00 web1 sshd[999]: Connection closed by 1.2.3.4 port 22").is_none());
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn unverified_failures_are_aggregated_separately() {
        let mut a = Aggregator::new(Duration::from_secs(300));
        let fail = |svc: &str| LoginEvent { service: svc.into(), ..parse_line("Failed password for root from 198.51.100.7 port 1 ssh2").unwrap() };
        a.push(fail("ssh"));
        for _ in 0..50 {
            a.push(fail(SERVICE_UNVERIFIED));
        }
        let mut out = a.flush(true);
        out.sort_by(|x, y| x.service.cmp(&y.service));
        assert_eq!(out.len(), 2);
        assert_eq!((out[0].service.as_str(), out[0].count), ("ssh", 1));
        assert_eq!((out[1].service.as_str(), out[1].count), (SERVICE_UNVERIFIED, 50));
        // Erfolg meldet beide vorher
        a.push(fail("ssh"));
        a.push(fail(SERVICE_UNVERIFIED));
        assert_eq!(a.push(parse_line("Accepted password for root from 198.51.100.7 port 2 ssh2").unwrap()).len(), 3);
        assert!(a.flush(true).is_empty());
    }

    #[test]
    fn aggregates_failures() {
        let mut a = Aggregator::new(Duration::from_secs(300));
        for u in ["admin", "root", "test"] {
            assert!(a.push(parse_line(&format!("Failed password for {u} from 198.51.100.7 port 1 ssh2")).unwrap()).is_empty());
        }
        // Erfolg derselben IP: erst die Fehlversuche (3, Benutzer *), dann der Erfolg
        let out = a.push(parse_line("Accepted password for root from 198.51.100.7 port 2 ssh2").unwrap());
        assert_eq!(out.len(), 2);
        assert_eq!((out[0].count, out[0].user.as_str(), out[0].success), (3, "*", false));
        assert!(out[1].success);
        assert!(a.flush(true).is_empty());
    }
}
