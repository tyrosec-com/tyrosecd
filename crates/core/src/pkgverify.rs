//! Gehört eine geänderte Systemdatei unverändert zu einem installierten Paket?
//!
//! Praxisfall: `unattended-upgrades` aktualisierte das Paket `sos`, eine neue Datei davon fand erst
//! der periodische Scan 10 Minuten später – nach dem Paket-Update-Fenster – und es gab den kritischen Fehlalarm
//! „Systembibliothek außerhalb eines Paket-Updates geändert“. Ohne geprüften Prozess gleicht der Agent solche Dateien
//! deshalb mit der Paketdatenbank ab: Stimmt die Prüfsumme mit dem Eintrag des besitzenden Pakets überein (dpkg: MD5
//! aus `<paket>.md5sums`, rpm: SHA-256 aus der RPM-Datenbank), ist es eine Datei aus einem Paket. Eine manipulierte
//! Datei hat eine andere Prüfsumme und wird weiter gemeldet. Die Paketdatenbank kann nur root ändern.
//!
//! Bewusst sparsam: nur für Systemordner, nur ohne Paket-Markierung, höchstens `PER_MINUTE` Abfragen je Minute
//! (Paket-Updates selbst sind über den geprüften Prozess bzw. das Update-Fenster markiert), je Aufruf mit Zeitgrenze.

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const PER_MINUTE: u32 = 120;
const TIMEOUT: Duration = Duration::from_secs(5);

/// Systemordner, in denen Paketdateien liegen (Regeln „Systemprogramm/Bibliothek geändert“), und /etc für
/// Konfigurationsdateien aus Paketen (Praxisfall: /etc/sudoers beim Update des Pakets sudo)
pub fn in_scope(path: &str) -> bool {
    ["/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/lib64/", "/usr/libexec/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/etc/"]
        .iter()
        .any(|d| path.starts_with(d))
        && !path.contains("/../")
}

static BUDGET: Mutex<Option<(Instant, u32)>> = Mutex::new(None);

fn take_budget() -> bool {
    let mut g = BUDGET.lock().unwrap();
    let now = Instant::now();
    let (start, n) = g.get_or_insert((now, 0));
    if now.duration_since(*start) >= Duration::from_secs(60) {
        *start = now;
        *n = 0;
    }
    if *n >= PER_MINUTE {
        return false;
    }
    *n += 1;
    true
}

/// Befehl mit Zeitgrenze ausführen; Ausgabe (stdout) bei Erfolg
fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let mut child = Command::new(cmd).args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().ok()?;
    let deadline = Instant::now() + TIMEOUT;
    loop {
        match child.try_wait().ok()? {
            Some(st) => {
                let mut out = String::new();
                child.stdout.take()?.take(4 << 20).read_to_string(&mut out).ok()?;
                return st.success().then_some(out);
            }
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

/// Ausgabe von `dpkg-query -S <pfad>` → besitzende Pakete (ohne Umleitungen/„diversion“-Zeilen)
pub fn parse_dpkg_search(out: &str, path: &str) -> Vec<String> {
    let mut pkgs = Vec::new();
    for l in out.lines() {
        if l.starts_with("diversion ") {
            continue;
        }
        let Some((left, p)) = l.rsplit_once(": ") else { continue };
        if p != path {
            continue;
        }
        pkgs.extend(left.split(", ").map(|s| s.trim().to_string()).filter(|s| !s.is_empty()));
    }
    pkgs
}

/// MD5 eines Pfads aus einer `.md5sums`-Datei (Zeilen „<md5>  <pfad ohne führendes />“)
pub fn md5_from_list(list: &str, path: &str) -> Option<String> {
    let rel = path.trim_start_matches('/');
    list.lines().find_map(|l| {
        let (md5, p) = l.split_once("  ")?;
        (p == rel && md5.len() == 32).then(|| md5.to_ascii_lowercase())
    })
}

/// MD5 einer Konfigurationsdatei aus `dpkg-query -W -f='${Conffiles}'` (Zeilen „ <pfad> <md5>[ obsolete]“)
pub fn md5_from_conffiles(out: &str, path: &str) -> Option<String> {
    out.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        let (p, md5) = (it.next()?, it.next()?);
        (p == path && md5.len() == 32 && it.next() != Some("obsolete")).then(|| md5.to_ascii_lowercase())
    })
}

/// SHA-256 eines Pfads aus `rpm -qf --qf '[%{FILENAMES}\t%{FILEDIGESTS}\n]'`
pub fn sha256_from_rpm(out: &str, path: &str) -> Option<String> {
    out.lines().find_map(|l| {
        let (p, d) = l.split_once('\t')?;
        (p == path && d.len() == 64).then(|| d.to_ascii_lowercase())
    })
}

fn first_word(out: Option<String>) -> Option<String> {
    out?.split_whitespace().next().map(|s| s.to_ascii_lowercase())
}

/// merged-/usr: dpkg führt Dateien teils als /lib/…, auf dem System liegen sie unter /usr/lib/… (und umgekehrt)
fn variants(path: &str) -> Vec<String> {
    let mut v = vec![path.to_string()];
    match path.strip_prefix("/usr") {
        Some(rest) if ["/bin/", "/sbin/", "/lib/", "/lib64/"].iter().any(|d| rest.starts_with(d)) => v.push(rest.to_string()),
        Some(_) => {}
        None => v.push(format!("/usr{path}")),
    }
    v
}

fn dpkg_matches(path: &str) -> Option<bool> {
    if !std::path::Path::new("/var/lib/dpkg/status").exists() {
        return None;
    }
    for p in variants(path) {
        let Some(out) = run("dpkg-query", &["-S", "--", &p]) else { continue };
        for pkg in parse_dpkg_search(&out, &p) {
            let name = pkg.split(':').next().unwrap_or(&pkg).to_string();
            // Konfigurationsdatei: Prüfsumme der unveränderten Paketfassung steht in der Paketdatenbank (Conffiles) –
            // stimmt sie überein, ist es genau die Datei aus dem Paket (eine zusätzliche Zeile ändert die Prüfsumme)
            if p.starts_with("/etc/") {
                let have = first_word(run("md5sum", &["--", path]))?;
                // dpkg trägt die neue Prüfsumme erst nach dem Austausch der Datei ein – bei Abweichung einmal kurz warten
                for attempt in 0..2 {
                    if attempt > 0 {
                        std::thread::sleep(Duration::from_millis(1500));
                    }
                    let Some(conf) = run("dpkg-query", &["-W", "-f=${Conffiles}\n", "--", &pkg]) else { break };
                    match md5_from_conffiles(&conf, &p) {
                        Some(want) if want == have => return Some(true),
                        Some(_) => continue,
                        None => break,
                    }
                }
                continue;
            }
            let lists = [format!("/var/lib/dpkg/info/{pkg}.md5sums"), format!("/var/lib/dpkg/info/{name}.md5sums")];
            let Some(want) = lists.iter().find_map(|f| std::fs::read_to_string(f).ok().and_then(|l| md5_from_list(&l, &p))) else { continue };
            let have = first_word(run("md5sum", &["--", path]))?;
            return Some(have == want);
        }
    }
    Some(false)
}

fn rpm_matches(path: &str) -> Option<bool> {
    if !["/var/lib/rpm", "/usr/lib/sysimage/rpm"].iter().any(|d| std::path::Path::new(d).exists()) {
        return None;
    }
    for p in variants(path) {
        let Some(out) = run("rpm", &["-qf", "--qf", "[%{FILENAMES}\t%{FILEDIGESTS}\n]", "--", &p]) else { continue };
        let Some(want) = sha256_from_rpm(&out, &p) else { continue };
        let have = first_word(run("sha256sum", &["--", path]))?;
        return Some(have == want);
    }
    Some(false)
}

/// true = Datei gehört zu einem Paket und ist unverändert. Ohne Paketdatenbank, ohne Budget oder bei Fehlern: false
/// (dann gelten die üblichen Regeln – lieber ein Alarm zu viel als einer zu wenig).
pub fn from_package(path: &str) -> bool {
    if !in_scope(path) || !take_budget() {
        return false;
    }
    dpkg_matches(path).or_else(|| rpm_matches(path)).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpkg_search_output() {
        let out = "python3-sos: /usr/lib/python3/dist-packages/sos/report/plugins/freeipmi.py\n";
        assert_eq!(parse_dpkg_search(out, "/usr/lib/python3/dist-packages/sos/report/plugins/freeipmi.py"), vec!["python3-sos"]);
        let out = "diversion by dash from: /bin/sh\ndiversion by dash to: /bin/sh.distrib\ndash: /bin/sh\n";
        assert_eq!(parse_dpkg_search(out, "/bin/sh"), vec!["dash"]);
        let out = "libc6:amd64, libc6-dev:amd64: /usr/lib/x86_64-linux-gnu/libc.so.6\n";
        assert_eq!(parse_dpkg_search(out, "/usr/lib/x86_64-linux-gnu/libc.so.6"), vec!["libc6:amd64", "libc6-dev:amd64"]);
        // anderer Pfad (Ordner-Treffer) zählt nicht
        assert!(parse_dpkg_search("coreutils: /usr/bin\n", "/usr/bin/ls").is_empty());
    }

    #[test]
    fn md5_and_rpm_lookup() {
        let list = "0123456789abcdef0123456789abcdef  usr/lib/python3/dist-packages/sos/x.py\nffffffffffffffffffffffffffffffff  usr/bin/sosreport\n";
        assert_eq!(md5_from_list(list, "/usr/bin/sosreport").as_deref(), Some("ffffffffffffffffffffffffffffffff"));
        assert_eq!(md5_from_list(list, "/usr/bin/other"), None);
        let d = "ab".repeat(32);
        let out = format!("/usr/bin/ls\t{d}\n/usr/bin/dir\t\n");
        assert_eq!(sha256_from_rpm(&out, "/usr/bin/ls").as_deref(), Some(d.as_str()));
        assert_eq!(sha256_from_rpm(&out, "/usr/bin/dir"), None); // leerer Digest (Symlink/Ordner)
    }

    #[test]
    fn conffile_lookup() {
        let out = " /etc/sudoers 0123456789abcdef0123456789abcdef\n /etc/sudo.conf ffffffffffffffffffffffffffffffff\n /etc/old.conf aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa obsolete\n";
        assert_eq!(md5_from_conffiles(out, "/etc/sudoers").as_deref(), Some("0123456789abcdef0123456789abcdef"));
        assert_eq!(md5_from_conffiles(out, "/etc/old.conf"), None); // nicht mehr Teil des Pakets
        assert_eq!(md5_from_conffiles(out, "/etc/other"), None);
        assert!(in_scope("/etc/sudoers"));
    }

    #[test]
    fn scope_and_variants() {
        assert!(in_scope("/usr/lib/python3/dist-packages/sos/x.py"));
        assert!(!in_scope("/var/www/html/index.php"));
        assert!(!in_scope("/usr/lib/../../tmp/x"));
        assert_eq!(variants("/usr/lib/x"), vec!["/usr/lib/x", "/lib/x"]);
        assert_eq!(variants("/lib/x"), vec!["/lib/x", "/usr/lib/x"]);
        assert_eq!(variants("/usr/share/x"), vec!["/usr/share/x"]);
    }

    #[test]
    fn budget_limits_queries() {
        let mut ok = 0;
        for _ in 0..(PER_MINUTE + 10) {
            if take_budget() {
                ok += 1;
            }
        }
        assert!(ok <= PER_MINUTE);
    }
}
