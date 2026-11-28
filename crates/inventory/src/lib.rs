//! Server inventory: running services, processes (grouped), open ports with
//! binding, firewall summary (main plan 22, 24.8 – brought forward).
//!
//! Read-only; uses existing tools (systemctl, nft, iptables-save, ufw,
//! firewall-cmd) if present. Nothing is installed or changed.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::process::Command;

use serde::Serialize;

/// Detected web applications (kind, version, root, media/cache folders, plugins) – implemented in the check crate,
/// which runs the per-app hardening checks on the same data
pub use tyrosd_check::app;
pub mod backup;
pub mod containers;
pub mod dbconf;
pub mod host;
pub mod shop;
pub mod software;
pub mod unpackaged;

#[derive(Serialize, Debug, Default)]
pub struct Inventory {
    pub services: Vec<Service>,
    pub processes: Vec<ProcGroup>,
    pub listeners: Vec<Listener>,
    pub firewall: Firewall,
    /// installed software for vulnerability matching (server)
    pub software: software::Software,
    /// SSH server settings and "reboot required" (security score)
    pub ssh: host::Ssh,
    pub reboot: host::Reboot,
    /// detected shops (stage C1) and outgoing connections (stage C3)
    pub shops: Vec<shop::Shop>,
    pub egress: Vec<shop::Egress>,
    /// detected backups with the time of the most recent one (since 0.3.0)
    pub backups: Vec<backup::Backup>,
    /// Domains from the web server configuration (server_name/ServerName) – for the server's TLS and reachability checks
    pub sites: Vec<String>,
    /// Containers with their own packages (packages are in software.packages with location "container:<name>")
    pub containers: Vec<containers::Container>,
    /// detected webroots (since 0.4.15) – places where the server can have decoys created; filled in by the agent
    pub webroots: Vec<String>,
    /// MySQL/MariaDB logging setting (since 0.4.16, decoys phase 2)
    pub mysql_conf: dbconf::MysqlConf,
    /// Beaconing sample: last completed hour (since 0.5.2; new outgoing connections per minute)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub beacons: Option<tyrosd_detect::beacon::BeaconHour>,
    /// Detected web applications (since 0.5.10): CMS, shops, frameworks with version, media/cache folders and plugins
    pub apps: Vec<app::App>,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Service {
    pub unit: String,
    pub description: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct ProcGroup {
    /// detected application (e.g. "PHP-FPM"), otherwise the program name
    pub app: String,
    pub exe: String,
    pub count: u32,
    pub users: Vec<String>,
    pub rss_mb: u64,
}

#[derive(Serialize, Debug, Clone)]
pub struct Listener {
    pub proto: String,
    pub addr: String,
    pub port: u16,
    /// local | private | public
    pub scope: String,
    pub process: String,
    pub pid: i32,
    /// blocked | allowed | unknown (host firewall; the hoster's firewall is not visible)
    pub firewall: String,
}

#[derive(Serialize, Debug, Default)]
pub struct Firewall {
    /// nftables | iptables | ufw | firewalld | none
    pub backend: String,
    pub active: bool,
    /// accept | drop | reject | unknown (incoming, IPv4)
    pub input_policy: String,
    pub allowed_ports: Vec<u16>,
    pub rules: u32,
    pub detail: String,
}

/// Known applications based on program and command line.
fn app_name(comm: &str, exe: &str, cmd: &str) -> Option<&'static str> {
    let base = exe.rsplit('/').next().unwrap_or(comm);
    let c = cmd.to_ascii_lowercase();
    Some(match () {
        _ if base.starts_with("php-fpm") || comm.starts_with("php-fpm") => "PHP-FPM",
        _ if base.starts_with("php") => "PHP (CLI)",
        _ if base == "mysqld" => "MySQL",
        _ if base == "mariadbd" || base == "mysqld_safe" => "MariaDB",
        _ if base == "postgres" || comm == "postgres" => "PostgreSQL",
        _ if base == "java" && c.contains("solr") => "Solr",
        _ if base == "java" && (c.contains("elasticsearch") || c.contains("opensearch")) => "Elasticsearch/OpenSearch",
        _ if base == "java" => "Java",
        _ if base == "redis-server" => "Redis",
        _ if base == "memcached" => "Memcached",
        _ if base == "nginx" => "nginx",
        _ if base == "apache2" || base == "httpd" => "Apache",
        _ if base == "caddy" => "Caddy",
        _ if base == "node" || base == "nodejs" => "Node.js",
        _ if base.starts_with("python") => "Python",
        _ if base == "dockerd" => "Docker",
        _ if base == "containerd" => "containerd",
        _ if base == "sshd" || comm.starts_with("sshd") => "OpenSSH",
        _ if comm == "master" && exe.contains("postfix") => "Postfix",
        _ if base == "dovecot" => "Dovecot",
        _ if base == "exim4" || base == "exim" => "Exim",
        _ if base == "varnishd" => "Varnish",
        _ if base == "rabbitmq-server" || c.contains("rabbit") => "RabbitMQ",
        _ if base == "mongod" => "MongoDB",
        _ if base == "sw-engine" || c.contains("psa") => "Plesk",
        _ if base == "crowdsec" => "CrowdSec",
        _ if base == "fail2ban-server" => "fail2ban",
        _ if base == "tyrosd" || base == "tyrosecd" => "tyrosecd",
        _ => return None,
    })
}

fn uid_names() -> HashMap<u32, String> {
    std::fs::read_to_string("/etc/passwd")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            Some((f.get(2)?.parse().ok()?, f.first()?.to_string()))
        })
        .collect()
}

pub fn processes() -> Vec<ProcGroup> {
    let names = uid_names();
    let mut groups: BTreeMap<String, ProcGroup> = BTreeMap::new();
    let mut users: HashMap<String, BTreeSet<String>> = HashMap::new();
    let Ok(rd) = std::fs::read_dir("/proc") else { return vec![] };
    for e in rd.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
        let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else { continue };
        let field = |k: &str| status.lines().find(|l| l.starts_with(k)).and_then(|l| l.split_whitespace().nth(1)).unwrap_or("");
        let rss_kb: u64 = field("VmRSS:").parse().unwrap_or(0);
        if rss_kb == 0 {
            continue; // kernel threads
        }
        let comm = field("Name:").to_string();
        let uid: u32 = field("Uid:").parse().unwrap_or(0);
        let exe = std::fs::read_link(format!("/proc/{pid}/exe")).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        let cmd = std::fs::read(format!("/proc/{pid}/cmdline")).map(|b| String::from_utf8_lossy(&b).replace('\0', " ")).unwrap_or_default();
        let app = app_name(&comm, &exe, &cmd).map(str::to_string).unwrap_or_else(|| comm.clone());
        let key = format!("{app}\u{0}{}", exe.trim_end_matches(" (deleted)"));
        let g = groups.entry(key.clone()).or_insert_with(|| ProcGroup { app: app.clone(), exe: exe.clone(), count: 0, users: vec![], rss_mb: 0 });
        g.count += 1;
        g.rss_mb += rss_kb / 1024;
        users.entry(key).or_default().insert(names.get(&uid).cloned().unwrap_or_else(|| uid.to_string()));
    }
    let mut v: Vec<ProcGroup> = groups
        .into_iter()
        .map(|(k, mut g)| {
            g.users = users.remove(&k).map(|s| s.into_iter().collect()).unwrap_or_default();
            g
        })
        .collect();
    v.sort_by(|a, b| b.rss_mb.cmp(&a.rss_mb).then(a.app.cmp(&b.app)));
    v.truncate(150);
    v
}

pub fn services() -> Vec<Service> {
    let Ok(out) = Command::new("systemctl")
        .args(["list-units", "--type=service", "--state=running", "--no-legend", "--plain", "--no-pager"])
        .output()
    else {
        return vec![];
    };
    let mut v: Vec<Service> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let unit = it.next()?.to_string();
            let desc: Vec<&str> = it.skip(3).collect(); // load active sub
            Some(Service { unit, description: desc.join(" ") })
        })
        .collect();
    v.sort();
    v
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let o = Command::new(cmd).args(args).output().ok()?;
    if !o.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Ports from "dport 80", "--dport 443", "dport { 80, 443 }", "22/tcp ALLOW".
fn ports_in(s: &str, out: &mut BTreeSet<u16>) {
    let t = s.replace(['{', '}', ','], " ");
    let w: Vec<&str> = t.split_whitespace().collect();
    for i in 0..w.len() {
        if w[i] == "dport" || w[i] == "--dport" || w[i] == "--dports" {
            for x in w.iter().skip(i + 1) {
                match x.parse::<u16>() {
                    Ok(p) => {
                        out.insert(p);
                    }
                    Err(_) => {
                        if let Some((a, b)) = x.split_once([':', '-']) {
                            if let (Ok(a), Ok(b)) = (a.parse::<u16>(), b.parse::<u16>()) {
                                if b >= a && b - a < 64 {
                                    out.extend(a..=b);
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }
    }
}

pub fn firewall() -> Firewall {
    let mut fw = Firewall { backend: "none".into(), input_policy: "unknown".into(), ..Default::default() };
    let mut allowed = BTreeSet::new();
    // ufw from the configuration files (also works in the hardened service without
    // CAP_NET_ADMIN and without a writable /run, unlike `ufw status`)
    if let Some(f) = ufw_from_files() {
        return f;
    }
    // ufw (Ubuntu) – says the most about the intent
    if let Some(s) = run("ufw", &["status", "verbose"]) {
        if s.contains("Status: active") {
            fw.backend = "ufw".into();
            fw.active = true;
            fw.input_policy = if s.contains("deny (incoming)") { "drop" } else if s.contains("reject (incoming)") { "reject" } else { "accept" }.into();
            for l in s.lines().filter(|l| l.contains("ALLOW IN") || l.contains("ALLOW ")) {
                if let Some(p) = l.split_whitespace().next().and_then(|x| x.split('/').next()).and_then(|x| x.parse::<u16>().ok()) {
                    allowed.insert(p);
                }
                fw.rules += 1;
            }
            fw.allowed_ports = allowed.into_iter().collect();
            return fw;
        }
    }
    // firewalld (RHEL)
    if let Some(s) = run("firewall-cmd", &["--state"]) {
        if s.trim() == "running" {
            fw.backend = "firewalld".into();
            fw.active = true;
            fw.input_policy = "drop".into(); // default zone drops anything not allowed
            if let Some(all) = run("firewall-cmd", &["--list-all"]) {
                for l in all.lines() {
                    let l = l.trim();
                    if let Some(p) = l.strip_prefix("ports:") {
                        for x in p.split_whitespace() {
                            if let Some(n) = x.split('/').next().and_then(|n| n.parse::<u16>().ok()) {
                                allowed.insert(n);
                            }
                        }
                    }
                    if let Some(s) = l.strip_prefix("services:") {
                        for svc in s.split_whitespace() {
                            if let Some(p) = match svc { "ssh" => Some(22), "http" => Some(80), "https" => Some(443), "smtp" => Some(25), "imaps" => Some(993), "mysql" => Some(3306), _ => None } {
                                allowed.insert(p);
                            }
                        }
                    }
                }
                fw.detail = all.lines().take(30).collect::<Vec<_>>().join("\n");
            }
            fw.allowed_ports = allowed.into_iter().collect();
            return fw;
        }
    }
    // nftables
    if let Some(s) = run("nft", &["list", "ruleset"]) {
        if s.contains("hook input") {
            fw.backend = "nftables".into();
            fw.active = true;
            let mut in_input = false;
            for l in s.lines() {
                let t = l.trim();
                if t.contains("hook input") {
                    in_input = true;
                    fw.input_policy = if t.contains("policy drop") { "drop" } else if t.contains("policy reject") { "reject" } else { "accept" }.into();
                } else if t.starts_with("chain ") {
                    in_input = false;
                } else if in_input && t.contains("accept") {
                    ports_in(t, &mut allowed);
                }
                if t.contains("accept") || t.contains("drop") || t.contains("reject") {
                    fw.rules += 1;
                }
            }
            fw.detail = s.lines().take(60).collect::<Vec<_>>().join("\n");
            fw.allowed_ports = allowed.into_iter().collect();
            return fw;
        }
    }
    // iptables (legacy or nft wrapper)
    if let Some(s) = run("iptables-save", &[]) {
        let rules = s.lines().filter(|l| l.starts_with("-A ")).count() as u32;
        let policy = s.lines().find_map(|l| l.strip_prefix(":INPUT ")).and_then(|l| l.split_whitespace().next()).unwrap_or("ACCEPT");
        if rules > 0 || policy != "ACCEPT" {
            fw.backend = "iptables".into();
            fw.active = true;
            fw.rules = rules;
            fw.input_policy = policy.to_ascii_lowercase();
            for l in s.lines().filter(|l| l.starts_with("-A INPUT") && l.contains("-j ACCEPT")) {
                ports_in(l, &mut allowed);
            }
            fw.detail = s.lines().filter(|l| l.starts_with("-A INPUT") || l.starts_with(':')).take(60).collect::<Vec<_>>().join("\n");
            fw.allowed_ports = allowed.into_iter().collect();
        }
    }
    fw
}

/// ufw state from /etc/ufw (active?, default policy, allowed ports).
fn ufw_from_files() -> Option<Firewall> {
    let conf = std::fs::read_to_string("/etc/ufw/ufw.conf").ok()?;
    let enabled = conf.lines().any(|l| l.trim().eq_ignore_ascii_case("ENABLED=yes"));
    if !enabled {
        return None;
    }
    let def = std::fs::read_to_string("/etc/default/ufw").unwrap_or_default();
    let policy = def
        .lines()
        .find_map(|l| l.trim().strip_prefix("DEFAULT_INPUT_POLICY="))
        .map(|v| v.trim_matches('"').to_ascii_lowercase())
        .unwrap_or_else(|| "drop".into());
    let mut allowed = BTreeSet::new();
    let mut rules = 0;
    for f in ["/etc/ufw/user.rules", "/etc/ufw/user6.rules"] {
        for l in std::fs::read_to_string(f).unwrap_or_default().lines() {
            // ### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
            if let Some(t) = l.strip_prefix("### tuple ### ") {
                rules += 1;
                let w: Vec<&str> = t.split_whitespace().collect();
                if w.first() == Some(&"allow") && w.last() == Some(&"in") {
                    for p in w.get(2).unwrap_or(&"").split(',') {
                        if let Ok(n) = p.parse::<u16>() {
                            allowed.insert(n);
                        } else if let Some((a, b)) = p.split_once(':') {
                            if let (Ok(a), Ok(b)) = (a.parse::<u16>(), b.parse::<u16>()) {
                                if b >= a && b - a < 64 {
                                    allowed.extend(a..=b);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Some(Firewall {
        backend: "ufw".into(),
        active: true,
        input_policy: if policy == "accept" { "accept".into() } else if policy == "reject" { "reject".into() } else { "drop".into() },
        allowed_ports: allowed.into_iter().collect(),
        rules,
        detail: "read from /etc/ufw".into(),
    })
}

fn scope(addr: &str, public: bool) -> &'static str {
    if addr.starts_with("127.") || addr == "::1" {
        "local"
    } else if public {
        "public"
    } else {
        "private"
    }
}

pub fn collect() -> Inventory {
    collect_in(tyrosd_check::default_webroots("/"))
}

/// Like `collect`, with the given webroots (e.g. including the web server's docroots). Apps and shops are
/// searched in these plus the default webroots.
pub fn collect_in(webroots: Vec<String>) -> Inventory {
    let mut search = webroots.clone();
    search.extend(tyrosd_check::default_webroots("/"));
    search.sort();
    search.dedup();
    let copy = search.clone();
    search.retain(|a| !copy.iter().any(|b| b != a && a.starts_with(&format!("{b}/"))));
    let apps = app::detect(&search);
    let fw = firewall();
    let owners = tyrosd_check::system::socket_owners();
    let mut seen = BTreeSet::new();
    let mut listeners = Vec::new();
    for l in tyrosd_check::system::listeners() {
        if !seen.insert((l.proto, l.addr.clone(), l.port)) {
            continue;
        }
        let (pid, comm) = owners.get(&l.inode).cloned().unwrap_or((0, "?".into()));
        let sc = scope(&l.addr, l.public);
        let firewall = if sc != "public" {
            "-"
        } else if !fw.active || fw.input_policy == "accept" {
            "allowed"
        } else if fw.allowed_ports.contains(&l.port) {
            "allowed"
        } else if fw.input_policy == "drop" || fw.input_policy == "reject" {
            "blocked"
        } else {
            "unknown"
        };
        listeners.push(Listener { proto: l.proto.into(), addr: l.addr, port: l.port, scope: sc.into(), process: comm, pid, firewall: firewall.into() });
    }
    listeners.sort_by(|a, b| a.port.cmp(&b.port).then(a.proto.cmp(&b.proto)));
    let ports: Vec<u16> = listeners.iter().map(|l| l.port).collect();
    let (cts, ct_pkgs) = containers::detect();
    // WordPress/lockfiles also in the configured webroots and the application roots (composer.lock above public/)
    let mut roots = search.clone();
    roots.extend(apps.iter().map(|a| a.root.clone()));
    let mut software = software::collect_with(&roots);
    software.packages.extend(ct_pkgs);
    Inventory {
        services: services(),
        processes: processes(),
        egress: shop::egress(&ports),
        listeners,
        firewall: fw,
        software,
        containers: cts,
        ssh: host::ssh("/"),
        reboot: host::reboot(),
        shops: shop::from_apps(&apps),
        backups: backup::detect("/"),
        sites: sites(),
        webroots,
        mysql_conf: dbconf::mysql(),
        beacons: tyrosd_detect::beacon::last_hour(),
        apps,
    }
}

/// Domains of all websites (without placeholders, wildcards, IPs), at most 50
pub fn sites() -> Vec<String> {
    let mut v: Vec<String> = tyrosd_source_weblog::docroots()
        .into_iter()
        .flat_map(|(_, names)| names.split(", ").map(|n| n.trim().trim_start_matches("www.").to_ascii_lowercase()).collect::<Vec<_>>())
        .filter(|n| n.contains('.') && !n.contains('*') && !n.ends_with(".local") && !n.ends_with(".localhost") && n.parse::<std::net::IpAddr>().is_err())
        .collect();
    v.sort();
    v.dedup();
    v.truncate(50);
    v
}

/// Fingerprint for "has anything changed?" (without RAM/count, which fluctuate).
pub fn fingerprint(inv: &Inventory) -> String {
    let mut s = String::new();
    for c in &inv.containers {
        s.push_str(&format!("ct:{}:{}:{}:{}\n", c.name, c.state, c.os, c.packages));
    }
    for d in &inv.sites {
        s.push_str(d);
        s.push('\n');
    }
    // new backup → send the inventory again (time rounded to the hour)
    for b in &inv.backups {
        s.push_str(&format!("{}:{}:{}\n", b.kind, b.path, b.last / 3600));
    }
    for x in &inv.services {
        s.push_str(&x.unit);
        s.push('\n');
    }
    for p in &inv.processes {
        s.push_str(&p.app);
        s.push_str(&p.exe);
        s.push('\n');
    }
    for l in &inv.listeners {
        s.push_str(&format!("{}:{}:{}:{}:{}\n", l.proto, l.addr, l.port, l.process, l.firewall));
    }
    s.push_str(&format!("{}:{}:{}:{:?}", inv.firewall.backend, inv.firewall.active, inv.firewall.input_policy, inv.firewall.allowed_ports));
    for p in &inv.software.packages {
        s.push_str(&format!("\n{}|{}|{}|{}", p.ecosystem, p.name, p.version, p.location));
    }
    s.push_str(&format!("\nssh:{:?}\nreboot:{}:{}:{}", inv.ssh, inv.reboot.required, inv.reboot.running_kernel, inv.reboot.newest_kernel));
    for x in &inv.shops {
        s.push_str(&format!("\nshop:{}:{}:{}", x.kind, x.root, x.version));
    }
    for a in &inv.apps {
        s.push_str(&format!("
app:{}:{}:{}:{}", a.kind, a.root, a.version, a.plugins.iter().map(|p| format!("{}={}", p.name, p.version)).collect::<Vec<_>>().join(",")));
    }
    // Egress: only process + destination port (destination IPs and counts change constantly)
    let mut eg: Vec<String> = inv.egress.iter().map(|e| format!("{}:{}", e.process, e.port)).collect();
    eg.sort();
    eg.dedup();
    s.push_str(&format!("\negress:{}", eg.join(",")));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_parsing() {
        let mut p = BTreeSet::new();
        ports_in("tcp dport { 22, 80, 443 } accept", &mut p);
        ports_in("-A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT", &mut p);
        ports_in("-A INPUT -p tcp -m multiport --dports 8443:8445 -j ACCEPT", &mut p);
        assert_eq!(p.into_iter().collect::<Vec<_>>(), vec![22, 80, 443, 8080, 8443, 8444, 8445]);
    }

    #[test]
    fn apps() {
        assert_eq!(app_name("php-fpm8.3", "/usr/sbin/php-fpm8.3", ""), Some("PHP-FPM"));
        assert_eq!(app_name("java", "/usr/bin/java", "java -Dsolr.solr.home=/var/solr"), Some("Solr"));
        assert_eq!(app_name("mariadbd", "/usr/sbin/mariadbd", ""), Some("MariaDB"));
        assert_eq!(app_name("foo", "/opt/foo/bin/foo", ""), None);
    }

    #[test]
    fn collects() {
        let inv = collect();
        assert!(!inv.processes.is_empty());
    }
}
