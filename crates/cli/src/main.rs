//! tyrosd – agent CLI
//!
//! Product:     enroll | run | check | probe
//! Diagnostics: watch (local, without central server) | scan | diff-test

mod actions;
mod decoy;
mod monitor;
mod yara_rules;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use monitor::{install_signal_handler, log, BackendChoice, Monitor, MonitorOpts, STOP};
use tyrosd_core::hash::Algo;
use tyrosd_core::policy::Policy;
use tyrosd_core::sink::{JsonlSink, MultiSink, Sink};
use tyrosd_core::state::State;
use tyrosd_core::Processor;
use tyrosd_proto as pb;
use tyrosd_source_scan::ScanConfig;
use tyrosd_transport::{client::Client, sender, sink::SpoolSink, update, AgentConfig, Spool};

const DEFAULT_CONFIG: &str = "/etc/tyrosecd/agent.toml";

#[derive(Parser)]
#[command(name = "tyrosecd", version = update::AGENT_VERSION, about = "tyrosecd – Linux server guard (agent)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
enum BackendArg {
    Auto,
    Fanotify,
    Inotify,
    None,
}

impl From<BackendArg> for BackendChoice {
    fn from(b: BackendArg) -> Self {
        match b {
            BackendArg::Auto => BackendChoice::Auto,
            BackendArg::Fanotify => BackendChoice::Fanotify,
            BackendArg::Inotify => BackendChoice::Inotify,
            BackendArg::None => BackendChoice::None,
        }
    }
}

#[derive(clap::Args, Clone)]
struct Common {
    /// Events as JSON lines (file, or - for stdout)
    #[arg(long, default_value = "/var/log/tyrosd-spike/events.jsonl")]
    events_out: String,
    /// Budget for stored content (diff base, compressed) in MB
    #[arg(long, default_value_t = 500)]
    cache_mb: u64,
    /// State file (embedded database: hashes, metadata, diff base)
    #[arg(long, default_value = "/var/lib/tyrosd-spike/state.redb")]
    state: String,
    /// RAM cache of the state file in MB
    #[arg(long, default_value_t = 16)]
    state_cache_mb: usize,
    /// sha256 | blake3
    #[arg(long, default_value = "sha256")]
    hash: Algo,
    /// additional policy rules (JSON: {"rules":[{"glob":"…","mode":"full"}]})
    #[arg(long)]
    policy: Option<String>,
    /// Write diff text (truncated) into events
    #[arg(long)]
    emit_diff: bool,
    /// Scan threads (0 = automatic: half of the CPU cores, at least 1)
    #[arg(long, default_value_t = 0)]
    threads: usize,
    /// Scan read limit in MB/s (0 = off)
    #[arg(long, default_value_t = 0)]
    rate_mb: u64,
    /// Scan with IO class idle + nice
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    low_prio: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Enroll with the central server (one-time token from the web interface)
    Enroll {
        #[arg(long)]
        server: Option<String>,
        #[arg(long)]
        token: Option<String>,
        /// Read the token from a file (recommended; does not appear in the process list).
        /// Otherwise env TYROSD_TOKEN or stdin
        #[arg(long)]
        token_file: Option<String>,
        /// CA file for the server certificate (self-hosted/test only)
        #[arg(long)]
        server_ca: Option<String>,
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: String,
        #[arg(long)]
        data_dir: Option<String>,
    },
    /// Agent service: monitoring, scans, metrics, sending to the central server
    Run {
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: String,
    },
    /// Real-time monitoring, local only (diagnostics, without central server)
    Watch {
        #[arg(long, default_value = "auto")]
        backend: BackendArg,
        /// Roots for events (default: /)
        #[arg(long = "root")]
        roots: Vec<String>,
        /// Roots for the scan (default: profile directories)
        #[arg(long = "scan-root")]
        scan_roots: Vec<String>,
        /// Seconds between reconciliation scans (0 = only at startup)
        #[arg(long, default_value_t = 21600)]
        scan_interval: u64,
        /// No scan at startup
        #[arg(long)]
        no_start_scan: bool,
        #[arg(long, default_value_t = 300)]
        debounce_ms: u64,
        /// Unbounded fanotify queue (kernel memory grows if the agent hangs – for tests only).
        /// Default: bounded (16,384 events); on overflow a notice + reconciliation scan
        #[arg(long)]
        unlimited_queue: bool,
        #[command(flatten)]
        c: Common,
    },
    /// One-time reconciliation scan (baseline if no state exists)
    Scan {
        #[arg(long = "root")]
        roots: Vec<String>,
        /// Re-hash all files
        #[arg(long)]
        full_hash: bool,
        #[command(flatten)]
        c: Common,
    },
    /// Compromise check (without central server)
    Check {
        /// Webroots (default: automatic)
        #[arg(long = "webroot")]
        webroots: Vec<String>,
        /// Without queries to WordPress.org
        #[arg(long)]
        offline: bool,
        /// System root (e.g. a mounted image)
        #[arg(long, default_value = "/")]
        sysroot: String,
        /// JSON report
        #[arg(long)]
        json_out: Option<String>,
        #[arg(long, default_value_t = 90)]
        days: i64,
        #[arg(long)]
        skip_suid_scan: bool,
        #[arg(long, default_value_t = 40)]
        max_findings: usize,
    },
    /// Deploy window: mark changes until `end` (or expiry) as deploy
    Deploy {
        #[command(subcommand)]
        action: DeployCmd,
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: String,
    },
    /// Check/install updates (only signed, higher versions)
    Update {
        /// Release source (default: update_base from the configuration)
        #[arg(long)]
        base: Option<String>,
        /// only check, do not install
        #[arg(long)]
        check: bool,
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: String,
    },
    /// Enable/disable actions from the central server (restore, quarantine, block IP)
    Actions {
        #[command(subcommand)]
        action: ActionsCmd,
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: String,
    },
    /// Show the server inventory: services, processes, open ports, firewall
    Inventory {
        /// output as JSON
        #[arg(long)]
        json: bool,
    },
    /// System capabilities (backend matrix)
    Probe,
    /// Diff + patch round trip of two files
    DiffTest { old: String, new: String },
}

#[derive(Subcommand)]
enum ActionsCmd {
    /// enable (if omitted: restore, quarantine, block_ip)
    Enable {
        kinds: Vec<String>,
        /// additional folder (besides the detected webroots) in which restoring is allowed (can be repeated)
        #[arg(long = "path")]
        paths: Vec<String>,
    },
    /// disable again (if omitted: all)
    Disable { kinds: Vec<String> },
    /// show enabled actions
    Status,
    /// rewrite the systemd drop-in (write permission for the webroots), e.g. after new webroots or updates
    Refresh,
}

#[derive(Subcommand)]
enum DeployCmd {
    /// Deploy starts (e.g. in CI before `rsync`/`git pull`)
    Start {
        #[arg(long, default_value = "deploy")]
        label: String,
        /// the window ends automatically after this many minutes at the latest
        #[arg(long, default_value_t = 30)]
        minutes: u64,
        /// only these paths (default: all)
        #[arg(long = "path")]
        paths: Vec<String>,
    },
    /// Deploy finished
    End,
}

/// Enrollment token: --token-file, env TYROSD_TOKEN, stdin – or (deprecated, visible in the process list) --token
fn enroll_token(token: Option<String>, token_file: Option<String>) -> Result<String> {
    let t = if let Some(f) = token_file {
        std::fs::read_to_string(&f).with_context(|| f.clone())?
    } else if let Some(t) = token {
        log("Note: --token is visible in the process list – better use --token-file=… or the TYROSD_TOKEN environment variable");
        t
    } else if let Ok(t) = std::env::var("TYROSD_TOKEN") {
        t
    } else {
        use std::io::IsTerminal;
        if std::io::stdin().is_terminal() {
            eprint!("Token: ");
        }
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        s
    };
    let t = t.trim().to_string();
    if t.is_empty() {
        bail!("Token missing (--token-file=…, TYROSD_TOKEN environment variable or via stdin)");
    }
    Ok(t)
}

fn deploy_marker(config: &str) -> String {
    let dir = AgentConfig::load(config).map(|c| c.data_dir).unwrap_or_else(|_| "/var/lib/tyrosecd".into());
    format!("{dir}/deploy.json")
}

fn default_scan_roots() -> Vec<String> {
    [
        "/etc", "/root", "/home", "/var/www", "/srv", "/var/spool/cron", "/usr/local", "/opt", "/tmp", "/var/tmp", "/dev/shm",
        "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/lib/systemd/system", "/lib/systemd/system", "/boot",
    ]
    .iter()
    .filter(|p| std::path::Path::new(p).exists())
    // /bin → /usr/bin: not twice with merged /usr
    .filter(|p| !std::fs::symlink_metadata(p).map(|m| m.file_type().is_symlink()).unwrap_or(false))
    .map(|s| s.to_string())
    .collect()
}

fn auto_threads(n: usize) -> usize {
    if n > 0 {
        n
    } else {
        std::thread::available_parallelism().map(|n| (n.get() / 2).max(1)).unwrap_or(1)
    }
}

fn processor(c: &Common) -> Result<Arc<Processor>> {
    let policy = match &c.policy {
        Some(p) => Policy::from_file(p)?,
        None => Policy::default_policy(),
    };
    let state = State::open(&c.state, c.state_cache_mb, c.cache_mb * 1024 * 1024).context("state file")?;
    let sink = JsonlSink::open(Some(&c.events_out))?;
    let mut p = Processor::new(Arc::new(policy), state, Box::new(sink), c.hash);
    p.emit_diff = c.emit_diff;
    p.deploy = Some(tyrosd_core::deploy::DeployWindow::new("/var/lib/tyrosd-spike/deploy.json"));
    Ok(Arc::new(p))
}

fn scan_cfg(c: &Common, roots: Vec<String>, full_hash: bool) -> ScanConfig {
    ScanConfig {
        roots,
        threads: auto_threads(c.threads),
        rate_mb_s: if c.rate_mb == 0 { None } else { Some(c.rate_mb) },
        low_prio: c.low_prio,
        one_fs: false,
        full_hash,
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Probe => probe(),
        Cmd::DiffTest { old, new } => {
            let a = std::fs::read(&old)?;
            let b = std::fs::read(&new)?;
            let d = tyrosd_core::diff::make_patch(&a, &b);
            let r = tyrosd_core::diff::apply_patch(&a, &d.patch)?;
            print!("{}", String::from_utf8_lossy(&d.patch));
            let ok = r == b;
            eprintln!("changed lines: {} · patch {} B · round trip: {}", d.changed_lines, d.patch.len(), if ok { "OK" } else { "ERROR" });
            std::process::exit(if ok { 0 } else { 1 });
        }
        Cmd::Check { webroots, offline, sysroot, json_out, days, skip_suid_scan, max_findings } => {
            let cfg = tyrosd_check::CheckConfig { sysroot, webroots, offline, timeline_days: days, skip_suid_scan, skip_dpkg_verify: false, state_dir: None };
            let report = tyrosd_check::run(cfg);
            print!("{}", tyrosd_check::render_text(&report, max_findings));
            if let Some(p) = json_out {
                std::fs::write(&p, serde_json::to_vec_pretty(&report)?)?;
                log(format!("JSON report: {p}"));
            }
            let worst = report.findings.iter().map(|f| f.severity).max();
            std::process::exit(match worst {
                Some(tyrosd_check::Severity::Critical) => 3,
                Some(tyrosd_check::Severity::High) => 2,
                Some(tyrosd_check::Severity::Medium) => 1,
                _ => 0,
            });
        }
        Cmd::Scan { roots, full_hash, c } => {
            let proc = processor(&c)?;
            let roots = if roots.is_empty() { default_scan_roots() } else { roots };
            let rep = tyrosd_source_scan::scan(&scan_cfg(&c, roots, full_hash), &proc)?;
            let mut v = serde_json::to_value(&rep)?;
            v["processor"] = serde_json::to_value(&*proc.stats.lock().unwrap())?;
            println!("{}", serde_json::to_string_pretty(&v)?);
            Ok(())
        }
        Cmd::Watch { backend, roots, scan_roots, scan_interval, no_start_scan, debounce_ms, unlimited_queue, c } => {
            let proc = processor(&c)?;
            let roots = if roots.is_empty() { vec!["/".to_string()] } else { roots };
            let scan_roots = if scan_roots.is_empty() { default_scan_roots() } else { scan_roots };
            install_signal_handler();
            let mon = Monitor::start(
                proc,
                MonitorOpts {
                    backend: backend.into(),
                    roots,
                    scan: scan_cfg(&c, scan_roots, false),
                    scan_interval: if scan_interval == 0 { Duration::from_secs(u64::MAX / 4) } else { Duration::from_secs(scan_interval) },
                    start_scan: !no_start_scan,
                    debounce: Duration::from_millis(debounce_ms),
                    unlimited_queue,
                },
            )?;
            log(format!("Backend: {} · Events → {}", mon.backend, c.events_out));
            mon.run_until_stop()
        }
        Cmd::Enroll { server, token, token_file, server_ca, config, data_dir } => {
            let token = enroll_token(token, token_file)?;
            let mut cfg = if std::path::Path::new(&config).exists() {
                AgentConfig::load(&config)?
            } else {
                let Some(s) = server.clone() else { bail!("--server missing (no configuration present)") };
                toml::from_str::<AgentConfig>(&format!("server = {s:?}"))?
            };
            if let Some(s) = server {
                cfg.server = s;
            }
            if let Some(d) = data_dir {
                cfg.data_dir = d;
            }
            let ca = match server_ca {
                Some(p) => Some(std::fs::read_to_string(&p).with_context(|| p.clone())?),
                None => None,
            };
            tyrosd_transport::enroll::enroll(&mut cfg, &token, ca, &config)?;
            log(format!("Configuration: {config} · start with: tyrosecd run"));
            Ok(())
        }
        Cmd::Run { config } => run_agent(&config),
        Cmd::Inventory { json } => {
            let inv = tyrosd_inventory::collect();
            if json {
                println!("{}", serde_json::to_string_pretty(&inv)?);
                return Ok(());
            }
            let f = &inv.firewall;
            println!("Firewall: {} · active {} · incoming {} · allowed ports {:?} · {} rules", f.backend, f.active, f.input_policy, f.allowed_ports, f.rules);
            println!("\nOpen ports:");
            for l in &inv.listeners {
                let fw = match l.firewall.as_str() {
                    "blocked" => " (blocked by host firewall)",
                    "allowed" => " (reachable from outside unless a hosting provider firewall blocks it)",
                    _ => "",
                };
                println!("  {:>5}/{:<4} {:<40} {:<8} {}{}", l.port, l.proto, l.addr, l.scope, l.process, fw);
            }
            println!("\nProcesses (by RAM):");
            for p in inv.processes.iter().take(40) {
                println!("  {:<26} {:>3}× {:>6} MB  {:<20} {}", p.app, p.count, p.rss_mb, p.users.join(","), p.exe);
            }
            println!("\nRunning services: {}", inv.services.iter().map(|s| s.unit.trim_end_matches(".service")).collect::<Vec<_>>().join(", "));
            let sw = &inv.software;
            let mut by: std::collections::BTreeMap<&str, usize> = Default::default();
            for p in &sw.packages {
                *by.entry(p.source.as_str()).or_default() += 1;
            }
            println!("\nSoftware ({}): {}", if sw.os_ecosystem.is_empty() { "distribution unknown" } else { &sw.os_ecosystem }, by.iter().map(|(k, v)| format!("{k} {v}")).collect::<Vec<_>>().join(" · "));
            for p in sw.packages.iter().filter(|p| p.source != "pkg") {
                println!("  {:<10} {:<40} {:<16} {}", p.source, p.name, p.version, p.location);
            }
            Ok(())
        }
        Cmd::Update { base, check, config } => {
            let cfg = AgentConfig::load(&config).ok();
            let base = base
                .or_else(|| cfg.as_ref().and_then(|c| c.update_base.clone()))
                .ok_or_else(|| anyhow::anyhow!("--base missing (no update_base in the configuration)"))?;
            log(format!("installed: {} · source {base}", update::AGENT_VERSION));
            let dd = cfg.as_ref().map(|c| c.data_dir.clone()).unwrap_or_else(|| "/var/lib/tyrosecd".into());
            match update::check(&base, &dd)? {
                None => log("no newer signed version"),
                Some(m) if check => log(format!("available: {} (signature valid)", m.version)),
                Some(m) => {
                    update::apply(&base, &m, &dd)?;
                    log(format!("Update to {} installed – now run: systemctl restart tyrosecd", m.version));
                }
            }
            Ok(())
        }
        Cmd::Actions { action, config } => {
            let mut cfg = AgentConfig::load(&config)?;
            let pick = |k: Vec<String>| -> Result<Vec<String>> {
                let k = if k.is_empty() { actions::KINDS.iter().map(|s| s.to_string()).collect() } else { k };
                if let Some(bad) = k.iter().find(|x| !actions::KINDS.contains(&x.as_str())) {
                    bail!("unknown action {bad} (allowed: {})", actions::KINDS.join(", "));
                }
                Ok(k)
            };
            // Write permission (systemd drop-in) matching the enabled actions; webroots detected as in the check
            let dropin = |cfg: &AgentConfig, restart: bool| -> Result<()> {
                if !std::path::Path::new("/run/systemd/system").is_dir() {
                    return Ok(());
                }
                // detected webroots (also from the web server configuration); in system areas
                // (e.g. /usr/share/nginx/html) they remain blocked
                let mut paths: Vec<String> = decoy::webroots();
                paths.extend(cfg.action_paths.iter().cloned());
                let msg = actions::write_dropin(actions::DROPIN, &cfg.actions, &paths, restart).map_err(|e| anyhow::anyhow!(e))?;
                log(msg);
                Ok(())
            };
            match action {
                ActionsCmd::Enable { kinds, paths } => {
                    for k in pick(kinds)? {
                        if !cfg.actions.contains(&k) {
                            cfg.actions.push(k);
                        }
                    }
                    for p in paths {
                        let p = p.trim_end_matches('/').to_string();
                        if !cfg.action_paths.contains(&p) {
                            cfg.action_paths.push(p);
                        }
                    }
                    // validate first (invalid folders), then save
                    actions::dropin_content(&cfg.actions, &cfg.action_paths).map_err(|e| anyhow::anyhow!(e))?;
                    cfg.save(&config)?;
                    dropin(&cfg, true)?;
                }
                ActionsCmd::Disable { kinds } => {
                    let k = pick(kinds)?;
                    cfg.actions.retain(|a| !k.contains(a));
                    cfg.save(&config)?;
                    dropin(&cfg, true)?;
                }
                ActionsCmd::Status => {}
                ActionsCmd::Refresh => dropin(&cfg, false)?,
            }
            log(format!(
                "Actions from the central server: {}",
                if cfg.actions.is_empty() { "none (off)".to_string() } else { cfg.actions.join(", ") }
            ));
            Ok(())
        }
        Cmd::Deploy { action, config } => {
            let m = deploy_marker(&config);
            match action {
                DeployCmd::Start { label, minutes, paths } => {
                    tyrosd_core::deploy::DeployWindow::start(&m, &label, minutes, paths)?;
                    log(format!("Deploy window “{label}” active (max. {minutes} min)"));
                }
                DeployCmd::End => {
                    tyrosd_core::deploy::DeployWindow::end(&m)?;
                    log("Deploy window ended");
                }
            }
            Ok(())
        }
    }
}

/// Remembers newly created PHP files in web directories (not during deploys/package updates).
struct RecentPhpSink(Arc<tyrosd_source_weblog::RecentPhp>);

impl Sink for RecentPhpSink {
    fn emit(&self, e: &tyrosd_core::Event) {
        if !matches!(e.op, tyrosd_core::Op::Create | tyrosd_core::Op::Rename) {
            return;
        }
        let note = e.note.as_deref().unwrap_or("");
        if note.split(',').any(|n| n == "pkg" || n.starts_with("deploy:")) {
            return;
        }
        self.0.note(&e.path, e.comm.as_deref().unwrap_or(""));
    }
}

/// Real-time malware check (security plan, item 5): every new/changed PHP/JS file in web directories
/// is checked against the patterns of the compromise check. Own thread with a bounded queue, so that
/// large deploys do not slow down monitoring. If the queue is full, nothing is silently dropped
/// (security review: "webshell scan drops under load"): losses are counted, their folders queued and
/// re-checked as soon as the queue is empty.
type WebshellJob = (String, String, Vec<String>, bool, i32, String);

#[derive(Default)]
struct WebshellDrops {
    count: std::sync::atomic::AtomicU64,
    dirs: std::sync::Mutex<std::collections::HashSet<String>>,
}

struct WebshellSink(std::sync::mpsc::SyncSender<WebshellJob>, Arc<WebshellDrops>);

/// queue at most this many folders for the re-scan (beyond that: periodic reconciliation + check)
const WEBSHELL_RESCAN_DIRS: usize = 2000;
/// at most this many files per re-checked folder
const WEBSHELL_RESCAN_FILES: usize = 5000;

fn web_code(path: &str) -> bool {
    // in containers the path inside the container counts (/var/lib/machines/app/var/www/… → /var/www/…)
    let l = tyrosd_core::container::effective(path).to_ascii_lowercase();
    let web = l.starts_with("/var/www/") || l.starts_with("/srv/") || l.contains("/public_html/") || l.contains("/httpdocs/") || l.starts_with("/usr/share/nginx/");
    web && [".php", ".phtml", ".phar", ".php5", ".php7", ".pht", ".inc", ".js"].iter().any(|e| l.ends_with(e)) && !l.contains("/node_modules/")
}

impl Sink for WebshellSink {
    fn emit(&self, e: &tyrosd_core::Event) {
        if !matches!(e.op, tyrosd_core::Op::Create | tyrosd_core::Op::Modify | tyrosd_core::Op::Rename) || !(web_code(&e.path) || yara_rules::tmp_file(&e.path)) {
            return;
        }
        let note = e.note.as_deref().unwrap_or("");
        if note.split(',').any(|n| n == "pkg") {
            return;
        }
        let deploy = note.split(',').any(|n| n.starts_with("deploy:"));
        let job = (e.path.clone(), e.comm.clone().unwrap_or_default(), e.proc_chain.clone(), deploy, e.pid.unwrap_or(0), e.exe.clone().unwrap_or_default());
        if let Err(std::sync::mpsc::TrySendError::Full(job)) = self.0.try_send(job) {
            self.1.count.fetch_add(1, Ordering::Relaxed);
            if let Some((dir, _)) = job.0.rsplit_once('/') {
                let mut d = self.1.dirs.lock().unwrap();
                if d.len() < WEBSHELL_RESCAN_DIRS {
                    d.insert(dir.to_string());
                }
            }
        }
    }
}

fn webshell_worker(spool: Arc<Spool>) -> WebshellSink {
    let (tx, rx) = std::sync::mpsc::sync_channel::<WebshellJob>(2000);
    let drops = Arc::new(WebshellDrops::default());
    let drops2 = drops.clone();
    std::thread::Builder::new()
        .name("webshell-scan".into())
        .spawn(move || {
            let mut recent: std::collections::HashMap<String, std::time::Instant> = Default::default();
            // YARA: scan the same file at most once per minute (temp files are often written in many steps)
            let mut yara_seen: std::collections::HashMap<String, std::time::Instant> = Default::default();
            let mut check = |(path, comm, chain, deploy, pid, exe): WebshellJob| {
                if !yara_seen.get(&path).is_some_and(|t| t.elapsed() < Duration::from_secs(60)) {
                    if yara_seen.len() > 20_000 {
                        yara_seen.retain(|_, t| t.elapsed() < Duration::from_secs(60));
                    }
                    yara_seen.insert(path.clone(), std::time::Instant::now());
                    let limit = if web_code(&path) { yara_rules::MAX_WEB } else { yara_rules::MAX_OTHER };
                    let yh = yara_rules::scan_path(&path, limit);
                    if !yh.is_empty() {
                        let key = format!("yara|{path}|{}", yh.iter().map(|h| h.rule.as_str()).collect::<Vec<_>>().join(","));
                        if !recent.get(&key).is_some_and(|t| t.elapsed() < Duration::from_secs(3600)) {
                            recent.insert(key.clone(), std::time::Instant::now());
                            let by = if comm.is_empty() { String::new() } else { format!("\nWritten by: {comm}") };
                            let sev = if deploy { "medium" } else { tyrosd_yara::severity(&yh) };
                            let _ = spool.push(
                                tyrosd_core::now_ns(),
                                pb::envelope::Body::Detection(pb::Detection {
                                    rule: "yara".into(),
                                    severity: sev.into(),
                                    title: format!("Malware signature in file: {} ({})", path.rsplit('/').next().unwrap_or(&path), yh[0].rule),
                                    detail: format!("{}{by}{}", tyrosd_yara::detail(&path, &yh), if deploy { "\n(written during a deploy window)" } else { "" }),
                                    pid: pid.max(0) as u32,
                                    exe: exe.clone(),
                                    proc_chain: chain.clone(),
                                    key,
                                }),
                            );
                        }
                    }
                }
                let hits = tyrosd_check::web::scan_file(&path);
                if hits.is_empty() {
                    return;
                }
                let key = format!("{path}|{}", hits.join(","));
                if recent.get(&key).is_some_and(|t| t.elapsed() < Duration::from_secs(3600)) {
                    return;
                }
                if recent.len() > 5000 {
                    recent.clear();
                }
                recent.insert(key.clone(), std::time::Instant::now());
                let by = if comm.is_empty() { String::new() } else { format!("\nWritten by: {comm}") };
                let _ = spool.push(
                    tyrosd_core::now_ns(),
                    pb::envelope::Body::Detection(pb::Detection {
                        rule: "webshell_written".into(),
                        severity: if deploy { "high" } else { "critical" }.into(),
                        title: format!(
                            "Malicious code detected in file: {}{}",
                            path.rsplit('/').next().unwrap_or(&path),
                            tyrosd_core::container::container_path(&path).map(|c| format!(" [Container {}]", c.label)).unwrap_or_default()
                        ),
                        detail: format!("{path}\nPattern: {}{by}{}", hits.join(", "), if deploy { "\n(written during a deploy window)" } else { "" }),
                        pid: pid.max(0) as u32,
                        exe,
                        proc_chain: chain,
                        key,
                    }),
                );
            };
            loop {
                match rx.recv_timeout(Duration::from_secs(2)) {
                    Ok(job) => check(job),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        // Queue empty: re-check skipped folders
                        let dirs: Vec<String> = std::mem::take(&mut *drops2.dirs.lock().unwrap()).into_iter().collect();
                        if dirs.is_empty() {
                            continue;
                        }
                        let lost = drops2.count.swap(0, Ordering::Relaxed);
                        log(format!("Malware check: {lost} files skipped under load – re-checking {} folders", dirs.len()));
                        for d in dirs {
                            let Ok(rd) = std::fs::read_dir(&d) else { continue };
                            for e in rd.flatten().take(WEBSHELL_RESCAN_FILES) {
                                let p = e.path().to_string_lossy().into_owned();
                                if e.file_type().is_ok_and(|t| t.is_file()) && web_code(&p) {
                                    check((p, String::new(), Vec::new(), false, 0, String::new()));
                                }
                            }
                        }
                    }
                    Err(_) => return,
                }
            }
        })
        .ok();
    WebshellSink(tx, drops)
}

/// Remove leftovers of the self-update of early versions (`/tmp/tyrosd-new`, reported by the check as
/// "ELF program in /tmp") – only exactly these names, only regular root-owned ELF files, older than
/// one day (an update currently in progress is never affected).
fn cleanup_stale_update_files() {
    use std::os::unix::fs::MetadataExt;
    for p in ["/tmp/tyrosd-new", "/tmp/tyrosecd-new", "/var/tmp/tyrosd-new", "/var/tmp/tyrosecd-new"] {
        let Ok(m) = std::fs::symlink_metadata(p) else { continue };
        let old = m.modified().ok().and_then(|t| t.elapsed().ok()).is_some_and(|d| d > Duration::from_secs(86_400));
        let mut head = [0u8; 4];
        let elf = std::fs::File::open(p).and_then(|mut f| std::io::Read::read_exact(&mut f, &mut head)).is_ok() && &head == b"\x7fELF";
        if m.is_file() && m.uid() == 0 && old && elf && std::fs::remove_file(p).is_ok() {
            log(format!("old update file {p} removed"));
        }
    }
}

/// Switch the former default address of the central server to `SERVER_DEFAULT` if it is reachable (TLS with
/// server CA, hostname and client certificate). Saves the configuration; true = switched.
fn migrate_server(config: &str, cfg: &mut AgentConfig) -> bool {
    use tyrosd_transport::config::{legacy_server, SERVER_DEFAULT};
    if !legacy_server(&cfg.server) {
        return false;
    }
    match tyrosd_transport::client::probe(cfg, SERVER_DEFAULT) {
        Ok(()) => {
            let old = std::mem::replace(&mut cfg.server, SERVER_DEFAULT.to_string());
            match cfg.save(config) {
                Ok(()) => log(format!("Central server switched: {old} → {SERVER_DEFAULT}")),
                Err(e) => log(format!("Central server {SERVER_DEFAULT} reachable, but the configuration cannot be saved ({e:#}) – applies to this run only")),
            }
            true
        }
        Err(e) => {
            log(format!("Central server stays {} – new address not reachable yet ({e:#})", cfg.server));
            false
        }
    }
}

/// Agent service connected to the central server.
fn run_agent(config: &str) -> Result<()> {
    let mut cfg = AgentConfig::load(config)?;
    if !cfg.enrolled() {
        bail!("not enrolled – first run: tyrosecd enroll --server … --token …");
    }
    cleanup_stale_update_files();
    // former default address (app.tyrosec.com:8443) → ingest.tyrosec.com (port 443): only if the new address
    // is reachable; otherwise everything stays as before and a background attempt switches the configuration later
    if !migrate_server(config, &mut cfg) && tyrosd_transport::config::legacy_server(&cfg.server) {
        let (path, c) = (config.to_string(), cfg.clone());
        std::thread::Builder::new().name("server-migrate".into()).spawn(move || {
            let mut c = c;
            loop {
                std::thread::sleep(Duration::from_secs(6 * 3600));
                if migrate_server(&path, &mut c) {
                    log("new address applies from the next agent restart");
                    break;
                }
            }
        })?;
    }
    // Revert to the old version if an update repeatedly fails to start stably
    // (only without systemd; under systemd the unit's ExecStartPre handles this)
    if std::env::var_os("INVOCATION_ID").is_none() {
        if let Some(msg) = update::startup_check(&cfg.data_dir) {
            log(msg);
            std::process::exit(75);
        }
    }
    let state = State::open(&cfg.state_path(), 16, cfg.cache_mb * 1024 * 1024).context("state file")?;
    let first_run = !state.is_complete();
    let spool = Arc::new(Spool::open_limited(&cfg.spool_path(), cfg.spool_mb * 1024 * 1024, cfg.spool_max_mb.max(1) * 1024 * 1024).context("Spool")?);
    let _ = monitor::REPORT_SPOOL.set(spool.clone());
    // newly created PHP files (for the access-log analysis: "new file is being requested")
    let recent_php = Arc::new(tyrosd_source_weblog::RecentPhp::default());
    let recent_path = format!("{}/recent_php.json", cfg.data_dir);
    recent_php.load(&recent_path);
    let mut sinks: Vec<Box<dyn Sink>> =
        vec![Box::new(SpoolSink { spool: spool.clone() }), Box::new(RecentPhpSink(recent_php.clone())), Box::new(webshell_worker(spool.clone()))];
    if let Some(j) = &cfg.events_jsonl {
        sinks.push(Box::new(JsonlSink::open(Some(j))?));
    }
    let mut p = Processor::new(Arc::new(Policy::default_policy()), state.clone(), Box::new(MultiSink(sinks)), Algo::Sha256);
    p.deploy = Some(tyrosd_core::deploy::DeployWindow::new(format!("{}/deploy.json", cfg.data_dir)));
    let proc = Arc::new(p);
    install_signal_handler();
    let scan_roots = if cfg.scan_roots.is_empty() { default_scan_roots() } else { cfg.scan_roots.clone() };
    // Sending and heartbeat before setting up monitoring: on large servers (137,000 folders, inotify) that takes
    // minutes – the server should still show up immediately as "reporting" (real-world case on one installation)
    let backend_shared = Arc::new(std::sync::RwLock::new("start".to_string()));
    let stop = Arc::new(AtomicBool::new(false));
    // Sending
    let snd = sender::Sender {
        client: Client::new(&cfg, true)?,
        spool: spool.clone(),
        state: state.clone(),
        stats: Default::default(),
    };
    let st = stop.clone();
    let sender_thread = std::thread::Builder::new().name("sender".into()).spawn(move || snd.run(st))?;
    // Heartbeat
    {
        let client = Client::new(&cfg, true)?;
        let (sp, st, be) = (spool.clone(), stop.clone(), backend_shared.clone());
        let (auto_update, fixed_base, data_dir) = (cfg.auto_update, cfg.update_base.clone(), cfg.data_dir.clone());
        let sources = cfg.update_sources.clone();
        let yara_on = cfg.yara;
        if yara_on {
            yara_rules::start(cfg.data_dir.clone());
        }
        // Beaconing sample: every 30 s record new outgoing connections per minute (incl. TIME_WAIT;
        // analysis in the central server)
        if cfg.beaconing {
            // Domain names of the targets from DNS responses (read only; without AF_PACKET/CAP_NET_RAW in the unit:
            // no names)
            let st_dns = stop.clone();
            let _ = std::thread::Builder::new().name("beacon-dns".into()).spawn(move || tyrosd_detect::dns::run(st_dns, |m: String| log(m)));
            let st = stop.clone();
            let _ = std::thread::Builder::new().name("beacon".into()).spawn(move || {
                let mut s = tyrosd_detect::beacon::Sampler::default();
                while !st.load(Ordering::Relaxed) {
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
                    tyrosd_detect::beacon::sample(&mut s, now);
                    for _ in 0..tyrosd_detect::beacon::INTERVAL_S {
                        if st.load(Ordering::Relaxed) {
                            break;
                        }
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
            });
        }
        // Actions: restore blocks after a restart; permissions are re-read on every heartbeat
        actions::maintain_blocks(&cfg.data_dir, true);
        let (cfg_path, act_spool, act_dir, act_state) = (config.to_string(), spool.clone(), cfg.data_dir.clone(), state.clone());
        let central = cfg.server.trim_start_matches("https://").split(['/', ':']).next().unwrap_or("").to_string();
        let cfg_path2 = cfg_path.clone();
        std::thread::Builder::new()
            .name("heartbeat".into())
            .spawn(move || {
                let enabled = move || actions::enabled(&cfg_path2);
                sender::heartbeat_loop(client, sp, be, st, Duration::from_secs(20), enabled, move |ack| {
                    actions::maintain_blocks(&act_dir, false);
                    if !ack.actions.is_empty() {
                        let (list, allowed) = (ack.actions.clone(), actions::enabled(&cfg_path));
                        let (sp2, dir2, central2, st2) = (act_spool.clone(), act_dir.clone(), central.clone(), act_state.clone());
                        std::thread::spawn(move || {
                            for a in list {
                                // each ID at most once (repetition → reported again as "already executed")
                                let Some((ok, message)) = actions::execute_once(&a, &allowed, &dir2, &central2, &st2) else {
                                    continue; // currently running in another thread – its result follows
                                };
                                log(format!("Action {} #{}: {}", a.kind, a.id, message));
                                let _ = sp2.push(tyrosd_core::now_ns(), pb::envelope::Body::ActionResult(pb::ActionResult { id: a.id, ok, message }));
                            }
                        });
                    }
                    if ack.run_check {
                        log("Central server requests a compromise check");
                        CHECK_REQUESTED.store(true, Ordering::SeqCst);
                    }
                    // YARA rule pack: only signed, higher and from an allowed source (like the agent update)
                    if yara_on && !ack.rules_version.is_empty() {
                        yara_rules::on_ack(&ack.rules_version, &ack.rules_base, &sources, &data_dir);
                    }
                    // The central server only reports "version X available"; only signed + higher versions are installed
                    if !auto_update || ack.update_version.is_empty() || !update::version_gt(&ack.update_version, update::AGENT_VERSION) {
                        return;
                    }
                    if update::failed_version(&data_dir).as_deref() == Some(ack.update_version.as_str()) {
                        return; // this version has already been rolled back
                    }
                    if UPDATING.swap(true, Ordering::SeqCst) {
                        return; // already running
                    }
                    // Source: set locally (admin) or reported by the central server – the latter
                    // only if it is in the allowed list (protection against a compromised central server)
                    let base = match fixed_base.clone() {
                        Some(b) => b,
                        None if update::source_allowed(&ack.update_base, &sources) => ack.update_base.clone(),
                        None => {
                            if !WARNED_SOURCE.swap(true, Ordering::SeqCst) {
                                log(format!("Update source {} not allowed (update_sources) – ignored", ack.update_base));
                            }
                            UPDATING.store(false, Ordering::SeqCst);
                            return;
                        }
                    };
                    let dd = data_dir.clone();
                    std::thread::spawn(move || {
                        let r = update::check(&base, &dd).and_then(|m| match m {
                            Some(m) => update::apply(&base, &m, &dd).map(|_| Some(m.version)),
                            None => Ok(None),
                        });
                        match r {
                            Ok(Some(v)) => {
                                log(format!("Update to {v} installed – restarting"));
                                UPDATE_APPLIED.store(true, Ordering::SeqCst);
                                STOP.store(true, Ordering::SeqCst);
                            }
                            Ok(None) => UPDATING.store(false, Ordering::SeqCst),
                            Err(e) => {
                                log(format!("Update rejected: {e:#}"));
                                // do not retry on every heartbeat
                                std::thread::sleep(Duration::from_secs(3600));
                                UPDATING.store(false, Ordering::SeqCst);
                            }
                        }
                    });
                })
            })?;
    }
    let mon = Monitor::start(
        proc.clone(),
        MonitorOpts {
            backend: BackendChoice::Auto,
            roots: cfg.roots.clone(),
            scan: ScanConfig { roots: scan_roots, threads: auto_threads(0), rate_mb_s: None, low_prio: true, one_fs: false, full_hash: false },
            scan_interval: Duration::from_secs(cfg.scan_interval_s.max(300)),
            start_scan: true,
            debounce: Duration::from_millis(300),
            unlimited_queue: false,
        },
    )?;
    let backend = mon.backend.to_string();
    *backend_shared.write().unwrap() = backend.clone();
    log(format!("Agent running · Host {} · Backend {} · central server {}", cfg.host_id, backend, cfg.server));
    spool.push(
        tyrosd_core::now_ns(),
        pb::envelope::Body::Lifecycle(pb::Lifecycle {
            kind: "start".into(),
            host: Some(tyrosd_transport::enroll::host_info(&backend)),
            detail: if first_run { "first_run".into() } else { String::new() },
        }),
    )?;

    // Renew the client certificate (security review K4): check daily, renew via mTLS once < 14 days remain
    {
        let client = Client::new(&cfg, true)?;
        let (cfg2, st) = (cfg.clone(), stop.clone());
        std::thread::Builder::new().name("cert-renew".into()).spawn(move || {
            let mut wait = Duration::from_secs(60);
            while !st.load(Ordering::Relaxed) {
                let t = std::time::Instant::now();
                while t.elapsed() < wait {
                    if st.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
                wait = match tyrosd_transport::renew::maybe_renew(&cfg2, &client) {
                    Ok(None) => Duration::from_secs(24 * 3600),
                    Ok(Some(until)) => {
                        log(format!("Client certificate renewed – valid until {}", fmt_date(until)));
                        Duration::from_secs(24 * 3600)
                    }
                    Err(e) => {
                        let left = tyrosd_transport::renew::days_left(&cfg2).map(|d| format!("{d} days")).unwrap_or_else(|_| "unknown".into());
                        log(format!("Certificate renewal failed (remaining validity {left}): {e:#} – retrying in 1 h"));
                        Duration::from_secs(3600)
                    }
                };
            }
        })?;
    }
    // SSH logins
    {
        let (sp, st) = (spool.clone(), stop.clone());
        std::thread::Builder::new().name("auth".into()).spawn(move || {
            tyrosd_source_auth::run(st, move |e| {
                let _ = sp.push(tyrosd_core::now_ns(), pb::envelope::Body::Login(e));
            })
        })?;
    }
    // Decoy credentials: report opening of the decoy files (decoy plan, phase 1); secret addresses are
    // checked by the access-log analysis
    {
        let sp = spool.clone();
        let r = decoy::start_watch(&cfg.data_dir, move |id, path, pid| {
            let p = tyrosd_core::procinfo::lookup(pid);
            let comm = p.comm.clone().unwrap_or_default();
            // Backup and scanning programs routinely read everything – notice only
            let routine = decoy::routine_reader(&comm);
            let d = pb::Detection {
                rule: "decoy_read".into(),
                severity: if routine { "low" } else { "high" }.into(),
                title: format!("Decoy file read by {comm}"),
                detail: format!("{path}\nProgram: {}\nProcess chain: {}", p.exe.clone().unwrap_or_default(), p.chain.join(" ← ")),
                pid: pid.max(0) as u32,
                exe: p.exe.clone().unwrap_or_default(),
                proc_chain: p.chain.clone(),
                key: format!("decoy:{id}"),
            };
            let _ = sp.push(tyrosd_core::now_ns(), pb::envelope::Body::Detection(d));
        });
        match r {
            Ok(()) => log(format!("Decoys: {} active", decoy::load(&cfg.data_dir).len())),
            Err(e) => log(format!("Decoy watch not available: {e}")),
        }
    }
    // Access logs (nginx/Apache): webshell requests, sensitive files, WordPress logins
    {
        let (sp, st, recent) = (spool.clone(), stop.clone(), recent_php.clone());
        let rp = recent_path.clone();
        std::thread::Builder::new().name("weblog".into()).spawn(move || {
            let saver = {
                let (recent, st) = (recent.clone(), st.clone());
                std::thread::spawn(move || {
                    let mut last = std::time::Instant::now();
                    while !st.load(Ordering::Relaxed) {
                        std::thread::sleep(Duration::from_secs(5));
                        if last.elapsed() >= Duration::from_secs(600) {
                            recent.save(&rp);
                            last = std::time::Instant::now();
                        }
                    }
                    recent.save(&rp);
                })
            };
            tyrosd_source_weblog::run(st, recent, move |o| {
                let body = match o {
                    tyrosd_source_weblog::Out::Detect(d) => pb::envelope::Body::Detection(d),
                    tyrosd_source_weblog::Out::Login(l) => pb::envelope::Body::Login(l),
                };
                let _ = sp.push(tyrosd_core::now_ns(), body);
            });
            let _ = saver.join();
        })?;
    }
    // Metrics
    {
        let (sp, st) = (spool.clone(), stop.clone());
        let every = Duration::from_secs(cfg.metrics_interval_s.clamp(5, 60));
        std::thread::Builder::new().name("metrics".into()).spawn(move || {
            let mut c = tyrosd_metrics::Collector::default();
            while !st.load(Ordering::Relaxed) {
                std::thread::sleep(every);
                if let Some(p) = c.sample() {
                    let _ = sp.push(tyrosd_core::now_ns(), pb::envelope::Body::Metrics(pb::MetricBatch { points: vec![p] }));
                }
            }
        })?;
    }
    // Server inventory: collect every 10 min, send on change (otherwise every 6 h)
    {
        let (sp, st) = (spool.clone(), stop.clone());
        let every = cfg.inventory_interval_s.clamp(30, 86400);
        std::thread::Builder::new().name("inventory".into()).spawn(move || {
            let mut last = String::new();
            let mut last_sent = std::time::Instant::now();
            std::thread::sleep(Duration::from_secs(20));
            while !st.load(Ordering::Relaxed) {
                // Locations for decoys and app detection: same as for placing and write permission (incl. web server configuration)
                let inv = tyrosd_inventory::collect_in(decoy::webroots());
                // app roots for the deploy detection (process starts)
                tyrosd_detect::set_app_roots(inv.apps.iter().map(|a| a.root.clone()).collect());
                let fp = tyrosd_inventory::fingerprint(&inv);
                if fp != last || last_sent.elapsed() > Duration::from_secs(6 * 3600) {
                    if let Ok(js) = serde_json::to_vec(&inv) {
                        let z = zstd::encode_all(&js[..], 3).unwrap_or_default();
                        let _ = sp.push(tyrosd_core::now_ns(), pb::envelope::Body::Inventory(pb::InventoryReport { json_zstd: z }));
                        last = fp;
                        last_sent = std::time::Instant::now();
                    }
                }
                for _ in 0..every {
                    if st.load(Ordering::Relaxed) {
                        break;
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        })?;
    }
    // Detections: process starts (proc connector), reverse shell, SMTP/mining connections (stage C)
    {
        let sp = spool.clone();
        tyrosd_detect::run(&STOP, move |d| {
            log(format!("Detection [{}] {}", d.severity, d.title));
            match sp.push(tyrosd_core::now_ns(), pb::envelope::Body::Detection(d)) {
                Ok(seq) => log(format!("Detection queued (seq {seq})")),
                Err(e) => log(format!("Detection not queued: {e:#}")),
            }
        });
    }
    // Confirm the update once the agent has been running stably for 2 min
    {
        let (sp, dd) = (spool.clone(), cfg.data_dir.clone());
        std::thread::Builder::new().name("update-confirm".into()).spawn(move || {
            std::thread::sleep(Duration::from_secs(120));
            if let Some((from, to)) = update::confirm(&dd) {
                log(format!("Update {from} → {to} confirmed"));
                let _ = sp.push(
                    tyrosd_core::now_ns(),
                    pb::envelope::Body::Lifecycle(pb::Lifecycle { kind: "updated".into(), host: None, detail: format!("{from} → {to}") }),
                );
            }
        })?;
    }
    // Compromise check (master plan 21.2): after the first baseline, then daily
    // and on request from the web interface (via the heartbeat response)
    {
        let (sp, stt, dd) = (spool.clone(), state.clone(), cfg.data_dir.clone());
        std::thread::Builder::new().name("check".into()).spawn(move || {
            while !stt.is_complete() && !STOP.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_secs(5));
            }
            let daily = Duration::from_secs(24 * 3600);
            // Time of the last check survives restarts (up to 0.4.12 the day started anew on every restart – with
            // frequent updates/restarts the check did not run for days)
            let stamp = std::path::Path::new(&dd).join("last_check");
            let saved = std::fs::read_to_string(&stamp).ok().and_then(|s| s.trim().parse::<u64>().ok())
                .map(|t| std::time::UNIX_EPOCH + Duration::from_secs(t));
            let mut last = if first_run { None } else { Some(saved.unwrap_or_else(std::time::SystemTime::now)) };
            while !STOP.load(Ordering::Relaxed) {
                let due = last.map(|t| t.elapsed().map(|e| e >= daily).unwrap_or(false)).unwrap_or(true);
                let asked = CHECK_REQUESTED.swap(false, Ordering::SeqCst);
                if due || asked {
                    log(if asked { "Compromise check (requested) …" } else { "Compromise check …" });
                    // state of the package/theme hashes (sent only when changed, otherwise every 7 days) in the data folder
                    // same webroots as the inventory (web server configuration incl. non-standard docroots),
                    // otherwise applications outside /var/www are never checked
                    let report = tyrosd_check::run(tyrosd_check::CheckConfig { webroots: decoy::webroots(), state_dir: Some(dd.clone()), ..Default::default() });
                    log(format!("Compromise check done: {} findings", report.findings.len()));
                    if let Ok(js) = serde_json::to_vec(&report) {
                        let z = zstd::encode_all(&js[..], 3).unwrap_or_default();
                        let _ = sp.push(tyrosd_core::now_ns(), pb::envelope::Body::Check(pb::CheckReport { json_zstd: z }));
                    }
                    let now = std::time::SystemTime::now();
                    last = Some(now);
                    if let Ok(d) = now.duration_since(std::time::UNIX_EPOCH) {
                        let _ = std::fs::write(&stamp, d.as_secs().to_string());
                    }
                }
                std::thread::sleep(Duration::from_secs(5));
            }
        })?;
    }

    mon.run_until_stop()?;
    let _ = spool.push(
        tyrosd_core::now_ns(),
        pb::envelope::Body::Lifecycle(pb::Lifecycle { kind: "stop".into(), host: None, detail: if UPDATE_APPLIED.load(Ordering::SeqCst) { "update".into() } else { "SIGTERM".into() } }),
    );
    stop.store(true, Ordering::Relaxed);
    let _ = sender_thread.join();
    log("Agent stopped");
    if UPDATE_APPLIED.load(Ordering::SeqCst) {
        std::process::exit(75); // systemd (Restart=on-failure) starts the new binary
    }
    Ok(())
}

/// Unix seconds → "DD.MM.YYYY" (UTC)
fn fmt_date(ts: i64) -> String {
    // Days since 1970 → date (algorithm by Howard Hinnant)
    let z = ts.div_euclid(86400) + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{d:02}.{m:02}.{y}")
}

static UPDATING: AtomicBool = AtomicBool::new(false);
static WARNED_SOURCE: AtomicBool = AtomicBool::new(false);
static UPDATE_APPLIED: AtomicBool = AtomicBool::new(false);
static CHECK_REQUESTED: AtomicBool = AtomicBool::new(false);

fn probe() -> Result<()> {
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default().trim().to_string();
    let btf = std::path::Path::new("/sys/kernel/btf/vmlinux").exists();
    let fan = tyrosd_source_fanotify::probe();
    let limit = std::fs::read_to_string("/proc/sys/fs/inotify/max_user_watches").unwrap_or_default().trim().to_string();
    let init = std::fs::read_to_string("/proc/1/comm").unwrap_or_default().trim().to_string();
    let os = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let os = os.lines().find_map(|l| l.strip_prefix("PRETTY_NAME=")).unwrap_or("").trim_matches('"').to_string();
    let pm = ["dpkg", "rpm", "apk", "pacman", "zypper"].into_iter().filter(|b| tyrosd_check::pkg::which(b)).collect::<Vec<_>>();
    let mounts: Vec<String> = tyrosd_source_fanotify::mounts()
        .into_iter()
        .filter(|m| {
            !matches!(
                m.fstype.as_str(),
                "proc" | "sysfs" | "cgroup" | "cgroup2" | "devpts" | "mqueue" | "debugfs" | "tracefs" | "securityfs" | "pstore" | "bpf" | "autofs"
                    | "fusectl" | "configfs" | "hugetlbfs" | "binfmt_misc" | "nsfs" | "devtmpfs"
            )
        })
        .map(|m| format!("{} {}", m.mount_point, m.fstype))
        .collect();
    let v = serde_json::json!({
        "os": os,
        "kernel": kernel,
        "btf": btf,
        "fanotify_dfid_name": fan.is_ok(),
        "fanotify_error": fan.err().map(|e| format!("{e:#}")),
        "inotify_max_user_watches": limit,
        "pid1": init,
        "package_managers": pm,
        "selinux": std::fs::read_to_string("/sys/fs/selinux/enforce").ok().map(|s| s.trim().to_string()),
        "apparmor": std::path::Path::new("/sys/kernel/security/apparmor").exists(),
        "psi": std::path::Path::new("/proc/pressure/cpu").exists(),
        "journald": std::path::Path::new("/run/systemd/journal").exists(),
        "wtmpdb": std::path::Path::new("/var/lib/wtmpdb/wtmp.db").exists(),
        "mounts": mounts,
        "expected_backend": if tyrosd_source_fanotify::probe().is_ok() { "fanotify" } else { "inotify" },
    });
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}
