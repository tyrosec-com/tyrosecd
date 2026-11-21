//! tyrosd – Agent-CLI
//!
//! Produkt:  enroll | run | check | probe
//! Diagnose: watch (lokal, ohne Zentrale) | scan | diff-test

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
#[command(name = "tyrosecd", version = update::AGENT_VERSION, about = "tyrosecd – Linux-Server-Wächter (Agent)")]
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
    /// Ereignisse als JSON-Zeilen (Datei oder - für stdout)
    #[arg(long, default_value = "/var/log/tyrosd-spike/events.jsonl")]
    events_out: String,
    /// Budget für gespeicherte Inhalte (Diff-Basis, komprimiert) in MB
    #[arg(long, default_value_t = 500)]
    cache_mb: u64,
    /// Zustandsdatei (eingebettete Datenbank: Hashes, Metadaten, Diff-Basis)
    #[arg(long, default_value = "/var/lib/tyrosd-spike/state.redb")]
    state: String,
    /// RAM-Cache der Zustandsdatei in MB
    #[arg(long, default_value_t = 16)]
    state_cache_mb: usize,
    /// sha256 | blake3
    #[arg(long, default_value = "sha256")]
    hash: Algo,
    /// zusätzliche Policy-Regeln (JSON: {"rules":[{"glob":"…","mode":"full"}]})
    #[arg(long)]
    policy: Option<String>,
    /// Diff-Text (gekürzt) in Events schreiben
    #[arg(long)]
    emit_diff: bool,
    /// Scan-Threads (0 = automatisch: Hälfte der CPU-Kerne, mindestens 1)
    #[arg(long, default_value_t = 0)]
    threads: usize,
    /// Scan-Lese-Limit in MB/s (0 = aus)
    #[arg(long, default_value_t = 0)]
    rate_mb: u64,
    /// Scan mit IO-Klasse idle + nice
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    low_prio: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Bei der Zentrale anmelden (Einmal-Token aus der Web-Oberfläche)
    Enroll {
        #[arg(long)]
        server: Option<String>,
        #[arg(long)]
        token: Option<String>,
        /// Token aus Datei lesen (empfohlen; erscheint nicht in der Prozessliste). Sonst Umgebung TYROSD_TOKEN oder stdin
        #[arg(long)]
        token_file: Option<String>,
        /// CA-Datei für das Server-Zertifikat (nur Self-hosted/Test)
        #[arg(long)]
        server_ca: Option<String>,
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: String,
        #[arg(long)]
        data_dir: Option<String>,
    },
    /// Agent-Dienst: Überwachung, Scans, Metriken, Versand an die Zentrale
    Run {
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: String,
    },
    /// Echtzeit-Überwachung nur lokal (Diagnose, ohne Zentrale)
    Watch {
        #[arg(long, default_value = "auto")]
        backend: BackendArg,
        /// Wurzeln für Events (Standard: /)
        #[arg(long = "root")]
        roots: Vec<String>,
        /// Wurzeln für den Scan (Standard: Profilverzeichnisse)
        #[arg(long = "scan-root")]
        scan_roots: Vec<String>,
        /// Sekunden zwischen Abgleich-Scans (0 = nur beim Start)
        #[arg(long, default_value_t = 21600)]
        scan_interval: u64,
        /// Kein Scan beim Start
        #[arg(long)]
        no_start_scan: bool,
        #[arg(long, default_value_t = 300)]
        debounce_ms: u64,
        /// fanotify-Queue unbegrenzt (Kernel-Speicher wächst, wenn der Agent hängt – nur für Tests).
        /// Standard: begrenzt (16 384 Ereignisse); bei Überlauf Meldung + Abgleich-Scan
        #[arg(long)]
        unlimited_queue: bool,
        #[command(flatten)]
        c: Common,
    },
    /// Einmaliger Abgleich-Scan (Baseline, wenn kein Zustand vorhanden)
    Scan {
        #[arg(long = "root")]
        roots: Vec<String>,
        /// Alle Dateien neu hashen
        #[arg(long)]
        full_hash: bool,
        #[command(flatten)]
        c: Common,
    },
    /// Kompromittierungs-Check (ohne Zentrale)
    Check {
        /// Webroots (Standard: automatisch)
        #[arg(long = "webroot")]
        webroots: Vec<String>,
        /// Ohne Abfragen bei WordPress.org
        #[arg(long)]
        offline: bool,
        /// Systemwurzel (z. B. gemountetes Image)
        #[arg(long, default_value = "/")]
        sysroot: String,
        /// JSON-Bericht
        #[arg(long)]
        json_out: Option<String>,
        #[arg(long, default_value_t = 90)]
        days: i64,
        #[arg(long)]
        skip_suid_scan: bool,
        #[arg(long, default_value_t = 40)]
        max_findings: usize,
    },
    /// Deploy-Fenster: Änderungen bis `end` (oder Ablauf) als Deploy markieren
    Deploy {
        #[command(subcommand)]
        action: DeployCmd,
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: String,
    },
    /// Update prüfen/installieren (nur signierte, höhere Versionen)
    Update {
        /// Release-Quelle (Standard: update_base aus der Konfiguration)
        #[arg(long)]
        base: Option<String>,
        /// nur prüfen, nicht installieren
        #[arg(long)]
        check: bool,
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: String,
    },
    /// Aktionen aus der Zentrale freischalten/sperren (Wiederherstellen, Quarantäne, IP sperren)
    Actions {
        #[command(subcommand)]
        action: ActionsCmd,
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: String,
    },
    /// Server-Inventar anzeigen: Dienste, Prozesse, offene Ports, Firewall
    Inventory {
        /// als JSON ausgeben
        #[arg(long)]
        json: bool,
    },
    /// Fähigkeiten des Systems (Backend-Matrix)
    Probe,
    /// Diff + Patch-Round-Trip zweier Dateien
    DiffTest { old: String, new: String },
}

#[derive(Subcommand)]
enum ActionsCmd {
    /// freischalten (ohne Angabe: restore, quarantine, block_ip)
    Enable {
        kinds: Vec<String>,
        /// weiterer Ordner (außer den erkannten Webroots), in dem wiederhergestellt werden darf (mehrfach möglich)
        #[arg(long = "path")]
        paths: Vec<String>,
    },
    /// wieder sperren (ohne Angabe: alle)
    Disable { kinds: Vec<String> },
    /// freigeschaltete Aktionen anzeigen
    Status,
    /// systemd-Drop-in (Schreibfreigabe der Webroots) neu schreiben, z. B. nach neuen Webroots oder Updates
    Refresh,
}

#[derive(Subcommand)]
enum DeployCmd {
    /// Deploy beginnt (z. B. im CI vor `rsync`/`git pull`)
    Start {
        #[arg(long, default_value = "deploy")]
        label: String,
        /// spätestens nach so vielen Minuten endet das Fenster automatisch
        #[arg(long, default_value_t = 30)]
        minutes: u64,
        /// nur diese Pfade (Standard: alle)
        #[arg(long = "path")]
        paths: Vec<String>,
    },
    /// Deploy beendet
    End,
}

/// Enrollment-Token: --token-file, Umgebung TYROSD_TOKEN, stdin – oder (veraltet, sichtbar in der Prozessliste) --token
fn enroll_token(token: Option<String>, token_file: Option<String>) -> Result<String> {
    let t = if let Some(f) = token_file {
        std::fs::read_to_string(&f).with_context(|| f.clone())?
    } else if let Some(t) = token {
        log("Hinweis: --token ist in der Prozessliste sichtbar – besser --token-file=… oder Umgebung TYROSD_TOKEN");
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
        bail!("Token fehlt (--token-file=…, Umgebung TYROSD_TOKEN oder über stdin)");
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
    // /bin → /usr/bin bei merged-/usr nicht doppelt
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
    let state = State::open(&c.state, c.state_cache_mb, c.cache_mb * 1024 * 1024).context("Zustandsdatei")?;
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
            eprintln!("geänderte Zeilen: {} · Patch {} B · Round-Trip: {}", d.changed_lines, d.patch.len(), if ok { "OK" } else { "FEHLER" });
            std::process::exit(if ok { 0 } else { 1 });
        }
        Cmd::Check { webroots, offline, sysroot, json_out, days, skip_suid_scan, max_findings } => {
            let cfg = tyrosd_check::CheckConfig { sysroot, webroots, offline, timeline_days: days, skip_suid_scan, skip_dpkg_verify: false };
            let report = tyrosd_check::run(cfg);
            print!("{}", tyrosd_check::render_text(&report, max_findings));
            if let Some(p) = json_out {
                std::fs::write(&p, serde_json::to_vec_pretty(&report)?)?;
                log(format!("JSON-Bericht: {p}"));
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
                let Some(s) = server.clone() else { bail!("--server fehlt (keine Konfiguration vorhanden)") };
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
            log(format!("Konfiguration: {config} · starten mit: tyrosecd run"));
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
            println!("Firewall: {} · aktiv {} · eingehend {} · erlaubte Ports {:?} · {} Regeln", f.backend, f.active, f.input_policy, f.allowed_ports, f.rules);
            println!("\nOffene Ports:");
            for l in &inv.listeners {
                let fw = match l.firewall.as_str() {
                    "blocked" => " (Host-Firewall blockiert)",
                    "allowed" => " (von außen erreichbar, sofern keine Hoster-Firewall)",
                    _ => "",
                };
                println!("  {:>5}/{:<4} {:<40} {:<8} {}{}", l.port, l.proto, l.addr, l.scope, l.process, fw);
            }
            println!("\nProzesse (nach RAM):");
            for p in inv.processes.iter().take(40) {
                println!("  {:<26} {:>3}× {:>6} MB  {:<20} {}", p.app, p.count, p.rss_mb, p.users.join(","), p.exe);
            }
            println!("\nLaufende Dienste: {}", inv.services.iter().map(|s| s.unit.trim_end_matches(".service")).collect::<Vec<_>>().join(", "));
            let sw = &inv.software;
            let mut by: std::collections::BTreeMap<&str, usize> = Default::default();
            for p in &sw.packages {
                *by.entry(p.source.as_str()).or_default() += 1;
            }
            println!("\nSoftware ({}): {}", if sw.os_ecosystem.is_empty() { "Distribution unbekannt" } else { &sw.os_ecosystem }, by.iter().map(|(k, v)| format!("{k} {v}")).collect::<Vec<_>>().join(" · "));
            for p in sw.packages.iter().filter(|p| p.source != "pkg") {
                println!("  {:<10} {:<40} {:<16} {}", p.source, p.name, p.version, p.location);
            }
            Ok(())
        }
        Cmd::Update { base, check, config } => {
            let cfg = AgentConfig::load(&config).ok();
            let base = base
                .or_else(|| cfg.as_ref().and_then(|c| c.update_base.clone()))
                .ok_or_else(|| anyhow::anyhow!("--base fehlt (keine update_base in der Konfiguration)"))?;
            log(format!("installiert: {} · Quelle {base}", update::AGENT_VERSION));
            let dd = cfg.as_ref().map(|c| c.data_dir.clone()).unwrap_or_else(|| "/var/lib/tyrosecd".into());
            match update::check(&base, &dd)? {
                None => log("keine neuere signierte Version"),
                Some(m) if check => log(format!("verfügbar: {} (Signatur gültig)", m.version)),
                Some(m) => {
                    update::apply(&base, &m, &dd)?;
                    log(format!("Update auf {} installiert – jetzt: systemctl restart tyrosecd", m.version));
                }
            }
            Ok(())
        }
        Cmd::Actions { action, config } => {
            let mut cfg = AgentConfig::load(&config)?;
            let pick = |k: Vec<String>| -> Result<Vec<String>> {
                let k = if k.is_empty() { actions::KINDS.iter().map(|s| s.to_string()).collect() } else { k };
                if let Some(bad) = k.iter().find(|x| !actions::KINDS.contains(&x.as_str())) {
                    bail!("unbekannte Aktion {bad} (erlaubt: {})", actions::KINDS.join(", "));
                }
                Ok(k)
            };
            // Schreibfreigabe (systemd-Drop-in) passend zu den freigeschalteten Aktionen; Webroots wie beim Check erkannt
            let dropin = |cfg: &AgentConfig, restart: bool| -> Result<()> {
                if !std::path::Path::new("/run/systemd/system").is_dir() {
                    return Ok(());
                }
                // erkannte Webroots (auch aus der Webserver-Konfiguration); in Systembereichen (z. B. /usr/share/nginx/html)
                // bleiben sie gesperrt
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
                    // erst prüfen (ungültige Ordner), dann speichern
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
                "Aktionen aus der Zentrale: {}",
                if cfg.actions.is_empty() { "keine (aus)".to_string() } else { cfg.actions.join(", ") }
            ));
            Ok(())
        }
        Cmd::Deploy { action, config } => {
            let m = deploy_marker(&config);
            match action {
                DeployCmd::Start { label, minutes, paths } => {
                    tyrosd_core::deploy::DeployWindow::start(&m, &label, minutes, paths)?;
                    log(format!("Deploy-Fenster „{label}“ aktiv (max. {minutes} min)"));
                }
                DeployCmd::End => {
                    tyrosd_core::deploy::DeployWindow::end(&m)?;
                    log("Deploy-Fenster beendet");
                }
            }
            Ok(())
        }
    }
}

/// Merkt neu angelegte PHP-Dateien in Web-Verzeichnissen (nicht bei Deploys/Paket-Updates).
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

/// Schadcode-Prüfung in Echtzeit (Plan „Sicherheit“, Punkt 5): jede neue/geänderte PHP-/JS-Datei in Web-Verzeichnissen
/// wird mit den Mustern des Kompromittierungs-Checks geprüft. Eigener Thread mit begrenzter Warteschlange, damit
/// große Deploys die Überwachung nicht ausbremsen. Ist die Warteschlange voll, wird nichts stillschweigend verworfen
/// (Sicherheitsprüfung: „Webshell-Scan verwirft bei Last“): Verluste werden gezählt, ihre Ordner vorgemerkt und
/// nachgeprüft, sobald die Warteschlange leer ist.
type WebshellJob = (String, String, Vec<String>, bool, i32, String);

#[derive(Default)]
struct WebshellDrops {
    count: std::sync::atomic::AtomicU64,
    dirs: std::sync::Mutex<std::collections::HashSet<String>>,
}

struct WebshellSink(std::sync::mpsc::SyncSender<WebshellJob>, Arc<WebshellDrops>);

/// höchstens so viele Ordner für den Nachscan vormerken (darüber: periodischer Abgleich + Check)
const WEBSHELL_RESCAN_DIRS: usize = 2000;
/// höchstens so viele Dateien je nachgeprüftem Ordner
const WEBSHELL_RESCAN_FILES: usize = 5000;

fn web_code(path: &str) -> bool {
    // in Containern zählt der Pfad im Container (/var/lib/machines/app/var/www/… → /var/www/…)
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
            // YARA: dieselbe Datei höchstens einmal je Minute prüfen (Temp-Dateien werden oft in vielen Schritten geschrieben)
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
                            let by = if comm.is_empty() { String::new() } else { format!("\nGeschrieben von: {comm}") };
                            let sev = if deploy { "medium" } else { tyrosd_yara::severity(&yh) };
                            let _ = spool.push(
                                tyrosd_core::now_ns(),
                                pb::envelope::Body::Detection(pb::Detection {
                                    rule: "yara".into(),
                                    severity: sev.into(),
                                    title: format!("Schadcode-Signatur in Datei: {} ({})", path.rsplit('/').next().unwrap_or(&path), yh[0].rule),
                                    detail: format!("{}{by}{}", tyrosd_yara::detail(&path, &yh), if deploy { "\n(während eines Deploy-Fensters geschrieben)" } else { "" }),
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
                let by = if comm.is_empty() { String::new() } else { format!("\nGeschrieben von: {comm}") };
                let _ = spool.push(
                    tyrosd_core::now_ns(),
                    pb::envelope::Body::Detection(pb::Detection {
                        rule: "webshell_written".into(),
                        severity: if deploy { "high" } else { "critical" }.into(),
                        title: format!(
                            "Schadcode in Datei erkannt: {}{}",
                            path.rsplit('/').next().unwrap_or(&path),
                            tyrosd_core::container::container_path(&path).map(|c| format!(" [Container {}]", c.label)).unwrap_or_default()
                        ),
                        detail: format!("{path}\nMuster: {}{by}{}", hits.join(", "), if deploy { "\n(während eines Deploy-Fensters geschrieben)" } else { "" }),
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
                        // Warteschlange leer: übersprungene Ordner nachprüfen
                        let dirs: Vec<String> = std::mem::take(&mut *drops2.dirs.lock().unwrap()).into_iter().collect();
                        if dirs.is_empty() {
                            continue;
                        }
                        let lost = drops2.count.swap(0, Ordering::Relaxed);
                        log(format!("Schadcode-Prüfung: {lost} Dateien bei Last übersprungen – prüfe {} Ordner nach", dirs.len()));
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

/// Reste der Selbst-Aktualisierung früher Versionen (`/tmp/tyrosd-new`, vom Check als
/// „ELF-Programm in /tmp“ gemeldet) entfernen – nur genau diese Namen, nur reguläre root-eigene ELF-Dateien, älter als
/// ein Tag (ein gerade laufendes Update ist nie betroffen).
fn cleanup_stale_update_files() {
    use std::os::unix::fs::MetadataExt;
    for p in ["/tmp/tyrosd-new", "/tmp/tyrosecd-new", "/var/tmp/tyrosd-new", "/var/tmp/tyrosecd-new"] {
        let Ok(m) = std::fs::symlink_metadata(p) else { continue };
        let old = m.modified().ok().and_then(|t| t.elapsed().ok()).is_some_and(|d| d > Duration::from_secs(86_400));
        let mut head = [0u8; 4];
        let elf = std::fs::File::open(p).and_then(|mut f| std::io::Read::read_exact(&mut f, &mut head)).is_ok() && &head == b"\x7fELF";
        if m.is_file() && m.uid() == 0 && old && elf && std::fs::remove_file(p).is_ok() {
            log(format!("alte Update-Datei {p} entfernt"));
        }
    }
}

/// Frühere Standardadresse der Zentrale auf `SERVER_DEFAULT` umstellen, wenn diese erreichbar ist (TLS mit
/// Server-CA, Hostname und Client-Zertifikat). Speichert die Konfiguration; true = umgestellt.
fn migrate_server(config: &str, cfg: &mut AgentConfig) -> bool {
    use tyrosd_transport::config::{legacy_server, SERVER_DEFAULT};
    if !legacy_server(&cfg.server) {
        return false;
    }
    match tyrosd_transport::client::probe(cfg, SERVER_DEFAULT) {
        Ok(()) => {
            let old = std::mem::replace(&mut cfg.server, SERVER_DEFAULT.to_string());
            match cfg.save(config) {
                Ok(()) => log(format!("Zentrale umgestellt: {old} → {SERVER_DEFAULT}")),
                Err(e) => log(format!("Zentrale {SERVER_DEFAULT} erreichbar, Konfiguration aber nicht speicherbar ({e:#}) – gilt nur für diesen Lauf")),
            }
            true
        }
        Err(e) => {
            log(format!("Zentrale bleibt {} – neue Adresse noch nicht erreichbar ({e:#})", cfg.server));
            false
        }
    }
}

/// Agent-Dienst mit Anbindung an die Zentrale.
fn run_agent(config: &str) -> Result<()> {
    let mut cfg = AgentConfig::load(config)?;
    if !cfg.enrolled() {
        bail!("nicht angemeldet – zuerst: tyrosecd enroll --server … --token …");
    }
    cleanup_stale_update_files();
    // frühere Standardadresse (app.tyrosec.com:8443) → ingest.tyrosec.com (Port 443): nur wenn die neue Adresse
    // erreichbar ist; sonst bleibt alles beim Alten und ein Hintergrund-Versuch stellt die Konfiguration später um
    if !migrate_server(config, &mut cfg) && tyrosd_transport::config::legacy_server(&cfg.server) {
        let (path, c) = (config.to_string(), cfg.clone());
        std::thread::Builder::new().name("server-umzug".into()).spawn(move || {
            let mut c = c;
            loop {
                std::thread::sleep(Duration::from_secs(6 * 3600));
                if migrate_server(&path, &mut c) {
                    log("neue Adresse gilt ab dem nächsten Neustart des Agents");
                    break;
                }
            }
        })?;
    }
    // Rückkehr zur alten Version, wenn ein Update wiederholt nicht stabil startet
    // (nur ohne systemd; unter systemd erledigt das ExecStartPre der Unit)
    if std::env::var_os("INVOCATION_ID").is_none() {
        if let Some(msg) = update::startup_check(&cfg.data_dir) {
            log(msg);
            std::process::exit(75);
        }
    }
    let state = State::open(&cfg.state_path(), 16, cfg.cache_mb * 1024 * 1024).context("Zustandsdatei")?;
    let first_run = !state.is_complete();
    let spool = Arc::new(Spool::open_limited(&cfg.spool_path(), cfg.spool_mb * 1024 * 1024, cfg.spool_max_mb.max(1) * 1024 * 1024).context("Spool")?);
    let _ = monitor::REPORT_SPOOL.set(spool.clone());
    // neu angelegte PHP-Dateien (für die Access-Log-Auswertung: „neue Datei wird aufgerufen“)
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
    // Versand und Heartbeat vor dem Einrichten der Überwachung: auf großen Servern (137 000 Ordner, inotify) dauert
    // das Minuten – der Server soll trotzdem sofort als „meldet sich“ erscheinen (Praxisfall bei einer Installation)
    let backend_shared = Arc::new(std::sync::RwLock::new("start".to_string()));
    let stop = Arc::new(AtomicBool::new(false));
    // Versand
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
        // Beaconing-Stichprobe: alle 30 s neue ausgehende Verbindungen je Minute vermerken (inkl. TIME_WAIT; Auswertung in der Zentrale)
        if cfg.beaconing {
            // Domainnamen der Ziele aus DNS-Antworten (nur lesen; ohne AF_PACKET/CAP_NET_RAW in der Unit: ohne Namen)
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
        // Aktionen: Sperren nach Neustart wiederherstellen; Freischaltung wird je Heartbeat frisch gelesen
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
                                // jede ID höchstens einmal (Wiederholung → erneut gemeldet als „bereits ausgeführt“)
                                let Some((ok, message)) = actions::execute_once(&a, &allowed, &dir2, &central2, &st2) else {
                                    continue; // läuft gerade in einem anderen Thread – dessen Ergebnis folgt
                                };
                                log(format!("Aktion {} #{}: {}", a.kind, a.id, message));
                                let _ = sp2.push(tyrosd_core::now_ns(), pb::envelope::Body::ActionResult(pb::ActionResult { id: a.id, ok, message }));
                            }
                        });
                    }
                    if ack.run_check {
                        log("Zentrale fordert Kompromittierungs-Check an");
                        CHECK_REQUESTED.store(true, Ordering::SeqCst);
                    }
                    // YARA-Regelpaket: nur signiert, höher und von einer erlaubten Quelle (wie das Agent-Update)
                    if yara_on && !ack.rules_version.is_empty() {
                        yara_rules::on_ack(&ack.rules_version, &ack.rules_base, &sources, &data_dir);
                    }
                    // Zentrale meldet nur „Version X verfügbar“; installiert wird nur signiert + höher
                    if !auto_update || ack.update_version.is_empty() || !update::version_gt(&ack.update_version, update::AGENT_VERSION) {
                        return;
                    }
                    if update::failed_version(&data_dir).as_deref() == Some(ack.update_version.as_str()) {
                        return; // diese Version wurde bereits zurückgerollt
                    }
                    if UPDATING.swap(true, Ordering::SeqCst) {
                        return; // läuft bereits
                    }
                    // Quelle: lokal festgelegt (Admin) oder von der Zentrale gemeldet – letztere
                    // nur, wenn sie in der erlaubten Liste steht (Schutz bei kompromittierter Zentrale)
                    let base = match fixed_base.clone() {
                        Some(b) => b,
                        None if update::source_allowed(&ack.update_base, &sources) => ack.update_base.clone(),
                        None => {
                            if !WARNED_SOURCE.swap(true, Ordering::SeqCst) {
                                log(format!("Update-Quelle {} nicht erlaubt (update_sources) – ignoriert", ack.update_base));
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
                                log(format!("Update auf {v} installiert – Neustart"));
                                UPDATE_APPLIED.store(true, Ordering::SeqCst);
                                STOP.store(true, Ordering::SeqCst);
                            }
                            Ok(None) => UPDATING.store(false, Ordering::SeqCst),
                            Err(e) => {
                                log(format!("Update abgelehnt: {e:#}"));
                                // nicht bei jedem Heartbeat erneut versuchen
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
    log(format!("Agent läuft · Host {} · Backend {} · Zentrale {}", cfg.host_id, backend, cfg.server));
    spool.push(
        tyrosd_core::now_ns(),
        pb::envelope::Body::Lifecycle(pb::Lifecycle {
            kind: "start".into(),
            host: Some(tyrosd_transport::enroll::host_info(&backend)),
            detail: if first_run { "first_run".into() } else { String::new() },
        }),
    )?;

    // Client-Zertifikat erneuern (Sicherheitsprüfung K4): täglich prüfen, ab < 14 Tagen Restlaufzeit über mTLS erneuern
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
                        log(format!("Client-Zertifikat erneuert – gültig bis {}", fmt_date(until)));
                        Duration::from_secs(24 * 3600)
                    }
                    Err(e) => {
                        let left = tyrosd_transport::renew::days_left(&cfg2).map(|d| format!("{d} Tage")).unwrap_or_else(|_| "unbekannt".into());
                        log(format!("Zertifikats-Erneuerung fehlgeschlagen (Restlaufzeit {left}): {e:#} – neuer Versuch in 1 h"));
                        Duration::from_secs(3600)
                    }
                };
            }
        })?;
    }
    // SSH-Anmeldungen
    {
        let (sp, st) = (spool.clone(), stop.clone());
        std::thread::Builder::new().name("auth".into()).spawn(move || {
            tyrosd_source_auth::run(st, move |e| {
                let _ = sp.push(tyrosd_core::now_ns(), pb::envelope::Body::Login(e));
            })
        })?;
    }
    // Köder-Zugangsdaten: Öffnen der Köder-Dateien melden (Plan Köder, Phase 1); geheime Adressen prüft die Access-Log-Auswertung
    {
        let sp = spool.clone();
        let r = decoy::start_watch(&cfg.data_dir, move |id, path, pid| {
            let p = tyrosd_core::procinfo::lookup(pid);
            let comm = p.comm.clone().unwrap_or_default();
            // Sicherungs- und Prüfprogramme lesen routinemäßig alles – nur Hinweis
            let routine = decoy::routine_reader(&comm);
            let d = pb::Detection {
                rule: "decoy_read".into(),
                severity: if routine { "low" } else { "high" }.into(),
                title: format!("Köder-Datei gelesen von {comm}"),
                detail: format!("{path}
Programm: {}
Prozesskette: {}", p.exe.clone().unwrap_or_default(), p.chain.join(" ← ")),
                pid: pid.max(0) as u32,
                exe: p.exe.clone().unwrap_or_default(),
                proc_chain: p.chain.clone(),
                key: format!("decoy:{id}"),
            };
            let _ = sp.push(tyrosd_core::now_ns(), pb::envelope::Body::Detection(d));
        });
        match r {
            Ok(()) => log(format!("Köder: {} aktiv", decoy::load(&cfg.data_dir).len())),
            Err(e) => log(format!("Köder-Beobachtung nicht verfügbar: {e}")),
        }
    }
    // Access-Logs (nginx/Apache): Webshell-Aufrufe, sensible Dateien, WordPress-Logins
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
    // Metriken
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
    // Server-Inventar: alle 10 min erfassen, senden bei Änderung (sonst alle 6 h)
    {
        let (sp, st) = (spool.clone(), stop.clone());
        let every = cfg.inventory_interval_s.clamp(30, 86400);
        std::thread::Builder::new().name("inventory".into()).spawn(move || {
            let mut last = String::new();
            let mut last_sent = std::time::Instant::now();
            std::thread::sleep(Duration::from_secs(20));
            while !st.load(Ordering::Relaxed) {
                let mut inv = tyrosd_inventory::collect();
                // Orte für Köder: wie bei Anlegen und Schreibfreigabe (inkl. Webserver-Konfiguration)
                inv.webroots = decoy::webroots();
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
    // Erkennungen: Prozessstarts (Proc-Connector), Reverse Shell, SMTP/Mining-Verbindungen (Stufe C)
    {
        let sp = spool.clone();
        tyrosd_detect::run(&STOP, move |d| {
            log(format!("Erkennung [{}] {}", d.severity, d.title));
            match sp.push(tyrosd_core::now_ns(), pb::envelope::Body::Detection(d)) {
                Ok(seq) => log(format!("Erkennung eingereiht (seq {seq})")),
                Err(e) => log(format!("Erkennung nicht eingereiht: {e:#}")),
            }
        });
    }
    // Update bestätigen, wenn der Agent 2 min stabil läuft
    {
        let (sp, dd) = (spool.clone(), cfg.data_dir.clone());
        std::thread::Builder::new().name("update-confirm".into()).spawn(move || {
            std::thread::sleep(Duration::from_secs(120));
            if let Some((from, to)) = update::confirm(&dd) {
                log(format!("Update {from} → {to} bestätigt"));
                let _ = sp.push(
                    tyrosd_core::now_ns(),
                    pb::envelope::Body::Lifecycle(pb::Lifecycle { kind: "updated".into(), host: None, detail: format!("{from} → {to}") }),
                );
            }
        })?;
    }
    // Kompromittierungs-Check (Hauptplan 21.2): nach der ersten Baseline, danach täglich
    // und auf Anforderung aus der Web-Oberfläche (über die Heartbeat-Antwort)
    {
        let (sp, stt, dd) = (spool.clone(), state.clone(), cfg.data_dir.clone());
        std::thread::Builder::new().name("check".into()).spawn(move || {
            while !stt.is_complete() && !STOP.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_secs(5));
            }
            let daily = Duration::from_secs(24 * 3600);
            // Zeitpunkt des letzten Checks überlebt Neustarts (bis 0.4.12 begann der Tag bei jedem Neustart neu – bei
            // häufigen Updates/Neustarts lief der Check tagelang nicht)
            let stamp = std::path::Path::new(&dd).join("last_check");
            let saved = std::fs::read_to_string(&stamp).ok().and_then(|s| s.trim().parse::<u64>().ok())
                .map(|t| std::time::UNIX_EPOCH + Duration::from_secs(t));
            let mut last = if first_run { None } else { Some(saved.unwrap_or_else(std::time::SystemTime::now)) };
            while !STOP.load(Ordering::Relaxed) {
                let due = last.map(|t| t.elapsed().map(|e| e >= daily).unwrap_or(false)).unwrap_or(true);
                let asked = CHECK_REQUESTED.swap(false, Ordering::SeqCst);
                if due || asked {
                    log(if asked { "Kompromittierungs-Check (angefordert) …" } else { "Kompromittierungs-Check …" });
                    let report = tyrosd_check::run(tyrosd_check::CheckConfig::default());
                    log(format!("Kompromittierungs-Check fertig: {} Funde", report.findings.len()));
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
    log("Agent beendet");
    if UPDATE_APPLIED.load(Ordering::SeqCst) {
        std::process::exit(75); // systemd (Restart=on-failure) startet das neue Binary
    }
    Ok(())
}

/// Unix-Sekunden → „TT.MM.JJJJ“ (UTC)
fn fmt_date(ts: i64) -> String {
    // Tage seit 1970 → Datum (Algorithmus von Howard Hinnant)
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
