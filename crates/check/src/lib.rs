//! Kompromittierungs-Check (Hauptplan 21.2, Prototyp nach 27.5).
//! Läuft ohne Zentrale; Abgleich gegen externe Referenzen (WordPress.org)
//! plus lokale Inventur. Ergebnis: Funde mit Schwere + Liste „bitte bestätigen“.

pub mod gitindex;
pub mod pkg;
pub mod persistence;
pub mod system;
pub mod timeline;
pub mod web;
pub mod wordpress;
/// Sicheres Lesen unter fremden Wurzeln (Container) – für Crates ohne direkte Abhängigkeit von tyrosd-core
pub use tyrosd_core::rootfs;

use serde::Serialize;

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Web,
    Persistence,
    Binaries,
    Runtime,
    Network,
    History,
}

impl Category {
    pub fn label(&self) -> &'static str {
        match self {
            Category::Web => "Web-Code",
            Category::Persistence => "Persistenz",
            Category::Binaries => "Programme",
            Category::Runtime => "Laufender Zustand",
            Category::Network => "Netzwerk",
            Category::History => "Vorgeschichte",
        }
    }
    pub fn all() -> [Category; 6] {
        [Category::Web, Category::Persistence, Category::Binaries, Category::Runtime, Category::Network, Category::History]
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct Finding {
    pub severity: Severity,
    pub category: Category,
    /// Stabiler Kurzname der Prüfung, z. B. `wp_core_modified`
    pub check: &'static str,
    pub title: String,
    pub path: Option<String>,
    pub detail: Option<String>,
}

/// Eintrag, den der Nutzer einmal bestätigen muss (SSH-Key, Cronjob …).
#[derive(Serialize, Clone, Debug)]
pub struct ConfirmItem {
    pub kind: &'static str,
    pub path: String,
    pub value: String,
}

#[derive(Serialize, Default, Debug)]
pub struct Report {
    pub tool: String,
    pub host: HostInfo,
    pub started_ts: i64,
    pub duration_ms: u128,
    pub summary: Vec<CategorySummary>,
    pub findings: Vec<Finding>,
    pub confirm: Vec<ConfirmItem>,
    pub stats: serde_json::Map<String, serde_json::Value>,
    pub timeline: Option<timeline::Timeline>,
    pub notes: Vec<String>,
    /// Programme/Bibliotheken mit Paket, Version und md5 – Abgleich gegen offizielle Pakete in der Zentrale
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub binaries: Vec<BinaryRef>,
}

#[derive(Serialize, Clone, Debug)]
pub struct BinaryRef {
    pub path: String,
    pub package: String,
    pub version: String,
    /// dpkg-Systeme: md5 der Datei
    #[serde(skip_serializing_if = "String::is_empty")]
    pub md5: String,
    /// RPM-Systeme: SHA-256 der Datei (selbst berechnet) und Paket-Architektur
    #[serde(skip_serializing_if = "String::is_empty")]
    pub sha256: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub arch: String,
}

#[derive(Serialize, Default, Debug)]
pub struct HostInfo {
    pub hostname: String,
    pub kernel: String,
    pub os: String,
    pub package_manager: String,
}

#[derive(Serialize, Debug)]
pub struct CategorySummary {
    pub category: Category,
    pub label: &'static str,
    /// rot / gelb / grün
    pub light: &'static str,
    pub counts: [usize; 5],
}

#[derive(Clone, Debug)]
pub struct CheckConfig {
    /// Wurzel des zu prüfenden Systems (für Tests/Offline-Scan: gemountetes Image)
    pub sysroot: String,
    pub webroots: Vec<String>,
    pub offline: bool,
    pub timeline_days: i64,
    pub skip_suid_scan: bool,
    pub skip_dpkg_verify: bool,
}

impl Default for CheckConfig {
    fn default() -> Self {
        CheckConfig {
            sysroot: "/".into(),
            webroots: Vec::new(),
            offline: false,
            timeline_days: 90,
            skip_suid_scan: false,
            skip_dpkg_verify: false,
        }
    }
}

/// Sammelt Funde und Statistik.
pub struct Ctx {
    pub cfg: CheckConfig,
    pub report: Report,
    pub pkgs: pkg::PackageDb,
    /// Dateien, die gegen eine Referenz geprüft und unverändert sind
    pub verified: std::collections::HashSet<String>,
}

impl Ctx {
    pub fn add(&mut self, severity: Severity, category: Category, check: &'static str, title: impl Into<String>, path: Option<String>, detail: Option<String>) {
        self.report.findings.push(Finding { severity, category, check, title: title.into(), path, detail });
    }
    pub fn confirm(&mut self, kind: &'static str, path: impl Into<String>, value: impl Into<String>) {
        self.report.confirm.push(ConfirmItem { kind, path: path.into(), value: value.into() });
    }
    pub fn stat(&mut self, k: &str, v: impl Into<serde_json::Value>) {
        self.report.stats.insert(k.to_string(), v.into());
    }
    /// Pfad innerhalb des geprüften Systems
    pub fn p(&self, abs: &str) -> String {
        if self.cfg.sysroot == "/" {
            abs.to_string()
        } else {
            format!("{}{}", self.cfg.sysroot.trim_end_matches('/'), abs)
        }
    }
}

fn read_trim(p: &str) -> String {
    std::fs::read_to_string(p).map(|s| s.trim().to_string()).unwrap_or_default()
}

fn os_pretty(sysroot_p: &str) -> String {
    let s = std::fs::read_to_string(sysroot_p).unwrap_or_default();
    s.lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim_matches('"').to_string())
        .unwrap_or_default()
}

/// Standard-Webroots, falls keine angegeben.
pub fn default_webroots(sysroot: &str) -> Vec<String> {
    let pre = sysroot.trim_end_matches('/');
    default_webroots_in(&tyrosd_core::rootfs::FsRoot::host(sysroot)).into_iter().map(|r| format!("{pre}{r}")).collect()
}

/// Standard-Webroots unter einer Wurzel, als Pfade **relativ** zu ihr (Container: `FsRoot::Contained`)
pub fn default_webroots_in(fs: &tyrosd_core::rootfs::FsRoot) -> Vec<String> {
    let mut v = Vec::new();
    for p in ["/var/www", "/srv/www", "/srv/http", "/usr/share/nginx/html"] {
        if fs.is_dir(p) {
            v.push(p.to_string());
        }
    }
    for base in ["/home", "/var/www/vhosts"] {
        for (name, _) in fs.read_dir(base, 10_000) {
            for sub in ["public_html", "httpdocs", "www", "htdocs"] {
                let p = format!("{base}/{name}/{sub}");
                if fs.is_dir(&p) {
                    v.push(p);
                }
            }
        }
    }
    v.sort();
    v.dedup();
    // verschachtelte Wurzeln entfernen (/var/www enthält /var/www/vhosts/...)
    let copy = v.clone();
    v.retain(|a| !copy.iter().any(|b| b != a && a.starts_with(&format!("{b}/"))));
    v
}

pub fn run(mut cfg: CheckConfig) -> Report {
    let t0 = std::time::Instant::now();
    if cfg.webroots.is_empty() {
        cfg.webroots = default_webroots(&cfg.sysroot);
    }
    let pkgs = pkg::PackageDb::load(&cfg.sysroot);
    let mut ctx = Ctx { cfg, report: Report::default(), pkgs, verified: Default::default() };
    ctx.report.tool = format!("tyrosecd-check {}", env!("CARGO_PKG_VERSION"));
    ctx.report.started_ts = tyrosd_core::now_ns();
    ctx.report.host = HostInfo {
        hostname: tyrosd_core::rootfs::cap_name(&read_trim(&ctx.p("/etc/hostname")), 64),
        kernel: read_trim("/proc/sys/kernel/osrelease"),
        os: os_pretty(&ctx.p("/etc/os-release")),
        package_manager: ctx.pkgs.kind.to_string(),
    };
    ctx.stat("package_files_known", ctx.pkgs.files.len());
    ctx.stat("webroots", ctx.cfg.webroots.clone());

    wordpress::check(&mut ctx);
    web::check(&mut ctx);
    persistence::check(&mut ctx);
    system::check(&mut ctx);
    timeline::check(&mut ctx);

    // Sortieren: schwerste zuerst
    ctx.report.findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.category.cmp(&b.category)));
    ctx.report.summary = Category::all()
        .iter()
        .map(|c| {
            let mut counts = [0usize; 5];
            for f in ctx.report.findings.iter().filter(|f| f.category == *c) {
                counts[f.severity as usize] += 1;
            }
            let light = if counts[4] + counts[3] > 0 {
                "rot"
            } else if counts[2] > 0 {
                "gelb"
            } else {
                "grün"
            };
            CategorySummary { category: *c, label: c.label(), light, counts }
        })
        .collect();
    ctx.report.duration_ms = t0.elapsed().as_millis();
    ctx.report
}

/// Lesbarer Kurzbericht.
pub fn render_text(r: &Report, max_findings: usize) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(s, "Kompromittierungs-Check · {} · {} · Kernel {}", r.host.hostname, r.host.os, r.host.kernel);
    let _ = writeln!(s, "Dauer: {:.1} s · Paket-DB: {}\n", r.duration_ms as f64 / 1000.0, r.host.package_manager);
    for c in &r.summary {
        let icon = match c.light {
            "rot" => "[ROT ]",
            "gelb" => "[GELB]",
            _ => "[GRÜN]",
        };
        let _ = writeln!(
            s,
            "{icon} {:<18} kritisch {} · hoch {} · mittel {} · niedrig {}",
            c.label, c.counts[4], c.counts[3], c.counts[2], c.counts[1]
        );
    }
    let relevant: Vec<&Finding> = r.findings.iter().filter(|f| f.severity >= Severity::Medium).collect();
    let _ = writeln!(s, "\nFunde (mittel und höher): {}", relevant.len());
    for f in relevant.iter().take(max_findings) {
        let sev = match f.severity {
            Severity::Critical => "KRITISCH",
            Severity::High => "HOCH",
            Severity::Medium => "MITTEL",
            Severity::Low => "niedrig",
            Severity::Info => "info",
        };
        let _ = writeln!(s, "  {sev:<8} {}{}", f.title, f.path.as_ref().map(|p| format!(" — {p}")).unwrap_or_default());
        if let Some(d) = &f.detail {
            let _ = writeln!(s, "           {}", d.chars().take(160).collect::<String>());
        }
    }
    if relevant.len() > max_findings {
        let _ = writeln!(s, "  … {} weitere (siehe JSON)", relevant.len() - max_findings);
    }
    let _ = writeln!(s, "\nBitte bestätigen: {} Einträge (SSH-Keys, Cronjobs, Dienste, offene Ports …)", r.confirm.len());
    let mut kinds: std::collections::BTreeMap<&str, usize> = Default::default();
    for c in &r.confirm {
        *kinds.entry(c.kind).or_default() += 1;
    }
    for (k, n) in kinds {
        let _ = writeln!(s, "  {k}: {n}");
    }
    for n in &r.notes {
        let _ = writeln!(s, "Hinweis: {n}");
    }
    s
}
