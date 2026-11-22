//! Compromise check (main plan 21.2, prototype per 27.5).
//! Runs without the central server; compares against external references (WordPress.org)
//! plus a local inventory. Result: findings with severity + a "please confirm" list.

pub mod app;
pub mod apphard;
pub mod composer;
pub mod gitindex;
pub mod pkg;
pub mod persistence;
pub mod plugins;
pub mod system;
pub mod timeline;
pub mod web;
pub mod wordpress;
pub mod wpthemes;
/// Safe reading under foreign roots (containers) – for crates without a direct dependency on tyrosd-core
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
            Category::Web => "Web code",
            Category::Persistence => "Persistence",
            Category::Binaries => "Programs",
            Category::Runtime => "Running state",
            Category::Network => "Network",
            Category::History => "History",
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
    /// Stable short name of the check, e.g. `wp_core_modified`
    pub check: &'static str,
    pub title: String,
    pub path: Option<String>,
    pub detail: Option<String>,
}

/// Entry the user has to confirm once (SSH key, cron job …).
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
    /// Programs/libraries with package, version and md5 – compared against official packages on the central server
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub binaries: Vec<BinaryRef>,
    /// Hashes of the installed Composer packages per project (since 0.5.10; only when due, see `composer`)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub composer: Vec<composer::ComposerProject>,
    /// Hashes of the WordPress themes per installation (since 0.5.10; only when due, see `wpthemes`)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub wp_themes: Vec<wpthemes::WpThemes>,
}

#[derive(Serialize, Clone, Debug)]
pub struct BinaryRef {
    pub path: String,
    pub package: String,
    pub version: String,
    /// dpkg systems: md5 of the file
    #[serde(skip_serializing_if = "String::is_empty")]
    pub md5: String,
    /// RPM systems: SHA-256 of the file (computed locally) and package architecture
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
    /// red / yellow / green
    pub light: &'static str,
    pub counts: [usize; 5],
}

#[derive(Clone, Debug)]
pub struct CheckConfig {
    /// Root of the system to check (for tests/offline scan: mounted image)
    pub sysroot: String,
    pub webroots: Vec<String>,
    pub offline: bool,
    pub timeline_days: i64,
    pub skip_suid_scan: bool,
    pub skip_dpkg_verify: bool,
    /// Folder for the "last sent" state of the package/theme hashes; `None`: no hashes in the report
    pub state_dir: Option<String>,
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
            state_dir: None,
        }
    }
}

/// Collects findings and statistics.
pub struct Ctx {
    pub cfg: CheckConfig,
    pub report: Report,
    pub pkgs: pkg::PackageDb,
    /// Files that were checked against a reference and are unchanged
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
    /// Path within the checked system
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

/// Default webroots if none are given.
pub fn default_webroots(sysroot: &str) -> Vec<String> {
    let pre = sysroot.trim_end_matches('/');
    default_webroots_in(&tyrosd_core::rootfs::FsRoot::host(sysroot)).into_iter().map(|r| format!("{pre}{r}")).collect()
}

/// Default webroots under a root, as paths **relative** to it (containers: `FsRoot::Contained`)
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
    // remove nested roots (/var/www contains /var/www/vhosts/...)
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
    let apps = app::detect(&ctx.cfg.webroots);
    apphard::check(&mut ctx, &apps);
    if let Some(dir) = ctx.cfg.state_dir.clone() {
        let dir = std::path::Path::new(&dir);
        ctx.report.composer = composer::hashes(&apps, &dir.join("composer_sent.json"), false);
        ctx.report.wp_themes = wpthemes::hashes(&apps, &dir.join("wp_themes_sent.json"), false);
        let files: usize = ctx.report.composer.iter().flat_map(|p| &p.packages).map(|p| p.files.len() + p.large.len()).sum();
        ctx.stat("composer_hashed_files", files);
        let files: usize = ctx.report.wp_themes.iter().flat_map(|w| &w.themes).map(|t| t.files.len() + t.large.len()).sum();
        ctx.stat("wp_theme_hashed_files", files);
    }
    web::check(&mut ctx);
    persistence::check(&mut ctx);
    system::check(&mut ctx);
    timeline::check(&mut ctx);

    // sort: most severe first
    ctx.report.findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.category.cmp(&b.category)));
    ctx.report.summary = Category::all()
        .iter()
        .map(|c| {
            let mut counts = [0usize; 5];
            for f in ctx.report.findings.iter().filter(|f| f.category == *c) {
                counts[f.severity as usize] += 1;
            }
            // traffic light; the central stores it as before (it maps red/yellow/green)
            let light = if counts[4] + counts[3] > 0 {
                "red"
            } else if counts[2] > 0 {
                "yellow"
            } else {
                "green"
            };
            CategorySummary { category: *c, label: c.label(), light, counts }
        })
        .collect();
    ctx.report.duration_ms = t0.elapsed().as_millis();
    ctx.report
}

/// Readable short report.
pub fn render_text(r: &Report, max_findings: usize) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(s, "Compromise check · {} · {} · kernel {}", r.host.hostname, r.host.os, r.host.kernel);
    let _ = writeln!(s, "Duration: {:.1} s · package DB: {}\n", r.duration_ms as f64 / 1000.0, r.host.package_manager);
    for c in &r.summary {
        let icon = match c.light {
            "red" => "[RED ]",
            "yellow" => "[YLW ]",
            _ => "[GRN ]",
        };
        let _ = writeln!(
            s,
            "{icon} {:<18} critical {} · high {} · medium {} · low {}",
            c.label, c.counts[4], c.counts[3], c.counts[2], c.counts[1]
        );
    }
    let relevant: Vec<&Finding> = r.findings.iter().filter(|f| f.severity >= Severity::Medium).collect();
    let _ = writeln!(s, "\nFindings (medium and above): {}", relevant.len());
    for f in relevant.iter().take(max_findings) {
        let sev = match f.severity {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "low",
            Severity::Info => "info",
        };
        let _ = writeln!(s, "  {sev:<8} {}{}", f.title, f.path.as_ref().map(|p| format!(" — {p}")).unwrap_or_default());
        if let Some(d) = &f.detail {
            let _ = writeln!(s, "           {}", d.chars().take(160).collect::<String>());
        }
    }
    if relevant.len() > max_findings {
        let _ = writeln!(s, "  … {} more (see JSON)", relevant.len() - max_findings);
    }
    let _ = writeln!(s, "\nPlease confirm: {} entries (SSH keys, cron jobs, services, open ports …)", r.confirm.len());
    let mut kinds: std::collections::BTreeMap<&str, usize> = Default::default();
    for c in &r.confirm {
        *kinds.entry(c.kind).or_default() += 1;
    }
    for (k, n) in kinds {
        let _ = writeln!(s, "  {k}: {n}");
    }
    for n in &r.notes {
        let _ = writeln!(s, "Note: {n}");
    }
    s
}
