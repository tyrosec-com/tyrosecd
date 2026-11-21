//! WordPress: Core- und Plugin-Dateien gegen die offiziellen Prüfsummen von
//! WordPress.org, unbekannte Dateien im Core, PHP in Uploads, Must-Use-Plugins.

use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use regex::Regex;
use serde_json::Value;

use crate::{web, Category, Ctx, Severity};
use tyrosd_core::rootfs::{self, FsRoot, Kind};

fn agent() -> &'static ureq::Agent {
    static A: OnceLock<ureq::Agent> = OnceLock::new();
    A.get_or_init(|| {
        ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(20))
            .user_agent(concat!("tyrosecd-check/", env!("CARGO_PKG_VERSION")))
            .build()
    })
}

/// GET → JSON. `Ok(None)` bei 404.
fn get_json(url: &str) -> Result<Option<Value>, String> {
    match agent().get(url).call() {
        Ok(r) => r.into_json::<Value>().map(Some).map_err(|e| e.to_string()),
        Err(ureq::Error::Status(404, _)) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

pub struct WpInstall {
    pub root: String,
    pub version: String,
    pub locale: String,
}

fn re(s: &str) -> Regex {
    Regex::new(s).unwrap()
}

/// WordPress-Installationen unter den Webroots finden (Tiefe ≤ 5).
pub fn find(webroots: &[String]) -> Vec<WpInstall> {
    find_in(&FsRoot::host(""), webroots)
}

/// Wie `find`, unter einer Wurzel (Container: `FsRoot::Contained`, Webroots und Ergebnis relativ zur Wurzel).
/// Gelesen wird nur über `FsRoot` (Container: openat2, nur reguläre Dateien, ≤ 1 MiB).
pub fn find_in(fs: &FsRoot, webroots: &[String]) -> Vec<WpInstall> {
    let ver_re = re(r#"\$wp_version\s*=\s*'([^']+)'"#);
    let loc_re = re(r#"\$wp_local_package\s*=\s*'([^']+)'"#);
    let mut out = Vec::new();
    for w in webroots {
        let mut found = Vec::new();
        fs.walk(w, 5, 1_000_000, &mut |p, k| {
            let name = p.rsplit('/').next().unwrap_or("");
            if k == Kind::Dir {
                return !matches!(name, "node_modules" | "vendor" | ".git" | "wp-content" | "uploads" | "cache");
            }
            if name == "version.php" && p.trim_end_matches("/version.php").ends_with("/wp-includes") {
                found.push(p.to_string());
            }
            false
        });
        found.sort();
        for p in found {
            let Some(s) = fs.read_string(&p, rootfs::SMALL) else { continue };
            let Some(v) = ver_re.captures(&s).map(|c| c[1].to_string()) else { continue };
            let locale = loc_re.captures(&s).map(|c| c[1].to_string()).unwrap_or_else(|| "en_US".into());
            let root = p.trim_end_matches("/wp-includes/version.php").to_string();
            out.push(WpInstall { root, version: v, locale });
        }
    }
    out
}

fn is_php(p: &str) -> bool {
    let l = p.to_ascii_lowercase();
    [".php", ".phtml", ".phar", ".php3", ".php4", ".php5", ".php7", ".php8", ".pht", ".phps", ".inc"].iter().any(|e| l.ends_with(e))
}

fn md5(p: &str) -> Option<String> {
    tyrosd_core::hash::md5_file(p).ok()
}

pub fn check(ctx: &mut Ctx) {
    let installs = find(&ctx.cfg.webroots);
    ctx.stat("wp_installs", installs.len());
    let mut plugins_with_ref = 0usize;
    let mut plugins_without_ref = Vec::new();
    let mut core_checked = 0usize;
    for wp in &installs {
        core(ctx, wp, &mut core_checked);
        let (with, without) = plugins(ctx, wp);
        plugins_with_ref += with;
        plugins_without_ref.extend(without);
        uploads(ctx, wp);
        mu_plugins(ctx, wp);
    }
    ctx.stat("wp_core_files_checked", core_checked);
    ctx.stat("wp_plugins_with_reference", plugins_with_ref);
    ctx.stat("wp_plugins_without_reference", plugins_without_ref.len());
    ctx.stat("wp_plugins_without_reference_list", plugins_without_ref);
}

fn core(ctx: &mut Ctx, wp: &WpInstall, checked: &mut usize) {
    if ctx.cfg.offline {
        ctx.report.notes.push(format!("Offline: WordPress-Core {} in {} nicht gegen WordPress.org geprüft", wp.version, wp.root));
        return;
    }
    let url = format!(
        "https://api.wordpress.org/core/checksums/1.0/?version={}&locale={}",
        wp.version, wp.locale
    );
    let mut sums = match get_json(&url) {
        Ok(Some(v)) => v.get("checksums").cloned().unwrap_or(Value::Null),
        Ok(None) => Value::Null,
        Err(e) => {
            ctx.report.notes.push(format!("WordPress.org nicht erreichbar ({e}); Core nicht geprüft"));
            return;
        }
    };
    if !sums.is_object() && wp.locale != "en_US" {
        // Fallback: englische Prüfsummen
        let url = format!("https://api.wordpress.org/core/checksums/1.0/?version={}&locale=en_US", wp.version);
        if let Ok(Some(v)) = get_json(&url) {
            sums = v.get("checksums").cloned().unwrap_or(Value::Null);
        }
    }
    let Some(map) = sums.as_object() else {
        ctx.add(Severity::Medium, Category::Web, "wp_core_no_reference",
            format!("Keine offiziellen Prüfsummen für WordPress {} ({})", wp.version, wp.locale),
            Some(wp.root.clone()), Some("Version unbekannt oder manipuliert (wp-includes/version.php prüfen)".into()));
        return;
    };
    let mut modified = 0;
    let mut known: std::collections::HashSet<String> = Default::default();
    for (rel, sum) in map {
        known.insert(rel.clone());
        // wp-content (Standard-Themes/-Plugins) wird separat aktualisiert
        if rel.starts_with("wp-content/") {
            continue;
        }
        let Some(expected) = sum.as_str() else { continue };
        let full = format!("{}/{}", wp.root, rel);
        *checked += 1;
        match md5(&full) {
            Some(h) if h == expected => {
                ctx.verified.insert(full);
            }
            Some(_) => {
                modified += 1;
                let sev = if is_php(rel) || rel.ends_with(".js") { Severity::High } else { Severity::Medium };
                let hits = web::scan_file(&full);
                let sev = if hits.is_empty() { sev } else { Severity::Critical };
                ctx.add(sev, Category::Web, "wp_core_modified",
                    "WordPress-Core-Datei weicht von offizieller Prüfsumme ab", Some(full),
                    Some(if hits.is_empty() { format!("WordPress {}", wp.version) } else { format!("WordPress {} · Muster: {}", wp.version, hits.join(", ")) }));
            }
            None => {
                if rel.starts_with("wp-admin/") || rel.starts_with("wp-includes/") {
                    ctx.add(Severity::Low, Category::Web, "wp_core_missing", "WordPress-Core-Datei fehlt", Some(full), None);
                }
            }
        }
    }
    // Unbekannte Dateien in wp-admin / wp-includes / Root
    for sub in ["wp-admin", "wp-includes"] {
        for e in walkdir::WalkDir::new(format!("{}/{}", wp.root, sub)).follow_links(false).into_iter().flatten() {
            if !e.file_type().is_file() {
                continue;
            }
            let full = e.path().to_string_lossy().into_owned();
            let rel = full[wp.root.len() + 1..].to_string();
            if !known.contains(&rel) {
                let hits = web::scan_file(&full);
                let sev = if !hits.is_empty() { Severity::Critical } else if is_php(&rel) { Severity::High } else { Severity::Low };
                ctx.add(sev, Category::Web, "wp_core_unknown_file", "Unbekannte Datei im WordPress-Core", Some(full),
                    if hits.is_empty() { None } else { Some(format!("Muster: {}", hits.join(", "))) });
            }
        }
    }
    if let Ok(rd) = std::fs::read_dir(&wp.root) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if e.path().is_file() && is_php(&name) && !known.contains(&name) && name != "wp-config.php" {
                let full = e.path().to_string_lossy().into_owned();
                let hits = web::scan_file(&full);
                let sev = if hits.is_empty() { Severity::Medium } else { Severity::Critical };
                ctx.add(sev, Category::Web, "wp_root_unknown_php", "Unbekannte PHP-Datei im WordPress-Verzeichnis", Some(full),
                    if hits.is_empty() { Some("kein Teil von WordPress; Herkunft klären".into()) } else { Some(format!("Muster: {}", hits.join(", "))) });
            }
        }
    }
    ctx.stat(&format!("wp_core_modified:{}", wp.root), modified);
}

/// Plugin-Header lesen: (Version)
pub fn plugin_version(dir: &Path) -> Option<String> {
    plugin_version_in(&FsRoot::host(""), &dir.to_string_lossy())
}

/// Wie `plugin_version`, Verzeichnis relativ zur Wurzel `fs`
pub fn plugin_version_in(fs: &FsRoot, dir: &str) -> Option<String> {
    let name_re = re(r"(?mi)^[ \t/*#@]*Plugin Name\s*:");
    let ver_re = re(r"(?mi)^[ \t/*#@]*Version\s*:\s*([^\s*]+)");
    let mut names: Vec<String> = fs.read_dir(dir, 10_000).into_iter().map(|(n, _)| n).filter(|n| n.ends_with(".php")).collect();
    if names.is_empty() && !fs.is_dir(dir) {
        return None;
    }
    names.sort();
    for n in names {
        let Some(data) = fs.read_head(&format!("{}/{n}", dir.trim_end_matches('/')), 8192) else { continue };
        let head = String::from_utf8_lossy(&data).into_owned();
        if name_re.is_match(&head) {
            return ver_re.captures(&head).map(|c| c[1].to_string());
        }
    }
    None
}

fn plugins(ctx: &mut Ctx, wp: &WpInstall) -> (usize, Vec<String>) {
    let base = format!("{}/wp-content/plugins", wp.root);
    let mut with = 0;
    let mut without = Vec::new();
    let Ok(rd) = std::fs::read_dir(&base) else { return (0, without) };
    for e in rd.flatten() {
        if !e.path().is_dir() {
            continue;
        }
        let slug = e.file_name().to_string_lossy().into_owned();
        let Some(version) = plugin_version(&e.path()) else {
            without.push(format!("{slug} (ohne Version)"));
            continue;
        };
        let refs = if ctx.cfg.offline {
            None
        } else {
            match get_json(&format!("https://downloads.wordpress.org/plugin-checksums/{slug}/{version}.json")) {
                Ok(v) => v,
                Err(err) => {
                    ctx.report.notes.push(format!("Plugin {slug}: Prüfsummen nicht abrufbar ({err})"));
                    None
                }
            }
        };
        let files: Option<HashMap<String, Vec<String>>> = refs.as_ref().and_then(|v| v.get("files")).and_then(|f| f.as_object()).map(|m| {
            m.iter()
                .map(|(k, v)| {
                    let md5s = match v.get("md5") {
                        Some(Value::String(s)) => vec![s.clone()],
                        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
                        _ => vec![],
                    };
                    (k.clone(), md5s)
                })
                .collect()
        });
        let Some(files) = files else {
            without.push(format!("{slug} {version}"));
            ctx.add(Severity::Info, Category::Web, "wp_plugin_no_reference",
                format!("Plugin ohne offizielle Prüfsummen: {slug} {version}"), Some(e.path().to_string_lossy().into_owned()),
                Some("Premium-, eigenes oder entferntes Plugin: nur Muster-Prüfung".into()));
            continue;
        };
        with += 1;
        let root = e.path().to_string_lossy().into_owned();
        for f in walkdir::WalkDir::new(&root).follow_links(false).into_iter().flatten() {
            if !f.file_type().is_file() {
                continue;
            }
            let full = f.path().to_string_lossy().into_owned();
            let rel = &full[root.len() + 1..];
            match files.get(rel) {
                Some(sums) => match md5(&full) {
                    Some(h) if sums.contains(&h) => {
                        ctx.verified.insert(full);
                    }
                    Some(_) => {
                        let hits = web::scan_file(&full);
                        let sev = if !hits.is_empty() { Severity::Critical } else if is_php(rel) || rel.ends_with(".js") { Severity::High } else { Severity::Low };
                        ctx.add(sev, Category::Web, "wp_plugin_modified",
                            format!("Plugin-Datei weicht ab ({slug} {version})"), Some(full),
                            if hits.is_empty() { None } else { Some(format!("Muster: {}", hits.join(", "))) });
                    }
                    None => {}
                },
                None if is_php(rel) => {
                    let hits = web::scan_file(&full);
                    let sev = if hits.is_empty() { Severity::High } else { Severity::Critical };
                    ctx.add(sev, Category::Web, "wp_plugin_unknown_php",
                        format!("Unbekannte PHP-Datei in Plugin {slug} {version}"), Some(full),
                        if hits.is_empty() { None } else { Some(format!("Muster: {}", hits.join(", "))) });
                }
                None => {}
            }
        }
    }
    (with, without)
}

fn uploads(ctx: &mut Ctx, wp: &WpInstall) {
    let base = format!("{}/wp-content/uploads", wp.root);
    for e in walkdir::WalkDir::new(&base).follow_links(false).into_iter().flatten() {
        if !e.file_type().is_file() {
            continue;
        }
        let full = e.path().to_string_lossy().into_owned();
        if is_php(&full) {
            let hits = web::scan_file(&full);
            // index.php mit „Silence is golden“ ist harmlos
            if hits.is_empty() && full.ends_with("/index.php") && e.metadata().map(|m| m.len() < 64).unwrap_or(false) {
                continue;
            }
            let sev = if hits.is_empty() { Severity::High } else { Severity::Critical };
            ctx.add(sev, Category::Web, "php_in_uploads", "PHP-Datei im Upload-Verzeichnis", Some(full),
                if hits.is_empty() { None } else { Some(format!("Muster: {}", hits.join(", "))) });
        }
    }
}

fn mu_plugins(ctx: &mut Ctx, wp: &WpInstall) {
    let base = format!("{}/wp-content/mu-plugins", wp.root);
    for e in walkdir::WalkDir::new(&base).max_depth(2).follow_links(false).into_iter().flatten() {
        if e.file_type().is_file() && is_php(&e.path().to_string_lossy()) {
            let full = e.path().to_string_lossy().into_owned();
            let hits = web::scan_file(&full);
            if !hits.is_empty() {
                ctx.add(Severity::Critical, Category::Web, "wp_mu_plugin_suspicious", "Verdächtiges Must-Use-Plugin", Some(full.clone()), Some(format!("Muster: {}", hits.join(", "))));
            }
            ctx.confirm("wp_mu_plugin", full, "Must-Use-Plugin (wird immer geladen)");
        }
    }
}
