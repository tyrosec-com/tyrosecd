//! Hardening checks per detected application (see `app`): debug/developer mode in production,
//! installation tools left open, configuration files writable by all users and files under
//! `vendor/` changed after the Composer installation. Read only.
//!
//! Finding titles are stable (the central server translates them); the detail names the setting
//! and the file: `<SETTING>=<value> in <path>`.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

use regex::Regex;

use crate::app::{read_small, App, SMALL};
use crate::{Category, Ctx, Severity};

/// Maximum number of entries visited under one `vendor/`
pub const VENDOR_MAX_FILES: usize = 50_000;
/// Number of paths listed in the detail
const VENDOR_LIST: usize = 20;
/// Grace period after the installation (Composer runs, post-install scripts)
const VENDOR_GRACE_S: u64 = 3600;

pub fn check(ctx: &mut Ctx, apps: &[App]) {
    ctx.stat("apps", apps.iter().map(|a| format!("{} {} {}", a.kind, a.version, a.root)).collect::<Vec<_>>());
    let mut done: HashSet<String> = HashSet::new();
    for a in apps {
        for f in findings(a) {
            // WordPress and WooCommerce share root and configuration: report each file once
            if done.insert(format!("{}|{}", f.check, f.path)) {
                ctx.add(f.severity, Category::Web, f.check, f.title, Some(f.path), Some(f.detail));
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AppFinding {
    pub severity: Severity,
    pub check: &'static str,
    pub title: String,
    pub path: String,
    pub detail: String,
}

/// All hardening findings of one app
pub fn findings(a: &App) -> Vec<AppFinding> {
    let root = Path::new(&a.root);
    let mut out = Vec::new();
    debug_mode(a, root, &mut out);
    install_tool(a, root, &mut out);
    config_writable(a, root, &mut out);
    if let Some(f) = vendor_changed(a, root, VENDOR_MAX_FILES) {
        out.push(f);
    }
    if let Some(f) = crate::composer::autoload_foreign(a) {
        out.push(f);
    }
    out
}

fn s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

fn debug_finding(a: &App, path: &Path, setting: &str) -> AppFinding {
    AppFinding {
        severity: Severity::High,
        check: "app_debug_mode",
        title: format!("Debug mode enabled in production: {}", a.kind),
        path: s(path),
        detail: format!("{setting} in {}", path.display()),
    }
}

// ---------------------------------------------------------------------------------------------
// Parsers

/// `.env` file: `KEY=value`, `export KEY=value`, quoted values, comments (`#` at the start or after
/// whitespace in unquoted values). Later lines override earlier ones (as in dotenv).
pub fn parse_env(s: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for l in s.lines() {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let l = l.strip_prefix("export ").unwrap_or(l);
        let Some((k, v)) = l.split_once('=') else { continue };
        let k = k.trim();
        if k.is_empty() || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.') {
            continue;
        }
        let v = v.trim();
        let val = if let Some(q) = v.chars().next().filter(|c| *c == '"' || *c == '\'') {
            v[1..].split(q).next().unwrap_or("").to_string()
        } else {
            let cut = v.find(" #").or_else(|| v.find("\t#")).unwrap_or(v.len());
            v[..cut].trim().to_string()
        };
        m.insert(k.to_string(), val);
    }
    m
}

fn truthy(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1" | "(true)" | "on" | "yes")
}

/// PHP source without comment lines and `/* … */` blocks (enough for configuration files)
pub fn strip_php_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("/*") {
        out.push_str(&rest[..i]);
        match rest[i + 2..].find("*/") {
            Some(j) => rest = &rest[i + 2 + j + 2..],
            None => {
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    out.lines().filter(|l| !(l.trim_start().starts_with("//") || l.trim_start().starts_with('#'))).collect::<Vec<_>>().join("\n")
}

/// Value of `'key' => value` in a PHP array (quoted or bare such as `true`), first occurrence
pub fn php_kv(s: &str, key: &str) -> Option<String> {
    for q in ['\'', '"'] {
        let pat = format!("{q}{key}{q}");
        let mut from = 0;
        while let Some(i) = s[from..].find(&pat) {
            let at = from + i + pat.len();
            from = at;
            let r = s[at..].trim_start();
            let Some(r) = r.strip_prefix("=>") else { continue };
            let r = r.trim_start();
            return Some(match r.chars().next() {
                Some(c @ ('\'' | '"')) => r[1..].split(c).next().unwrap_or("").to_string(),
                _ => r.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect(),
            });
        }
    }
    None
}

fn wp_define_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"(?i)\bdefine\s*\(\s*['"](WP_DEBUG|WP_DEBUG_DISPLAY)['"]\s*,\s*([^)]*?)\s*\)"#).unwrap())
}

/// `true` / `false` / `None` (not set or not a literal) for the WordPress constants; the first
/// `define` counts (PHP ignores redefinitions)
pub fn wp_defines(s: &str) -> (Option<bool>, Option<bool>) {
    let s = strip_php_comments(s);
    let (mut debug, mut display) = (None, None);
    let (mut seen_debug, mut seen_display) = (false, false);
    for c in wp_define_re().captures_iter(&s) {
        let v = c[2].trim().trim_matches(['\'', '"']).to_ascii_lowercase();
        let b = match v.as_str() {
            "true" | "1" => Some(true),
            "false" | "0" | "" => Some(false),
            _ => None,
        };
        if c[1].eq_ignore_ascii_case("WP_DEBUG") && !seen_debug {
            seen_debug = true;
            debug = b;
        } else if c[1].eq_ignore_ascii_case("WP_DEBUG_DISPLAY") && !seen_display {
            seen_display = true;
            display = b;
        }
    }
    (debug, display)
}

// ---------------------------------------------------------------------------------------------
// app_debug_mode

/// APP_ENV from the Symfony dotenv files: `.env.local.php` (if present, replaces the others),
/// otherwise `.env` overridden by `.env.local`. Returns (value, file it came from).
fn symfony_env(root: &Path) -> Option<(String, PathBuf)> {
    let lp = root.join(".env.local.php");
    if let Some(s) = read_small(&lp, SMALL) {
        return php_kv(&strip_php_comments(&s), "APP_ENV").map(|v| (v, lp));
    }
    let mut found = None;
    for f in [".env", ".env.local"] {
        let p = root.join(f);
        if let Some(v) = read_small(&p, SMALL).and_then(|s| parse_env(&s).remove("APP_ENV")) {
            found = Some((v, p));
        }
    }
    found
}

fn debug_mode(a: &App, root: &Path, out: &mut Vec<AppFinding>) {
    match a.kind.as_str() {
        "Laravel" => {
            // cached configuration (`php artisan config:cache`) replaces .env
            let cached = root.join("bootstrap/cache/config.php");
            if let Some(c) = read_small(&cached, 8 * SMALL) {
                let c = strip_php_comments(&c);
                let app_part = c.find("'app' =>").map(|i| &c[i..]).unwrap_or("");
                if php_kv(app_part, "debug").map(|v| truthy(&v)).unwrap_or(false) {
                    out.push(debug_finding(a, &cached, "debug=true"));
                }
                return;
            }
            let p = root.join(".env");
            if let Some(v) = read_small(&p, SMALL).and_then(|s| parse_env(&s).remove("APP_DEBUG")) {
                if truthy(&v) {
                    out.push(debug_finding(a, &p, "APP_DEBUG=true"));
                }
            }
        }
        "Symfony" | "Shopware" | "Contao" => {
            if let Some((v, p)) = symfony_env(root) {
                if v.trim().eq_ignore_ascii_case("dev") {
                    out.push(debug_finding(a, &p, "APP_ENV=dev"));
                }
            }
        }
        "Magento" => {
            let p = root.join("app/etc/env.php");
            if let Some(s) = read_small(&p, SMALL) {
                if php_kv(&strip_php_comments(&s), "MAGE_MODE").map(|v| v.eq_ignore_ascii_case("developer")).unwrap_or(false) {
                    out.push(debug_finding(a, &p, "MAGE_MODE=developer"));
                }
            }
        }
        "WordPress" | "WooCommerce" => {
            let Some(p) = wp_config(root) else { return };
            let Some(s) = read_small(&p, SMALL) else { return };
            // errors are only displayed if WP_DEBUG is on; WP_DEBUG_DISPLAY defaults to true
            match wp_defines(&s) {
                (Some(true), Some(true)) => out.push(debug_finding(a, &p, "WP_DEBUG=true, WP_DEBUG_DISPLAY=true")),
                (Some(true), None) => out.push(debug_finding(a, &p, "WP_DEBUG=true (WP_DEBUG_DISPLAY not set to false)")),
                _ => {}
            }
        }
        "Joomla" => {
            static R: OnceLock<Regex> = OnceLock::new();
            let re = R.get_or_init(|| Regex::new(r#"(?m)^\s*(?:public|var)\s+\$debug\s*=\s*['"]?(1|true)['"]?\s*;"#).unwrap());
            let p = root.join("configuration.php");
            if read_small(&p, SMALL).map(|s| re.is_match(&strip_php_comments(&s))).unwrap_or(false) {
                out.push(debug_finding(a, &p, "debug=true"));
            }
        }
        "Nextcloud" => {
            let p = root.join("config/config.php");
            if read_small(&p, SMALL).and_then(|s| php_kv(&strip_php_comments(&s), "debug")).map(|v| truthy(&v)).unwrap_or(false) {
                out.push(debug_finding(a, &p, "debug=true"));
            }
        }
        _ => {}
    }
}

/// wp-config.php in the root or (as WordPress allows) in the folder above it
fn wp_config(root: &Path) -> Option<PathBuf> {
    let p = root.join("wp-config.php");
    if std::fs::metadata(&p).map(|m| m.is_file()).unwrap_or(false) {
        return Some(p);
    }
    let parent = root.parent()?;
    let up = parent.join("wp-config.php");
    let other_wp = parent.join("wp-settings.php").exists();
    (!other_wp && std::fs::metadata(&up).map(|m| m.is_file()).unwrap_or(false)).then_some(up)
}

// ---------------------------------------------------------------------------------------------
// app_install_tool

fn install_finding(a: &App, path: &Path, what: &str) -> AppFinding {
    AppFinding {
        severity: Severity::High,
        check: "app_install_tool",
        title: format!("Installation tool accessible: {}", a.kind),
        path: s(path),
        detail: format!("{what} present: {}", path.display()),
    }
}

fn file(p: &Path) -> bool {
    std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false)
}

fn install_tool(a: &App, root: &Path, out: &mut Vec<AppFinding>) {
    match a.kind.as_str() {
        "TYPO3" => {
            for rel in ["typo3conf/ENABLE_INSTALL_TOOL", "public/typo3conf/ENABLE_INSTALL_TOOL", "var/transient/ENABLE_INSTALL_TOOL", "typo3temp/var/transient/ENABLE_INSTALL_TOOL",
                "public/typo3temp/var/transient/ENABLE_INSTALL_TOOL", "config/ENABLE_INSTALL_TOOL"] {
                let p = root.join(rel);
                if file(&p) {
                    out.push(install_finding(a, &p, "ENABLE_INSTALL_TOOL"));
                }
            }
        }
        "Joomla" => {
            let p = root.join("installation");
            if p.is_dir() {
                out.push(install_finding(a, &p, "Installation folder"));
            }
        }
        "PrestaShop" => {
            for rel in ["install", "install-dev"] {
                let p = root.join(rel);
                if file(&p.join("index.php")) {
                    out.push(install_finding(a, &p, "Installation folder"));
                }
            }
        }
        "JTL-Shop" => {
            let p = root.join("install");
            if file(&p.join("index.php")) {
                out.push(install_finding(a, &p, "Installation folder"));
            }
        }
        "Shopware" => {
            let phar = root.join("public/shopware-installer.phar.php");
            if file(&phar) {
                out.push(install_finding(a, &phar, "Installer file"));
            }
            let rec = root.join("public/recovery/install/index.php");
            if file(&rec) && !root.join("install.lock").exists() {
                out.push(install_finding(a, &rec, "Installer file"));
            }
        }
        "Shopware 5" => {
            let rec = root.join("recovery/install/index.php");
            if file(&rec) && !root.join("recovery/install/data/install.lock").exists() {
                out.push(install_finding(a, &rec, "Installer file"));
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------------------------
// app_config_writable

fn config_files(kind: &str) -> &'static [&'static str] {
    match kind {
        "Laravel" | "Symfony" | "Shopware" | "Contao" => &[".env", ".env.local", ".env.local.php"],
        "Next.js" | "Nuxt" => &[".env", ".env.local", ".env.production"],
        "Magento" => &["app/etc/env.php"],
        "TYPO3" => &["typo3conf/LocalConfiguration.php", "public/typo3conf/LocalConfiguration.php", "config/system/settings.php", "typo3conf/system/settings.php"],
        "Joomla" => &["configuration.php"],
        "Drupal" => &["sites/default/settings.php"],
        "Nextcloud" => &["config/config.php"],
        "PrestaShop" => &["app/config/parameters.php", "config/settings.inc.php"],
        "Shopware 5" => &["config.php"],
        "JTL-Shop" => &["includes/config.JTL-Shop.ini.php"],
        _ => &[],
    }
}

fn config_writable(a: &App, root: &Path, out: &mut Vec<AppFinding>) {
    use std::os::unix::fs::PermissionsExt;
    let mut files: Vec<PathBuf> = config_files(&a.kind).iter().map(|r| root.join(r)).collect();
    if a.kind == "WordPress" || a.kind == "WooCommerce" {
        files.extend(wp_config(root));
    }
    for p in files {
        // permissions of the file itself (a symbolic link is resolved: its own mode does not matter)
        let Ok(m) = std::fs::metadata(&p) else { continue };
        let mode = m.permissions().mode() & 0o7777;
        if m.is_file() && mode & 0o002 != 0 {
            out.push(AppFinding {
                severity: Severity::Medium,
                check: "app_config_writable",
                title: format!("Configuration file writable by all users: {}", a.kind),
                path: s(&p),
                detail: format!("Mode {mode:04o} on {}", p.display()),
            });
        }
    }
}

// ---------------------------------------------------------------------------------------------
// vendor_changed_after_install

/// Composer root of an app: the app root, or the folder above a docroot (`public`, `web` …)
pub(crate) fn composer_root(root: &Path) -> Option<PathBuf> {
    if root.join("vendor").is_dir() {
        return Some(root.to_path_buf());
    }
    let name = root.file_name()?.to_string_lossy();
    if ["public", "pub", "web", "htdocs"].contains(&name.as_ref()) {
        let p = root.parent()?;
        if p.join("vendor").is_dir() {
            return Some(p.to_path_buf());
        }
    }
    None
}

const CODE_EXT: &[&str] = &["php", "phtml", "phar", "inc", "php3", "php4", "php5", "php7", "php8", "pht", "js", "mjs", "sh", "py", "pl", "so"];

fn is_code(name: &str) -> bool {
    name == ".htaccess" || name.rsplit_once('.').map(|(_, e)| CODE_EXT.contains(&e.to_ascii_lowercase().as_str())).unwrap_or(false)
}

/// Folders inside vendor/ that packages legitimately write at runtime
fn runtime_dir(rel: &str) -> bool {
    rel.contains("/DefinitionCache/Serializer") || rel.starts_with("mpdf/mpdf/tmp") || rel.ends_with("/cache") || rel.contains("/cache/")
}

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).ok()?.modified().ok()
}

pub fn vendor_changed(a: &App, root: &Path, max_files: usize) -> Option<AppFinding> {
    let croot = composer_root(root)?;
    let vendor = croot.join("vendor");
    let refs = [croot.join("composer.lock"), vendor.join("composer/installed.json")];
    let (ref_path, ref_time) = refs.iter().filter_map(|p| mtime(p).map(|t| (p.clone(), t))).max_by_key(|(_, t)| *t)?;
    let limit = ref_time + Duration::from_secs(VENDOR_GRACE_S);
    let mut hits: Vec<(SystemTime, String)> = Vec::new();
    let mut total = 0usize;
    let mut visited = 0usize;
    let mut truncated = false;
    let mut it = walkdir::WalkDir::new(&vendor).follow_links(false).max_depth(16).into_iter();
    while let Some(e) = it.next() {
        let Ok(e) = e else { continue };
        visited += 1;
        if visited > max_files {
            truncated = true;
            break;
        }
        let rel = e.path().strip_prefix(&vendor).map(|r| r.to_string_lossy().into_owned()).unwrap_or_default();
        if e.file_type().is_dir() {
            // vendor/composer and vendor/autoload.php are rewritten by `composer dump-autoload`
            if (e.depth() == 1 && (rel == "composer" || rel == "bin")) || e.file_name() == ".git" || e.file_name() == "node_modules" || runtime_dir(&rel) {
                it.skip_current_dir();
            }
            continue;
        }
        if !e.file_type().is_file() || (e.depth() == 1 && rel == "autoload.php") || !is_code(&e.file_name().to_string_lossy()) {
            continue;
        }
        let Some(t) = e.metadata().ok().and_then(|m| m.modified().ok()) else { continue };
        if t > limit {
            total += 1;
            if hits.len() < 10_000 {
                hits.push((t, e.path().to_string_lossy().into_owned()));
            }
        }
    }
    if total == 0 {
        return None;
    }
    // newest first
    hits.sort_by(|x, y| y.0.cmp(&x.0).then(x.1.cmp(&y.1)));
    let ref_name = ref_path.strip_prefix(&croot).map(|r| r.to_string_lossy().into_owned()).unwrap_or_else(|_| s(&ref_path));
    let mut detail = format!("{total} files under {} are newer than {ref_name} (more than 1 h after installation):", vendor.display());
    for (_, p) in hits.iter().take(VENDOR_LIST) {
        detail.push('\n');
        detail.push_str(p);
    }
    if total > VENDOR_LIST {
        detail.push_str(&format!("\n… and {} more", total - VENDOR_LIST));
    }
    if truncated {
        detail.push_str(&format!("\n(walk stopped after {max_files} files)"));
    }
    Some(AppFinding {
        severity: Severity::Medium,
        check: "vendor_changed_after_install",
        title: format!("Files under vendor/ changed after installation: {}", a.kind),
        path: s(&vendor),
        detail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn w(root: &Path, rel: &str, content: &str) -> PathBuf {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, content).unwrap();
        p
    }
    fn app_of(kind: &str, root: &Path) -> App {
        App { kind: kind.into(), root: root.to_string_lossy().into_owned(), ..Default::default() }
    }
    fn checks(f: &[AppFinding]) -> Vec<&str> {
        f.iter().map(|x| x.check).collect()
    }
    fn set_mtime(p: &Path, secs_ago: u64) {
        let t = SystemTime::now() - Duration::from_secs(secs_ago);
        std::fs::File::options().write(true).open(p).unwrap().set_modified(t).unwrap();
    }

    #[test]
    fn env_parsing() {
        let m = parse_env("# comment\nAPP_DEBUG=true # inline\nexport APP_ENV=\"prod\"\nQUOTED='a #b'\nEMPTY=\n bad line\nX=1\nX=2\n");
        assert_eq!(m["APP_DEBUG"], "true");
        assert_eq!(m["APP_ENV"], "prod");
        assert_eq!(m["QUOTED"], "a #b");
        assert_eq!(m["EMPTY"], "");
        assert_eq!(m["X"], "2");
        assert!(!m.contains_key("bad line"));
        assert!(truthy("1") && truthy("TRUE") && truthy("(true)") && !truthy("false") && !truthy(""));
    }

    #[test]
    fn laravel_debug() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        let a = app_of("Laravel", r);
        w(r, ".env", "APP_ENV=production\n# APP_DEBUG=true\nAPP_DEBUG=false\n");
        assert!(findings(&a).is_empty());
        w(r, ".env", "APP_DEBUG=\"true\"\n");
        let f = findings(&a);
        assert_eq!(checks(&f), vec!["app_debug_mode"]);
        assert_eq!(f[0].title, "Debug mode enabled in production: Laravel");
        assert_eq!(f[0].detail, format!("APP_DEBUG=true in {}/.env", r.display()));
        // cached configuration wins over .env
        w(r, "bootstrap/cache/config.php", "<?php return array (\n  'app' => \n  array (\n    'name' => 'Shop',\n    'debug' => false,\n  ),\n  'logging' => array ('debug' => true),\n);");
        assert!(findings(&a).is_empty());
        w(r, "bootstrap/cache/config.php", "<?php return array (\n  'app' => \n  array (\n    'debug' => true,\n  ),\n);");
        assert_eq!(findings(&a)[0].detail, format!("debug=true in {}/bootstrap/cache/config.php", r.display()));
        assert_eq!(findings(&a).len(), 1);
    }

    #[test]
    fn symfony_env_override() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        let a = app_of("Shopware", r);
        w(r, ".env", "APP_ENV=dev\n");
        w(r, ".env.local", "APP_ENV=prod\n");
        assert!(findings(&a).is_empty());
        w(r, ".env.local", "APP_ENV='dev'\n");
        let f = findings(&a);
        assert_eq!(f[0].title, "Debug mode enabled in production: Shopware");
        assert_eq!(f[0].detail, format!("APP_ENV=dev in {}/.env.local", r.display()));
        // compiled .env.local.php replaces the dotenv files
        w(r, ".env.local.php", "<?php\n\nreturn array (\n  'APP_ENV' => 'prod',\n);");
        assert!(findings(&a).is_empty());
    }

    #[test]
    fn magento_mode() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        let a = app_of("Magento", r);
        w(r, "app/etc/env.php", "<?php\nreturn [\n    // 'MAGE_MODE' => 'developer',\n    'MAGE_MODE' => 'production',\n];");
        assert!(findings(&a).is_empty());
        w(r, "app/etc/env.php", "<?php\nreturn [\n    'backend' => ['frontName' => 'admin'],\n    \"MAGE_MODE\" => \"developer\",\n];");
        assert_eq!(findings(&a)[0].detail, format!("MAGE_MODE=developer in {}/app/etc/env.php", r.display()));
    }

    #[test]
    fn wordpress_debug() {
        assert_eq!(wp_defines("define( 'WP_DEBUG', true );"), (Some(true), None));
        assert_eq!(wp_defines("define('WP_DEBUG', true); define('WP_DEBUG_DISPLAY', false);"), (Some(true), Some(false)));
        assert_eq!(wp_defines("// define('WP_DEBUG', true);\ndefine('WP_DEBUG', false);"), (Some(false), None));
        assert_eq!(wp_defines("/* define('WP_DEBUG', true); */"), (None, None));
        assert_eq!(wp_defines("define('WP_DEBUG', getenv('X') === 'y');"), (None, None));
        let t = tempfile::tempdir().unwrap();
        let r = t.path().join("wp");
        let a = app_of("WordPress", &r);
        w(&r, "wp-config.php", "<?php\ndefine('WP_DEBUG', true);\ndefine('WP_DEBUG_DISPLAY', false);\n");
        assert!(findings(&a).is_empty());
        w(&r, "wp-config.php", "<?php\ndefine('WP_DEBUG', true);\n");
        let f = findings(&a);
        assert_eq!(f[0].title, "Debug mode enabled in production: WordPress");
        assert_eq!(f[0].detail, format!("WP_DEBUG=true (WP_DEBUG_DISPLAY not set to false) in {}/wp-config.php", r.display()));
        // display without WP_DEBUG has no effect
        w(&r, "wp-config.php", "<?php\ndefine('WP_DEBUG_DISPLAY', true);\n");
        assert!(findings(&a).is_empty());
        // wp-config.php one folder above
        std::fs::remove_file(r.join("wp-config.php")).unwrap();
        w(t.path(), "wp-config.php", "<?php define('WP_DEBUG', 1); define('WP_DEBUG_DISPLAY', true);");
        assert_eq!(findings(&a)[0].detail, format!("WP_DEBUG=true, WP_DEBUG_DISPLAY=true in {}/wp-config.php", t.path().display()));
    }

    #[test]
    fn joomla_and_nextcloud_debug() {
        let t = tempfile::tempdir().unwrap();
        let j = t.path().join("j");
        w(&j, "configuration.php", "<?php\nclass JConfig {\n\tpublic $debug = false;\n}");
        assert!(findings(&app_of("Joomla", &j)).is_empty());
        w(&j, "configuration.php", "<?php\nclass JConfig {\n\tpublic $debug = '1';\n}");
        assert_eq!(checks(&findings(&app_of("Joomla", &j))), vec!["app_debug_mode"]);
        let n = t.path().join("n");
        w(&n, "config/config.php", "<?php\n$CONFIG = array (\n  'debug' => true,\n);");
        assert_eq!(findings(&app_of("Nextcloud", &n))[0].detail, format!("debug=true in {}/config/config.php", n.display()));
    }

    #[test]
    fn install_tools() {
        let t = tempfile::tempdir().unwrap();
        let ty = t.path().join("typo3");
        let p = w(&ty, "typo3conf/ENABLE_INSTALL_TOOL", "KEEP_FILE");
        let f = findings(&app_of("TYPO3", &ty));
        assert_eq!(checks(&f), vec!["app_install_tool"]);
        assert_eq!(f[0].title, "Installation tool accessible: TYPO3");
        assert_eq!(f[0].detail, format!("ENABLE_INSTALL_TOOL present: {}", p.display()));
        let jo = t.path().join("joomla");
        std::fs::create_dir_all(jo.join("installation")).unwrap();
        assert_eq!(findings(&app_of("Joomla", &jo))[0].detail, format!("Installation folder present: {}/installation", jo.display()));
        let sw = t.path().join("sw");
        w(&sw, "public/recovery/install/index.php", "<?php");
        assert_eq!(findings(&app_of("Shopware", &sw)).len(), 1);
        w(&sw, "install.lock", "");
        assert!(findings(&app_of("Shopware", &sw)).is_empty());
    }

    #[test]
    fn world_writable_config() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        let p = w(r, "app/etc/env.php", "<?php return [];");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(findings(&app_of("Magento", r)).is_empty());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666)).unwrap();
        let f = findings(&app_of("Magento", r));
        assert_eq!(checks(&f), vec!["app_config_writable"]);
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(f[0].title, "Configuration file writable by all users: Magento");
        assert_eq!(f[0].detail, format!("Mode 0666 on {}", p.display()));
    }

    #[test]
    fn vendor_after_install() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path().join("app");
        let lock = w(&r, "composer.lock", "{}");
        let installed = w(&r, "vendor/composer/installed.json", "{}");
        let old = w(&r, "vendor/acme/lib/src/A.php", "<?php");
        let newer = w(&r, "vendor/acme/lib/src/B.php", "<?php");
        let other = w(&r, "vendor/acme/lib/README.md", "text");
        let autoload = w(&r, "vendor/autoload.php", "<?php");
        let classmap = w(&r, "vendor/composer/autoload_classmap.php", "<?php");
        for p in [&lock, &installed, &old] {
            set_mtime(p, 3 * 86400);
        }
        for p in [&other, &autoload, &classmap] {
            set_mtime(p, 60);
        }
        set_mtime(&newer, 2 * 86400); // 1 day after installation
        let a = app_of("Laravel", &r.join("public"));
        let f = vendor_changed(&a, &r.join("public"), VENDOR_MAX_FILES).expect("finding");
        assert_eq!(f.check, "vendor_changed_after_install");
        assert_eq!(f.title, "Files under vendor/ changed after installation: Laravel");
        assert_eq!(f.path, format!("{}/vendor", r.display()));
        assert_eq!(f.detail, format!("1 files under {0}/vendor are newer than vendor/composer/installed.json (more than 1 h after installation):\n{0}/vendor/acme/lib/src/B.php", r.display()));
        // within the grace period: no finding
        set_mtime(&newer, 3 * 86400 - 600);
        assert!(vendor_changed(&a, &r, VENDOR_MAX_FILES).is_none());
        // more than 20: list is capped, walk limit is noted
        for i in 0..25 {
            let p = w(&r, &format!("vendor/acme/many/F{i}.php"), "<?php");
            set_mtime(&p, 3600 * 2);
        }
        let f = vendor_changed(&a, &r, VENDOR_MAX_FILES).unwrap();
        assert!(f.detail.starts_with("25 files under"), "{}", f.detail);
        assert_eq!(f.detail.lines().count(), 1 + 20 + 1, "{}", f.detail);
        assert!(f.detail.ends_with("… and 5 more"));
        let f = vendor_changed(&a, &r, 10).unwrap();
        assert!(f.detail.ends_with("(walk stopped after 10 files)"), "{}", f.detail);
        // a symbolic link to a folder outside is not followed
        let outside = tempfile::tempdir().unwrap();
        w(outside.path(), "X.php", "<?php");
        std::fs::remove_dir_all(r.join("vendor/acme/many")).unwrap();
        std::os::unix::fs::symlink(outside.path(), r.join("vendor/acme/link")).unwrap();
        assert!(vendor_changed(&a, &r, VENDOR_MAX_FILES).is_none());
    }

    #[test]
    fn php_kv_values() {
        assert_eq!(php_kv("'a' => 'x', 'b' => true", "b").as_deref(), Some("true"));
        assert_eq!(php_kv("\"MAGE_MODE\"=>\"default\"", "MAGE_MODE").as_deref(), Some("default"));
        assert_eq!(php_kv("'MAGE_MODE'", "MAGE_MODE"), None);
        assert_eq!(strip_php_comments("a\n/* x\n y */b\n  // c\n# d\ne"), "a\nb\ne");
    }
}
