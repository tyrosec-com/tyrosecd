//! Composer projects of the detected apps:
//! - `composer_autoload_foreign`: the generated autoloader (`vendor/composer/autoload_*.php`) loads files
//!   that belong neither to an installed package nor to the project's own autoload configuration, or
//!   contains code Composer never generates (eval, base64, includes from temporary folders …).
//! - Hashes of all files of the installed packages (SHA-256, path relative to the package folder) for the
//!   comparison with the original packages on the central server – only when `composer.lock` or
//!   `vendor/composer/installed.json` changed since the last report, otherwise at most every 7 days.
//!
//! Read only; walks never follow symbolic links and are bounded.

use std::collections::{BTreeMap, HashMap};
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::app::{read_small, App, SMALL};
use crate::apphard::{composer_root, AppFinding};
use crate::Severity;

/// Maximum number of hashed files per report (all app roots together)
pub const MAX_HASH_FILES: usize = 100_000;
/// Files larger than this: size only
pub const MAX_HASH_SIZE: u64 = 5 << 20;
/// Budget for the uncompressed JSON of the `composer` section (the report must stay well below the
/// central server's limit for check reports)
pub const MAX_HASH_JSON: usize = 5 << 20;
/// Resend unchanged projects after this many seconds
pub const RESEND_S: u64 = 7 * 86400;
/// Size limit for installed.json / autoload files
const BIG: u64 = 32 << 20;

/// Package from `vendor/composer/installed.json`
#[derive(Debug, Clone, PartialEq)]
pub struct Installed {
    pub name: String,
    pub version: String,
    /// absolute, lexically normalised install folder
    pub dir: PathBuf,
}

/// Lexical normalisation (`.` and `..`), no file system access
pub fn norm(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            c => out.push(c.as_os_str()),
        }
    }
    out
}

/// Packages from installed.json (Composer 2: `{"packages": […]}` with `install-path` relative to
/// `vendor/composer`; Composer 1: a plain list, install folder `vendor/<name>`). Packages whose folder lies
/// outside the project (`croot`) and metapackages are left out.
pub fn installed(croot: &Path) -> Option<Vec<Installed>> {
    let vendor = croot.join("vendor");
    let s = read_small(&vendor.join("composer/installed.json"), BIG)?;
    let v: serde_json::Value = serde_json::from_str(&s).ok()?;
    let list = v.get("packages").and_then(|p| p.as_array()).or_else(|| v.as_array())?;
    let mut out = Vec::new();
    for p in list {
        let Some(name) = p["name"].as_str() else { continue };
        if p["type"].as_str() == Some("metapackage") || name.contains("..") {
            continue;
        }
        let dir = match p.get("install-path") {
            Some(serde_json::Value::String(ip)) => norm(&vendor.join("composer").join(ip)),
            Some(serde_json::Value::Null) => continue,
            _ => norm(&vendor.join(name)),
        };
        if !dir.starts_with(croot) || dir == croot {
            continue;
        }
        let version = p["version"].as_str().unwrap_or("").to_string();
        out.push(Installed { name: name.to_string(), version, dir });
    }
    Some(out)
}

/// Folders/files of the project's own autoload configuration (composer.json `autoload` and `autoload-dev`)
fn project_autoload(croot: &Path) -> Option<Vec<PathBuf>> {
    let s = read_small(&croot.join("composer.json"), SMALL)?;
    let v: serde_json::Value = serde_json::from_str(&s).ok()?;
    let mut out = Vec::new();
    for sec in ["autoload", "autoload-dev"] {
        let a = &v[sec];
        for kind in ["psr-4", "psr-0"] {
            for (_, dirs) in a[kind].as_object().into_iter().flatten() {
                let dirs: Vec<&str> = match dirs {
                    serde_json::Value::String(d) => vec![d.as_str()],
                    serde_json::Value::Array(l) => l.iter().filter_map(|d| d.as_str()).collect(),
                    _ => vec![],
                };
                out.extend(dirs.into_iter().map(|d| norm(&croot.join(d))));
            }
        }
        for kind in ["classmap", "files"] {
            out.extend(a[kind].as_array().into_iter().flatten().filter_map(|d| d.as_str()).map(|d| norm(&croot.join(d))));
        }
    }
    // an empty prefix ("": "") means the whole project
    Some(out)
}

fn entry_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    // `'key' => $vendorDir . '/x'`, `$baseDir . '/x'`, `__DIR__ . '/..' . '/x'`, or a plain string `'/x'`
    R.get_or_init(|| {
        Regex::new(r#"(?m)'((?:[^'\\]|\\.)*)'\s*=>\s*(?:(\$vendorDir|\$baseDir)\s*\.\s*'([^']*)'|__DIR__\s*\.\s*'([^']*)'\s*\.\s*'([^']*)'|'(/[^']*)')"#).unwrap()
    })
}

fn code_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(concat!(
            r#"(?i)\b(?:eval|assert|create_function)\s*\(|\b(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|convert_uudecode)\s*\("#,
            r#"|\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b|\b(?:system|shell_exec|passthru|proc_open|popen|curl_exec|fsockopen)\s*\("#,
            r#"|(?:include|require)(?:_once)?\s*\(?\s*['"](?:/|https?:|php:|data:|phar:)"#,
            r#"|['"](?:/tmp/|/var/tmp/|/dev/shm/)"#
        ))
        .unwrap()
    })
}

/// Autoload entries (key, absolute path) of one generated file
pub fn autoload_entries(src: &str, composer_dir: &Path) -> Vec<(String, PathBuf)> {
    let vendor = composer_dir.parent().map(Path::to_path_buf).unwrap_or_default();
    let base = vendor.parent().map(Path::to_path_buf).unwrap_or_default();
    let mut out = Vec::new();
    for c in entry_re().captures_iter(src) {
        let key = c[1].replace("\\\\", "\\");
        let p = if let Some(var) = c.get(2) {
            let b = if var.as_str() == "$vendorDir" { &vendor } else { &base };
            norm(&b.join(c[3].trim_start_matches('/')))
        } else if let Some(up) = c.get(4) {
            norm(&composer_dir.join(up.as_str().trim_start_matches('/')).join(c[5].trim_start_matches('/')))
        } else {
            norm(Path::new(&c[6]))
        };
        out.push((key, p));
    }
    out
}

const AUTOLOAD_FILES: &[&str] = &["autoload_files.php", "autoload_static.php", "autoload_real.php", "autoload_classmap.php"];

/// `composer_autoload_foreign` for one app (one finding per Composer project)
pub fn autoload_foreign(a: &App) -> Option<AppFinding> {
    let croot = composer_root(Path::new(&a.root))?;
    let cdir = croot.join("vendor/composer");
    let pkgs = installed(&croot);
    let own = project_autoload(&croot);
    let owned = |p: &Path| -> Option<bool> {
        if p.starts_with(&cdir) {
            return Some(true);
        }
        let pk = pkgs.as_ref()?;
        if pk.iter().any(|x| p.starts_with(&x.dir)) {
            return Some(true);
        }
        if p.starts_with(croot.join("vendor")) {
            return Some(false);
        }
        if !p.starts_with(&croot) {
            return Some(false);
        }
        let own = own.as_ref()?;
        Some(own.iter().any(|d| p.starts_with(d)))
    };
    let mut bad: Vec<String> = Vec::new();
    let mut total = 0usize;
    for f in AUTOLOAD_FILES {
        let fp = cdir.join(f);
        let Some(src) = read_small(&fp, BIG) else { continue };
        if let Some(m) = code_re().find(&src) {
            total += 1;
            if bad.len() < 10 {
                bad.push(format!("{}: unexpected code `{}`", fp.display(), m.as_str().trim()));
            }
        }
        for (key, p) in autoload_entries(&src, &cdir) {
            if owned(&p) == Some(false) {
                total += 1;
                if bad.len() < 10 {
                    bad.push(format!("{}: {key} => {}", fp.display(), p.display()));
                }
            }
        }
    }
    if total == 0 {
        return None;
    }
    let mut detail = format!("{total} entries not generated by Composer for the installed packages or the project:");
    for b in &bad {
        detail.push('\n');
        detail.push_str(b);
    }
    if total > bad.len() {
        detail.push_str(&format!("\n… and {} more", total - bad.len()));
    }
    Some(AppFinding {
        severity: Severity::High,
        check: "composer_autoload_foreign",
        title: format!("Composer autoloader loads foreign code: {}", a.kind),
        path: cdir.to_string_lossy().into_owned(),
        detail,
    })
}

// ---------------------------------------------------------------------------------------------
// Package hashes

#[derive(Serialize, Debug, Clone, Default)]
pub struct ComposerProject {
    /// Composer project folder (contains vendor/)
    pub root: String,
    /// Detected app kinds with this project folder
    pub apps: Vec<String>,
    pub packages: Vec<PackageFiles>,
    /// true if the file or size limit was reached (not all files listed)
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

#[derive(Serialize, Debug, Clone, Default)]
pub struct PackageFiles {
    pub name: String,
    pub version: String,
    /// install folder relative to the project folder, e.g. `vendor/monolog/monolog`
    pub path: String,
    /// path relative to the package folder → SHA-256 (hex)
    pub files: BTreeMap<String, String>,
    /// files larger than 5 MiB: path → size in bytes (not hashed)
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub large: BTreeMap<String, u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
struct Sent {
    /// fingerprint of composer.lock + installed.json (mtime, size)
    fp: String,
    /// Unix seconds of the last report
    ts: u64,
}

fn fingerprint(croot: &Path) -> String {
    use std::os::unix::fs::MetadataExt;
    [croot.join("composer.lock"), croot.join("vendor/composer/installed.json")]
        .iter()
        .map(|p| std::fs::metadata(p).map(|m| format!("{}.{}:{}", m.mtime(), m.mtime_nsec(), m.size())).unwrap_or_else(|_| "-".into()))
        .collect::<Vec<_>>()
        .join("|")
}

fn now_s() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Limits for one hash collection
#[derive(Clone, Copy)]
pub(crate) struct Budget {
    pub files: usize,
    pub bytes: usize,
    pub max_files: usize,
    pub max_bytes: usize,
}

impl Budget {
    pub fn new(max_files: usize, max_bytes: usize) -> Budget {
        Budget { files: 0, bytes: 0, max_files, max_bytes }
    }
    pub fn exhausted(&self) -> bool {
        self.files >= self.max_files || self.bytes >= self.max_bytes
    }
}

/// Hash all files below `dir` (no symbolic links, without .git/node_modules) into `files`/`large`;
/// returns false when a limit was hit
pub(crate) fn hash_dir(dir: &Path, files: &mut BTreeMap<String, String>, large: &mut BTreeMap<String, u64>, b: &mut Budget) -> bool {
    let mut it = walkdir::WalkDir::new(dir).follow_links(false).max_depth(24).sort_by_file_name().into_iter();
    while let Some(e) = it.next() {
        let Ok(e) = e else { continue };
        if e.file_type().is_dir() {
            if e.depth() > 0 && (e.file_name() == ".git" || e.file_name() == "node_modules") {
                it.skip_current_dir();
            }
            continue;
        }
        if !e.file_type().is_file() {
            continue;
        }
        let Ok(rel) = e.path().strip_prefix(dir) else { continue };
        let rel = rel.to_string_lossy().into_owned();
        if b.files >= b.max_files || b.bytes + rel.len() + 72 > b.max_bytes {
            return false;
        }
        let Ok(m) = e.metadata() else { continue };
        if m.len() > MAX_HASH_SIZE {
            b.bytes += rel.len() + 24;
            large.insert(rel, m.len());
        } else {
            let Ok((h, _, _)) = tyrosd_core::hash::hash_file_nofollow(tyrosd_core::hash::Algo::Sha256, &e.path().to_string_lossy()) else { continue };
            b.bytes += rel.len() + 72;
            files.insert(rel, h);
        }
        b.files += 1;
    }
    true
}

/// "When was what sent" (small JSON file in the agent's data folder)
pub(crate) struct SentState {
    path: PathBuf,
    map: HashMap<String, Sent>,
    now: u64,
    changed: bool,
}

impl SentState {
    pub fn load(path: &Path) -> SentState {
        let map = read_small(path, SMALL).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        SentState { path: path.to_path_buf(), map, now: now_s(), changed: false }
    }
    /// Changed fingerprint or last report older than 7 days
    pub fn due(&self, key: &str, fp: &str) -> bool {
        self.map.get(key).map(|s| s.fp != fp || self.now.saturating_sub(s.ts) >= RESEND_S).unwrap_or(true)
    }
    pub fn mark(&mut self, key: &str, fp: String) {
        self.map.insert(key.to_string(), Sent { fp, ts: self.now });
        self.changed = true;
    }
    /// Write (atomically); entries for which `keep` is false are dropped
    pub fn save(mut self, keep: impl Fn(&str) -> bool) {
        if !self.changed {
            return;
        }
        self.map.retain(|k, _| keep(k));
        if let Ok(js) = serde_json::to_vec(&self.map) {
            let tmp = self.path.with_extension("tmp");
            if std::fs::write(&tmp, js).is_ok() {
                let _ = std::fs::rename(&tmp, &self.path);
            }
        }
    }
}

/// Package hashes of the Composer projects of `apps` that are due (changed since the last report or
/// older than 7 days according to the state file `state`). The state file is updated for the returned
/// projects. `force`: ignore the state (manual run).
pub fn hashes(apps: &[App], state: &Path, force: bool) -> Vec<ComposerProject> {
    let mut st = SentState::load(state);
    let mut roots: Vec<(PathBuf, Vec<String>)> = Vec::new();
    for a in apps {
        let Some(c) = composer_root(Path::new(&a.root)) else { continue };
        match roots.iter_mut().find(|(r, _)| *r == c) {
            Some((_, kinds)) => {
                if !kinds.contains(&a.kind) {
                    kinds.push(a.kind.clone());
                }
            }
            None => roots.push((c, vec![a.kind.clone()])),
        }
    }
    let mut b = Budget::new(MAX_HASH_FILES, MAX_HASH_JSON);
    let mut out = Vec::new();
    for (croot, kinds) in roots {
        if b.exhausted() {
            break;
        }
        let key = croot.to_string_lossy().into_owned();
        let fp = fingerprint(&croot);
        if !force && !st.due(&key, &fp) {
            continue;
        }
        let Some(pkgs) = installed(&croot) else { continue };
        let mut proj = ComposerProject { root: key.clone(), apps: kinds, ..Default::default() };
        for p in pkgs {
            let path = p.dir.strip_prefix(&croot).map(|r| r.to_string_lossy().into_owned()).unwrap_or_default();
            let mut pf = PackageFiles { name: p.name, version: p.version, path, ..Default::default() };
            b.bytes += pf.name.len() + pf.version.len() + pf.path.len() + 64;
            let complete = hash_dir(&p.dir, &mut pf.files, &mut pf.large, &mut b);
            proj.packages.push(pf);
            if !complete {
                proj.truncated = true;
                break;
            }
        }
        st.mark(&key, fp);
        out.push(proj);
    }
    st.save(|k| Path::new(k).join("vendor").is_dir());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(root: &Path, rel: &str, content: &str) -> PathBuf {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, content).unwrap();
        p
    }
    fn app_of(kind: &str, root: &Path) -> App {
        App { kind: kind.into(), root: root.to_string_lossy().into_owned(), ..Default::default() }
    }

    const INSTALLED_V2: &str = r#"{"packages":[
        {"name":"monolog/monolog","version":"3.7.0","install-path":"../monolog/monolog"},
        {"name":"symfony/polyfill-mbstring","version":"v1.31.0","install-path":"../symfony/polyfill-mbstring"},
        {"name":"acme/meta","version":"1.0.0","type":"metapackage","install-path":null},
        {"name":"acme/plugin","version":"2.0.0","install-path":"../../wp-content/plugins/plugin"},
        {"name":"evil/escape","version":"1.0.0","install-path":"../../../../etc"}
    ],"dev":false}"#;

    fn project(r: &Path) {
        w(r, "composer.json", r#"{"autoload":{"psr-4":{"App\\":"app/"},"files":["app/helpers.php"]},"autoload-dev":{"psr-4":{"Tests\\":["tests/"]}}}"#);
        w(r, "composer.lock", "{}");
        w(r, "vendor/composer/installed.json", INSTALLED_V2);
        w(r, "vendor/monolog/monolog/src/Logger.php", "<?php class Logger {}");
        w(r, "vendor/monolog/monolog/README.md", "readme");
        w(r, "vendor/symfony/polyfill-mbstring/bootstrap.php", "<?php");
        w(r, "wp-content/plugins/plugin/plugin.php", "<?php");
        w(r, "artisan", "");
    }

    #[test]
    fn installed_formats() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        project(r);
        let p = installed(r).unwrap();
        let names: Vec<&str> = p.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, vec!["monolog/monolog", "symfony/polyfill-mbstring", "acme/plugin"]);
        assert_eq!(p[2].dir, r.join("wp-content/plugins/plugin"));
        // Composer 1: a plain list, folder vendor/<name>
        w(r, "vendor/composer/installed.json", r#"[{"name":"monolog/monolog","version":"1.27.1"}]"#);
        let p = installed(r).unwrap();
        assert_eq!((p[0].version.as_str(), p[0].dir.clone()), ("1.27.1", r.join("vendor/monolog/monolog")));
    }

    #[test]
    fn autoload_clean_and_foreign() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        project(r);
        let a = app_of("Laravel", r);
        w(r, "vendor/composer/autoload_files.php", "<?php\n\n// autoload_files.php @generated by Composer\n\n$vendorDir = dirname(__DIR__);\n$baseDir = dirname($vendorDir);\n\nreturn array(\n    '0e6d7bf4a5811bfa5cf40c5ccd6fae6a' => $vendorDir . '/symfony/polyfill-mbstring/bootstrap.php',\n    'abc' => $baseDir . '/app/helpers.php',\n);\n");
        w(r, "vendor/composer/autoload_static.php", "<?php\nclass ComposerStaticInitX {\n    public static $files = array (\n        '0e6d7bf4a5811bfa5cf40c5ccd6fae6a' => __DIR__ . '/..' . '/symfony/polyfill-mbstring/bootstrap.php',\n    );\n    public static $classMap = array (\n        'App\\\\Models\\\\User' => __DIR__ . '/../..' . '/app/Models/User.php',\n        'Composer\\\\InstalledVersions' => __DIR__ . '/..' . '/composer/InstalledVersions.php',\n        'Plugin' => __DIR__ . '/../..' . '/wp-content/plugins/plugin/plugin.php',\n    );\n}\n");
        w(r, "vendor/composer/autoload_real.php", "<?php\nclass ComposerAutoloaderInitX {\n    public static function getLoader() {\n        require __DIR__ . '/platform_check.php';\n        require __DIR__ . '/autoload_static.php';\n        $filesToLoad = \\Composer\\Autoload\\ComposerStaticInitX::$files;\n        $requireFile = \\Closure::bind(static function ($fileIdentifier, $file) { require $file; }, null, null);\n    }\n}\n");
        assert_eq!(autoload_foreign(&a), None);
        // a file outside packages and project autoload, an unknown vendor folder, and injected code
        w(r, "vendor/composer/autoload_files.php", "<?php\n$vendorDir = dirname(__DIR__);\n$baseDir = dirname($vendorDir);\nreturn array(\n    'x1' => $baseDir . '/public/uploads/x.php',\n    'x2' => $vendorDir . '/unknown/pkg/boot.php',\n    'x3' => '/tmp/.cache/l.php',\n);\n");
        w(r, "vendor/composer/autoload_real.php", "<?php\n@eval(base64_decode('ZWNobyAxOw=='));\n");
        let f = autoload_foreign(&a).expect("finding");
        assert_eq!(f.check, "composer_autoload_foreign");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.title, "Composer autoloader loads foreign code: Laravel");
        let cdir = r.join("vendor/composer");
        assert!(f.detail.starts_with("5 entries not generated by Composer"), "{}", f.detail);
        assert!(f.detail.contains(&format!("{}/autoload_files.php: x1 => {}/public/uploads/x.php", cdir.display(), r.display())), "{}", f.detail);
        assert!(f.detail.contains(&format!("x2 => {}/vendor/unknown/pkg/boot.php", r.display())));
        assert!(f.detail.contains("x3 => /tmp/.cache/l.php"));
        assert!(f.detail.contains(&format!("{}/autoload_real.php: unexpected code `eval(`", cdir.display())), "{}", f.detail);
    }

    #[test]
    fn package_hashes_and_state() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path().join("app");
        project(&r);
        let big = r.join("vendor/monolog/monolog/big.bin");
        std::fs::File::create(&big).unwrap().set_len(MAX_HASH_SIZE + 1).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", r.join("vendor/monolog/monolog/link")).unwrap();
        let state = t.path().join("composer_sent.json");
        let apps = vec![app_of("WordPress", &r), app_of("WooCommerce", &r)];
        let v = hashes(&apps, &state, false);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].apps, vec!["WordPress", "WooCommerce"]);
        assert!(!v[0].truncated);
        let m = &v[0].packages[0];
        assert_eq!((m.name.as_str(), m.version.as_str(), m.path.as_str()), ("monolog/monolog", "3.7.0", "vendor/monolog/monolog"));
        assert_eq!(m.files.keys().collect::<Vec<_>>(), vec!["README.md", "src/Logger.php"]);
        assert_eq!(m.files["README.md"], tyrosd_core::hash::hash_bytes(tyrosd_core::hash::Algo::Sha256, b"readme"));
        assert_eq!(m.large.get("big.bin"), Some(&(MAX_HASH_SIZE + 1)));
        assert_eq!(v[0].packages[2].path, "wp-content/plugins/plugin");
        let js = serde_json::to_value(&v[0]).unwrap();
        assert!(js.get("truncated").is_none());
        // unchanged: not sent again; changed installed.json: sent again
        assert!(hashes(&apps, &state, false).is_empty());
        std::thread::sleep(std::time::Duration::from_millis(20));
        w(&r, "vendor/composer/installed.json", &format!("{INSTALLED_V2} "));
        assert_eq!(hashes(&apps, &state, false).len(), 1);
        assert_eq!(hashes(&apps, &state, true).len(), 1);
    }

    #[test]
    fn normalise() {
        assert_eq!(norm(Path::new("/a/b/../c/./d")), PathBuf::from("/a/c/d"));
        assert_eq!(norm(Path::new("/a/../../b")), PathBuf::from("/b"));
    }
}
