//! Detection of web applications in the webroots (CMS, shops, frameworks) with version and the
//! application's media/upload and cache folders.
//!
//! Read only and bounded: directories are walked to a limited depth with a limited number of
//! entries, symbolic links are never followed during the walk, large trees (`vendor`,
//! `node_modules`, caches, uploads) are skipped. Files are read only if they are small regular
//! files (non-blocking open, so a FIFO never blocks).
//!
//! WordPress with WooCommerce is reported as two entries with the same root: `WordPress` and
//! `WooCommerce` (the shop entry carries the WooCommerce version and the same media/cache folders).

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct App {
    /// WordPress | WooCommerce | Magento | Shopware | Shopware 5 | PrestaShop | JTL-Shop | Laravel | Symfony |
    /// TYPO3 | Contao | Joomla | Drupal | Nextcloud | Next.js | Nuxt
    pub kind: String,
    #[serde(default)]
    pub version: String,
    pub root: String,
    /// Upload/media folders (PHP never belongs there); only existing ones
    #[serde(default)]
    pub media: Vec<String>,
    /// Folders with many legitimate changes (caches, generated code); only existing ones
    #[serde(default)]
    pub cache: Vec<String>,
    /// Plugins/modules/themes of the app (WordPress, Magento app/code, Shopware custom/plugins, PrestaShop modules)
    #[serde(default)]
    pub plugins: Vec<crate::plugins::Plugin>,
}

/// Maximum walk depth below a webroot
const MAX_DEPTH: usize = 4;
/// Maximum directory entries visited per webroot
const MAX_ENTRIES: usize = 20_000;
/// Maximum number of reported apps
const MAX_APPS: usize = 200;
/// Size limit for files read during detection/checks
pub const SMALL: u64 = 1 << 20;
/// Larger limit for lock files
const LOCK: u64 = 16 << 20;

/// Directories never descended into while looking for apps
const SKIP: &[&str] = &[
    "vendor", "node_modules", ".git", "var", "cache", "uploads", "media", "pub", "storage", "wp-content", ".next", ".nuxt",
    "generated", "fileadmin", "typo3temp", "sites", "files", "images", "img", "data", "tmp", "logs", "log", "backup", "backups",
];

/// Docroot names whose parent is usually the application root
const DOCROOT_NAMES: &[&str] = &["public", "pub", "web", "htdocs"];

/// Reads a small regular file (non-blocking open, at most `limit` bytes; `None` otherwise).
/// Symbolic links are followed (shared configuration of deploy tools), but only to a regular file.
pub fn read_small(p: &Path, limit: u64) -> Option<String> {
    use std::os::unix::fs::OpenOptionsExt;
    let m = std::fs::metadata(p).ok()?;
    if !m.is_file() || m.len() > limit {
        return None;
    }
    let f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC).open(p).ok()?;
    if !f.metadata().ok()?.is_file() {
        return None;
    }
    let mut buf = Vec::new();
    f.take(limit + 1).read_to_end(&mut buf).ok()?;
    if buf.len() as u64 > limit {
        return None;
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// First `n` bytes of a regular file (non-blocking open, symbolic links followed)
pub fn read_head(p: &Path, n: u64) -> Option<String> {
    use std::os::unix::fs::OpenOptionsExt;
    if !std::fs::metadata(p).ok()?.is_file() {
        return None;
    }
    let f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC).open(p).ok()?;
    if !f.metadata().ok()?.is_file() {
        return None;
    }
    let mut buf = Vec::new();
    f.take(n).read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

fn is_file(p: &Path) -> bool {
    std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false)
}

fn is_dir(p: &Path) -> bool {
    std::fs::metadata(p).map(|m| m.is_dir()).unwrap_or(false)
}

fn lock_json(root: &Path) -> Option<serde_json::Value> {
    serde_json::from_str(&read_small(&root.join("composer.lock"), LOCK)?).ok()
}

/// Version of the first matching package in `composer.lock`
pub fn composer_version(root: &Path, pkgs: &[&str]) -> String {
    let Some(v) = lock_json(root) else { return String::new() };
    lock_version(&v, pkgs).unwrap_or_default()
}

fn lock_version(v: &serde_json::Value, pkgs: &[&str]) -> Option<String> {
    for p in v["packages"].as_array().into_iter().flatten() {
        if pkgs.contains(&p["name"].as_str().unwrap_or("")) {
            return Some(p["version"].as_str().unwrap_or("").trim_start_matches('v').to_string());
        }
    }
    None
}

/// Text after `marker` (skipping `= ' " , (` and spaces), digits and dots only
pub fn grep_version(file: &Path, marker: &str) -> String {
    let Some(s) = read_small(file, SMALL) else { return String::new() };
    version_after(&s, marker)
}

pub fn version_after(s: &str, marker: &str) -> String {
    s.find(marker)
        .map(|i| {
            s[i + marker.len()..]
                .trim_start_matches([' ', '\t', '=', '>', '\'', '"', ',', '('])
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
                .collect::<String>()
        })
        .filter(|v| v.starts_with(|c: char| c.is_ascii_digit()))
        .unwrap_or_default()
}

/// Version from package.json of an installed npm package, else the (cleaned) range from the app's package.json
fn npm_version(root: &Path, pkg: &str, manifest: &serde_json::Value) -> String {
    if let Some(v) = read_small(&root.join("node_modules").join(pkg).join("package.json"), SMALL)
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v["version"].as_str().map(str::to_string))
    {
        return v;
    }
    let spec = manifest["dependencies"][pkg].as_str().or_else(|| manifest["devDependencies"][pkg].as_str()).unwrap_or("");
    let v: String = spec.trim_start_matches(['^', '~', '=', '>', '<', ' ', 'v']).chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-').collect();
    if v.starts_with(|c: char| c.is_ascii_digit()) { v } else { String::new() }
}

/// Existing folders among `rel` below `root`
fn existing(root: &Path, rel: &[&str]) -> Vec<String> {
    rel.iter().map(|r| root.join(r)).filter(|p| is_dir(p)).map(|p| p.to_string_lossy().into_owned()).collect()
}

fn app(kind: &str, version: String, root: &Path, media: &[&str], cache: &[&str]) -> App {
    let plugins = crate::plugins::collect(kind, root);
    App { kind: kind.into(), version, root: root.to_string_lossy().into_owned(), media: existing(root, media), cache: existing(root, cache), plugins }
}

fn wp_version(root: &Path) -> String {
    let s = read_small(&root.join("wp-includes/version.php"), SMALL).unwrap_or_default();
    s.lines().find_map(|l| l.trim().strip_prefix("$wp_version")).map(|r| version_after(r, "")).unwrap_or_default()
}

fn joomla_version(root: &Path) -> String {
    if let Some(s) = read_small(&root.join("administrator/manifests/files/joomla.xml"), SMALL) {
        if let Some(i) = s.find("<version>") {
            let v = version_after(&s[i..], "<version>");
            if !v.is_empty() {
                return v;
            }
        }
    }
    let s = read_small(&root.join("libraries/src/Version.php"), SMALL).unwrap_or_default();
    let part = |k: &str| version_after(&s, k);
    let (a, b, c) = (part("MAJOR_VERSION"), part("MINOR_VERSION"), part("PATCH_VERSION"));
    if a.is_empty() { String::new() } else { format!("{a}.{}.{}", if b.is_empty() { "0" } else { &b }, if c.is_empty() { "0" } else { &c }) }
}

fn typo3_version(root: &Path, from_lock: String) -> String {
    for base in [root.to_path_buf(), root.join("public")] {
        let v = grep_version(&base.join("typo3/sysext/core/Classes/Information/Typo3Version.php"), "VERSION");
        if !v.is_empty() {
            return v;
        }
        let v = grep_version(&base.join("typo3/sysext/core/ext_emconf.php"), "'version'");
        if !v.is_empty() {
            return v;
        }
    }
    from_lock
}

/// Nextcloud data directory from config/config.php (`'datadirectory' => '…'`), default `<root>/data`
fn nextcloud_data(root: &Path) -> Vec<String> {
    let conf = read_small(&root.join("config/config.php"), SMALL).unwrap_or_default();
    let dir = conf
        .find("'datadirectory'")
        .and_then(|i| {
            let r = conf[i + "'datadirectory'".len()..].trim_start_matches([' ', '\t', '=', '>']);
            let q = r.chars().next().filter(|c| *c == '\'' || *c == '"')?;
            r[1..].split(q).next().map(str::to_string)
        })
        .filter(|d| d.starts_with('/'))
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("data"));
    if is_dir(&dir) { vec![dir.to_string_lossy().into_owned()] } else { vec![] }
}

/// Apps in one directory (WordPress with WooCommerce: two entries)
pub fn detect_dir(p: &Path) -> Vec<App> {
    let j = |r: &str| p.join(r);
    let mut out = Vec::new();
    // composer.lock parsed once per folder
    let lk = if is_file(&j("composer.lock")) { lock_json(p) } else { None };
    let cv = |pkgs: &[&str]| lk.as_ref().and_then(|v| lock_version(v, pkgs)).unwrap_or_default();
    let lock_has = |pkgs: &[&str]| lk.as_ref().map(|v| lock_version(v, pkgs).is_some()).unwrap_or(false);
    if is_file(&j("bin/magento")) && (is_file(&j("app/etc/env.php")) || is_file(&j("app/etc/di.xml"))) {
        let v = cv(&["magento/product-community-edition", "magento/product-enterprise-edition", "magento/magento2-base"]);
        out.push(app("Magento", v, p, &["pub/media"], &["var/cache", "var/page_cache", "generated"]));
    } else if is_dir(&j("vendor/shopware/core")) || is_dir(&j("vendor/shopware/platform")) {
        let v = cv(&["shopware/core", "shopware/platform"]);
        out.push(app("Shopware", v, p, &["public/media", "public/thumbnail"], &["var/cache"]));
    } else if is_file(&j("engine/Shopware/Application.php")) {
        let mut v = grep_version(&j("engine/Shopware/Application.php"), "VERSION");
        if v.is_empty() {
            v = cv(&["shopware/shopware"]);
        }
        out.push(app("Shopware 5", v, p, &["media"], &["var/cache", "web/cache"]));
    } else if is_file(&j("classes/PrestaShopAutoload.php")) || (is_file(&j("config/settings.inc.php")) && is_dir(&j("classes"))) {
        let mut v = grep_version(&j("app/AppKernel.php"), "VERSION");
        if v.is_empty() {
            v = grep_version(&j("config/settings.inc.php"), "_PS_VERSION_");
        }
        out.push(app("PrestaShop", v, p, &["img", "upload", "download"], &["var/cache", "cache"]));
    } else if is_file(&j("includes/config.JTL-Shop.ini.php")) || is_file(&j("includes/defines_inc.php")) {
        let v = grep_version(&j("includes/defines_inc.php"), "APPLICATION_VERSION");
        out.push(app("JTL-Shop", v, p, &["mediafiles", "bilder", "media"], &["templates_c"]));
    } else if is_dir(&j("vendor/contao/core-bundle")) || lock_has(&["contao/core-bundle"]) {
        let v = cv(&["contao/core-bundle", "contao/contao"]);
        out.push(app("Contao", v, p, &["files"], &["var/cache", "assets/images", "public/assets/images", "web/assets/images"]));
    } else if is_dir(&j("typo3/sysext/core")) || is_dir(&j("public/typo3/sysext/core")) || is_dir(&j("vendor/typo3/cms-core")) || lock_has(&["typo3/cms-core"]) {
        out.push(app("TYPO3", typo3_version(p, cv(&["typo3/cms-core"])), p, &["fileadmin", "public/fileadmin"], &["typo3temp", "public/typo3temp", "var/cache"]));
    } else if is_file(&j("artisan")) && (is_dir(&j("vendor/laravel/framework")) || lock_has(&["laravel/framework"])) {
        let v = cv(&["laravel/framework"]);
        out.push(app("Laravel", v, p, &["storage/app/public", "public/storage"], &["storage/framework", "bootstrap/cache"]));
    } else if is_file(&j("bin/console")) && (is_dir(&j("vendor/symfony/framework-bundle")) || lock_has(&["symfony/framework-bundle"])) {
        let v = cv(&["symfony/framework-bundle"]);
        out.push(app("Symfony", v, p, &["public/uploads"], &["var/cache"]));
    } else if is_file(&j("core/lib/Drupal.php")) {
        let v = grep_version(&j("core/lib/Drupal.php"), "const VERSION");
        out.push(app("Drupal", v, p, &["sites/default/files"], &["sites/default/files/php", "sites/default/files/css", "sites/default/files/js"]));
    } else if is_file(&j("libraries/src/Version.php")) || is_file(&j("administrator/manifests/files/joomla.xml")) {
        out.push(app("Joomla", joomla_version(p), p, &["images"], &["cache", "administrator/cache"]));
    } else if is_file(&j("version.php")) && (is_file(&j("occ")) || is_dir(&j("lib/private"))) {
        let v = read_small(&j("version.php"), SMALL).map(|s| version_after(&s, "$OC_VersionString")).unwrap_or_default();
        let mut a = app("Nextcloud", v, p, &[], &[]);
        a.media = nextcloud_data(p);
        out.push(a);
    } else if is_file(&j("wp-includes/version.php")) && (is_file(&j("wp-settings.php")) || is_file(&j("wp-load.php"))) {
        let media = ["wp-content/uploads"];
        let cache = ["wp-content/cache"];
        out.push(app("WordPress", wp_version(p), p, &media, &cache));
        let woo = j("wp-content/plugins/woocommerce/woocommerce.php");
        if is_file(&woo) {
            out.push(app("WooCommerce", grep_version(&woo, "Version:"), p, &media, &cache));
        }
    } else if let Some(m) = read_small(&j("package.json"), SMALL).and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok()) {
        let has = |name: &str| !m["dependencies"][name].is_null() || !m["devDependencies"][name].is_null();
        if has("next") && is_dir(&j(".next")) {
            out.push(app("Next.js", npm_version(p, "next", &m), p, &["public/uploads"], &[".next/cache"]));
        } else if has("nuxt") && (is_dir(&j(".nuxt")) || is_dir(&j(".output"))) {
            out.push(app("Nuxt", npm_version(p, "nuxt", &m), p, &["public/uploads"], &[".nuxt", "node_modules/.cache"]));
        }
    }
    out
}

/// Apps in the webroots: the webroot itself, folders below it (depth ≤ 4) and – for docroots named
/// `public`/`pub`/`web`/`htdocs` – the folder above it. Duplicates (same kind and root) are removed.
pub fn detect(webroots: &[String]) -> Vec<App> {
    let mut out: Vec<App> = Vec::new();
    let push = |out: &mut Vec<App>, found: Vec<App>| {
        for a in found {
            if out.len() < MAX_APPS && !out.iter().any(|b| b.kind == a.kind && b.root == a.root) {
                out.push(a);
            }
        }
    };
    for w in webroots {
        let wp = Path::new(w.trim_end_matches('/'));
        if wp.as_os_str().is_empty() || wp == Path::new("/") {
            continue;
        }
        // app root above the docroot (e.g. Laravel/Symfony/Shopware with `public`, Magento with `pub`)
        if let (Some(name), Some(parent)) = (wp.file_name().map(|n| n.to_string_lossy().into_owned()), wp.parent()) {
            if DOCROOT_NAMES.contains(&name.as_str()) && parent.components().count() > 2 {
                let found = detect_dir(parent);
                if !found.is_empty() {
                    push(&mut out, found);
                    continue;
                }
            }
        }
        let mut seen = 0usize;
        let mut it = walkdir::WalkDir::new(wp).max_depth(MAX_DEPTH).follow_links(false).into_iter();
        while let Some(e) = it.next() {
            let Ok(e) = e else { continue };
            seen += 1;
            if seen > MAX_ENTRIES {
                break;
            }
            if !e.file_type().is_dir() {
                continue;
            }
            if e.depth() > 0 && SKIP.contains(&e.file_name().to_string_lossy().as_ref()) {
                it.skip_current_dir();
                continue;
            }
            let found = detect_dir(e.path());
            if !found.is_empty() {
                push(&mut out, found);
                it.skip_current_dir();
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(root: &Path, rel: &str, content: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }
    fn d(root: &Path, rel: &str) {
        std::fs::create_dir_all(root.join(rel)).unwrap();
    }
    fn lock(pkg: &str, ver: &str) -> String {
        format!(r#"{{"packages":[{{"name":"psr/log","version":"3.0.0"}},{{"name":"{pkg}","version":"{ver}"}}]}}"#)
    }
    fn one(root: &Path) -> App {
        let v = detect(&[root.to_string_lossy().into_owned()]);
        assert_eq!(v.len(), 1, "{v:?}");
        v.into_iter().next().unwrap()
    }
    fn rel(a: &[String], root: &Path) -> Vec<String> {
        a.iter().map(|p| p.strip_prefix(&format!("{}/", root.display())).unwrap_or(p).to_string()).collect()
    }

    #[test]
    fn wordpress_and_woocommerce() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path().join("site");
        w(&r, "wp-includes/version.php", "<?php\n$wp_version = '6.7.1';\n");
        w(&r, "wp-settings.php", "<?php");
        w(&r, "wp-content/plugins/woocommerce/woocommerce.php", "/**\n * Plugin Name: WooCommerce\n * Version: 9.4.2\n */");
        d(&r, "wp-content/uploads");
        let v = detect(&[t.path().to_string_lossy().into_owned()]);
        assert_eq!(v.len(), 2, "{v:?}");
        assert_eq!((v[0].kind.as_str(), v[0].version.as_str()), ("WordPress", "6.7.1"));
        assert_eq!((v[1].kind.as_str(), v[1].version.as_str()), ("WooCommerce", "9.4.2"));
        assert_eq!(v[0].root, v[1].root);
        assert_eq!(rel(&v[0].media, &r), vec!["wp-content/uploads"]);
        assert!(v[0].cache.is_empty(), "only existing folders");
    }

    #[test]
    fn magento() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path().join("shop");
        w(&r, "bin/magento", "#!/usr/bin/env php");
        w(&r, "app/etc/env.php", "<?php return [];");
        w(&r, "composer.lock", &lock("magento/product-community-edition", "2.4.7-p3"));
        d(&r, "pub/media");
        d(&r, "var/cache");
        d(&r, "generated");
        let a = one(t.path());
        assert_eq!((a.kind.as_str(), a.version.as_str()), ("Magento", "2.4.7-p3"));
        assert_eq!(rel(&a.media, &r), vec!["pub/media"]);
        assert_eq!(rel(&a.cache, &r), vec!["var/cache", "generated"]);
    }

    #[test]
    fn shopware_6_via_docroot_parent() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path().join("www/shop");
        d(&r, "vendor/shopware/core");
        w(&r, "composer.lock", &lock("shopware/core", "v6.6.8.2")); // guard:ok (version, not an address)
        d(&r, "public/media");
        d(&r, "public/thumbnail");
        d(&r, "var/cache");
        // webroot is the docroot `public` (web server configuration)
        let v = detect(&[r.join("public").to_string_lossy().into_owned()]);
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!((v[0].kind.as_str(), v[0].version.as_str(), v[0].root.as_str()), ("Shopware", "6.6.8.2", r.to_str().unwrap())); // guard:ok
        assert_eq!(rel(&v[0].media, &r), vec!["public/media", "public/thumbnail"]);
    }

    #[test]
    fn shopware_5_prestashop_jtl() {
        let t = tempfile::tempdir().unwrap();
        w(&t.path().join("sw5"), "engine/Shopware/Application.php", "<?php class Application { const VERSION = '5.7.19'; }");
        w(&t.path().join("ps"), "classes/PrestaShopAutoload.php", "<?php");
        w(&t.path().join("ps"), "app/AppKernel.php", "<?php class AppKernel { const VERSION = '8.1.7'; }");
        d(&t.path().join("ps"), "img");
        w(&t.path().join("jtl"), "includes/defines_inc.php", "<?php define('APPLICATION_VERSION', '5.3.1');");
        d(&t.path().join("jtl"), "templates_c");
        let mut v = detect(&[t.path().to_string_lossy().into_owned()]);
        v.sort_by(|a, b| a.kind.cmp(&b.kind));
        let got: Vec<(&str, &str)> = v.iter().map(|a| (a.kind.as_str(), a.version.as_str())).collect();
        assert_eq!(got, vec![("JTL-Shop", "5.3.1"), ("PrestaShop", "8.1.7"), ("Shopware 5", "5.7.19")]);
        assert_eq!(v[0].cache.len(), 1);
        assert_eq!(v[1].media.len(), 1);
    }

    #[test]
    fn laravel() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        w(r, "artisan", "#!/usr/bin/env php");
        w(r, "composer.lock", &lock("laravel/framework", "v11.31.0"));
        d(r, "storage/app/public");
        d(r, "storage/framework");
        d(r, "bootstrap/cache");
        let a = one(r);
        assert_eq!((a.kind.as_str(), a.version.as_str()), ("Laravel", "11.31.0"));
        assert_eq!(rel(&a.media, r), vec!["storage/app/public"]);
        assert_eq!(rel(&a.cache, r), vec!["storage/framework", "bootstrap/cache"]);
    }

    #[test]
    fn symfony_but_not_for_shopware_or_laravel() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        w(r, "bin/console", "#!/usr/bin/env php");
        w(r, "composer.lock", &lock("symfony/framework-bundle", "v7.1.5"));
        d(r, "var/cache");
        let a = one(r);
        assert_eq!((a.kind.as_str(), a.version.as_str()), ("Symfony", "7.1.5"));
        d(r, "vendor/shopware/core");
        assert_eq!(one(r).kind, "Shopware");
        let t2 = tempfile::tempdir().unwrap();
        w(t2.path(), "bin/console", "");
        w(t2.path(), "artisan", "");
        w(t2.path(), "composer.lock", r#"{"packages":[{"name":"laravel/framework","version":"v10.0.0"},{"name":"symfony/framework-bundle","version":"v6.4.0"}]}"#);
        assert_eq!(one(t2.path()).kind, "Laravel");
    }

    #[test]
    fn typo3_classic_and_composer() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path().join("classic");
        w(&r, "typo3/sysext/core/Classes/Information/Typo3Version.php", "<?php final class Typo3Version { protected const VERSION = '12.4.22'; }");
        d(&r, "fileadmin");
        d(&r, "typo3temp");
        let a = one(&r);
        assert_eq!((a.kind.as_str(), a.version.as_str()), ("TYPO3", "12.4.22"));
        assert_eq!((a.media.len(), a.cache.len()), (1, 1));
        let c = t.path().join("composer");
        w(&c, "composer.lock", &lock("typo3/cms-core", "v13.4.1"));
        d(&c, "public/fileadmin");
        let a = one(&c);
        assert_eq!((a.kind.as_str(), a.version.as_str()), ("TYPO3", "13.4.1"));
        assert_eq!(rel(&a.media, &c), vec!["public/fileadmin"]);
    }

    #[test]
    fn contao() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        w(r, "composer.lock", &lock("contao/core-bundle", "5.3.10"));
        w(r, "bin/console", "");
        d(r, "files");
        d(r, "assets/images");
        let a = one(r);
        assert_eq!((a.kind.as_str(), a.version.as_str()), ("Contao", "5.3.10"));
        assert_eq!(rel(&a.cache, r), vec!["assets/images"]);
    }

    #[test]
    fn joomla_drupal_nextcloud() {
        let t = tempfile::tempdir().unwrap();
        let j = t.path().join("joomla");
        w(&j, "administrator/manifests/files/joomla.xml", "<extension><name>files_joomla</name><version>5.2.1</version></extension>");
        d(&j, "images");
        d(&j, "administrator/cache");
        let a = one(&j);
        assert_eq!((a.kind.as_str(), a.version.as_str(), a.media.len(), a.cache.len()), ("Joomla", "5.2.1", 1, 1));
        let j4 = t.path().join("joomla4");
        w(&j4, "libraries/src/Version.php", "<?php final class Version {\n public const MAJOR_VERSION = 4;\n public const MINOR_VERSION = 4;\n public const PATCH_VERSION = 9;\n}");
        assert_eq!(one(&j4).version, "4.4.9");
        let dr = t.path().join("drupal");
        w(&dr, "core/lib/Drupal.php", "<?php class Drupal {\n  const VERSION = '10.3.6';\n}");
        d(&dr, "sites/default/files");
        let a = one(&dr);
        assert_eq!((a.kind.as_str(), a.version.as_str(), a.media.len()), ("Drupal", "10.3.6", 1));
        let nc = t.path().join("nextcloud");
        let data = t.path().join("ncdata");
        d(&data, "");
        w(&nc, "version.php", "<?php\n$OC_Version = array(30,0,2,1);\n$OC_VersionString = '30.0.2';\n");
        w(&nc, "occ", "#!/usr/bin/env php");
        w(&nc, "config/config.php", &format!("<?php\n$CONFIG = array (\n  'datadirectory' => '{}',\n);", data.display()));
        let a = one(&nc);
        assert_eq!((a.kind.as_str(), a.version.as_str()), ("Nextcloud", "30.0.2"));
        assert_eq!(a.media, vec![data.to_string_lossy().into_owned()]);
    }

    #[test]
    fn nextjs_and_nuxt() {
        let t = tempfile::tempdir().unwrap();
        let n = t.path().join("next");
        w(&n, "package.json", r#"{"dependencies":{"next":"^14.2.3","react":"18.3.1"}}"#);
        d(&n, ".next/cache");
        let a = one(&n);
        assert_eq!((a.kind.as_str(), a.version.as_str()), ("Next.js", "14.2.3"));
        assert_eq!(rel(&a.cache, &n), vec![".next/cache"]);
        w(&n, "node_modules/next/package.json", r#"{"name":"next","version":"14.2.15"}"#);
        assert_eq!(one(&n).version, "14.2.15");
        let x = t.path().join("nuxt");
        w(&x, "package.json", r#"{"devDependencies":{"nuxt":"~3.13.0"}}"#);
        d(&x, ".nuxt");
        let a = one(&x);
        assert_eq!((a.kind.as_str(), a.version.as_str()), ("Nuxt", "3.13.0"));
        // package.json without a build folder: not an app (just a frontend toolchain)
        let y = t.path().join("plain");
        w(&y, "package.json", r#"{"dependencies":{"next":"14.0.0"}}"#);
        assert!(detect(&[y.to_string_lossy().into_owned()]).is_empty());
    }

    #[test]
    fn walk_is_bounded_and_skips_symlinks() {
        let t = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        w(outside.path(), "artisan", "");
        w(outside.path(), "composer.lock", &lock("laravel/framework", "v11.0.0"));
        d(t.path(), "a");
        std::os::unix::fs::symlink(outside.path(), t.path().join("a/link")).unwrap();
        // inside node_modules / too deep: not searched
        w(&t.path().join("x/node_modules/pkg"), "artisan", "");
        w(&t.path().join("x/node_modules/pkg"), "composer.lock", &lock("laravel/framework", "v11.0.0"));
        let deep = t.path().join("1/2/3/4/5");
        w(&deep, "artisan", "");
        w(&deep, "composer.lock", &lock("laravel/framework", "v11.0.0"));
        assert!(detect(&[t.path().to_string_lossy().into_owned()]).is_empty());
    }

    #[test]
    fn duplicates_removed() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path().join("app");
        w(&r, "artisan", "");
        w(&r, "composer.lock", &lock("laravel/framework", "v11.0.0"));
        d(&r, "public");
        let v = detect(&[t.path().to_string_lossy().into_owned(), r.join("public").to_string_lossy().into_owned()]);
        assert_eq!(v.len(), 1, "{v:?}");
    }

    #[test]
    fn fifo_is_not_read() {
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("fifo");
        let c = std::ffi::CString::new(f.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(read_small(&f, SMALL).is_none());
    }
}
