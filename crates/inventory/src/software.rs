//! Installed software for vulnerability matching on the server
//! (main plan 28.3). Read only, execute nothing:
//! - System packages from dpkg/rpm/apk – with **source package** names, because OSV lists
//!   distribution advisories (Debian DSA/DLA, Ubuntu USN …) per source package
//! - WordPress core, plugins, themes (version from the headers)
//! - Composer (`composer.lock`) and npm (`package-lock.json`) in the webroots
//!
//! Container roots are read only via `FsRoot::Contained` (openat2 with `RESOLVE_IN_ROOT`, regular
//! files only, size limits).

use std::collections::BTreeSet;
use std::path::Path;

use serde::Serialize;
use tyrosd_check::rootfs::{self, FsRoot, Kind};

#[derive(Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Package {
    /// OSV ecosystem, e.g. "Debian:12", "Ubuntu:24.04:LTS", "AlmaLinux:9", "Packagist", "npm", "WordPress"
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    /// pkg | wp-core | wp-plugin | wp-theme | composer | npm
    pub source: String,
    /// Location (webroot or lockfile), empty for system packages
    pub location: String,
}

#[derive(Serialize, Debug, Default)]
pub struct Software {
    pub os_ecosystem: String,
    /// `ID` and `VERSION_ID` from os-release – for end of support on the server (independent of the ecosystem)
    pub os_id: String,
    pub os_version: String,
    pub packages: Vec<Package>,
}

fn os_release() -> (String, String) {
    os_release_in(&FsRoot::host("/"))
}

/// os-release under a different root (test roots; containers via `os_release_in`)
pub fn os_release_at(root: &str) -> (String, String) {
    os_release_in(&FsRoot::host(root))
}

/// os-release under a root
pub fn os_release_in(fs: &FsRoot) -> (String, String) {
    let s = fs.read_string("/etc/os-release", rootfs::SMALL).or_else(|| fs.read_string("/usr/lib/os-release", rootfs::SMALL)).unwrap_or_default();
    let get = |k: &str| s.lines().find_map(|l| l.strip_prefix(&format!("{k}="))).map(|v| rootfs::cap_name(v.trim_matches('"'), 64)).unwrap_or_default();
    (get("ID"), get("VERSION_ID"))
}

/// OSV ecosystem name of the distribution.
pub fn os_ecosystem() -> String {
    ecosystem_of(os_release())
}

/// Ecosystem from (ID, VERSION_ID)
pub fn ecosystem_of((id, ver): (String, String)) -> String {
    let major = ver.split('.').next().unwrap_or("").to_string();
    match id.as_str() {
        "debian" => format!("Debian:{major}"),
        // OSV: Ubuntu LTS as "Ubuntu:24.04:LTS"
        "ubuntu" => {
            let lts = ver.ends_with(".04") && major.parse::<u32>().map(|m| m % 2 == 0).unwrap_or(false);
            if lts { format!("Ubuntu:{ver}:LTS") } else { format!("Ubuntu:{ver}") }
        }
        "almalinux" => format!("AlmaLinux:{major}"),
        "rocky" => format!("Rocky Linux:{major}"),
        // RHEL family: binary compatible with AlmaLinux (same source packages and versions) → AlmaLinux advisories.
        // OSV lists Red Hat only per repository and binary package; CentOS 7 and older no longer have data.
        "rhel" | "centos" | "ol" | "cloudlinux" | "eurolinux" | "navylinux" | "virtuozzo" | "miraclelinux"
            if matches!(major.as_str(), "8" | "9" | "10") => format!("AlmaLinux:{major}"),
        // openSUSE: OSV lists advisories per source package; SLES uses the same packages as Leap of the same version
        "opensuse-leap" | "sles" | "sled" | "sles_sap" if ver.contains('.') => format!("openSUSE:Leap {ver}"),
        "opensuse-tumbleweed" | "opensuse-slowroll" => "openSUSE:Tumbleweed".into(),
        "alpine" => {
            let mm: Vec<&str> = ver.split('.').take(2).collect();
            format!("Alpine:v{}", mm.join("."))
        }
        _ => String::new(),
    }
}

/// dpkg: installed packages, grouped by source package (name, version).
pub fn dpkg_packages(eco: &str) -> Vec<Package> {
    dpkg_packages_in(&FsRoot::host("/"), eco)
}

pub fn dpkg_packages_in(fs: &FsRoot, eco: &str) -> Vec<Package> {
    fs.read_string("/var/lib/dpkg/status", rootfs::PKG_DB).map(|s| parse_dpkg(&s, eco)).unwrap_or_default()
}

pub fn parse_dpkg(s: &str, eco: &str) -> Vec<Package> {
    let mut out = BTreeSet::new();
    for block in s.split("\n\n") {
        let mut name = "";
        let mut version = "";
        let mut source = "";
        let mut installed = false;
        for l in block.lines() {
            if let Some(v) = l.strip_prefix("Package: ") {
                name = v.trim();
            } else if let Some(v) = l.strip_prefix("Version: ") {
                version = v.trim();
            } else if let Some(v) = l.strip_prefix("Source: ") {
                source = v.trim();
            } else if let Some(v) = l.strip_prefix("Status: ") {
                installed = v.ends_with(" installed");
            }
        }
        if !installed || name.is_empty() || version.is_empty() {
            continue;
        }
        // "Source: openssl (3.0.13-1)" → source name + possibly a different source version
        let (src_name, src_ver) = match source.split_once(' ') {
            Some((n, v)) => (n, v.trim_matches(|c| c == '(' || c == ')')),
            None if !source.is_empty() => (source, version),
            None => (name, version),
        };
        out.insert(Package { ecosystem: eco.into(), name: src_name.into(), version: src_ver.into(), source: "pkg".into(), location: String::new() });
    }
    out.into_iter().collect()
}

/// rpm (Alma/Rocky): source package from SOURCERPM.
pub fn rpm_packages(eco: &str) -> Vec<Package> {
    rpm_query(&[], eco)
}

/// `rpm -qa` with additional arguments, time limit 120 s
fn rpm_query(extra: &[&str], eco: &str) -> Vec<Package> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    let Ok(mut child) = Command::new("rpm")
        .args(extra)
        .args(["-qa", "--qf", "%{SOURCERPM}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\n"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return vec![];
    };
    // read output in a separate thread (else rpm blocks on a full buffer), wait for the end with a time limit
    let Some(so) = child.stdout.take() else { return vec![] };
    let reader = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = so.take(64 << 20).read_to_end(&mut v);
        v
    });
    let t0 = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if t0.elapsed() < std::time::Duration::from_secs(120) => std::thread::sleep(std::time::Duration::from_millis(100)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return vec![];
            }
        }
    }
    let out = reader.join().unwrap_or_default();
    parse_rpm_qa(&String::from_utf8_lossy(&out), eco)
}

/// Output of `rpm -qa --qf '%{SOURCERPM}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\n'`
pub fn parse_rpm_qa(s: &str, eco: &str) -> Vec<Package> {
    let mut out = BTreeSet::new();
    for l in s.lines() {
        let f: Vec<&str> = l.split('\t').collect();
        if f.len() < 4 || f[0] == "(none)" {
            continue;
        }
        // name-version-release.src.rpm → name
        let srpm = f[0].trim_end_matches(".src.rpm");
        let name = srpm.rsplitn(3, '-').nth(2).unwrap_or(srpm);
        let ver = if f[1] == "0" { format!("{}-{}", f[2], f[3]) } else { format!("{}:{}-{}", f[1], f[2], f[3]) };
        out.insert(Package { ecosystem: eco.into(), name: name.into(), version: ver, source: "pkg".into(), location: String::new() });
    }
    out.into_iter().collect()
}

/// Location of the RPM database under a root (symlink /var/lib/rpm → ../../usr/lib/sysimage/rpm stays in the root)
fn rpm_db_dir(fs: &FsRoot) -> Option<&'static str> {
    ["/var/lib/rpm", "/usr/lib/sysimage/rpm"].into_iter().find(|d| fs.is_dir(d))
}

/// RPM packages under a root. For containers no `rpm --root <container root>`: rpm resolves paths there by itself
/// (absolute symlinks led to the host, FIFOs/devices blocked). Instead, the database files are copied via
/// `FsRoot` (openat2, regular files only, each ≤ 256 MiB, total ≤ 512 MiB) into a separate directory readable only
/// by root and queried there with `rpm --dbpath` (time limit 120 s).
pub fn rpm_packages_in(fs: &FsRoot, eco: &str) -> Vec<Package> {
    if fs.is_host_root() {
        return rpm_packages(eco);
    }
    let Some(db) = rpm_db_dir(fs) else { return vec![] };
    if !tyrosd_check::pkg::which("rpm") {
        return vec![];
    }
    let tmp = std::env::temp_dir().join(format!("tyrosecd-rpmdb-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)));
    {
        use std::os::unix::fs::DirBuilderExt;
        // create new (fails if the name already exists – also as a symlink), root only
        if std::fs::DirBuilder::new().mode(0o700).create(&tmp).is_err() {
            return vec![];
        }
    }
    let mut budget: u64 = 512 << 20;
    let mut copied = false;
    for (name, kind) in fs.read_dir(db, 1000) {
        if kind != Kind::File || name.starts_with('.') || name.starts_with("__db") {
            continue;
        }
        let Some(data) = fs.read(&format!("{db}/{name}"), (256u64 << 20).min(budget)) else { continue };
        budget = budget.saturating_sub(data.len() as u64);
        use std::os::unix::fs::OpenOptionsExt;
        let w = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(tmp.join(&name))
            .and_then(|mut f| std::io::Write::write_all(&mut f, &data));
        copied |= w.is_ok();
    }
    let out = if copied { rpm_query(&["--dbpath", &tmp.to_string_lossy()], eco) } else { vec![] };
    let _ = std::fs::remove_dir_all(&tmp);
    out
}

/// apk (Alpine): origin package (o:) and version (V:).
pub fn apk_packages(eco: &str) -> Vec<Package> {
    apk_packages_in(&FsRoot::host("/"), eco)
}

pub fn apk_packages_in(fs: &FsRoot, eco: &str) -> Vec<Package> {
    let Some(s) = fs.read_string("/lib/apk/db/installed", rootfs::PKG_DB) else { return vec![] };
    let mut out = BTreeSet::new();
    for block in s.split("\n\n") {
        let get = |k: &str| block.lines().find_map(|l| l.strip_prefix(k)).unwrap_or("");
        let (p, v, o) = (get("P:"), get("V:"), get("o:"));
        if !p.is_empty() && !v.is_empty() {
            let name = if o.is_empty() { p } else { o };
            out.insert(Package { ecosystem: eco.into(), name: name.into(), version: v.into(), source: "pkg".into(), location: String::new() });
        }
    }
    out.into_iter().collect()
}

fn theme_version_in(fs: &FsRoot, dir: &str) -> Option<String> {
    let css = fs.read_head(&format!("{dir}/style.css"), 8192)?;
    let head = String::from_utf8_lossy(&css).into_owned();
    head.lines().find_map(|l| {
        let t = l.trim_start_matches([' ', '\t', '*', '/']);
        t.strip_prefix("Version:").map(|v| v.trim().to_string())
    })
}

/// WordPress core, plugins and themes under the webroots.
pub fn wordpress(webroots: &[String]) -> Vec<Package> {
    wordpress_in(&FsRoot::host(""), webroots)
}

/// Like `wordpress`, under a root (webroots and locations relative to it)
pub fn wordpress_in(fs: &FsRoot, webroots: &[String]) -> Vec<Package> {
    let mut out = Vec::new();
    for wp in tyrosd_check::wordpress::find_in(fs, webroots) {
        out.push(Package { ecosystem: "WordPress".into(), name: "wordpress".into(), version: wp.version.clone(), source: "wp-core".into(), location: wp.root.clone() });
        for (sub, kind) in [("plugins", "wp-plugin"), ("themes", "wp-theme")] {
            let base = format!("{}/wp-content/{sub}", wp.root);
            for (slug, k) in fs.read_dir(&base, 10_000) {
                if k != Kind::Dir {
                    continue;
                }
                let dir = format!("{base}/{slug}");
                let ver = if kind == "wp-plugin" { tyrosd_check::wordpress::plugin_version_in(fs, &dir) } else { theme_version_in(fs, &dir) };
                if let Some(v) = ver {
                    out.push(Package { ecosystem: "WordPress".into(), name: slug, version: v, source: kind.into(), location: wp.root.clone() });
                }
            }
        }
    }
    out
}

/// Default webroots plus the given roots, without nested duplicates
pub fn search_roots(roots: &[String]) -> Vec<String> {
    let mut v: Vec<String> = tyrosd_check::default_webroots("/");
    v.extend(roots.iter().map(|r| r.trim_end_matches('/').to_string()).filter(|r| r.starts_with('/') && r.len() > 1));
    v.sort();
    v.dedup();
    let copy = v.clone();
    v.retain(|a| !copy.iter().any(|b| b != a && a.starts_with(&format!("{b}/"))));
    v
}

/// composer.lock and package-lock.json (depth ≤ 4, without vendor/node_modules).
pub fn lockfiles(webroots: &[String]) -> Vec<Package> {
    lockfiles_in(&FsRoot::host(""), webroots)
}

/// Like `lockfiles`, under a root (webroots and locations relative to it)
pub fn lockfiles_in(fs: &FsRoot, webroots: &[String]) -> Vec<Package> {
    let mut out = Vec::new();
    for w in webroots {
        let mut found = Vec::new();
        fs.walk(w, 4, 1_000_000, &mut |p, k| {
            let name = p.rsplit('/').next().unwrap_or("");
            if k == Kind::Dir {
                // hidden folders (.git, .cargo, .cache, .npm …), dependency and build folders: not their own projects
                return !name.starts_with('.') && !matches!(name, "vendor" | "node_modules" | "cache" | "uploads" | "target" | "site-packages" | "dist-packages");
            }
            if matches!(name, "composer.lock" | "package-lock.json" | "Gemfile.lock" | "Cargo.lock") {
                found.push(p.to_string());
            }
            false
        });
        for p in found {
            if p.ends_with("/Gemfile.lock") || p.ends_with("/Cargo.lock") {
                if let Some(t) = fs.read(&p, 20 << 20).and_then(|d| String::from_utf8(d).ok()) {
                    out.extend(if p.ends_with("/Gemfile.lock") { parse_gemfile_lock(&t, &p) } else { parse_cargo_lock(&t, &p) });
                }
                continue;
            }
            let Some(v) = fs.read(&p, 20 << 20).and_then(|d| serde_json::from_slice::<serde_json::Value>(&d).ok()) else { continue };
            if p.ends_with("/composer.lock") {
                // development dependencies (packages-dev, "dev": true) do not run in production – left out (noise)
                for sec in ["packages"] {
                    for pkg in v[sec].as_array().into_iter().flatten() {
                        if let (Some(n), Some(ver)) = (pkg["name"].as_str(), pkg["version"].as_str()) {
                            out.push(Package { ecosystem: "Packagist".into(), name: n.into(), version: ver.trim_start_matches('v').into(), source: "composer".into(), location: p.clone() });
                        }
                    }
                }
            } else {
                for (k, pkg) in v["packages"].as_object().into_iter().flatten() {
                    let Some(n) = k.rsplit("node_modules/").next().filter(|n| !n.is_empty() && k.contains("node_modules/")) else { continue };
                    if pkg["dev"].as_bool() == Some(true) {
                        continue;
                    }
                    if let Some(ver) = pkg["version"].as_str() {
                        out.push(Package { ecosystem: "npm".into(), name: n.into(), version: ver.into(), source: "npm".into(), location: p.clone() });
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Gemfile.lock: gems under `GEM` → `specs:` (four spaces + `name (version)`; platform suffixes removed)
pub fn parse_gemfile_lock(t: &str, loc: &str) -> Vec<Package> {
    let mut out = Vec::new();
    let mut in_gem = false;
    for l in t.lines() {
        if !l.starts_with(' ') {
            in_gem = l == "GEM";
            continue;
        }
        if !in_gem || !l.starts_with("    ") || l.starts_with("     ") {
            continue;
        }
        let Some((name, rest)) = l.trim().split_once(" (") else { continue };
        let ver = rest.trim_end_matches(')').split('-').next().unwrap_or("").to_string();
        if !name.is_empty() && ver.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            out.push(Package { ecosystem: "RubyGems".into(), name: name.into(), version: ver, source: "gemfile".into(), location: loc.into() });
        }
    }
    out
}

/// Cargo.lock: `[[package]]` with `name` and `version`, only from crates.io (`source = "registry+…"`)
pub fn parse_cargo_lock(t: &str, loc: &str) -> Vec<Package> {
    let mut out = Vec::new();
    for block in t.split("[[package]]").skip(1) {
        let val = |k: &str| block.lines().find_map(|l| l.strip_prefix(&format!("{k} = \""))).map(|v| v.trim_end_matches('"').to_string());
        if let (Some(n), Some(v), Some(src)) = (val("name"), val("version"), val("source")) {
            if src.starts_with("registry+") {
                out.push(Package { ecosystem: "crates.io".into(), name: n, version: v, source: "cargo".into(), location: loc.into() });
            }
        }
    }
    out
}

/// Python packages installed with pip (not from the distribution): `*.dist-info/METADATA` in /usr/local/lib/python3*
/// and in virtual environments below /opt, /srv, /home, /root and the given roots
pub fn python_packages(roots: &[String]) -> Vec<Package> {
    let fs = FsRoot::host("");
    let mut dirs: Vec<String> = Vec::new();
    for base in ["/usr/local/lib", "/usr/local/lib64"] {
        for (n, k) in fs.read_dir(base, 1000) {
            if k == Kind::Dir && n.starts_with("python3") {
                for sub in ["site-packages", "dist-packages"] {
                    let d = format!("{base}/{n}/{sub}");
                    if fs.is_dir(&d) {
                        dirs.push(d);
                    }
                }
            }
        }
    }
    let mut tops: Vec<String> = ["/opt", "/srv", "/home", "/root"].iter().map(|s| s.to_string()).collect();
    tops.extend(roots.iter().cloned());
    for t in tops {
        fs.walk(&t, 7, 300_000, &mut |p, k| {
            if k != Kind::Dir {
                return false;
            }
            let name = p.rsplit('/').next().unwrap_or("");
            if name == "site-packages" || name == "dist-packages" {
                dirs.push(p.to_string());
                return false;
            }
            !matches!(name, "node_modules" | "vendor" | ".git" | ".cache" | "proc")
        });
    }
    dirs.sort();
    dirs.dedup();
    let mut out = Vec::new();
    for d in dirs.iter().take(200) {
        for (n, k) in fs.read_dir(d, 20_000) {
            if k != Kind::Dir || !(n.ends_with(".dist-info") || n.ends_with(".egg-info")) {
                continue;
            }
            let meta = if n.ends_with(".dist-info") { format!("{d}/{n}/METADATA") } else { format!("{d}/{n}/PKG-INFO") };
            let Some(t) = fs.read(&meta, 1 << 20).and_then(|b| String::from_utf8(b).ok()) else { continue };
            let head = t.split("\n\n").next().unwrap_or("");
            let field = |k: &str| head.lines().find_map(|l| l.strip_prefix(k)).map(|v| v.trim().to_string());
            if let (Some(name), Some(ver)) = (field("Name:"), field("Version:")) {
                out.push(Package { ecosystem: "PyPI".into(), name, version: ver, source: "pip".into(), location: d.clone() });
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Top-level folders outside the webroots where applications and their lockfiles usually live
pub fn app_dirs() -> Vec<String> {
    let fs = FsRoot::host("");
    let mut v = Vec::new();
    for base in ["/opt", "/srv", "/home"] {
        for (n, k) in fs.read_dir(base, 2000) {
            if k == Kind::Dir && !n.starts_with('.') && n != "tyrosecd" {
                v.push(format!("{base}/{n}"));
            }
        }
    }
    v
}

/// Packages under a root (host or test root), matching the package manager
pub fn packages_at(root: &str, eco: &str) -> Vec<Package> {
    packages_in(&FsRoot::host(root), eco)
}

/// Packages under a root; containers as `FsRoot::Contained`
pub fn packages_in(fs: &FsRoot, eco: &str) -> Vec<Package> {
    if fs.exists("/var/lib/dpkg/status") {
        dpkg_packages_in(fs, eco)
    } else if fs.exists("/lib/apk/db/installed") {
        apk_packages_in(fs, eco)
    } else if rpm_db_dir(fs).is_some() {
        rpm_packages_in(fs, eco)
    } else {
        Vec::new()
    }
}

/// Upper bound of packages in the inventory (central server: 50 000 per list; room for container packages)
pub const MAX_PACKAGES: usize = 40_000;

pub fn collect() -> Software {
    collect_with(&[])
}

/// Like `collect`, additionally searching WordPress and lockfiles in `roots` (webroots from the web server
/// configuration and application roots – e.g. /users/www/app with composer.lock above its public/ folder).
/// Nested roots are searched once.
pub fn collect_with(roots: &[String]) -> Software {
    let (os_id, os_version) = os_release();
    let eco = ecosystem_of((os_id.clone(), os_version.clone()));
    let mut packages = if Path::new("/var/lib/dpkg/status").exists() {
        dpkg_packages(&eco)
    } else if Path::new("/lib/apk/db/installed").exists() {
        apk_packages(&eco)
    } else {
        rpm_packages(&eco)
    };
    // running programs without a package (self-compiled, nvm, snaps) – before the lockfiles, so the limit keeps them
    packages.extend(crate::unpackaged::collect());
    let webroots = search_roots(roots);
    packages.extend(wordpress(&webroots));
    // lockfiles also in applications outside the webroots (/opt, /srv, /home) – package C of the CVE analysis
    let mut lockroots = webroots.clone();
    lockroots.extend(app_dirs());
    packages.extend(lockfiles(&search_roots(&lockroots)));
    packages.extend(python_packages(&webroots));
    // the central server keeps at most 50 000 entries per list – system packages come first and are always kept
    packages.truncate(MAX_PACKAGES);
    Software { os_ecosystem: eco, os_id, os_version, packages }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpkg_source_names() {
        let s = "Package: libssl3t64
Status: install ok installed
Source: openssl (3.0.13-0ubuntu3.4)
Version: 3.0.13-0ubuntu3.4

Package: openssl
Status: install ok installed
Version: 3.0.13-0ubuntu3.4

Package: libpam0g
Status: install ok installed
Source: pam
Version: 1.5.3-5

Package: weg
Status: deinstall ok config-files
Version: 1
";
        let p = parse_dpkg(s, "Ubuntu:24.04:LTS");
        let names: Vec<_> = p.iter().map(|x| format!("{} {}", x.name, x.version)).collect();
        assert_eq!(names, vec!["openssl 3.0.13-0ubuntu3.4", "pam 1.5.3-5"]);
    }

    #[test]
    fn rpm_output() {
        let p = parse_rpm_qa("openssl-3.0.7-27.el9.src.rpm\t1\t3.0.7\t27.el9\n(none)\t0\t1\t1\nbash-5.1.8-9.el9.src.rpm\t0\t5.1.8\t9.el9\n", "AlmaLinux:9");
        let names: Vec<_> = p.iter().map(|x| format!("{} {}", x.name, x.version)).collect();
        assert_eq!(names, vec!["bash 5.1.8-9.el9", "openssl 1:3.0.7-27.el9"]);
    }

    /// Container root: symlinks to host files and devices are not read, contents inside it are
    #[test]
    fn container_root_reads_stay_inside() {
        if !FsRoot::openat2_supported() {
            eprintln!("openat2 not available – test skipped");
            return;
        }
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir().unwrap();
        let ct = d.path().join("ct");
        std::fs::create_dir_all(ct.join("etc")).unwrap();
        std::fs::create_dir_all(ct.join("usr/lib")).unwrap();
        std::fs::create_dir_all(ct.join("var/lib/dpkg")).unwrap();
        std::fs::create_dir_all(ct.join("var/www/html/wp-includes")).unwrap();
        std::fs::create_dir_all(ct.join("var/www/html/wp-content/plugins/akismet")).unwrap();
        std::fs::create_dir_all(ct.join("var/www/app")).unwrap();
        std::fs::write(ct.join("usr/lib/os-release"), "ID=debian\nVERSION_ID=\"12\"\n").unwrap();
        symlink("/usr/lib/os-release", ct.join("etc/os-release")).unwrap();
        // dpkg status → device (formerly: memory exhausted); WordPress version → host file
        symlink("/dev/zero", ct.join("var/lib/dpkg/status")).unwrap();
        let host_secret = d.path().join("host-version.php");
        std::fs::write(&host_secret, "<?php $wp_version = '9.9.9-HOST';").unwrap();
        symlink(&host_secret, ct.join("var/www/html/wp-includes/version.php")).unwrap();
        std::fs::write(ct.join("var/www/html/wp-content/plugins/akismet/akismet.php"), "<?php\n/*\nPlugin Name: Akismet\nVersion: 5.3\n*/").unwrap();
        std::fs::write(ct.join("var/www/app/composer.lock"), r#"{"packages":[{"name":"monolog/monolog","version":"v3.5.0"}]}"#).unwrap();
        let fs = FsRoot::contained(&ct.to_string_lossy()).unwrap();
        assert_eq!(os_release_in(&fs), ("debian".to_string(), "12".to_string()));
        assert!(packages_in(&fs, "Debian:12").is_empty());
        let webroots = tyrosd_check::default_webroots_in(&fs);
        assert_eq!(webroots, vec!["/var/www".to_string()]);
        assert!(wordpress_in(&fs, &webroots).is_empty(), "host file as WordPress version");
        // the real version in the container is found, locations relative to the root
        std::fs::remove_file(ct.join("var/www/html/wp-includes/version.php")).unwrap();
        std::fs::write(ct.join("var/www/html/wp-includes/version.php"), "<?php $wp_version = '6.7.1';").unwrap();
        let wp = wordpress_in(&fs, &webroots);
        let got: Vec<_> = wp.iter().map(|p| format!("{} {} {} {}", p.source, p.name, p.version, p.location)).collect();
        assert_eq!(got, vec!["wp-core wordpress 6.7.1 /var/www/html", "wp-plugin akismet 5.3 /var/www/html"]);
        let lf = lockfiles_in(&fs, &webroots);
        assert_eq!((lf[0].name.as_str(), lf[0].version.as_str(), lf[0].location.as_str()), ("monolog/monolog", "3.5.0", "/var/www/app/composer.lock"));
    }

    #[test]
    fn ecosystem_mapping() {
        let e = |id: &str, v: &str| ecosystem_of((id.into(), v.into()));
        assert_eq!(e("rhel", "9.4"), "AlmaLinux:9");
        assert_eq!(e("centos", "9"), "AlmaLinux:9"); // CentOS Stream 9
        assert_eq!(e("centos", "7"), ""); // no data → only end of support
        assert_eq!(e("ol", "8.10"), "AlmaLinux:8");
        assert_eq!(e("cloudlinux", "9.5"), "AlmaLinux:9");
        assert_eq!(e("opensuse-leap", "15.6"), "openSUSE:Leap 15.6");
        assert_eq!(e("opensuse-leap", "16.0"), "openSUSE:Leap 16.0");
        assert_eq!(e("sles", "15.6"), "openSUSE:Leap 15.6");
        assert_eq!(e("opensuse-tumbleweed", "20261115"), "openSUSE:Tumbleweed");
        assert_eq!(e("amzn", "2023"), "");
        assert_eq!(e("debian", "13"), "Debian:13");
    }

    #[test]
    fn ecosystem_names() {
        // only check the format (runs in the build container: Debian)
        let e = os_ecosystem();
        assert!(e.is_empty() || e.contains(':'), "{e}");
    }

    #[test]
    fn search_roots_merge_and_dedup() {
        let r = search_roots(&["/users/www/app".into(), "/users/www/app/public".into(), "/users/www/shop/".into(), "relative".into(), "/".into()]);
        assert!(r.contains(&"/users/www/app".to_string()) && r.contains(&"/users/www/shop".to_string()));
        assert!(!r.contains(&"/users/www/app/public".to_string()), "nested root searched once");
        assert!(!r.iter().any(|x| x == "relative" || x == "/"));
    }

    #[test]
    fn lockfile_above_public_is_found_via_app_root() {
        let d = std::env::temp_dir().join(format!("tyrosd-lock-{}", std::process::id()));
        std::fs::create_dir_all(d.join("app/public")).unwrap();
        std::fs::write(d.join("app/composer.lock"), r#"{"packages":[{"name":"symfony/http-kernel","version":"v6.4.1"}]}"#).unwrap();
        let root = d.join("app").to_string_lossy().into_owned();
        assert!(lockfiles(&[format!("{root}/public")]).is_empty(), "webroot alone misses it");
        let p = lockfiles(&search_roots(&[format!("{root}/public"), root.clone()]));
        assert_eq!(p.iter().map(|x| (x.name.as_str(), x.version.as_str())).collect::<Vec<_>>(), vec![("symfony/http-kernel", "6.4.1")]);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn gemfile_and_cargo_locks() {
        let g = "GIT\n  remote: x\n  specs:\n    mygem (0.1.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n    actionpack (7.1.3)\n      rack (>= 2.2.4)\n    nokogiri (1.16.2-x86_64-linux)\n    rack (3.0.9)\n\nPLATFORMS\n  x86_64-linux\n";
        let p = parse_gemfile_lock(g, "/srv/app/Gemfile.lock");
        assert_eq!(p.iter().map(|x| (x.name.as_str(), x.version.as_str())).collect::<Vec<_>>(), vec![("actionpack", "7.1.3"), ("nokogiri", "1.16.2"), ("rack", "3.0.9")]);
        let c = "version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.197\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"myapp\"\nversion = \"0.1.0\"\n";
        let p = parse_cargo_lock(c, "/opt/x/Cargo.lock");
        assert_eq!(p.len(), 1);
        assert_eq!((p[0].name.as_str(), p[0].version.as_str(), p[0].ecosystem.as_str()), ("serde", "1.0.197", "crates.io"));
    }

    #[test]
    fn python_metadata_in_venv() {
        let d = std::env::temp_dir().join(format!("tyrosd-py-{}", std::process::id()));
        let sp = d.join("venv/lib/python3.12/site-packages/Django-5.0.1.dist-info");
        std::fs::create_dir_all(&sp).unwrap();
        std::fs::write(sp.join("METADATA"), "Metadata-Version: 2.1\nName: Django\nVersion: 5.0.1\n\nLong description Name: fake\n").unwrap();
        let p = python_packages(&[d.to_string_lossy().into_owned()]);
        assert!(p.iter().any(|x| x.ecosystem == "PyPI" && x.name == "Django" && x.version == "5.0.1"), "{p:?}");
        let _ = std::fs::remove_dir_all(d);
    }
}
