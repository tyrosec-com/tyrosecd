//! Installierte Software für den Schwachstellen-Abgleich in der Zentrale
//! (Hauptplan 28.3). Nur lesen, nichts ausführen:
//! - Systempakete aus dpkg/rpm/apk – mit **Quellpaket**-Namen, denn OSV führt
//!   Distributions-Advisories (Debian DSA/DLA, Ubuntu USN …) je Quellpaket
//! - WordPress-Core, Plugins, Themes (Version aus den Headern)
//! - Composer (`composer.lock`) und npm (`package-lock.json`) in den Webroots
//!
//! Container-Wurzeln werden nur über `FsRoot::Contained` gelesen (openat2 mit `RESOLVE_IN_ROOT`, nur reguläre
//! Dateien, Größengrenzen).

use std::collections::BTreeSet;
use std::path::Path;

use serde::Serialize;
use tyrosd_check::rootfs::{self, FsRoot, Kind};

#[derive(Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Package {
    /// OSV-Ökosystem, z. B. „Debian:12“, „Ubuntu:24.04:LTS“, „AlmaLinux:9“, „Packagist“, „npm“, „WordPress“
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    /// pkg | wp-core | wp-plugin | wp-theme | composer | npm
    pub source: String,
    /// Fundort (Webroot bzw. Lockfile), leer bei Systempaketen
    pub location: String,
}

#[derive(Serialize, Debug, Default)]
pub struct Software {
    pub os_ecosystem: String,
    /// `ID` und `VERSION_ID` aus os-release – für das Support-Ende in der Zentrale (unabhängig vom Ökosystem)
    pub os_id: String,
    pub os_version: String,
    pub packages: Vec<Package>,
}

fn os_release() -> (String, String) {
    os_release_in(&FsRoot::host("/"))
}

/// os-release unter einer anderen Wurzel (Test-Wurzeln; Container über `os_release_in`)
pub fn os_release_at(root: &str) -> (String, String) {
    os_release_in(&FsRoot::host(root))
}

/// os-release unter einer Wurzel
pub fn os_release_in(fs: &FsRoot) -> (String, String) {
    let s = fs.read_string("/etc/os-release", rootfs::SMALL).or_else(|| fs.read_string("/usr/lib/os-release", rootfs::SMALL)).unwrap_or_default();
    let get = |k: &str| s.lines().find_map(|l| l.strip_prefix(&format!("{k}="))).map(|v| rootfs::cap_name(v.trim_matches('"'), 64)).unwrap_or_default();
    (get("ID"), get("VERSION_ID"))
}

/// OSV-Ökosystemname der Distribution.
pub fn os_ecosystem() -> String {
    ecosystem_of(os_release())
}

/// Ökosystem aus (ID, VERSION_ID)
pub fn ecosystem_of((id, ver): (String, String)) -> String {
    let major = ver.split('.').next().unwrap_or("").to_string();
    match id.as_str() {
        "debian" => format!("Debian:{major}"),
        // OSV: Ubuntu-LTS als „Ubuntu:24.04:LTS“
        "ubuntu" => {
            let lts = ver.ends_with(".04") && major.parse::<u32>().map(|m| m % 2 == 0).unwrap_or(false);
            if lts { format!("Ubuntu:{ver}:LTS") } else { format!("Ubuntu:{ver}") }
        }
        "almalinux" => format!("AlmaLinux:{major}"),
        "rocky" => format!("Rocky Linux:{major}"),
        // RHEL-Familie: binärkompatibel zu AlmaLinux (gleiche Quellpakete und Versionen) → AlmaLinux-Meldungen.
        // OSV führt Red Hat nur je Repository und Binärpaket; CentOS 7 und älter haben keine Daten mehr.
        "rhel" | "centos" | "ol" | "cloudlinux" | "eurolinux" | "navylinux" | "virtuozzo" | "miraclelinux"
            if matches!(major.as_str(), "8" | "9" | "10") => format!("AlmaLinux:{major}"),
        // openSUSE: OSV führt Meldungen je Quellpaket; SLES nutzt dieselben Pakete wie Leap gleicher Version
        "opensuse-leap" | "sles" | "sled" | "sles_sap" if ver.contains('.') => format!("openSUSE:Leap {ver}"),
        "opensuse-tumbleweed" | "opensuse-slowroll" => "openSUSE:Tumbleweed".into(),
        "alpine" => {
            let mm: Vec<&str> = ver.split('.').take(2).collect();
            format!("Alpine:v{}", mm.join("."))
        }
        _ => String::new(),
    }
}

/// dpkg: installierte Pakete, gruppiert nach Quellpaket (Name, Version).
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
        // „Source: openssl (3.0.13-1)“ → Quellname + ggf. abweichende Quellversion
        let (src_name, src_ver) = match source.split_once(' ') {
            Some((n, v)) => (n, v.trim_matches(|c| c == '(' || c == ')')),
            None if !source.is_empty() => (source, version),
            None => (name, version),
        };
        out.insert(Package { ecosystem: eco.into(), name: src_name.into(), version: src_ver.into(), source: "pkg".into(), location: String::new() });
    }
    out.into_iter().collect()
}

/// rpm (Alma/Rocky): Quellpaket aus SOURCERPM.
pub fn rpm_packages(eco: &str) -> Vec<Package> {
    rpm_query(&[], eco)
}

/// `rpm -qa` mit zusätzlichen Argumenten, Zeitlimit 120 s
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
    // Ausgabe in einem eigenen Faden lesen (sonst blockiert rpm bei vollem Puffer), Ende mit Zeitlimit abwarten
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

/// Ausgabe von `rpm -qa --qf '%{SOURCERPM}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\n'`
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

/// Ort der RPM-Datenbank unter einer Wurzel (Symlink /var/lib/rpm → ../../usr/lib/sysimage/rpm bleibt in der Wurzel)
fn rpm_db_dir(fs: &FsRoot) -> Option<&'static str> {
    ["/var/lib/rpm", "/usr/lib/sysimage/rpm"].into_iter().find(|d| fs.is_dir(d))
}

/// RPM-Pakete unter einer Wurzel. Für Container kein `rpm --root <Container-Wurzel>`: rpm löst Pfade dort selbst auf
/// (absolute Symlinks führten auf den Host, FIFOs/Geräte blockierten). Stattdessen werden die Dateien der Datenbank über
/// `FsRoot` (openat2, nur reguläre Dateien, je ≤ 256 MiB, zusammen ≤ 512 MiB) in ein eigenes, nur für root lesbares
/// Verzeichnis kopiert und dort mit `rpm --dbpath` abgefragt (Zeitlimit 120 s).
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
        // neu anlegen (schlägt fehl, falls der Name schon existiert – auch als Symlink), nur für root
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

/// apk (Alpine): Herkunftspaket (o:) und Version (V:).
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

/// WordPress-Core, Plugins und Themes unter den Webroots.
pub fn wordpress(webroots: &[String]) -> Vec<Package> {
    wordpress_in(&FsRoot::host(""), webroots)
}

/// Wie `wordpress`, unter einer Wurzel (Webroots und Fundorte relativ zu ihr)
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

/// composer.lock und package-lock.json (Tiefe ≤ 4, ohne vendor/node_modules).
pub fn lockfiles(webroots: &[String]) -> Vec<Package> {
    lockfiles_in(&FsRoot::host(""), webroots)
}

/// Wie `lockfiles`, unter einer Wurzel (Webroots und Fundorte relativ zu ihr)
pub fn lockfiles_in(fs: &FsRoot, webroots: &[String]) -> Vec<Package> {
    let mut out = Vec::new();
    for w in webroots {
        let mut found = Vec::new();
        fs.walk(w, 4, 1_000_000, &mut |p, k| {
            let name = p.rsplit('/').next().unwrap_or("");
            if k == Kind::Dir {
                return !matches!(name, "vendor" | "node_modules" | ".git" | "cache" | "uploads");
            }
            if name == "composer.lock" || name == "package-lock.json" {
                found.push(p.to_string());
            }
            false
        });
        for p in found {
            let Some(v) = fs.read(&p, 20 << 20).and_then(|d| serde_json::from_slice::<serde_json::Value>(&d).ok()) else { continue };
            if p.ends_with("/composer.lock") {
                for sec in ["packages", "packages-dev"] {
                    for pkg in v[sec].as_array().into_iter().flatten() {
                        if let (Some(n), Some(ver)) = (pkg["name"].as_str(), pkg["version"].as_str()) {
                            out.push(Package { ecosystem: "Packagist".into(), name: n.into(), version: ver.trim_start_matches('v').into(), source: "composer".into(), location: p.clone() });
                        }
                    }
                }
            } else {
                for (k, pkg) in v["packages"].as_object().into_iter().flatten() {
                    let Some(n) = k.rsplit("node_modules/").next().filter(|n| !n.is_empty() && k.contains("node_modules/")) else { continue };
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

/// Pakete unter einer Wurzel (Host oder Test-Wurzel), passend zur Paketverwaltung
pub fn packages_at(root: &str, eco: &str) -> Vec<Package> {
    packages_in(&FsRoot::host(root), eco)
}

/// Pakete unter einer Wurzel; Container als `FsRoot::Contained`
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

pub fn collect() -> Software {
    let (os_id, os_version) = os_release();
    let eco = ecosystem_of((os_id.clone(), os_version.clone()));
    let mut packages = if Path::new("/var/lib/dpkg/status").exists() {
        dpkg_packages(&eco)
    } else if Path::new("/lib/apk/db/installed").exists() {
        apk_packages(&eco)
    } else {
        rpm_packages(&eco)
    };
    let webroots = tyrosd_check::default_webroots("/");
    packages.extend(wordpress(&webroots));
    packages.extend(lockfiles(&webroots));
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

    /// Container-Wurzel: Symlinks auf Host-Dateien und Geräte werden nicht gelesen, Inhalte innerhalb schon
    #[test]
    fn container_root_reads_stay_inside() {
        if !FsRoot::openat2_supported() {
            eprintln!("openat2 nicht verfügbar – Test übersprungen");
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
        // dpkg status → Gerät (früher: Speicher voll); WordPress-Version → Host-Datei
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
        assert!(wordpress_in(&fs, &webroots).is_empty(), "Host-Datei als WordPress-Version");
        // echte Version im Container wird gefunden, Fundorte relativ zur Wurzel
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
        assert_eq!(e("centos", "7"), ""); // ohne Daten → nur Support-Ende
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
        // nur Format prüfen (läuft im Build-Container: Debian)
        let e = os_ecosystem();
        assert!(e.is_empty() || e.contains(':'), "{e}");
    }
}
