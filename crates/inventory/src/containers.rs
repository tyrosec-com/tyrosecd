//! Container erkennen und mit ihren eigenen Paketen inventarisieren (Plan „Spitze“, B):
//! systemd-nspawn, Docker, Podman, LXC/Incus, Kubernetes. Erkennung über die Wurzel der Prozesse
//! (`/proc/<pid>/root` mit anderem Gerät/Inode als `/`), Zugriff auf die Dateien über diesen Pfad.
use serde::Serialize;
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;

use crate::software::{self, Package};
use tyrosd_check::rootfs::{self, FsRoot};

/// Höchstlänge von Container-Namen und Hostnamen an die Zentrale
pub const NAME_MAX: usize = 64;

#[derive(Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Container {
    pub id: String,
    pub name: String,
    /// nspawn | docker | podman | lxc | kubernetes | container
    pub kind: String,
    /// running | stopped
    pub state: String,
    pub os: String,
    pub ecosystem: String,
    /// `ID` und `VERSION_ID` aus os-release des Containers (Support-Ende des Basis-Images)
    pub os_id: String,
    pub os_version: String,
    pub packages: usize,
    /// Docker: Kennung der Schreibschicht (overlay2/<upper>/diff), damit die Zentrale Datei-Ereignisse dem Namen zuordnen kann
    pub upper: String,
}

/// Docker: (Name, Kennung der Schreibschicht) zur vollen Container-ID
fn docker_meta(full_id: &str) -> (String, String) {
    let name = std::fs::read_to_string(format!("/var/lib/docker/containers/{full_id}/config.v2.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v["Name"].as_str().map(|n| n.trim_start_matches('/').to_string()))
        .unwrap_or_default();
    let upper = std::fs::read_to_string(format!("/var/lib/docker/image/overlay2/layerdb/mounts/{full_id}/mount-id")).map(|s| s.trim().chars().take(12).collect()).unwrap_or_default();
    (name, upper)
}

fn full_docker_id(cgroup: &str) -> Option<String> {
    cgroup.split(['-', '/', '.']).find(|x| x.len() == 64 && x.chars().all(|c| c.is_ascii_hexdigit())).map(str::to_string)
}

pub const MAX: usize = 50;

/// Art und Name aus der cgroup eines Prozesses
pub fn classify(cgroup: &str) -> (String, String) {
    let c = cgroup.lines().map(|l| l.rsplit(':').next().unwrap_or("")).collect::<Vec<_>>().join("\n");
    let after = |pat: &str| c.find(pat).map(|i| c[i + pat.len()..].split(['/', '.', '\n']).next().unwrap_or("").to_string());
    if let Some(n) = after("systemd-nspawn@").or_else(|| after("machine-").filter(|n| !n.is_empty())) {
        return ("nspawn".into(), n.replace("\\x2d", "-"));
    }
    if let Some(id) = after("docker-").or_else(|| after("/docker/")) {
        return ("docker".into(), id.chars().take(12).collect());
    }
    if let Some(id) = after("libpod-") {
        return ("podman".into(), id.chars().take(12).collect());
    }
    if let Some(n) = after("lxc.payload.").or_else(|| after("/lxc/")) {
        return ("lxc".into(), n);
    }
    if c.contains("kubepods") {
        return ("kubernetes".into(), String::new());
    }
    ("container".into(), String::new())
}

fn hostname_in(fs: &FsRoot) -> String {
    fs.read_string("/etc/hostname", 4096).map(|s| rootfs::cap_name(&s, NAME_MAX)).unwrap_or_default()
}

fn pretty_os(fs: &FsRoot) -> String {
    let s = fs.read_string("/etc/os-release", rootfs::SMALL).or_else(|| fs.read_string("/usr/lib/os-release", rootfs::SMALL)).unwrap_or_default();
    s.lines().find_map(|l| l.strip_prefix("PRETTY_NAME=")).map(|v| rootfs::cap_name(v.trim_matches('"'), 128)).unwrap_or_default()
}

/// Pakete eines Containers mit Fundort „container:<name>“ (auch WordPress/Composer/npm in dessen Webroots)
fn inspect(fs: &FsRoot, name: &str) -> (String, String, Vec<Package>) {
    let eco = software::ecosystem_of(software::os_release_in(fs));
    let loc = format!("container:{name}");
    let mut pk: Vec<Package> = software::packages_in(fs, &eco).into_iter().map(|mut p| {
        p.location = loc.clone();
        p
    }).collect();
    let webroots = tyrosd_check::default_webroots_in(fs);
    for mut p in software::wordpress_in(fs, &webroots).into_iter().chain(software::lockfiles_in(fs, &webroots)) {
        p.location = format!("{loc}:{}", p.location);
        pk.push(p);
    }
    (pretty_os(fs), eco, pk)
}

/// Laufende Container (über /proc) und gestoppte nspawn-Maschinen → (Container, ihre Pakete)
pub fn detect() -> (Vec<Container>, Vec<Package>) {
    detect_at("/proc", "/var/lib/machines")
}

pub fn detect_at(proc_dir: &str, machines: &str) -> (Vec<Container>, Vec<Package>) {
    let host = std::fs::metadata("/").map(|m| (m.dev(), m.ino())).unwrap_or((0, 0));
    // je Wurzel ein Prozess (der mit der kleinsten PID)
    let mut roots: BTreeMap<(u64, u64), u32> = BTreeMap::new();
    if let Ok(rd) = std::fs::read_dir(proc_dir) {
        for e in rd.flatten() {
            let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else { continue };
            let Ok(m) = std::fs::metadata(format!("{proc_dir}/{pid}/root/")) else { continue };
            let k = (m.dev(), m.ino());
            if k == host {
                continue;
            }
            roots.entry(k).and_modify(|p| *p = (*p).min(pid)).or_insert(pid);
        }
    }
    let mut out = Vec::new();
    let mut pkgs = Vec::new();
    let mut seen_names = std::collections::HashSet::new();
    for (_, pid) in roots.into_iter().take(MAX) {
        let root = format!("{proc_dir}/{pid}/root");
        // Dateien des Containers nur über openat2 relativ zur Wurzel; ohne openat2
        // (Kernel < 5.6) wird der Container nicht inventarisiert statt unsicher gelesen
        let Ok(fs) = FsRoot::contained(&root) else { continue };
        let cg = std::fs::read_to_string(format!("{proc_dir}/{pid}/cgroup")).unwrap_or_default();
        let (kind, mut name) = classify(&cg);
        let mut upper = String::new();
        if kind == "docker" {
            if let Some(full) = full_docker_id(&cg) {
                let (n, u) = docker_meta(&full);
                if !n.is_empty() {
                    name = n;
                }
                upper = u;
            }
        }
        if name.is_empty() {
            name = hostname_in(&fs);
        }
        name = rootfs::cap_name(&name, NAME_MAX);
        if name.is_empty() {
            name = format!("pid-{pid}");
        }
        let (os, eco, pk) = inspect(&fs, &name);
        if (os.is_empty() || kind == "container") && pk.is_empty() {
            continue; // Schutzräume ohne eigene Paketverwaltung (Snap/Ubuntu Core, Browser-Sandbox, systemd) sind keine Container
        }
        seen_names.insert(name.clone());
        let (os_id, os_version) = software::os_release_in(&fs);
        out.push(Container { id: name.clone(), name: name.clone(), kind, state: "running".into(), os, ecosystem: eco, os_id, os_version, packages: pk.len(), upper });
        pkgs.extend(pk);
    }
    // gestoppte nspawn-Maschinen
    if let Ok(rd) = std::fs::read_dir(machines) {
        for e in rd.flatten().take(MAX) {
            let name = rootfs::cap_name(&e.file_name().to_string_lossy(), NAME_MAX);
            let root = e.path().to_string_lossy().to_string();
            if seen_names.contains(&name) || name.is_empty() || name.starts_with('.') || out.len() >= MAX {
                continue;
            }
            let Ok(fs) = FsRoot::contained(&root) else { continue };
            if !fs.is_dir("/etc") {
                continue;
            }
            let (os, eco, pk) = inspect(&fs, &name);
            let (os_id, os_version) = software::os_release_in(&fs);
            out.push(Container { id: name.clone(), name, kind: "nspawn".into(), state: "stopped".into(), os, ecosystem: eco, os_id, os_version, packages: pk.len(), upper: String::new() });
            pkgs.extend(pk);
        }
    }
    (out, pkgs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_kinds() {
        assert_eq!(classify("0::/machine.slice/systemd-nspawn@app.service/payload"), ("nspawn".into(), "app".into()));
        assert_eq!(classify("0::/system.slice/docker-3f2a9c1b7d4e5f60718293a4b5c6d7e8.scope"), ("docker".into(), "3f2a9c1b7d4e".into()));
        assert_eq!(classify("0::/machine.slice/libpod-abcdef0123456789.scope/container"), ("podman".into(), "abcdef012345".into()));
        assert_eq!(classify("0::/lxc.payload.web1/init.scope"), ("lxc".into(), "web1".into()));
        assert_eq!(classify("0::/kubepods.slice/kubepods-burstable.slice/x"), ("kubernetes".into(), String::new()));
    }

    #[test]
    fn stopped_machine_with_own_packages() {
        let base = std::env::temp_dir().join(format!("ct-{}", std::process::id()));
        let m = base.join("machines/app");
        std::fs::create_dir_all(m.join("etc")).unwrap();
        std::fs::create_dir_all(m.join("var/lib/dpkg")).unwrap();
        std::fs::write(m.join("etc/os-release"), "ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n").unwrap();
        std::fs::write(m.join("var/lib/dpkg/status"), "Package: openssl\nStatus: install ok installed\nVersion: 3.0.11-1~deb12u2\n\n").unwrap();
        let empty = base.join("proc");
        std::fs::create_dir_all(&empty).unwrap();
        let (c, p) = detect_at(empty.to_str().unwrap(), base.join("machines").to_str().unwrap());
        assert_eq!(c.len(), 1);
        assert_eq!((c[0].name.as_str(), c[0].state.as_str(), c[0].ecosystem.as_str(), c[0].packages), ("app", "stopped", "Debian:12", 1));
        assert_eq!((p[0].name.as_str(), p[0].location.as_str(), p[0].ecosystem.as_str()), ("openssl", "container:app", "Debian:12"));
        std::fs::remove_dir_all(&base).ok();
    }

    /// Feindliche Wurzel: Symlinks auf Host-Dateien und Geräte, überlange Namen
    #[test]
    fn hostile_root_is_read_safely() {
        if !FsRoot::openat2_supported() {
            eprintln!("openat2 nicht verfügbar – Test übersprungen");
            return;
        }
        use std::os::unix::fs::symlink;
        let base = tempfile::tempdir().unwrap();
        let long = "m".repeat(200);
        let m = base.path().join("machines").join(&long);
        std::fs::create_dir_all(m.join("etc")).unwrap();
        std::fs::create_dir_all(m.join("var/lib/dpkg")).unwrap();
        let host_os = base.path().join("host-os-release");
        std::fs::write(&host_os, "ID=hostos\nVERSION_ID=\"1\"\nPRETTY_NAME=\"HOST\"\n").unwrap();
        symlink(&host_os, m.join("etc/os-release")).unwrap();
        symlink("/dev/zero", m.join("var/lib/dpkg/status")).unwrap();
        let empty = base.path().join("proc");
        std::fs::create_dir_all(&empty).unwrap();
        let (c, p) = detect_at(empty.to_str().unwrap(), base.path().join("machines").to_str().unwrap());
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].name.chars().count(), NAME_MAX);
        assert_eq!((c[0].os.as_str(), c[0].os_id.as_str(), c[0].packages), ("", "", 0), "keine Host-Datei, kein Gerät gelesen");
        assert!(p.is_empty());
        // Hostname aus einer Container-Wurzel: gekürzt, ohne Steuerzeichen
        std::fs::write(m.join("etc/hostname"), format!("{}\n\u{1b}x", "h".repeat(100))).unwrap();
        let fs = FsRoot::contained(&m.to_string_lossy()).unwrap();
        assert_eq!(hostname_in(&fs), "h".repeat(NAME_MAX));
    }
}
