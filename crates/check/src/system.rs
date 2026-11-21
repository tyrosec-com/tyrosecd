//! Programme und Laufzeit: SUID/SGID, File-Capabilities, ausführbare Dateien
//! in temporären Verzeichnissen, Binaries gegen lokale Paket-DB, Prozesse
//! (gelöschtes Binary, /tmp, memfd, falsche Kernel-Threads), offene Ports.

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;

use crate::{Category, Ctx, Severity};

const TMP_DIRS: &[&str] = &["/tmp", "/var/tmp", "/dev/shm"];

pub fn check(ctx: &mut Ctx) {
    suid_caps(ctx);
    container_suid(ctx);
    tmp_exec(ctx);
    binaries(ctx);
    if ctx.cfg.sysroot == "/" {
        processes(ctx);
        ports(ctx);
    }
}

/// chroot-/Build-Umgebungen: Ordner mit vollständigem System und eigener Paketdatenbank (z. B. /srv/php-build/focal,
/// debootstrap-Ziele, schroot). Sie werden wie Container mit ihrer eigenen Paketdatenbank geprüft – SUID-Programme
/// darin gehören nicht zum Server selbst (Praxisfall: 15 Fehlalarme „SUID ohne Paket“ auf einem Entwickler-Rechner).
fn chroot_roots(ctx: &Ctx) -> Vec<String> {
    let looks_like_rootfs = |p: &std::path::Path| {
        p.join("etc/os-release").is_file()
            && p.join("usr/bin").is_dir()
            && (p.join("var/lib/dpkg/status").is_file() || p.join("var/lib/rpm").is_dir() || p.join("lib/apk/db/installed").is_file())
    };
    let mut out = Vec::new();
    for base in ["/srv", "/opt", "/var/chroot", "/var/lib/schroot/chroots"] {
        let Ok(rd) = std::fs::read_dir(ctx.p(base)) else { continue };
        for e in rd.flatten().take(200) {
            let p = e.path();
            if !e.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            if looks_like_rootfs(&p) {
                out.push(p.to_string_lossy().into_owned());
                continue;
            }
            // eine Ebene tiefer (z. B. /srv/php-build/focal)
            if let Ok(rd2) = std::fs::read_dir(&p) {
                for e2 in rd2.flatten().take(50) {
                    if e2.file_type().is_ok_and(|t| t.is_dir()) && looks_like_rootfs(&e2.path()) {
                        out.push(e2.path().to_string_lossy().into_owned());
                    }
                }
            }
        }
    }
    out.truncate(20);
    out
}

fn rel(ctx: &Ctx, p: &str) -> String {
    p.strip_prefix(ctx.cfg.sysroot.trim_end_matches('/')).unwrap_or(p).to_string()
}

/// SUID/SGID in Containern gegen die Paketdatenbank **des Containers** prüfen (nspawn, LXC/LXD/Incus und laufende
/// Container über /proc/<pid>/root). Volle Systeme (nspawn/LXC) → hoch; Docker/Podman-Images (oft Programme außerhalb
/// der Paketverwaltung) → mittel, also nur im Bericht.
fn container_suid(ctx: &mut Ctx) {
    if ctx.cfg.skip_suid_scan {
        return;
    }
    use std::os::unix::fs::MetadataExt;
    let mut roots: Vec<(String, String, bool)> = Vec::new(); // (Wurzel, Bezeichnung, volles System)
    let mut seen = std::collections::HashSet::new();
    let host = std::fs::metadata(ctx.p("/")).map(|m| (m.dev(), m.ino())).unwrap_or((0, 0));
    let mut push = |root: String, label: String, full: bool, roots: &mut Vec<(String, String, bool)>| {
        if let Ok(m) = std::fs::metadata(&root) {
            if (m.dev(), m.ino()) != host && seen.insert((m.dev(), m.ino())) && roots.len() < 20 {
                roots.push((root, label, full));
            }
        }
    };
    for c in chroot_roots(ctx) {
        let label = format!("chroot:{}", rel(ctx, &c));
        push(c, label, true, &mut roots);
    }
    for (dir, suffix) in [("/var/lib/machines", ""), ("/var/lib/lxc", "/rootfs"), ("/var/lib/lxd/containers", "/rootfs"), ("/var/lib/incus/containers", "/rootfs"),
        ("/var/snap/lxd/common/lxd/containers", "/rootfs")]
    {
        if let Ok(rd) = std::fs::read_dir(ctx.p(dir)) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if !name.starts_with('.') {
                    push(format!("{}{suffix}", e.path().to_string_lossy()), name, true, &mut roots);
                }
            }
        }
    }
    // laufende Container ohne festen Ablageort (Docker, Podman) – nur im echten System, nicht im Test-Sysroot
    if ctx.cfg.sysroot.trim_end_matches('/').is_empty() {
        if let Ok(rd) = std::fs::read_dir("/proc") {
            for e in rd.flatten() {
                let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else { continue };
                let cg = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
                if cg.contains("docker") || cg.contains("libpod") || cg.contains("kubepods") {
                    let name = cg.split(['-', '/']).find(|x| x.len() >= 12 && x.chars().all(|c| c.is_ascii_hexdigit())).map(|x| x[..12].to_string()).unwrap_or(format!("pid-{pid}"));
                    push(format!("/proc/{pid}/root"), format!("docker:{name}"), false, &mut roots);
                }
            }
        }
    }
    for (root, label, full) in roots {
        // Paketdatenbank des Containers nur über openat2 (Symlinks bleiben in der Wurzel, nur reguläre Dateien, Grenzen);
        // ohne openat2 (Kernel < 5.6) wird der Container übersprungen statt unsicher gelesen
        let Ok(fs) = tyrosd_core::rootfs::FsRoot::contained(&root) else { continue };
        let db = crate::pkg::PackageDb::load_in(&fs);
        if db.kind == "keine" {
            continue; // ohne Paketdatenbank nicht beurteilbar
        }
        let mut n = 0;
        for sub in ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt", "/home", "/root", "/srv", "/var", "/tmp", "/etc"] {
            let start = format!("{root}{sub}");
            // follow_root_links(false): ein Symlink /usr → / im Container zeigte sonst (über /proc/<pid>/root) auf den Host
            let mut it = walkdir::WalkDir::new(&start).follow_links(false).follow_root_links(false).same_file_system(true).into_iter();
            while let Some(entry) = it.next() {
                let Ok(e) = entry else { continue };
                let p = e.path().to_string_lossy().into_owned();
                if e.file_type().is_dir() {
                    if p.ends_with("/var/log") || p.ends_with("/var/lib/docker") || p.ends_with("/var/cache") {
                        it.skip_current_dir();
                    }
                    continue;
                }
                let Ok(m) = e.metadata() else { continue };
                if !e.file_type().is_file() || m.mode() & 0o6000 == 0 {
                    continue;
                }
                let inner = p[root.len()..].to_string();
                if db.owns(&inner) || n >= 200 {
                    continue;
                }
                n += 1;
                let in_tmp = TMP_DIRS.iter().any(|t| inner.starts_with(&format!("{t}/"))) || inner.starts_with("/home/") || inner.starts_with("/var/www/");
                let sev = if in_tmp { Severity::Critical } else if full { Severity::High } else { Severity::Medium };
                let what = if m.mode() & 0o4000 != 0 { "SUID" } else { "SGID" };
                ctx.add(sev, Category::Binaries, "suid_unowned", format!("{what}-Programm ohne Paket im Container {label}"), Some(p.clone()),
                    Some(format!("Modus {:o}, Besitzer uid {} · im Container: {inner} · Paketverwaltung des Containers: {}", m.mode() & 0o7777, m.uid(), db.kind)));
            }
        }
    }
}

fn suid_caps(ctx: &mut Ctx) {
    if ctx.cfg.skip_suid_scan {
        return;
    }
    let roots = ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt", "/home", "/root", "/srv", "/var", "/tmp", "/etc", "/dev/shm"];
    let chroots = chroot_roots(ctx);
    let mut n_suid = 0;
    let mut n_caps = 0;
    for r in roots {
        let start = ctx.p(r);
        let mut it = walkdir::WalkDir::new(&start).follow_links(false).same_file_system(true).into_iter();
        while let Some(entry) = it.next() {
            let Ok(e) = entry else { continue };
            if e.file_type().is_dir() {
                let p = e.path().to_string_lossy();
                // Container-Dateisysteme (eigene Paketverwaltung) gehören nicht zum Server selbst
                if ["/var/lib/docker", "/var/lib/containerd", "/var/log", "/proc", "/var/lib/machines", "/var/lib/lxc", "/var/lib/lxd", "/var/snap/lxd",
                    "/var/lib/incus", "/var/lib/containers", "/var/lib/libvirt/images"].iter().any(|d| p.ends_with(d))
                    || chroots.iter().any(|c| *c == p)
                {
                    it.skip_current_dir();
                }
                continue;
            }
            if !e.file_type().is_file() {
                continue;
            }
            let Ok(m) = e.metadata() else { continue };
            let p = e.path().to_string_lossy().into_owned();
            let r = rel(ctx, &p);
            let in_tmp = TMP_DIRS.iter().any(|t| r.starts_with(&format!("{t}/"))) || r.starts_with("/home/") || r.starts_with("/var/www/");
            if m.mode() & 0o6000 != 0 {
                n_suid += 1;
                if !ctx.pkgs.owns(&r) {
                    let sev = if in_tmp { Severity::Critical } else { Severity::High };
                    let what = if m.mode() & 0o4000 != 0 { "SUID" } else { "SGID" };
                    ctx.add(sev, Category::Binaries, "suid_unowned", format!("{what}-Programm ohne Paket"), Some(p.clone()), Some(format!("Modus {:o}, Besitzer uid {}", m.mode() & 0o7777, m.uid())));
                }
            }
            if m.mode() & 0o111 != 0 || m.len() > 0 {
                if let Some(caps) = tyrosd_core::event::read_caps(&p) {
                    n_caps += 1;
                    if !ctx.pkgs.owns(&r) {
                        ctx.add(Severity::High, Category::Binaries, "caps_unowned", "Programm mit File-Capabilities ohne Paket", Some(p.clone()), Some(format!("security.capability={caps}")));
                    } else {
                        ctx.confirm("file_caps", p.clone(), caps);
                    }
                }
            }
        }
    }
    ctx.stat("suid_sgid_files", n_suid);
    ctx.stat("files_with_caps", n_caps);
}

/// Unveränderte Kopie einer Systemdatei, z. B. die Chroot-Vorlage von Collabora
/// (/tmp/…/systemplate/lib64/ld-linux-x86-64.so.2 = /lib64/ld-linux-x86-64.so.2). Abgleich über Größe und
/// SHA-256 mit der Datei unter demselben Pfad-Ende im System. SUID/SGID-Dateien zählen nie als harmlose Kopie.
fn copy_of_system_file(ctx: &Ctx, p: &str, m: &std::fs::Metadata) -> bool {
    if m.mode() & 0o6000 != 0 || m.len() > 64 << 20 {
        return false;
    }
    let parts: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();
    for i in 1..parts.len().saturating_sub(1) {
        let rel = format!("/{}", parts[i..].join("/"));
        if !["/usr/", "/lib", "/bin/", "/sbin/", "/etc/", "/opt/"].iter().any(|d| rel.starts_with(d)) {
            continue;
        }
        let sys = ctx.p(&rel);
        let Ok(sm) = std::fs::metadata(&sys) else { continue };
        if !sm.is_file() || sm.len() != m.len() {
            continue;
        }
        let h = |f: &str| tyrosd_core::hash::hash_file(tyrosd_core::hash::Algo::Sha256, f).ok().map(|(h, _)| h);
        if h(p).is_some() && h(p) == h(&sys) {
            return true;
        }
    }
    false
}

/// Inode → (PID, Programm, Benutzer-ID) aller Dateien in temporären Ordnern, die ein laufender Prozess geladen hat
/// (/proc/<pid>/maps). Java entpackt native Bibliotheken (jansi, JNA, Netty, Snappy, SQLite-JDBC) nach /tmp bzw.
/// ins private /tmp des Dienstes und lädt sie von dort – Praxisfall: Elasticsearch, libjansi.so.
fn tmp_mapped(proc_dir: &str) -> std::collections::HashMap<u64, (i32, String, u32)> {
    let mut out = std::collections::HashMap::new();
    let Ok(rd) = std::fs::read_dir(proc_dir) else { return out };
    for e in rd.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
        let Ok(maps) = std::fs::read_to_string(format!("{proc_dir}/{pid}/maps")) else { continue };
        let mut hits = Vec::new();
        for l in maps.lines() {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() >= 6 && TMP_DIRS.iter().any(|t| f[5].starts_with(&format!("{t}/"))) {
                if let Ok(ino) = f[4].parse::<u64>() {
                    hits.push(ino);
                }
            }
        }
        if hits.is_empty() {
            continue;
        }
        let exe = std::fs::read_link(format!("{proc_dir}/{pid}/exe")).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        let uid = std::fs::read_to_string(format!("{proc_dir}/{pid}/status")).ok()
            .and_then(|s| s.lines().find_map(|l| l.strip_prefix("Uid:")).and_then(|v| v.split_whitespace().next()).and_then(|v| v.parse().ok()))
            .unwrap_or(0);
        for ino in hits {
            out.entry(ino).or_insert((pid, exe.clone(), uid));
        }
    }
    out
}

/// Pfad im privaten Temp-Ordner eines systemd-Dienstes: …/tmp/systemd-private-<32 hex>-<dienst>.service-<x>/tmp/…
fn service_private_tmp(p: &str) -> bool {
    p.split('/').any(|c| {
        c.strip_prefix("systemd-private-")
            .is_some_and(|r| r.len() > 34 && r.as_bytes()[..32].iter().all(u8::is_ascii_hexdigit) && r[33..].contains(".service-"))
    }) && p.contains(".service-") && p.split(".service-").nth(1).is_some_and(|r| r.contains("/tmp/"))
}

fn tmp_exec(ctx: &mut Ctx) {
    let mut n_copies = 0u64;
    let mut mapped: Option<std::collections::HashMap<u64, (i32, String, u32)>> = None;
    for t in TMP_DIRS {
        let base = ctx.p(t);
        for e in walkdir::WalkDir::new(&base).max_depth(6).follow_links(false).into_iter().flatten() {
            let p = e.path().to_string_lossy().into_owned();
            let name = e.file_name().to_string_lossy().into_owned();
            if e.depth() == 1 && e.file_type().is_dir() && name.starts_with('.') && !matches!(name.as_str(), ".X11-unix" | ".ICE-unix" | ".font-unix" | ".XIM-unix" | ".Test-unix") {
                ctx.add(Severity::Medium, Category::Runtime, "tmp_hidden_dir", "Verstecktes Verzeichnis in temporärem Ordner", Some(p.clone()), None);
            }
            if !e.file_type().is_file() {
                continue;
            }
            let Ok(m) = e.metadata() else { continue };
            let mut head = [0u8; 4];
            let elf = std::fs::File::open(&p).and_then(|mut f| std::io::Read::read_exact(&mut f, &mut head)).is_ok() && &head == b"\x7fELF";
            if (elf || m.mode() & 0o111 != 0) && copy_of_system_file(ctx, &p, &m) {
                n_copies += 1;
                continue;
            }
            // native Bibliothek, die ein Dienst (nicht root, Programm außerhalb von tmp) selbst entpackt hat und geladen hält
            if elf && name.contains(".so") && m.mode() & 0o6022 == 0 {
                let map = mapped.get_or_insert_with(|| tmp_mapped(&ctx.p("/proc")));
                if let Some((pid, exe, uid)) = map.get(&m.ino()).filter(|(pid, exe, uid)| *uid != 0 && *uid == m.uid() && !exe.is_empty() && !from_tmp(exe, *pid)) {
                    ctx.add(Severity::Info, Category::Runtime, "tmp_library_loaded", "Native Bibliothek eines laufenden Programms in temporärem Ordner", Some(p),
                        Some(format!("geladen von {exe} (PID {pid}, Benutzer-ID {uid}) – typisch für Java (JNA, jansi, Netty)")));
                    continue;
                }
            }
            // Bibliothek eines Dienstes in dessen privatem Temp-Ordner (systemd PrivateTmp), dem Dienst-Benutzer gehörend,
            // gerade nicht geladen (Praxisfall: Elasticsearch entpackt jansi beim Start) – nur ein Hinweis.
            // Ausführbare Programme dort oder Dateien von root bleiben ein Fund.
            if elf && name.contains(".so") && m.uid() != 0 && m.mode() & 0o6022 == 0 && service_private_tmp(&p) {
                ctx.add(Severity::Info, Category::Runtime, "tmp_library_service", "Native Bibliothek eines Dienstes in dessen privatem Temp-Ordner", Some(p),
                    Some(format!("Benutzer-ID {} – typisch für Java (JNA, jansi, Netty)", m.uid())));
                continue;
            }
            if elf || m.mode() & 0o111 != 0 {
                let sev = if elf { Severity::High } else { Severity::Medium };
                ctx.add(sev, Category::Runtime, "tmp_executable", if elf { "ELF-Programm in temporärem Verzeichnis" } else { "Ausführbare Datei in temporärem Verzeichnis" }, Some(p), Some(format!("Größe {} B, uid {}", m.len(), m.uid())));
            }
        }
    }
    ctx.stat("tmp_system_copies", n_copies);
}

/// Programme und Bibliotheken, die Rootkits typischerweise austauschen
fn watched_binary(p: &str) -> bool {
    ["/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/openssh/", "/usr/libexec/openssh/"].iter().any(|d| p.starts_with(d))
        || p.contains("/security/pam_")
        || p.contains("/libc.so") || p.contains("/libpam.so") || p.contains("/libkeyutils") || p.contains("/libaudit")
        // alle Bibliotheken der Pakete (Rootkits ersetzen gern libcrypt, libssl, libselinux, NSS-Module …)
        || (["/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/", "/usr/libexec/"].iter().any(|d| p.starts_with(d)) && (p.ends_with(".so") || p.contains(".so.")))
}

/// RPM-Systeme (Alma/Rocky/RHEL): SHA-256 selbst berechnen, gegen lokale RPM-DB prüfen (fälschbar) und
/// für den Abgleich mit den offiziellen Paketen in der Zentrale melden (Plan C4).
fn binaries_rpm(ctx: &mut Ctx) {
    let mut checked = 0;
    let mut bad = 0;
    let entries: Vec<(String, crate::pkg::RpmFile)> =
        ctx.pkgs.rpm.iter().filter(|(p, f)| watched_binary(p) && !f.sha256.is_empty()).map(|(a, b)| (a.clone(), b.clone())).collect();
    let mut done = std::collections::HashSet::new();
    for (p, f) in entries {
        let full = ctx.p(&p);
        let canon = std::fs::canonicalize(&full).map(|c| c.to_string_lossy().into_owned()).unwrap_or(full.clone());
        if !done.insert(canon) {
            continue;
        }
        let Ok((h, _)) = tyrosd_core::hash::hash_file(tyrosd_core::hash::Algo::Sha256, &full) else { continue };
        checked += 1;
        if ctx.report.binaries.len() < 30000 {
            ctx.report.binaries.push(crate::BinaryRef { path: p.clone(), package: f.name.clone(), version: f.evr.clone(), md5: String::new(), sha256: h.clone(), arch: f.arch.clone() });
        }
        if h != f.sha256 {
            bad += 1;
            ctx.add(Severity::High, Category::Binaries, "binary_pkg_mismatch", "Programm weicht von Paket-Prüfsumme ab", Some(full), Some("Abgleich mit lokaler RPM-Datenbank (fälschbar); Referenz-Abgleich folgt serverseitig".into()));
        }
    }
    ctx.stat("binaries_checked_rpm", checked);
    ctx.stat("binaries_mismatch_rpm", bad);
}

/// Programme der Paketverwaltung (comm, max. 15 Zeichen)
const PKG_TOOLS: &[&str] = &["dpkg", "apt", "apt-get", "aptitude", "unattended-upgr", "rpm", "dnf", "yum", "zypper", "packagekitd"];

/// Paketverwaltung gerade aktiv oder ihre Datenbank in den letzten 10 Minuten geändert? Dann passen Dateien und
/// Paketdatenbank während eines Updates nicht zusammen (Testlauf auf frischer VM: Check fiel in ein apt-get – 20 Fehlalarme
/// „Programm weicht vom Paket ab“ für coreutils/libc). Liefert den Grund.
pub fn pkg_manager_busy(root: &str) -> Option<String> {
    let base = root.trim_end_matches('/');
    for db in ["/var/lib/dpkg/status", "/var/lib/rpm/rpmdb.sqlite", "/var/lib/rpm/Packages", "/usr/lib/sysimage/rpm/rpmdb.sqlite"] {
        let age = std::fs::metadata(format!("{base}{db}")).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok());
        if age.is_some_and(|a| a < std::time::Duration::from_secs(600)) {
            return Some(format!("Paketdatenbank {db} vor weniger als 10 Minuten geändert"));
        }
    }
    // laufende Programme nur für das Wirtssystem (Container/chroot haben eigene Prozesse nicht in /proc)
    if base.is_empty() {
        for e in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
            if !e.file_name().to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            if let Ok(c) = std::fs::read_to_string(e.path().join("comm")) {
                let c = c.trim();
                if PKG_TOOLS.contains(&c) {
                    return Some(format!("Paketverwaltung läuft ({c})"));
                }
            }
        }
    }
    None
}

fn binaries(ctx: &mut Ctx) {
    if ctx.cfg.skip_dpkg_verify {
        return;
    }
    // während eines Updates nicht prüfen – der nächste Check holt es nach (auch keine Prüfsummen an die Zentrale)
    let root = ctx.p("/");
    if let Some(why) = pkg_manager_busy(&root) {
        ctx.stat("binaries_skipped", why);
        return;
    }
    if ctx.pkgs.kind == "rpm" {
        binaries_rpm(ctx);
        drop_if_pkg_started(ctx, &root);
        return;
    }
    if ctx.pkgs.md5.is_empty() {
        return;
    }
    let mut checked = 0;
    let mut bad = 0;
    let entries: Vec<(String, String)> = ctx
        .pkgs
        .md5
        .iter()
        .filter(|(p, _)| watched_binary(p))
        .map(|(a, b)| (a.clone(), b.clone()))
        .collect();
    let mut done = std::collections::HashSet::new();
    for (p, expected) in entries {
        let full = ctx.p(&p);
        // merged-/usr: /bin/ls und /usr/bin/ls sind dieselbe Datei
        let canon = std::fs::canonicalize(&full).map(|c| c.to_string_lossy().into_owned()).unwrap_or(full.clone());
        if !done.insert(canon.clone()) {
            continue;
        }
        let Ok(h) = tyrosd_core::hash::md5_file(&full) else { continue };
        checked += 1;
        // für den Abgleich gegen das offizielle Paket in der Zentrale (lokale DB ist fälschbar)
        if let Some(pkg) = ctx.pkgs.owner.get(&p) {
            if let Some(ver) = ctx.pkgs.versions.get(pkg) {
                if ctx.report.binaries.len() < 30000 {
                    ctx.report.binaries.push(crate::BinaryRef { path: p.clone(), package: pkg.clone(), version: ver.clone(), md5: h.clone(), sha256: String::new(), arch: String::new() });
                }
            }
        }
        if h != expected {
            bad += 1;
            ctx.add(Severity::High, Category::Binaries, "binary_pkg_mismatch", "Programm weicht von Paket-Prüfsumme ab", Some(full), Some("Abgleich mit lokaler dpkg-Datenbank (fälschbar); Referenz-Abgleich folgt serverseitig".into()));
        }
    }
    ctx.stat("binaries_checked_dpkg", checked);
    ctx.stat("binaries_mismatch_dpkg", bad);
    drop_if_pkg_started(ctx, &root);
}

/// Paketverwaltung hat während der Prüfung begonnen: Abweichungen und Prüfsummen dieses Durchlaufs verwerfen
fn drop_if_pkg_started(ctx: &mut Ctx, root: &str) {
    if let Some(why) = pkg_manager_busy(root) {
        ctx.report.findings.retain(|f| f.check != "binary_pkg_mismatch");
        ctx.report.binaries.clear();
        ctx.stat("binaries_skipped", format!("{why} (während der Prüfung)"));
    }
}

/// Programm liegt in einem temporären Verzeichnis – eingehängte AppImages (z. B. Collabora in Nextcloud,
/// /tmp/.mount_* mit echtem FUSE-Mount) ausgenommen – gemeinsame Prüfung mit der Echtzeit-Erkennung
fn from_tmp(exe: &str, pid: i32) -> bool {
    TMP_DIRS.iter().any(|t| exe.starts_with(&format!("{t}/"))) && !tyrosd_core::trust::appimage_for(exe, Some(pid))
}

fn processes(ctx: &mut Ctx) {
    let Ok(rd) = std::fs::read_dir("/proc") else { return };
    let mut n = 0;
    for e in rd.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
        n += 1;
        let Some(exe) = tyrosd_core::procinfo::exe(pid) else { continue };
        let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        let cmd = String::from_utf8_lossy(&cmdline).replace('\0', " ").trim().to_string();
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default().trim().to_string();
        let desc = format!("PID {pid} {comm}: {}", cmd.chars().take(160).collect::<String>());
        if exe.starts_with("/memfd:") || exe.contains("(deleted)") && exe.starts_with("/memfd") {
            ctx.add(Severity::Critical, Category::Runtime, "proc_memfd", "Prozess läuft aus dem Arbeitsspeicher (memfd, dateilos)", Some(exe.clone()), Some(desc.clone()));
            continue;
        }
        if from_tmp(&exe, pid) {
            ctx.add(Severity::Critical, Category::Runtime, "proc_from_tmp", "Prozess läuft aus temporärem Verzeichnis", Some(exe.clone()), Some(desc.clone()));
        }
        if let Some(orig) = exe.strip_suffix(" (deleted)") {
            if std::path::Path::new(orig).exists() && (orig.starts_with("/usr/") || orig.starts_with("/opt/")) {
                ctx.add(Severity::Low, Category::Runtime, "proc_stale_after_update", "Prozess nach Update nicht neu gestartet", Some(orig.to_string()), Some(desc.clone()));
            } else {
                ctx.add(Severity::High, Category::Runtime, "proc_deleted_exe", "Prozess, dessen Programmdatei gelöscht wurde", Some(exe.clone()), Some(desc.clone()));
            }
        }
        if cmd.starts_with('[') && cmd.ends_with(']') {
            ctx.add(Severity::Critical, Category::Runtime, "proc_fake_kthread", "Prozess tarnt sich als Kernel-Thread", Some(exe.clone()), Some(desc.clone()));
        }
    }
    ctx.stat("processes", n);
}

/// Listener aus /proc/net/{tcp,tcp6,udp,udp6} mit Prozess.
pub struct Listener {
    pub proto: &'static str,
    pub addr: String,
    pub port: u16,
    pub public: bool,
    pub inode: u64,
}

fn parse_addr(hex_addr: &str, v6: bool) -> Option<(String, u16, bool)> {
    let (a, p) = hex_addr.split_once(':')?;
    let port = u16::from_str_radix(p, 16).ok()?;
    if !v6 {
        let n = u32::from_str_radix(a, 16).ok()?;
        let ip = std::net::Ipv4Addr::from(n.to_le_bytes());
        let public = !(ip.is_loopback() || ip.is_private() || ip.is_link_local());
        return Some((ip.to_string(), port, public));
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let w = u32::from_str_radix(&a[i * 8..i * 8 + 8], 16).ok()?;
        bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    let ip = std::net::Ipv6Addr::from(bytes);
    let local = ip.is_loopback() || ip.to_ipv4_mapped().map(|v| v.is_loopback() || v.is_private()).unwrap_or(false) || (ip.segments()[0] & 0xfe00) == 0xfc00 || (ip.segments()[0] & 0xffc0) == 0xfe80;
    Some((ip.to_string(), port, !local))
}

pub fn listeners() -> Vec<Listener> {
    let mut v = Vec::new();
    for (file, proto, v6, state) in [("/proc/net/tcp", "tcp", false, "0A"), ("/proc/net/tcp6", "tcp6", true, "0A"), ("/proc/net/udp", "udp", false, "07"), ("/proc/net/udp6", "udp6", true, "07")] {
        let s = std::fs::read_to_string(file).unwrap_or_default();
        for l in s.lines().skip(1) {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 10 || f[3] != state {
                continue;
            }
            // UDP: nur Sockets ohne Gegenstelle
            if proto.starts_with("udp") && !f[2].ends_with(":0000") {
                continue;
            }
            if let Some((addr, port, public)) = parse_addr(f[1], v6) {
                v.push(Listener { proto, addr, port, public, inode: f[9].parse().unwrap_or(0) });
            }
        }
    }
    v
}

/// Socket-Inode → (PID, comm)
pub fn socket_owners() -> HashMap<u64, (i32, String)> {
    let mut m = HashMap::new();
    let Ok(rd) = std::fs::read_dir("/proc") else { return m };
    for e in rd.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default().trim().to_string();
        for fd in fds.flatten() {
            if let Ok(t) = std::fs::read_link(fd.path()) {
                let t = t.to_string_lossy();
                if let Some(i) = t.strip_prefix("socket:[").and_then(|x| x.strip_suffix(']')) {
                    if let Ok(i) = i.parse() {
                        m.insert(i, (pid, comm.clone()));
                    }
                }
            }
        }
    }
    m
}

fn ports(ctx: &mut Ctx) {
    let dangerous: HashMap<u16, &str> = [
        (3306, "MySQL/MariaDB"), (5432, "PostgreSQL"), (6379, "Redis"), (11211, "Memcached"), (27017, "MongoDB"),
        (9200, "Elasticsearch"), (9300, "Elasticsearch"), (2375, "Docker-API ohne TLS"), (2376, "Docker-API"),
        (5984, "CouchDB"), (8086, "InfluxDB"), (9000, "PHP-FPM/FastCGI"), (5601, "Kibana"), (15672, "RabbitMQ-Verwaltung"),
        (6443, "Kubernetes-API"), (10250, "Kubelet"), (2049, "NFS"), (111, "rpcbind"), (873, "rsync-Daemon"), (8983, "Solr"),
    ].into_iter().collect();
    let owners = socket_owners();
    let ls = listeners();
    let mut seen = std::collections::HashSet::new();
    for l in &ls {
        let (pid, comm) = owners.get(&l.inode).cloned().unwrap_or((0, "?".into()));
        if !seen.insert((l.proto, l.addr.clone(), l.port)) {
            continue;
        }
        let bind = if l.public { "öffentlich" } else { "lokal/privat" };
        if l.public {
            ctx.confirm("listener", format!("{}:{}/{}", l.addr, l.port, l.proto), format!("{comm} (PID {pid}), {bind}"));
        }
        if let Some(svc) = dangerous.get(&l.port) {
            if l.public && l.proto.starts_with("tcp") {
                ctx.add(Severity::High, Category::Network, "dangerous_service_public", format!("{svc} auf öffentlicher Adresse gebunden ({}:{})", l.addr, l.port), None,
                    Some(format!("{comm} (PID {pid}); Hoster-Firewall von hier nicht sichtbar")));
            }
        }
        let exe = if pid > 0 { tyrosd_core::procinfo::exe(pid).unwrap_or_default() } else { String::new() };
        if from_tmp(&exe, pid) {
            ctx.add(Severity::Critical, Category::Network, "listener_from_tmp", "Port wird von Programm aus temporärem Verzeichnis geöffnet", Some(exe), Some(format!("{}:{}", l.addr, l.port)));
        }
    }
    ctx.stat("listeners", ls.len());
    ctx.stat("listeners_public", ls.iter().filter(|l| l.public).count());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_manager_activity_skips_binary_check() {
        let d = std::env::temp_dir().join(format!("pkgbusy-{}", std::process::id()));
        std::fs::create_dir_all(d.join("var/lib/dpkg")).unwrap();
        let root = d.to_string_lossy().into_owned();
        assert!(pkg_manager_busy(&root).is_none(), "keine Paketdatenbank");
        let f = std::fs::File::create(d.join("var/lib/dpkg/status")).unwrap();
        assert!(pkg_manager_busy(&root).unwrap().contains("vor weniger als 10 Minuten"));
        f.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3600)).unwrap();
        assert!(pkg_manager_busy(&root).is_none(), "altes Update");
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn tmp_library_loaded_by_service_is_info_only() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let root = std::env::temp_dir().join(format!("tlib-{}", std::process::id()));
        let d = root.join("tmp/systemd-private-x-elasticsearch.service-y/tmp/elasticsearch-311");
        std::fs::create_dir_all(&d).unwrap();
        let lib = d.join("jansi-2.4.0-libjansi.so");
        let evil = root.join("tmp/evil.so");
        for f in [&lib, &evil] {
            std::fs::write(f, "ELF-lib").unwrap();
            std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o744)).unwrap();
        }
        // Besitzer der Bibliothek = Dienst-Benutzer (nicht root); im Test-Container als root angelegt → übertragen
        if std::fs::metadata(&lib).unwrap().uid() == 0 {
            std::os::unix::fs::chown(&lib, Some(1000), Some(1000)).unwrap();
        }
        let uid = std::fs::metadata(&lib).unwrap().uid();
        // Elasticsearch (java aus dem Paket) hat die Bibliothek geladen
        let pd = root.join("proc/4242");
        std::fs::create_dir_all(&pd).unwrap();
        let ino = std::fs::metadata(&lib).unwrap().ino();
        std::fs::write(pd.join("maps"), format!("7f2b88200000-7f2b88203000 r-xp 00000000 09:02 {ino}   /tmp/elasticsearch-311/jansi-2.4.0-libjansi.so
")).unwrap();
        std::os::unix::fs::symlink("/usr/share/elasticsearch/jdk/bin/java", pd.join("exe")).unwrap();
        std::fs::write(pd.join("status"), format!("Name:	java
Uid:	{uid}	{uid}	{uid}	{uid}
")).unwrap();
        let rep = crate::run(crate::CheckConfig { sysroot: root.to_string_lossy().into_owned(), offline: true, ..Default::default() });
        let f = |c: &str| rep.findings.iter().filter(|f| f.check == c).filter_map(|f| f.path.clone()).collect::<Vec<_>>();
        assert_eq!(f("tmp_library_loaded").len(), 1, "{:?}", f("tmp_executable"));
        assert!(f("tmp_executable").iter().all(|p| !p.ends_with("libjansi.so")));
        assert!(f("tmp_executable").iter().any(|p| p.ends_with("/tmp/evil.so"))); // nicht geladen → weiterhin Fund
        assert!(super::service_private_tmp("/tmp/systemd-private-5e633f568ebd42cdb0878b8129e0e22b-elasticsearch.service-6zhrXU/tmp/elasticsearch-3/libjansi.so"));
        assert!(!super::service_private_tmp("/tmp/systemd-private-evil/tmp/x.so"));
        assert!(!super::service_private_tmp("/tmp/elasticsearch-3/libjansi.so"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn tmp_copies_of_system_files_are_not_reported() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("tcopy-{}", std::process::id()));
        let tpl = root.join("tmp/systemd-private-x-apache2.service-y/tmp/coolwsd.z/systemplate/lib64");
        std::fs::create_dir_all(&tpl).unwrap();
        std::fs::create_dir_all(root.join("lib64")).unwrap();
        // Collabora-Vorlage: unveränderte Kopie → keine Meldung; gleicher Name, anderer Inhalt → Meldung
        for (f, body) in [(root.join("lib64/ld.so"), "ELF-orig"), (tpl.join("ld.so"), "ELF-orig"), (tpl.join("libc.so"), "ELF-fremd"), (root.join("lib64/libc.so"), "ELF-orig")] {
            std::fs::write(&f, body).unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let rep = crate::run(crate::CheckConfig { sysroot: root.to_string_lossy().into_owned(), offline: true, ..Default::default() });
        let hits: Vec<_> = rep.findings.iter().filter(|f| f.check == "tmp_executable").filter_map(|f| f.path.clone()).collect();
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].ends_with("/libc.so"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn chroot_build_root_is_checked_like_a_container() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("chroot-{}", std::process::id()));
        let c = root.join("srv/php-build/focal");
        std::fs::create_dir_all(c.join("usr/bin")).unwrap();
        std::fs::create_dir_all(c.join("etc")).unwrap();
        std::fs::create_dir_all(c.join("var/lib/dpkg/info")).unwrap();
        std::fs::write(c.join("etc/os-release"), "ID=ubuntu\n").unwrap();
        std::fs::write(c.join("var/lib/dpkg/status"), "").unwrap();
        std::fs::write(c.join("var/lib/dpkg/info/passwd.list"), "/usr/bin/chsh\n").unwrap();
        for (f, mode) in [("usr/bin/chsh", 0o4755), ("usr/bin/rootme", 0o4755)] {
            std::fs::write(c.join(f), "x").unwrap();
            std::fs::set_permissions(c.join(f), std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let rep = crate::run(crate::CheckConfig { sysroot: root.to_string_lossy().into_owned(), offline: true, ..Default::default() });
        let hits: Vec<_> = rep.findings.iter().filter(|f| f.check == "suid_unowned").filter_map(|f| f.path.clone()).collect();
        // chsh gehört dem Paket in der chroot – nur das fremde Programm wird gemeldet, und zwar im chroot-Durchgang
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].ends_with("/srv/php-build/focal/usr/bin/rootme"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn container_suid_uses_container_package_db() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("csuid-{}", std::process::id()));
        let m = root.join("var/lib/machines/app");
        std::fs::create_dir_all(m.join("usr/bin")).unwrap();
        std::fs::create_dir_all(m.join("var/lib/dpkg/info")).unwrap();
        std::fs::write(m.join("var/lib/dpkg/info/cron.list"), "/usr/bin/crontab\n").unwrap();
        for (f, mode) in [("usr/bin/crontab", 0o2755), ("usr/bin/rootme", 0o4755)] {
            std::fs::write(m.join(f), "x").unwrap();
            std::fs::set_permissions(m.join(f), std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let rep = crate::run(crate::CheckConfig { sysroot: root.to_string_lossy().into_owned(), offline: true, ..Default::default() });
        let hits: Vec<_> = rep.findings.iter().filter(|f| f.check == "suid_unowned").collect();
        assert_eq!(hits.len(), 1, "{:?}", hits.iter().map(|f| &f.path).collect::<Vec<_>>());
        assert!(hits[0].path.as_deref().unwrap().ends_with("/var/lib/machines/app/usr/bin/rootme"));
        assert_eq!(hits[0].severity, Severity::High);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn addr() {
        assert_eq!(parse_addr("0100007F:0050", false).unwrap(), ("127.0.0.1".into(), 80, false));
        assert_eq!(parse_addr("00000000:18EB", false).unwrap(), ("0.0.0.0".into(), 6379, true));
        let (a, p, public) = parse_addr("00000000000000000000000000000000:0016", true).unwrap();
        assert_eq!((a.as_str(), p, public), ("::", 22, true));
    }
}
