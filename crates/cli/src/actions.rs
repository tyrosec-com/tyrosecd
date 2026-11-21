//! Aktionen aus der Zentrale (Plan „Handeln“): Datei wiederherstellen, Quarantäne, IP sperren/entsperren.
//!
//! Sicherheit: Der Agent führt nur Arten aus, die **lokal** in `agent.toml` (`actions = [...]`) freigeschaltet sind –
//! per `tyrosecd actions enable`. Feste Liste, keine freien Befehle; strenge Pfad- und IP-Prüfung.
//!
//! Wiederherstellen/Quarantäne (Sicherheitsprüfung K1/K2):
//! - Pfad normalisiert (keine leeren, `.`- oder `..`-Teile), **aufgelöster** Pfad gegen eine Sperrliste geprüft
//!   (eigene Dateien, cron, ld.so, systemd, sudoers, Konten, .ssh, /usr, /root …),
//! - wiederhergestellt wird nur ein Inhalt, dessen SHA-256 der Agent selbst schon einmal für genau diesen Pfad
//!   gesehen hat (lokaler Zustand) – eine übernommene Zentrale kann keinen neuen Inhalt einschleusen,
//! - Dateizugriffe nur über Deskriptoren: Ordner ohne Symlinks geöffnet (O_NOFOLLOW je Pfadteil), Temp-Datei mit
//!   Zufallsnamen (O_CREAT|O_EXCL|O_NOFOLLOW), fchown/fchmod, renameat bzw. unlinkat relativ zum Ordner.
use std::ffi::CString;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use std::sync::Mutex;

use sha2::{Digest, Sha256};
use tyrosd_core::state::{ActionRun, State};
use tyrosd_proto as pb;

pub const KINDS: [&str; 4] = ["restore", "quarantine", "block_ip", "decoy"];
const MAX_RESTORE: usize = 32 << 20;
/// größte Datei, die in Quarantäne kopiert wird
const MAX_QUARANTINE: u64 = 16 << 20;

/// Ordner (samt Inhalt), in denen weder wiederhergestellt noch in Quarantäne verschoben wird.
/// Zusätzlich alle Orte, aus denen root Dateien ausführt oder Befehle als
/// Konfiguration liest (logrotate-Skripte, MOTD, sysctl, Bash-Vervollständigung, NetworkManager-/ifupdown-/DHCP-/PPP-Hooks,
/// Maintainer-Skripte der Paketverwaltung, anacron/incron, rsyslog-omprog, fail2ban-Aktionen, Kernel-/initramfs-Hooks,
/// Vertrauensspeicher für Zertifikate …).
const DENY_DIRS: &[&str] = &[
    "/opt/tyrosecd", "/etc/tyrosecd", "/var/lib/tyrosecd", "/var/lib/tyrosd", "/var/spool/cron", "/var/spool/at", "/var/spool/anacron",
    "/var/spool/incron", "/etc/systemd", "/lib/systemd", "/usr/lib/systemd", "/var/lib/systemd", "/etc/pam.d", "/etc/security", "/etc/ssh",
    "/etc/profile.d", "/etc/init.d", "/etc/init", "/etc/modprobe.d", "/etc/modules-load.d", "/etc/udev", "/etc/apt", "/etc/yum.repos.d",
    "/etc/yum", "/etc/dnf", "/etc/zypp", "/etc/pacman.d", "/etc/apk", "/etc/dpkg", "/var/lib/dpkg", "/var/lib/rpm", "/etc/logrotate.d",
    "/etc/update-motd.d", "/etc/sysctl.d", "/etc/bash_completion.d", "/etc/NetworkManager", "/etc/network", "/etc/networkd-dispatcher",
    "/etc/dhcp", "/etc/ppp", "/etc/sysconfig", "/etc/xdg", "/etc/X11", "/etc/kernel", "/etc/initramfs-tools", "/etc/dracut.conf.d",
    "/etc/grub.d", "/etc/default", "/etc/binfmt.d", "/etc/tmpfiles.d", "/etc/environment.d", "/etc/rsyslog.d", "/etc/syslog-ng", "/etc/audit",
    "/etc/fail2ban", "/etc/needrestart", "/etc/acpi", "/etc/pm", "/etc/polkit-1", "/etc/sudo.conf", "/etc/doas.conf", "/etc/doas.d",
    "/etc/selinux", "/etc/apparmor.d", "/etc/skel", "/etc/supervisor", "/etc/monit", "/etc/docker", "/etc/containerd", "/etc/containers",
    "/etc/ssl", "/etc/pki", "/etc/ca-certificates", "/etc/incron.d",
    "/root", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/boot", "/proc", "/sys", "/dev", "/run",
];
/// Namensanfänge (Dateien und Ordner): /etc/cron*, /etc/ld.so.*, /etc/sudoers*, Kontendateien samt Sicherungen, rc-Skripte …
const DENY_PREFIX: &[&str] = &[
    "/etc/cron", "/etc/anacrontab", "/etc/ld.so.", "/etc/sudoers", "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/subuid",
    "/etc/subgid", "/usr/local/bin/tyrosecd", "/etc/profile", "/etc/bash", "/etc/zsh", "/etc/csh", "/etc/environment", "/etc/rc", "/etc/inittab",
    "/etc/logrotate.conf", "/etc/sysctl.conf", "/etc/modules", "/etc/rsyslog.conf", "/etc/at.", "/etc/incron", "/etc/gitconfig",
    "/etc/login.defs", "/etc/securetty", "/etc/shells", "/etc/nsswitch.conf", "/etc/hosts", "/etc/resolv.conf", "/etc/fstab", "/etc/crypttab",
    "/etc/ca-certificates.conf",
];
/// zusätzlich für Quarantäne tabu (Systemdateien – Entfernen könnte den Server lahmlegen)
const NO_QUARANTINE: [&str; 10] = ["/etc/", "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/libexec/", "/lib/", "/lib64/", "/usr/share/"];

/// systemd-Drop-in für Wiederherstellen/Quarantäne. Die Grund-Unit härtet den Dienst (ProtectSystem=strict,
/// ProtectHome=read-only, ohne CAP_CHOWN/CAP_FOWNER) – damit schlägt Wiederherstellen im Webroot mit EROFS fehl.
/// Nur `tyrosecd actions enable|disable|refresh` (lokal, root, außerhalb des Dienstes)
/// schreibt diese Datei; der Dienst selbst kann /etc/systemd nicht ändern (ProtectSystem=strict, Sperrliste) –
/// eine übernommene Zentrale kann die Härtung also weder abschalten noch die Schreibfreigabe erweitern.
pub const DROPIN: &str = "/etc/systemd/system/tyrosecd.service.d/actions.conf";

/// Pfad, der in `ReadWritePaths=` stehen darf: absolut, normalisiert, ohne Leer-/Steuerzeichen, Anführungszeichen,
/// `\` und `%` (systemd-Platzhalter), nicht „/“ und nicht in der Sperrliste
pub fn dropin_path_ok(p: &str) -> bool {
    p != "/"
        && clean_path(p).is_ok()
        && !p.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '\'' | '\\' | '%' | ';'))
        && !denied(p, false)
        // auch kein Ordner, der gesperrte Bereiche enthält (/etc, /var, /var/lib …)
        && !DENY_DIRS.iter().chain(DENY_PREFIX).any(|d| d.starts_with(&format!("{p}/")))
}

/// Inhalt des Drop-ins für die freigeschalteten Aktionen – `None`, wenn keine Datei nötig ist (weder restore noch
/// quarantine). `paths`: Webroots (und weitere lokal angegebene Ordner), in denen wiederhergestellt werden darf.
pub fn dropin_content(kinds: &[String], paths: &[String]) -> Result<Option<String>, String> {
    let restore = kinds.iter().any(|k| k == "restore");
    let quarantine = kinds.iter().any(|k| k == "quarantine");
    // Köder: neue Dateien in Webroots anlegen – dieselbe Schreibfreigabe wie Wiederherstellen (nur Webroots)
    let decoy = kinds.iter().any(|k| k == "decoy");
    if !restore && !quarantine && !decoy {
        return Ok(None);
    }
    let mut rw: Vec<String> = Vec::new();
    for p in paths {
        let p = p.trim_end_matches('/');
        if !dropin_path_ok(p) {
            return Err(format!("Ordner {p} kann nicht freigegeben werden (Systembereich oder ungültiger Pfad)"));
        }
        rw.push(p.to_string());
    }
    if quarantine {
        // typische Malware-Ablagen (/dev/shm ist unter ProtectSystem ohnehin beschreibbar)
        rw.extend(["/tmp".to_string(), "/var/tmp".to_string()]);
    }
    rw.sort();
    rw.dedup();
    let mut s = String::from(
        "# Von „tyrosecd actions enable|disable|refresh“ geschrieben – nur lokal als root, nie von der Zentrale.\n\
         # Gibt dem Agenten Schreibrechte NUR für die folgenden Ordner (Wiederherstellen/Quarantäne) und die Fähigkeiten,\n\
         # Eigentümer/Rechte der wiederhergestellten Datei zu setzen. Die übrige Härtung der Unit bleibt.\n[Service]\n",
    );
    if !rw.is_empty() {
        // „-“: fehlende Ordner verhindern den Start nicht
        s.push_str("ReadWritePaths=");
        s.push_str(&rw.iter().map(|p| format!("-{p}")).collect::<Vec<_>>().join(" "));
        s.push('\n');
    }
    // mehrere CapabilityBoundingSet-Zeilen werden von systemd vereinigt (ODER)
    s.push_str("CapabilityBoundingSet=CAP_CHOWN CAP_FOWNER\n");
    Ok(Some(s))
}

/// Drop-in schreiben bzw. entfernen, danach `systemctl daemon-reload` (und auf Wunsch Dienst neu starten).
/// Läuft nur über die lokale Befehlszeile. `dropin` ist im Betrieb `DROPIN`.
pub fn write_dropin(dropin: &str, kinds: &[String], paths: &[String], restart: bool) -> Result<String, String> {
    let content = dropin_content(kinds, paths)?;
    let target = Path::new(dropin);
    let changed = match &content {
        Some(c) => {
            if std::fs::read_to_string(target).ok().as_deref() == Some(c.as_str()) {
                false
            } else {
                let dir = target.parent().ok_or("ungültiger Drop-in-Pfad")?;
                std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
                let tmp = dir.join(format!(".actions.conf.{}", random_hex()));
                let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o644).custom_flags(libc::O_NOFOLLOW).open(&tmp)
                    .map_err(|e| format!("{}: {e}", tmp.display()))?;
                f.write_all(c.as_bytes()).and_then(|_| f.sync_all()).map_err(|e| e.to_string())?;
                std::fs::rename(&tmp, target).map_err(|e| { let _ = std::fs::remove_file(&tmp); format!("{dropin}: {e}") })?;
                true
            }
        }
        None => match std::fs::remove_file(target) {
            Ok(()) => {
                if let Some(d) = target.parent() {
                    let _ = std::fs::remove_dir(d); // nur, wenn leer
                }
                true
            }
            Err(_) => false,
        },
    };
    if changed && dropin == DROPIN && Path::new("/run/systemd/system").is_dir() {
        let _ = Command::new("systemctl").arg("daemon-reload").status();
        if restart {
            let _ = Command::new("systemctl").args(["try-restart", "tyrosecd"]).status();
        }
    }
    Ok(match (&content, changed) {
        (Some(_), true) => format!("Schreibfreigabe für Aktionen eingerichtet: {dropin}"),
        (Some(_), false) => format!("Schreibfreigabe für Aktionen unverändert: {dropin}"),
        (None, true) => format!("Schreibfreigabe für Aktionen entfernt: {dropin}"),
        (None, false) => "keine Schreibfreigabe nötig".to_string(),
    })
}

/// Freigeschaltete Aktionen frisch aus der Konfiguration (Änderungen per CLI greifen ohne Neustart)
pub fn enabled(config: &str) -> Vec<String> {
    tyrosd_transport::config::AgentConfig::load(config)
        .map(|c| c.actions.into_iter().filter(|a| KINDS.contains(&a.as_str())).collect())
        .unwrap_or_default()
}

/// Pfad syntaktisch prüfen → (Ordner, Dateiname)
fn clean_path(p: &str) -> Result<(String, String), String> {
    if !p.starts_with('/') || p.contains('\0') || p.len() > 4000 {
        return Err("ungültiger Pfad".into());
    }
    let parts: Vec<&str> = p[1..].split('/').collect();
    if parts.iter().any(|c| c.is_empty() || *c == "." || *c == "..") {
        return Err("ungültiger Pfad".into());
    }
    let name = parts.last().unwrap().to_string();
    let dir = format!("/{}", parts[..parts.len() - 1].join("/"));
    Ok((dir, name))
}

/// Container-Dateisysteme unter einem Host-Pfad, die `container::container_path` (nur Schreibschichten und
/// Container-Wurzeln) nicht kennt: (Präfix, Suffix nach dem Namen) – zusammengesetzte Sichten und containerd-Snapshots
const CONTAINER_VIEWS: &[(&str, &str)] = &[
    ("/var/lib/docker/overlay2/", "/merged"),
    ("/var/lib/containers/storage/overlay/", "/merged"),
    ("/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/", "/fs"),
];

/// `/proc/<pid>/root/x`, `/proc/<pid>/task/<tid>/root/x` → `/x`
fn proc_root_inner(p: &str) -> Option<String> {
    let rest = p.strip_prefix("/proc/")?;
    let (pid, mut after) = rest.split_once('/')?;
    if !(pid.bytes().all(|c| c.is_ascii_digit()) || pid == "self" || pid == "thread-self") {
        return None;
    }
    if let Some(t) = after.strip_prefix("task/") {
        after = t.split_once('/')?.1;
    }
    let inner = after.strip_prefix("root")?;
    match inner {
        "" => Some("/".into()),
        i if i.starts_with('/') => Some(i.to_string()),
        _ => None,
    }
}

/// Pfad im Container, falls `p` in einem Container-Dateisystem liegt (`/proc/<pid>/root/…`, nspawn/LXC/Incus-Wurzeln,
/// Docker-/Podman-Schreibschichten und -Sichten, containerd-Snapshots)
fn container_inner(p: &str) -> Option<String> {
    if let Some(i) = proc_root_inner(p) {
        return Some(i);
    }
    if let Some(c) = tyrosd_core::container::container_path(p) {
        return Some(c.rel.to_string());
    }
    for (prefix, suffix) in CONTAINER_VIEWS {
        let Some(rest) = p.strip_prefix(prefix) else { continue };
        let (_, after) = rest.split_once('/')?;
        let tail = format!("/{after}");
        return match tail.strip_prefix(suffix)? {
            "" => Some("/".into()),
            i if i.starts_with('/') => Some(i.to_string()),
            _ => None,
        };
    }
    None
}

fn denied_plain(p: &str, quarantine: bool) -> bool {
    if quarantine && p.starts_with("/dev/shm/") {
        return false; // typische Malware-Ablage – Quarantäne erlaubt
    }
    DENY_DIRS.iter().any(|d| p == *d || p.starts_with(&format!("{d}/")))
        || DENY_PREFIX.iter().any(|d| p.starts_with(d))
        || p.split('/').any(|c| c == ".ssh")
}

/// `check` auf den Pfad und – bei Container-Pfaden – auf den **effektiven** Pfad im Container (bis zu 4 Ebenen
/// verschachtelt; tiefer → abgelehnt)
fn any_view(p: &str, check: impl Fn(&str) -> bool) -> bool {
    let mut cur = p.to_string();
    for _ in 0..5 {
        if check(&cur) {
            return true;
        }
        match container_inner(&cur) {
            Some(inner) if inner != cur => cur = inner,
            _ => return false,
        }
    }
    true
}

/// Pfad in gesperrtem Bereich? (`p` ist normalisiert). Auch der effektive Pfad im Container
/// zählt – `/var/lib/machines/web/etc/cron.d/x` ist für den Container dasselbe wie `/etc/cron.d/x` auf dem Host.
fn denied(p: &str, quarantine: bool) -> bool {
    any_view(p, |x| denied_plain(x, quarantine))
}

/// Systemordner, aus denen nichts in Quarantäne verschoben wird – ebenfalls auf dem effektiven Pfad
fn no_quarantine(p: &str) -> bool {
    any_view(p, |x| NO_QUARANTINE.iter().any(|d| x.starts_with(d)))
}

fn cstr(s: &str) -> Result<CString, String> {
    CString::new(s).map_err(|_| "ungültiger Pfad".to_string())
}

fn os_err(what: &str) -> String {
    format!("{what}: {}", std::io::Error::last_os_error())
}

/// Ordner Teil für Teil öffnen, ohne einem Symlink zu folgen (O_NOFOLLOW je Pfadteil)
fn open_dir_nofollow(dir: &str) -> Result<OwnedFd, String> {
    // SAFETY: gültiger C-String, Rückgabe geprüft
    let root = unsafe { libc::open(c"/".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if root < 0 {
        return Err(os_err("Ordner öffnen"));
    }
    let mut fd = unsafe { OwnedFd::from_raw_fd(root) };
    for part in dir.split('/').filter(|c| !c.is_empty()) {
        let c = cstr(part)?;
        // SAFETY: fd und c gültig
        let n = unsafe { libc::openat(fd.as_raw_fd(), c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if n < 0 {
            return Err(format!("Ordner {dir} nicht sicher zu öffnen (symbolischer Link oder fehlt): {}", std::io::Error::last_os_error()));
        }
        fd = unsafe { OwnedFd::from_raw_fd(n) };
    }
    Ok(fd)
}

/// Normalisieren, Elternordner auflösen, Sperrliste auf den **aufgelösten** Pfad → (Ordner-fd, Name, aufgelöster Pfad)
/// für Köder: wie Wiederherstellen (Sperrliste, Elternordner ohne Symlinks)
pub(crate) fn resolve_pub(p: &str) -> Result<(OwnedFd, String, String), String> {
    resolve(p, false)
}

fn resolve(p: &str, quarantine: bool) -> Result<(OwnedFd, String, String), String> {
    let (dir, name) = clean_path(p)?;
    if denied(p, quarantine) {
        return Err("Pfad in geschütztem Systembereich".into());
    }
    let real_dir = std::fs::canonicalize(&dir).map_err(|_| format!("Ordner {dir} existiert nicht"))?;
    let real_dir = real_dir.to_string_lossy().into_owned();
    let resolved = if real_dir == "/" { format!("/{name}") } else { format!("{real_dir}/{name}") };
    if denied(&resolved, quarantine) {
        return Err(format!("Pfad in geschütztem Systembereich (aufgelöst: {resolved})"));
    }
    let fd = open_dir_nofollow(&real_dir)?;
    Ok((fd, name, resolved))
}

fn fstatat(dir: &OwnedFd, name: &str) -> Result<Option<libc::stat>, String> {
    let c = cstr(name)?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: Zeiger gültig
    let r = unsafe { libc::fstatat(dir.as_raw_fd(), c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    if r == 0 {
        Ok(Some(st))
    } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        Ok(None)
    } else {
        Err(os_err("Ziel prüfen"))
    }
}

fn fstat(fd: &impl AsRawFd) -> Result<libc::stat, String> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: Zeiger gültig
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(os_err("fstat"));
    }
    Ok(st)
}

fn random_hex() -> String {
    let mut b = [0u8; 12];
    let ok = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).is_ok();
    if !ok {
        // Notbehelf; vor Übernahme schützt O_EXCL|O_NOFOLLOW, nicht die Zufälligkeit des Namens
        b[..8].copy_from_slice(&((tyrosd_core::now_ns() as u64) ^ ((std::process::id() as u64) << 32)).to_le_bytes());
    }
    hex(&b)
}

fn is_type(st: &libc::stat, t: libc::mode_t) -> bool {
    st.st_mode & libc::S_IFMT == t
}

/// Aktion ausführen → (ok, Meldung)
/// Freischaltung, die eine Aktionsart braucht
fn needed(kind: &str) -> &str {
    match kind {
        "unblock_ip" => "block_ip",
        "decoy_place" | "decoy_remove" => "decoy",
        k => k,
    }
}

pub fn execute(a: &pb::Action, allowed: &[String], data_dir: &str, central_host: &str, state: &State) -> (bool, String) {
    let need = needed(&a.kind);
    if !allowed.iter().any(|x| x == need) {
        return (false, format!("Aktion „{need}“ ist auf diesem Server nicht freigeschaltet (sudo tyrosecd actions enable)"));
    }
    let r = match a.kind.as_str() {
        "restore" => restore(a, state),
        "quarantine" => quarantine(&a.path, data_dir),
        "block_ip" => block_ip(&a.ip, a.duration_s, data_dir, central_host),
        "unblock_ip" => unblock_ip(&a.ip, data_dir),
        "decoy_place" => crate::decoy::place(a, data_dir, &crate::decoy::webroots()),
        "decoy_remove" => crate::decoy::remove(a, data_dir),
        k => Err(format!("unbekannte Aktion {k}")),
    };
    match r {
        Ok(m) => (true, m),
        Err(e) => (false, e),
    }
}

/// Aktion höchstens einmal ausführen (Sicherheitsprüfung: Wiederholung derselben ID durch die Zentrale, verlorene
/// Antwort, Neustart). Die ID wird **vor** der Ausführung dauerhaft als laufend vermerkt.
/// → `None`: läuft gerade bereits (nichts melden, das Ergebnis folgt), sonst (ok, Meldung) zum Melden.
pub fn execute_once(a: &pb::Action, allowed: &[String], data_dir: &str, central_host: &str, state: &State) -> Option<(bool, String)> {
    let need = needed(&a.kind);
    if !allowed.iter().any(|x| x == need) {
        // nicht vermerken: nach lokaler Freischaltung darf die Zentrale dieselbe Aktion erneut schicken
        return Some(execute(a, allowed, data_dir, central_host, state));
    }
    {
        // Sperre über Prüfen + Vermerken, damit „läuft gerade“ und „unterbrochen“ sicher unterscheidbar sind
        let mut running = RUNNING.lock().unwrap_or_else(|e| e.into_inner());
        match state.action_begin(a.id, tyrosd_core::now_ns()) {
            Ok(None) => {
                running.insert(a.id);
            }
            Ok(Some(ActionRun::Running { .. })) if running.contains(&a.id) => return None,
            Ok(Some(ActionRun::Running { .. })) => {
                return Some((false, "bereits ausgeführt (durch Neustart unterbrochen, Ergebnis unbekannt) – nicht wiederholt".into()))
            }
            Ok(Some(ActionRun::Done { ok, message, .. })) => return Some((ok, format!("bereits ausgeführt: {message}"))),
            // ohne verlässlichen Vermerk lieber nicht ausführen
            Err(e) => return Some((false, format!("Aktion nicht ausgeführt: Zustand nicht schreibbar ({e:#})"))),
        }
    }
    let (ok, message) = execute(a, allowed, data_dir, central_host, state);
    let _ = state.action_finish(a.id, tyrosd_core::now_ns(), ok, &message);
    RUNNING.lock().unwrap_or_else(|e| e.into_inner()).remove(&a.id);
    Some((ok, message))
}

/// in diesem Prozess gerade laufende Aktions-IDs
static RUNNING: Mutex<std::collections::BTreeSet<u64>> = Mutex::new(std::collections::BTreeSet::new());

fn restore(a: &pb::Action, state: &State) -> Result<String, String> {
    let (dir, name, resolved) = resolve(&a.path, false)?;
    if resolved != a.path {
        return Err(format!("Pfad enthält symbolische Links (aufgelöst: {resolved}) – nicht wiederhergestellt"));
    }
    let content = zstd::bulk::decompress(&a.content_zstd, MAX_RESTORE).map_err(|_| "Inhalt nicht lesbar".to_string())?;
    let sha: [u8; 32] = Sha256::digest(&content).into();
    if sha.as_slice() != a.content_hash.as_slice() {
        return Err("Prüfsumme des Inhalts stimmt nicht".into());
    }
    if !state.seen_hash(&a.path, &sha) {
        return Err("Inhalt entspricht keiner Fassung, die der Agent selbst für diese Datei gesehen hat – Wiederherstellung abgelehnt".into());
    }
    let (mode, uid, gid) = match fstatat(&dir, &name)? {
        Some(st) if is_type(&st, libc::S_IFLNK) => return Err("Ziel ist ein symbolischer Link".into()),
        Some(st) if !is_type(&st, libc::S_IFREG) => return Err("Ziel ist keine normale Datei".into()),
        // Rechte bleiben, aber nie SUID/SGID/Sticky
        Some(st) => (st.st_mode & 0o777, st.st_uid, st.st_gid),
        None => {
            // gelöschte Datei: neu anlegen, ohne SUID/SGID, Eigentümer wie der Ordner (z. B. www-data). Rechte nie von
            // der Zentrale übernommen: lokal zuletzt gesehene Rechte, sonst 0644 – die
            // Zentrale kann sie nur einschränken.
            let ds = fstat(&dir)?;
            let local = state.get(&a.path).map(|e| e.meta.mode);
            (restore_mode(local, a.mode) as libc::mode_t, ds.st_uid, ds.st_gid)
        }
    };
    let tmp = format!(".tyrosec-restore-{}", random_hex());
    let ctmp = cstr(&tmp)?;
    // SAFETY: dir und ctmp gültig
    let raw = unsafe { libc::openat(dir.as_raw_fd(), ctmp.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600 as libc::c_uint) };
    if raw < 0 {
        return Err(os_err("Schreiben fehlgeschlagen"));
    }
    let mut f = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(raw) });
    let fin = (|| -> Result<(), String> {
        f.write_all(&content).map_err(|e| format!("Schreiben fehlgeschlagen: {e}"))?;
        // SAFETY: fd gültig
        if unsafe { libc::fchown(f.as_raw_fd(), uid, gid) } != 0 {
            return Err(os_err("Ersetzen fehlgeschlagen (Eigentümer)"));
        }
        if unsafe { libc::fchmod(f.as_raw_fd(), mode) } != 0 {
            return Err(os_err("Ersetzen fehlgeschlagen (Rechte)"));
        }
        f.sync_all().map_err(|e| format!("Ersetzen fehlgeschlagen: {e}"))?;
        let cname = cstr(&name)?;
        if unsafe { libc::renameat(dir.as_raw_fd(), ctmp.as_ptr(), dir.as_raw_fd(), cname.as_ptr()) } != 0 {
            return Err(os_err("Ersetzen fehlgeschlagen"));
        }
        Ok(())
    })();
    if let Err(e) = fin {
        // SAFETY: dir und ctmp gültig
        unsafe { libc::unlinkat(dir.as_raw_fd(), ctmp.as_ptr(), 0) };
        return Err(e);
    }
    Ok(format!("{} wiederhergestellt ({} Bytes)", a.path, content.len()))
}

/// Rechte für eine neu angelegte (gelöschte) Datei: lokal zuletzt gesehene Rechte (sonst 0644), nie SUID/SGID/Sticky,
/// nie für alle schreibbar. Die Zentrale (`server`, 0 = keine Angabe) kann Bits nur **wegnehmen**, nie hinzufügen.
fn restore_mode(local: Option<u32>, server: u32) -> u32 {
    let base = local.map(|m| m & 0o777).unwrap_or(0o644) & !0o002;
    if server > 0 { base & server } else { base }
}

fn quarantine(p: &str, data_dir: &str) -> Result<String, String> {
    let (dir, name, resolved) = resolve(p, true)?;
    if no_quarantine(&resolved) {
        return Err("Systemdateien werden nicht in Quarantäne verschoben – bitte von Hand prüfen".into());
    }
    let cname = cstr(&name)?;
    // SAFETY: dir und cname gültig
    let raw = unsafe { libc::openat(dir.as_raw_fd(), cname.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if raw < 0 {
        return Err(match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ENOENT) => "Datei existiert nicht (mehr)".to_string(),
            Some(libc::ELOOP) => "symbolischer Link – wird nicht verschoben".to_string(),
            _ => os_err("Lesen fehlgeschlagen"),
        });
    }
    let f = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(raw) });
    let st = fstat(&f)?;
    if !is_type(&st, libc::S_IFREG) {
        return Err("keine normale Datei".into());
    }
    if st.st_size as u64 > MAX_QUARANTINE {
        return Err(format!("Datei zu groß für die Quarantäne ({} MB, Grenze {} MB) – bitte von Hand prüfen", st.st_size >> 20, MAX_QUARANTINE >> 20));
    }
    let mut data = Vec::new();
    (&f).take(MAX_QUARANTINE + 1).read_to_end(&mut data).map_err(|e| format!("Lesen fehlgeschlagen: {e}"))?;
    if data.len() as u64 > MAX_QUARANTINE {
        return Err("Datei zu groß für die Quarantäne".into());
    }
    let hash = hex(&Sha256::digest(&data));
    let qdir = Path::new(data_dir).join("quarantine");
    std::fs::create_dir_all(&qdir).map_err(|e| e.to_string())?;
    let _ = std::fs::set_permissions(&qdir, std::fs::Permissions::from_mode(0o700));
    let safe: String = resolved.trim_start_matches('/').chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' }).take(120).collect();
    let target = qdir.join(format!("{}-{}-{safe}", tyrosd_core::now_ns() / 1_000_000_000, &random_hex()[..8]));
    let write_new = |path: &Path, bytes: &[u8]| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(path)?;
        f.write_all(bytes)?;
        f.sync_all()
    };
    write_new(&target, &data).map_err(|e| format!("Kopieren fehlgeschlagen: {e}"))?;
    let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o000));
    let meta = serde_json::json!({ "path": resolved, "mode": st.st_mode & 0o7777, "uid": st.st_uid, "gid": st.st_gid, "size": st.st_size, "sha256": hash, "ts": tyrosd_core::now_ns() / 1_000_000_000 });
    let _ = write_new(&target.with_extension("json"), meta.to_string().as_bytes());
    // nur entfernen, wenn unter dem Namen noch dieselbe Datei liegt (nicht zwischendurch ausgetauscht)
    match fstatat(&dir, &name)? {
        Some(now) if now.st_ino == st.st_ino && now.st_dev == st.st_dev => {}
        _ => return Err(format!("Datei wurde währenddessen ausgetauscht – nicht entfernt (Kopie liegt in {})", target.display())),
    }
    // SAFETY: dir und cname gültig
    if unsafe { libc::unlinkat(dir.as_raw_fd(), cname.as_ptr(), 0) } != 0 {
        return Err(format!("Entfernen fehlgeschlagen (Kopie liegt in {}): {}", target.display(), std::io::Error::last_os_error()));
    }
    Ok(format!("in Quarantäne: {} (SHA-256 {}…)", target.display(), &hash[..16]))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// IPv4-gemappte IPv6-Adresse (::ffff:a.b.c.d) → IPv4 (sonst umginge sie die Prüfung privater Netze und
/// landete wirkungslos im IPv6-Set)
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// Nie sperren: private/lokale Netze und die Zentrale selbst (sonst schneidet sich der Agent ab)
fn blockable(ip: &IpAddr, central_host: &str) -> Result<(), String> {
    let ip = &canonical(*ip);
    let private = match ip {
        IpAddr::V4(v) => v.is_private() || v.is_loopback() || v.is_link_local() || v.is_unspecified() || v.is_broadcast() || v.is_multicast()
            || v.octets()[0] == 100 && (64..128).contains(&v.octets()[1]),
        IpAddr::V6(v) => v.is_loopback() || v.is_unspecified() || v.is_multicast() || (v.segments()[0] & 0xfe00) == 0xfc00 || (v.segments()[0] & 0xffc0) == 0xfe80,
    };
    if private {
        return Err("private oder lokale Adressen werden nicht gesperrt".into());
    }
    use std::net::ToSocketAddrs;
    if let Ok(addrs) = (central_host, 443).to_socket_addrs() {
        if addrs.into_iter().any(|a| canonical(a.ip()) == *ip) {
            return Err("die Adresse der Zentrale wird nicht gesperrt".into());
        }
    }
    Ok(())
}

fn have(cmd: &str) -> bool {
    ["/usr/sbin/", "/sbin/", "/usr/bin/", "/bin/"].iter().any(|d| Path::new(&format!("{d}{cmd}")).exists())
}

fn run(cmd: &str, args: &[&str]) -> Result<(), String> {
    let o = Command::new(cmd).args(args).output().map_err(|e| format!("{cmd}: {e}"))?;
    if o.status.success() {
        Ok(())
    } else {
        Err(format!("{cmd}: {}", String::from_utf8_lossy(&o.stderr).trim()))
    }
}

/// nftables-Tabelle mit Sets (Ablaufzeit eingebaut); legt Tabelle/Kette/Regeln einmalig an
fn nft_ready() -> Result<(), String> {
    run("nft", &["add", "table", "inet", "tyrosec"])?;
    run("nft", &["add", "set", "inet", "tyrosec", "block4", "{ type ipv4_addr; flags timeout; }"])?;
    run("nft", &["add", "set", "inet", "tyrosec", "block6", "{ type ipv6_addr; flags timeout; }"])?;
    run("nft", &["add", "chain", "inet", "tyrosec", "input", "{ type filter hook input priority -5; policy accept; }"])?;
    let o = Command::new("nft").args(["list", "chain", "inet", "tyrosec", "input"]).output().map_err(|e| e.to_string())?;
    if !String::from_utf8_lossy(&o.stdout).contains("@block4") {
        run("nft", &["add", "rule", "inet", "tyrosec", "input", "ip", "saddr", "@block4", "drop"])?;
        run("nft", &["add", "rule", "inet", "tyrosec", "input", "ip6", "saddr", "@block6", "drop"])?;
    }
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct Block {
    ip: String,
    until: i64, // 0 = dauerhaft
}

fn blocks_file(data_dir: &str) -> PathBuf {
    Path::new(data_dir).join("blocks.json")
}
fn load_blocks(data_dir: &str) -> Vec<Block> {
    std::fs::read(blocks_file(data_dir)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}
/// blocks.json wird von Aktionen (eigene Threads je Heartbeat) und der Wartung geändert – nur nacheinander
static BLOCKS_LOCK: Mutex<()> = Mutex::new(());

fn save_blocks(data_dir: &str, b: &[Block]) {
    // atomar ersetzen (Temp-Datei mit Zufallsnamen, O_EXCL|O_NOFOLLOW)
    let tmp = Path::new(data_dir).join(format!(".blocks-{}.tmp", random_hex()));
    let ok = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .and_then(|mut f| f.write_all(&serde_json::to_vec(b).unwrap_or_default()).and_then(|_| f.sync_all()))
        .and_then(|_| std::fs::rename(&tmp, blocks_file(data_dir)));
    if ok.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
}
fn now_s() -> i64 {
    tyrosd_core::now_ns() / 1_000_000_000
}

fn apply_block(ip: &IpAddr, secs: u32) -> Result<&'static str, String> {
    let s = ip.to_string();
    if have("nft") {
        nft_ready()?;
        let set = if ip.is_ipv4() { "block4" } else { "block6" };
        let el = if secs > 0 { format!("{{ {s} timeout {secs}s }}") } else { format!("{{ {s} }}") };
        let _ = run("nft", &["delete", "element", "inet", "tyrosec", set, &format!("{{ {s} }}")]);
        run("nft", &["add", "element", "inet", "tyrosec", set, &el])?;
        return Ok("nftables");
    }
    let tool = if ip.is_ipv4() { "iptables" } else { "ip6tables" };
    if !have(tool) {
        return Err("weder nftables noch iptables vorhanden".into());
    }
    if run(tool, &["-C", "INPUT", "-s", &s, "-j", "DROP", "-m", "comment", "--comment", "tyrosec"]).is_err() {
        run(tool, &["-I", "INPUT", "-s", &s, "-j", "DROP", "-m", "comment", "--comment", "tyrosec"])?;
    }
    Ok("iptables")
}

fn remove_block(ip: &IpAddr) {
    let s = ip.to_string();
    if have("nft") {
        let set = if ip.is_ipv4() { "block4" } else { "block6" };
        let _ = run("nft", &["delete", "element", "inet", "tyrosec", set, &format!("{{ {s} }}")]);
    }
    let tool = if ip.is_ipv4() { "iptables" } else { "ip6tables" };
    if have(tool) {
        while run(tool, &["-D", "INPUT", "-s", &s, "-j", "DROP", "-m", "comment", "--comment", "tyrosec"]).is_ok() {}
    }
}

fn block_ip(ip: &str, secs: u32, data_dir: &str, central_host: &str) -> Result<String, String> {
    let addr = canonical(ip.trim().parse().map_err(|_| "keine gültige IP-Adresse".to_string())?);
    blockable(&addr, central_host)?;
    let _g = BLOCKS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let how = apply_block(&addr, secs)?;
    let mut b: Vec<Block> = load_blocks(data_dir).into_iter().filter(|x| x.ip != addr.to_string()).collect();
    b.push(Block { ip: addr.to_string(), until: if secs > 0 { now_s() + secs as i64 } else { 0 } });
    save_blocks(data_dir, &b);
    Ok(format!("{addr} gesperrt ({how}{})", if secs > 0 { format!(", {} h", (secs + 1800) / 3600) } else { ", dauerhaft".into() }))
}

fn unblock_ip(ip: &str, data_dir: &str) -> Result<String, String> {
    let addr = canonical(ip.trim().parse().map_err(|_| "keine gültige IP-Adresse".to_string())?);
    let _g = BLOCKS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    remove_block(&addr);
    let b: Vec<Block> = load_blocks(data_dir).into_iter().filter(|x| x.ip != addr.to_string()).collect();
    save_blocks(data_dir, &b);
    Ok(format!("{addr} entsperrt"))
}

/// Beim Start Sperren wiederherstellen (nach Neustart leer) und abgelaufene entfernen (iptables kennt keine Ablaufzeit)
pub fn maintain_blocks(data_dir: &str, reapply: bool) {
    let _g = BLOCKS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let now = now_s();
    let mut keep = Vec::new();
    for b in load_blocks(data_dir) {
        let Ok(ip) = b.ip.parse::<IpAddr>() else { continue };
        if b.until > 0 && b.until <= now {
            remove_block(&ip);
            continue;
        }
        if reapply {
            let _ = apply_block(&ip, if b.until > 0 { (b.until - now) as u32 } else { 0 });
        }
        keep.push(b);
    }
    save_blocks(data_dir, &keep);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn state(dir: &Path) -> std::sync::Arc<State> {
        State::open(&dir.join("s.redb").to_string_lossy(), 4, 1 << 20).unwrap()
    }

    fn sha(b: &[u8]) -> [u8; 32] {
        Sha256::digest(b).into()
    }

    #[test]
    fn paths_and_ips_are_checked() {
        assert!(clean_path("/var/www/x/../etc/passwd").is_err());
        assert!(clean_path("relative").is_err());
        assert!(clean_path("//etc/passwd").is_err()); // leerer Pfadteil umgeht keine Sperrliste mehr
        assert!(clean_path("/var/www//x.php").is_err());
        assert!(clean_path("/var/www/./x.php").is_err());
        assert!(clean_path("/var/www/").is_err());
        assert_eq!(clean_path("/var/www/shop/index.php").unwrap(), ("/var/www/shop".to_string(), "index.php".to_string()));
        for p in [
            "/proc/1/mem", "/opt/tyrosecd/bin/tyrosecd", "/usr/local/bin/tyrosecd", "/etc/tyrosecd/agent.toml", "/var/lib/tyrosecd/agent.key",
            "/etc/cron.d/x", "/etc/crontab", "/var/spool/cron/crontabs/root", "/etc/ld.so.preload", "/etc/systemd/system/x.service",
            "/lib/systemd/system/x.service", "/usr/lib/systemd/system/x.service", "/etc/sudoers", "/etc/sudoers.d/x", "/etc/passwd", "/etc/shadow",
            "/etc/group", "/etc/gshadow", "/root/x", "/home/a/.ssh/authorized_keys", "/var/www/.ssh/authorized_keys", "/usr/bin/ls", "/bin/sh", "/sbin/x",
            "/lib/x.so", "/lib64/x.so", "/boot/vmlinuz", "/sys/x", "/dev/sda", "/run/x",
        ] {
            assert!(denied(p, false), "{p}");
            assert!(denied(p, true), "{p}");
        }
        assert!(!denied("/dev/shm/x", true));
        assert!(denied("/dev/shm/x", false));
        assert!(!denied("/var/www/shop/index.php", false));
        assert!(!denied("/home/a/public_html/index.php", false));
        // Root-Ausführungspfade
        for p in [
            "/etc/logrotate.d/nginx", "/etc/logrotate.conf", "/etc/update-motd.d/00-header", "/etc/sysctl.d/99-x.conf", "/etc/sysctl.conf",
            "/etc/bash_completion.d/x", "/usr/share/bash-completion/completions/x", "/etc/NetworkManager/dispatcher.d/x", "/var/lib/dpkg/info/x.postinst",
            "/etc/anacrontab", "/var/spool/anacron/cron.daily", "/etc/rc.local", "/etc/rc2.d/S01x", "/etc/network/if-up.d/x", "/etc/dhcp/dhclient-exit-hooks.d/x",
            "/etc/fail2ban/action.d/x.conf", "/etc/rsyslog.d/x.conf", "/etc/kernel/postinst.d/x", "/etc/apt/apt.conf.d/99x", "/etc/dpkg/dpkg.cfg.d/x",
            "/etc/gitconfig", "/etc/environment", "/etc/bash.bashrc", "/etc/ssl/certs/ca-certificates.crt", "/etc/default/grub", "/etc/modules",
        ] {
            assert!(denied(p, false), "{p}");
        }
        // effektiver Pfad im Container: dieselbe Sperrliste
        for p in [
            "/var/lib/machines/web/etc/cron.d/x", "/var/lib/machines/web/etc/systemd/system/x.service", "/var/lib/lxc/c1/rootfs/etc/sudoers",
            "/var/lib/docker/overlay2/3f2a9c1b7d4e/diff/etc/ld.so.preload", "/var/lib/docker/overlay2/3f2a9c1b7d4e/merged/root/.bashrc",
            "/var/lib/containers/storage/overlay/abc/merged/etc/profile.d/x.sh", "/var/lib/docker/overlay2/abc/merged/usr/bin/ls",
            "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/12/fs/etc/crontab", "/var/lib/machines/web/home/a/.ssh/authorized_keys",
            // Container im Container
            "/var/lib/machines/host2/var/lib/lxc/c/rootfs/etc/logrotate.d/x",
        ] {
            assert!(denied(p, false), "{p}");
            assert!(denied(p, true), "{p}");
        }
        assert_eq!(proc_root_inner("/proc/123/root/etc/cron.d/x").as_deref(), Some("/etc/cron.d/x"));
        assert_eq!(proc_root_inner("/proc/123/task/124/root/etc").as_deref(), Some("/etc"));
        assert_eq!(proc_root_inner("/proc/123/rootx"), None);
        assert_eq!(container_inner("/var/lib/docker/overlay2/abc/merged/var/www/x.php").as_deref(), Some("/var/www/x.php"));
        assert_eq!(container_inner("/var/lib/docker/overlay2/abc/mergedx/var/www/x.php"), None);
        // Webroots im Container bleiben erlaubt
        assert!(!denied("/var/lib/machines/web/var/www/shop/index.php", false));
        assert!(!denied("/var/lib/docker/overlay2/abc/merged/var/www/html/index.php", false));
        assert!(!no_quarantine("/var/lib/machines/web/var/www/shop/x.php"));
        assert!(no_quarantine("/var/lib/machines/web/etc/hostname"));
        assert!(no_quarantine("/var/lib/lxc/c1/rootfs/usr/bin/x"));
        for ip in ["10.0.0.1", "192.168.1.5", "127.0.0.1", "100.64.0.1", "::1", "fd00::1", "fe80::1"] {
            assert!(blockable(&ip.parse().unwrap(), "localhost").is_err(), "{ip}");
        }
        assert!(blockable(&"91.92.93.20".parse().unwrap(), "localhost").is_ok());
        // IPv4-gemappte IPv6-Adressen zählen wie die IPv4-Adresse
        for ip in ["::ffff:10.0.0.1", "::ffff:192.168.1.5", "::ffff:127.0.0.1", "::ffff:100.64.0.1", "::ffff:169.254.1.1", "::ffff:0.0.0.0"] {
            assert!(blockable(&ip.parse().unwrap(), "localhost").is_err(), "{ip}");
        }
        assert!(blockable(&"::ffff:91.92.93.20".parse().unwrap(), "localhost").is_ok());
        assert_eq!(canonical("::ffff:91.92.93.20".parse().unwrap()), "91.92.93.20".parse::<IpAddr>().unwrap());
        assert_eq!(canonical("2001:db8::1".parse().unwrap()), "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn dropin_only_for_local_actions() {
        let k = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(dropin_content(&k(&[]), &k(&["/var/www"])).unwrap(), None);
        assert_eq!(dropin_content(&k(&["block_ip"]), &k(&["/var/www"])).unwrap(), None);
        let c = dropin_content(&k(&["restore"]), &k(&["/var/www/", "/home/a/public_html"])).unwrap().unwrap();
        assert!(c.contains("\nReadWritePaths=-/home/a/public_html -/var/www\n"), "{c}");
        assert!(c.contains("\nCapabilityBoundingSet=CAP_CHOWN CAP_FOWNER\n"), "{c}");
        assert!(!c.contains("/tmp"));
        let q = dropin_content(&k(&["quarantine"]), &[]).unwrap().unwrap();
        assert!(q.contains("ReadWritePaths=-/tmp -/var/tmp\n"), "{q}");
        // Systembereiche, „/“ und Pfade mit systemd-Sonderzeichen werden nie freigegeben
        for bad in ["/", "/etc", "/var", "/var/lib", "/etc/cron.d", "/usr/share/nginx/html", "/var/www/a b", "/var/www/%h", "/var/www/x\nExecStartPre=/bin/sh", "relative", "/var/www/../etc"] {
            assert!(dropin_content(&k(&["restore"]), &k(&[bad])).is_err(), "{bad:?}");
        }
        // schreiben und wieder entfernen (Testpfad, kein systemctl)
        let d = std::env::temp_dir().join(format!("act-dropin-{}", std::process::id()));
        let f = d.join("tyrosecd.service.d/actions.conf");
        let fs = f.to_string_lossy().into_owned();
        assert!(write_dropin(&fs, &k(&["restore"]), &k(&["/var/www"]), false).unwrap().contains("eingerichtet"));
        assert_eq!(std::fs::metadata(&f).unwrap().mode() & 0o777, 0o644);
        assert!(write_dropin(&fs, &k(&["restore"]), &k(&["/var/www"]), false).unwrap().contains("unverändert"));
        assert!(write_dropin(&fs, &k(&["block_ip"]), &k(&["/var/www"]), false).unwrap().contains("entfernt"));
        assert!(!f.exists());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn mode_never_from_server() {
        assert_eq!(restore_mode(None, 0), 0o644);
        assert_eq!(restore_mode(None, 0o4777), 0o644); // Zentrale kann nichts hinzufügen
        assert_eq!(restore_mode(None, 0o600), 0o600); // … nur einschränken
        assert_eq!(restore_mode(Some(0o100755), 0), 0o755);
        assert_eq!(restore_mode(Some(0o100777), 0o777), 0o775); // nie für alle schreibbar
        assert_eq!(restore_mode(Some(0o104755), 0), 0o755); // nie SUID
    }

    #[test]
    fn same_action_runs_only_once() {
        let dir = std::env::temp_dir().join(format!("act-once-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let st = state(&dir);
        let allowed: Vec<String> = KINDS.iter().map(|s| s.to_string()).collect();
        let f = dir.join("evil.php");
        std::fs::write(&f, "<?php system($_GET['c']);").unwrap();
        let q = dir.join("q");
        let a = pb::Action { id: 4711, kind: "quarantine".into(), path: f.to_string_lossy().into(), ..Default::default() };
        let (ok, msg) = execute_once(&a, &allowed, q.to_str().unwrap(), "localhost", &st).unwrap();
        assert!(ok, "{msg}");
        // Datei wieder da (z. B. vom Angreifer neu angelegt) – dieselbe ID darf nichts mehr tun
        std::fs::write(&f, "neu").unwrap();
        let (ok2, msg2) = execute_once(&a, &allowed, q.to_str().unwrap(), "localhost", &st).unwrap();
        assert!(ok2 && msg2.starts_with("bereits ausgeführt") && msg2.contains(&msg), "{msg2}");
        assert!(f.exists());
        assert_eq!(std::fs::read_dir(q.join("quarantine")).unwrap().count(), 2);
        // durch Neustart unterbrochen (vermerkt, aber in diesem Prozess nicht laufend) → nicht wiederholt
        st.action_begin(4712, tyrosd_core::now_ns()).unwrap();
        let (ok, msg) = execute_once(&pb::Action { id: 4712, ..a.clone() }, &allowed, q.to_str().unwrap(), "localhost", &st).unwrap();
        assert!(!ok && msg.contains("unterbrochen"), "{msg}");
        assert!(f.exists());
        // läuft gerade (anderer Thread) → nichts melden
        RUNNING.lock().unwrap().insert(4713);
        st.action_begin(4713, tyrosd_core::now_ns()).unwrap();
        assert!(execute_once(&pb::Action { id: 4713, ..a.clone() }, &allowed, q.to_str().unwrap(), "localhost", &st).is_none());
        RUNNING.lock().unwrap().remove(&4713);
        // nicht freigeschaltet → nicht vermerkt, nach Freischaltung möglich
        let (ok, _) = execute_once(&pb::Action { id: 4714, ..a.clone() }, &[], q.to_str().unwrap(), "localhost", &st).unwrap();
        assert!(!ok);
        let (ok, msg) = execute_once(&pb::Action { id: 4714, ..a }, &allowed, q.to_str().unwrap(), "localhost", &st).unwrap();
        assert!(ok && !msg.starts_with("bereits"), "{msg}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn not_enabled_is_refused() {
        let d = std::env::temp_dir().join(format!("act-ne-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let st = state(&d);
        let a = pb::Action { id: 1, kind: "quarantine".into(), path: "/tmp/x".into(), ..Default::default() };
        let (ok, msg) = execute(&a, &[], "/tmp", "localhost", &st);
        assert!(!ok && msg.contains("nicht freigeschaltet"));
        let (ok, msg) = execute(&pb::Action { kind: "unblock_ip".into(), ..a.clone() }, &["restore".into()], "/tmp", "localhost", &st);
        assert!(!ok && msg.contains("block_ip"));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn restore_and_quarantine_roundtrip() {
        let dir = std::env::temp_dir().join(format!("act-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let st = state(&dir);
        let f = dir.join("index.php");
        std::fs::write(&f, "<?php eval($_POST['x']);").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o640)).unwrap();
        let good = b"<?php echo 'ok';\n";
        let path: String = f.to_string_lossy().into();
        let allowed: Vec<String> = KINDS.iter().map(|s| s.to_string()).collect();
        let a = pb::Action {
            id: 1, kind: "restore".into(), path: path.clone(),
            content_zstd: zstd::encode_all(&good[..], 1).unwrap(), content_hash: sha(good).to_vec(), ..Default::default()
        };
        // Fassung, die der Agent nie gesehen hat (z. B. von einer übernommenen Zentrale) → abgelehnt
        let (ok, msg) = execute(&a, &allowed, "/tmp", "localhost", &st);
        assert!(!ok && msg.contains("keiner Fassung"), "{msg}");
        // … für einen anderen Pfad gesehen zählt nicht
        st.remember(&format!("{}/other.php", dir.display()), &sha(good));
        assert!(!execute(&a, &allowed, "/tmp", "localhost", &st).0);
        st.remember(&path, &sha(good));
        let (ok, msg) = execute(&a, &allowed, "/tmp", "localhost", &st);
        assert!(ok, "{msg}");
        assert_eq!(std::fs::read(&f).unwrap(), good);
        assert_eq!(std::fs::metadata(&f).unwrap().mode() & 0o777, 0o640); // Rechte bleiben
        assert!(std::fs::read_dir(&dir).unwrap().flatten().all(|e| !e.file_name().to_string_lossy().starts_with(".tyrosec-restore-")));
        // falsche Prüfsumme → nichts geändert
        let bad = pb::Action { content_hash: vec![0; 32], ..a.clone() };
        assert!(!execute(&bad, &allowed, "/tmp", "localhost", &st).0);
        // Quarantäne: weg vom Ort, Kopie mit Rechten 000 + Metadaten
        let q = dir.join("q");
        let (ok, msg) = execute(&pb::Action { kind: "quarantine".into(), ..a.clone() }, &allowed, q.to_str().unwrap(), "localhost", &st);
        assert!(ok, "{msg}");
        assert!(!f.exists());
        let files: Vec<_> = std::fs::read_dir(q.join("quarantine")).unwrap().flatten().collect();
        assert_eq!(files.len(), 2);
        assert!(!execute(&pb::Action { kind: "quarantine".into(), path: "/etc/passwd".into(), ..a.clone() }, &allowed, "/tmp", "localhost", &st).0);
        // gelöschte Datei wiederherstellen: Rechte von der Zentrale (SUID, für alle schreibbar) werden nicht übernommen
        let (ok, msg) = execute(&pb::Action { id: 7, mode: 0o4777, ..a }, &allowed, "/tmp", "localhost", &st);
        assert!(ok, "{msg}");
        assert_eq!(std::fs::metadata(&f).unwrap().mode() & 0o7777, 0o644);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn symlinks_are_refused() {
        let dir = std::env::temp_dir().join(format!("act-ln-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let st = state(&dir);
        let allowed: Vec<String> = KINDS.iter().map(|s| s.to_string()).collect();
        let victim = dir.join("victim.txt");
        std::fs::write(&victim, "unverändert").unwrap();
        let good = b"neu";
        // Ziel ist ein Symlink → kein Schreiben durch den Link
        let link = dir.join("link.php");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        let lp: String = link.to_string_lossy().into();
        st.remember(&lp, &sha(good));
        let a = pb::Action { id: 1, kind: "restore".into(), path: lp.clone(), content_zstd: zstd::encode_all(&good[..], 1).unwrap(), content_hash: sha(good).to_vec(), ..Default::default() };
        let (ok, msg) = execute(&a, &allowed, "/tmp", "localhost", &st);
        assert!(!ok && msg.contains("symbolischer Link"), "{msg}");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "unverändert");
        // Quarantäne eines Symlinks → abgelehnt, Ziel bleibt
        let (ok, msg) = execute(&pb::Action { kind: "quarantine".into(), ..a.clone() }, &allowed, dir.join("q").to_str().unwrap(), "localhost", &st);
        assert!(!ok && msg.contains("symbolischer Link"), "{msg}");
        assert!(victim.exists() && link.exists());
        // Ordner über Symlink (z. B. auf /etc) → aufgelöster Pfad zählt
        let sub = dir.join("etc-link");
        std::os::unix::fs::symlink("/etc", &sub).unwrap();
        let p = format!("{}/cron.d/evil", sub.display());
        st.remember(&p, &sha(good));
        let (ok, msg) = execute(&pb::Action { path: p, ..a.clone() }, &allowed, "/tmp", "localhost", &st);
        assert!(!ok && msg.contains("geschützt"), "{msg}");
        // harmloser Ordner über Symlink: Pfad weicht vom Zustand ab → abgelehnt
        let real = dir.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let via = dir.join("via");
        std::os::unix::fs::symlink(&real, &via).unwrap();
        let p = format!("{}/x.php", via.display());
        st.remember(&p, &sha(good));
        let (ok, msg) = execute(&pb::Action { path: p, ..a }, &allowed, "/tmp", "localhost", &st);
        assert!(!ok && msg.contains("symbolische Links"), "{msg}");
        assert!(!real.join("x.php").exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}
