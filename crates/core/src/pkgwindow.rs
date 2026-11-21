//! Paket-Update-Fenster ohne Prozess-Zuordnung (inotify-Hosts, Hauptplan 25.3):
//! Wurden die Logs/Datenbanken der Paketmanager in den letzten Sekunden
//! geschrieben, gelten Änderungen an Systempfaden als Paket-Update.
//!
//! Sicherheitsprüfung H5 (`touch /var/log/dpkg.log` öffnete 2 min alarmfreies Fenster):
//! - nur für Ereignisse **ohne** Prozess-Zuordnung (inotify) oder deren Prozess schon beendet ist,
//! - nur, solange ein **echter** Paketmanager-Prozess läuft oder im Fenster lief (Programmdatei geprüft, `trust`),
//! - nie für Persistenzpfade (cron, ld.so.preload, systemd, sudoers, Konten, .ssh).

use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use crate::procinfo::ProcInfo;

const MARKERS: &[&str] = &[
    "/var/log/dpkg.log",
    "/var/lib/dpkg/status",
    "/var/log/dnf.rpm.log",
    "/var/log/yum.log",
    "/var/lib/rpm",
    "/usr/lib/sysimage/rpm",
    "/lib/apk/db/installed",
    "/var/log/pacman.log",
];

/// Arbeitsordner der Paketverwaltung in tmp (bewusst eng: nicht ganz /tmp – Schadcode dort bleibt sichtbar).
/// Beispiele: /var/tmp/mkinitramfs_*, /tmp/apt-dpkg-install-*
const PM_TMP: &[&str] = &["/tmp/apt-dpkg-install-", "/var/tmp/mkinitramfs", "/tmp/mkinitramfs", "/var/tmp/dracut", "/tmp/dracut", "/var/cache/apt/"];

/// Systempfade, die Paketmanager typischerweise schreiben
const SYSTEM: &[&str] = &["/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/etc/", "/boot/", "/opt/"];

/// Persistenzpfade: hier gibt es nie eine Ausnahme über das Zeitfenster. /lib/systemd und /usr/lib/systemd (Ablage der
/// Pakete für ihre Units; jedes `apt upgrade` ersetzt dort Units – Testlauf auf frischer VM: open-vm-tools/snapd/vgauth als
/// „kritisch“) stehen nicht hier, sondern gelten nur eingeschränkt als Update – siehe `systemd_lib_update`.
/// Eigene Units von Admins und Angreifern landen unter /etc/systemd – das bleibt streng.
pub fn is_persistence(path: &str) -> bool {
    const PREFIX: &[&str] = &["/etc/cron", "/var/spool/cron/", "/etc/ld.so.preload", "/etc/systemd/", "/etc/sudoers",
        "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"];
    PREFIX.iter().any(|p| path.starts_with(p)) || path.contains("/.ssh/") || path.ends_with("/.ssh")
}

/// Temporärer Name der Paketverwaltung → Zielname (`x.service.dpkg-new` → `x.service`, rpm: `x.service;6553f2a1`).
/// dpkg/rpm schreiben neue Fassungen zuerst unter diesem Namen und benennen dann um.
pub fn pkg_temp_target(path: &str) -> Option<&str> {
    for suf in [".dpkg-new", ".dpkg-tmp", ".apk-new"] {
        if let Some(t) = path.strip_suffix(suf) {
            return Some(t);
        }
    }
    let (t, tail) = path.rsplit_once(';')?;
    (tail.len() == 8 && tail.bytes().all(|b| b.is_ascii_hexdigit()) && !t.ends_with('/')).then_some(t)
}

/// Unter /lib/systemd bzw. /usr/lib/systemd gilt im Paket-Update-Fenster nur das
/// **Ersetzen einer bereits bekannten Datei** als Update (`existed`: Pfad – bzw. Ziel des temporären Namens – steht schon
/// im lokalen Zustand). Neue Dateien (neue Units), Generatoren, Presets, Sleep-/Shutdown-Hooks und alles in
/// `*.wants/`, `*.requires/`, `*.d/` bleiben Persistenz (Alarm). Andere Pfade: unverändert `true`.
pub fn systemd_lib_update(path: &str, existed: bool) -> bool {
    let Some(rest) = path.strip_prefix("/lib/systemd/").or_else(|| path.strip_prefix("/usr/lib/systemd/")) else { return true };
    if !existed {
        return false;
    }
    const PERSIST_DIRS: &[&str] = &["system-generators", "user-generators", "system-environment-generators", "user-environment-generators",
        "system-preset", "user-preset", "system-sleep", "system-shutdown"];
    let parts: Vec<&str> = rest.split('/').collect();
    let dirs = &parts[..parts.len().saturating_sub(1)];
    !dirs.iter().any(|d| PERSIST_DIRS.contains(d) || d.ends_with(".wants") || d.ends_with(".requires") || d.ends_with(".upholds") || d.ends_with(".d"))
}

pub struct PkgWindow {
    window: Duration,
    /// (geprüft um, Ergebnis)
    cache: Mutex<(Instant, bool)>,
    /// zuletzt ein echter Paketmanager-Prozess gesehen
    last_pm: Mutex<Option<Instant>>,
}

impl Default for PkgWindow {
    fn default() -> Self {
        PkgWindow { window: Duration::from_secs(120), cache: Mutex::new((Instant::now() - Duration::from_secs(10), false)), last_pm: Mutex::new(None) }
    }
}

/// Läuft gerade ein geprüfter Paketmanager-Prozess? (durchsucht /proc – nur, wenn die Marker frisch sind)
fn pm_running() -> bool {
    let Ok(rd) = std::fs::read_dir("/proc") else { return false };
    rd.flatten().any(|e| {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else { return false };
        let Ok(c) = std::fs::read_to_string(format!("/proc/{pid}/comm")) else { return false };
        let c = c.trim_end();
        crate::trust::PACKAGE_MANAGERS.contains(&c) && crate::trust::verified_program(pid, c)
    })
}

impl PkgWindow {
    /// Ein Ereignis mit geprüftem Paketmanager-Prozess wurde gesehen (verlängert das Fenster).
    pub fn saw_pm(&self) {
        *self.last_pm.lock().unwrap() = Some(Instant::now());
    }

    fn markers_fresh(&self) -> bool {
        let now = SystemTime::now();
        MARKERS.iter().any(|m| {
            std::fs::metadata(m)
                .and_then(|md| md.modified())
                .ok()
                .and_then(|t| now.duration_since(t).ok())
                .is_some_and(|age| age <= self.window)
        })
    }

    /// Läuft gerade (oder lief vor < 2 min) ein echter Paketmanager, und hat er seine Logs/Datenbank geschrieben?
    /// Ergebnis 1 s gecacht.
    pub fn active(&self) -> bool {
        let mut c = self.cache.lock().unwrap();
        if c.0.elapsed() < Duration::from_secs(1) {
            return c.1;
        }
        let act = self.markers_fresh() && {
            if pm_running() {
                self.saw_pm();
            }
            self.last_pm.lock().unwrap().is_some_and(|t| t.elapsed() <= self.window)
        };
        *c = (Instant::now(), act);
        act
    }

    /// Gilt das Fenster für dieses Ereignis? Nur ohne (lebende) Prozess-Zuordnung, nie für Persistenzpfade.
    /// `existed`: Pfad (bzw. Ziel eines temporären dpkg-/rpm-Namens) ist im lokalen Zustand bekannt.
    pub fn applies(&self, path: &str, existed: bool, proc: Option<&ProcInfo>) -> bool {
        if proc.is_some_and(|p| !p.gone && !p.chain.is_empty()) {
            return false; // Prozess bekannt: dann entscheidet allein die geprüfte Prozesskette
        }
        if is_persistence(path) || !systemd_lib_update(path, existed) {
            return false;
        }
        (SYSTEM.iter().any(|s| path.starts_with(s)) || PM_TMP.iter().any(|s| path.starts_with(s))) && self.active()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fenster mit „frischen Markern“ und gerade gesehenem Paketmanager
    fn open_window() -> PkgWindow {
        let w = PkgWindow::default();
        w.saw_pm();
        *w.cache.lock().unwrap() = (Instant::now(), true);
        w
    }

    #[test]
    fn persistence_never() {
        let w = open_window();
        assert!(w.applies("/usr/bin/ls", true, None));
        assert!(w.applies("/usr/bin/new-tool", false, None));
        // bekannte Paket-Units unter /lib/systemd werden bei Updates ersetzt → im Fenster als Update; /etc/systemd bleibt streng
        assert!(w.applies("/lib/systemd/system/snapd.service", true, None));
        assert!(w.applies("/usr/lib/systemd/system/vgauth.service", true, None));
        assert!(w.applies("/usr/lib/systemd/systemd-logind", true, None));
        for p in ["/etc/cron.d/x", "/etc/crontab", "/var/spool/cron/crontabs/root", "/etc/ld.so.preload", "/etc/systemd/system/x.service",
            "/etc/sudoers", "/etc/sudoers.d/x", "/etc/passwd", "/etc/shadow", "/etc/group", "/root/.ssh/authorized_keys"] {
            assert!(!w.applies(p, true, None), "{p}");
        }
    }

    #[test]
    fn lib_systemd_only_known_units() {
        let w = open_window();
        // neue Unit, Generatoren, Presets, Hooks, *.wants/*.requires/*.d bleiben Persistenz – auch wenn schon bekannt
        assert!(!w.applies("/lib/systemd/system/evil.service", false, None));
        assert!(!w.applies("/usr/lib/systemd/user/evil.service", false, None));
        for p in ["/usr/lib/systemd/system-generators/x", "/lib/systemd/user-generators/x", "/usr/lib/systemd/system-environment-generators/x",
            "/usr/lib/systemd/system-preset/90-x.preset", "/lib/systemd/user-preset/x.preset", "/lib/systemd/system-sleep/x",
            "/usr/lib/systemd/system-shutdown/x", "/lib/systemd/system/multi-user.target.wants/x.service",
            "/usr/lib/systemd/system/sockets.target.requires/x.socket", "/lib/systemd/system/ssh.service.d/override.conf",
            "/usr/lib/systemd/user/default.target.wants/x.service"] {
            assert!(!w.applies(p, true, None), "{p}");
            assert!(!w.applies(p, false, None), "{p}");
        }
        assert_eq!(pkg_temp_target("/lib/systemd/system/snapd.service.dpkg-new"), Some("/lib/systemd/system/snapd.service"));
        assert_eq!(pkg_temp_target("/usr/lib/systemd/system/sshd.service;6553f2a1"), Some("/usr/lib/systemd/system/sshd.service"));
        assert_eq!(pkg_temp_target("/usr/lib/systemd/system/sshd.service;xyz"), None);
        assert_eq!(pkg_temp_target("/usr/lib/systemd/system/sshd.service"), None);
    }

    #[test]
    fn only_without_living_process() {
        let w = open_window();
        let alive = ProcInfo { pid: 42, comm: Some("bash".into()), chain: vec!["bash".into(), "sshd".into()], ..Default::default() };
        assert!(!w.applies("/usr/bin/ls", true, Some(&alive)));
        let gone = ProcInfo { pid: 42, gone: true, ..Default::default() };
        assert!(w.applies("/usr/bin/ls", true, Some(&gone)));
    }

    #[test]
    fn touched_log_alone_opens_nothing() {
        // Marker frisch, aber nie ein echter Paketmanager gesehen → kein Fenster
        let w = PkgWindow::default();
        assert!(w.last_pm.lock().unwrap().is_none());
        if !pm_running() {
            assert!(!w.active());
            assert!(!w.applies("/usr/bin/ls", true, None));
        }
    }
}
