//! Prozess-Zuordnung über /proc (fanotify liefert nur die PID).
//! Muss sofort beim Rohereignis gelesen werden, kurzlebige Prozesse sind
//! sonst weg (Hauptplan 26.1).

use serde::Serialize;

#[derive(Serialize, Clone, Debug, Default)]
pub struct ProcInfo {
    pub pid: i32,
    pub exe: Option<String>,
    pub comm: Option<String>,
    /// comm-Namen der Elternkette, beginnend beim Prozess selbst.
    pub chain: Vec<String>,
    pub gone: bool,
    /// Prozess oder Vorfahre ist ein **geprüfter** Paketmanager (Programmdatei, nicht nur Name – siehe `trust`).
    /// Muss beim Rohereignis bestimmt werden, solange die Prozesse noch existieren.
    #[serde(skip)]
    pub pkg: bool,
}

fn comm(pid: i32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm")).ok().map(|s| s.trim_end().to_string())
}

pub fn ppid(pid: i32) -> Option<i32> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Feld 2 (comm) kann Leerzeichen/Klammern enthalten → nach letztem ')' parsen
    let rest = &s[s.rfind(')')? + 2..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

pub fn exe(pid: i32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok().map(|p| p.to_string_lossy().into_owned())
}

/// Startzeit eines Prozesses (Feld 22 in /proc/<pid>/stat) – unterscheidet eine wiederverwendete PID
fn start_time(pid: i32) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    s[s.rfind(')')? + 2..].split_whitespace().nth(19)?.parse().ok()
}

/// Kurzzeit-Gedächtnis geprüfter Paketverwaltungs-Prozesse: apt startet Dutzende sehr kurzlebige dpkg-Prozesse.
/// Ist einer beendet, bevor seine (verzögert verarbeiteten) Ereignisse dran sind, gilt er weiter als geprüft –
/// aber nur innerhalb von `PKG_MEMORY` und nur, wenn die PID nicht inzwischen einem anderen Prozess gehört
/// (Testlauf auf frischer VM: libtinfo/libtic „außerhalb eines Paket-Updates“, dpkg schon beendet).
const PKG_MEMORY: std::time::Duration = std::time::Duration::from_secs(60);
static PKG_SEEN: std::sync::Mutex<Option<std::collections::HashMap<i32, (Option<u64>, std::time::Instant, ProcInfo)>>> = std::sync::Mutex::new(None);

fn remember_pkg(info: &ProcInfo, start: Option<u64>) {
    let mut g = PKG_SEEN.lock().unwrap();
    let m = g.get_or_insert_with(Default::default);
    if m.len() > 4096 {
        m.retain(|_, (_, t, _)| t.elapsed() < PKG_MEMORY);
    }
    m.insert(info.pid, (start, std::time::Instant::now(), info.clone()));
}

/// geprüfter Paketverwaltungs-Prozess mit dieser PID, kürzlich gesehen und die PID seither nicht neu vergeben
fn recall_pkg(pid: i32, start_now: Option<u64>) -> Option<ProcInfo> {
    let g = PKG_SEEN.lock().unwrap();
    let (start, t, info) = g.as_ref()?.get(&pid)?;
    if t.elapsed() >= PKG_MEMORY {
        return None;
    }
    // läuft unter der PID schon ein anderer Prozess (andere Startzeit), gilt die Erinnerung nicht
    if start_now.is_some() && start_now != *start {
        return None;
    }
    let mut i = info.clone();
    i.gone = start_now.is_none();
    Some(i)
}

pub fn lookup(pid: i32) -> ProcInfo {
    let start = start_time(pid);
    let mut info = ProcInfo { pid, ..Default::default() };
    info.comm = comm(pid);
    info.exe = exe(pid);
    if info.comm.is_none() {
        // schon beendet: kürzlich als Paketverwaltung geprüft?
        return recall_pkg(pid, None).unwrap_or(ProcInfo { gone: true, ..info });
    }
    let mut cur = pid;
    for _ in 0..8 {
        match comm(cur) {
            Some(c) => {
                // teure Prüfung (exe, Eigentümer) nur für Namen aus der Liste
                if !info.pkg && crate::trust::PACKAGE_MANAGERS.contains(&c.as_str()) && crate::trust::verified_program(cur, &c) {
                    info.pkg = true;
                }
                info.chain.push(c)
            }
            None => break,
        }
        match ppid(cur) {
            Some(p) if p > 1 => cur = p,
            _ => break,
        }
    }
    if info.pkg {
        remember_pkg(&info, start);
        return info;
    }
    // während der Prüfung beendet (oder PID neu vergeben): Kette/Prüfung unvollständig → wie „beendet“ behandeln
    // (dann greift das Paket-Update-Fenster), sonst gälte ein unvollständig gelesener dpkg als ungeprüft bekannt
    let now = start_time(pid);
    if now.is_none() || now != start {
        return recall_pkg(pid, None).unwrap_or(ProcInfo { gone: true, ..info });
    }
    // läuft noch, nicht geprüft – evtl. eben noch geprüft (z. B. Kette kurz nicht lesbar)
    recall_pkg(pid, start).unwrap_or(info)
}

#[cfg(test)]
mod pkg_memory_tests {
    use super::*;

    #[test]
    fn verified_pkg_is_remembered_only_for_same_process() {
        let info = ProcInfo { pid: 999_001, comm: Some("dpkg".into()), chain: vec!["dpkg".into(), "apt-get".into()], pkg: true, ..Default::default() };
        remember_pkg(&info, Some(4242));
        // beendet: gilt weiter als geprüft, als „beendet“ markiert
        let r = recall_pkg(999_001, None).unwrap();
        assert!(r.pkg && r.gone && r.chain == info.chain);
        // derselbe Prozess läuft noch
        assert!(recall_pkg(999_001, Some(4242)).is_some_and(|r| r.pkg && !r.gone));
        // PID inzwischen neu vergeben → keine Erinnerung
        assert!(recall_pkg(999_001, Some(9999)).is_none());
        // unbekannte PID
        assert!(recall_pkg(999_002, None).is_none());
    }

    #[test]
    fn vanished_process_counts_as_gone() {
        // gibt es nicht: beendet, keine Kette, nicht geprüft
        let r = lookup(i32::MAX - 7);
        assert!(r.gone && !r.pkg && r.chain.is_empty());
        // eigener Prozess: läuft, Startzeit lesbar
        assert!(start_time(std::process::id() as i32).is_some());
    }
}

/// Gehört der Prozess (oder ein Vorfahre) zu einem Paketmanager? Nur über die geprüfte Programmdatei
/// (`ProcInfo::pkg`), nie über den Namen (Sicherheitsprüfung H4: Symlink „dpkg“ → bash).
pub fn is_package_manager(p: Option<&ProcInfo>) -> bool {
    p.is_some_and(|p| p.pkg)
}
