//! Package B (plan 2026-11-27): traces and hiding – read only, checked every 30 s.
//! - E3 log tampering: security logs deleted, truncated or replaced without a rotation (logrotate leaves a freshly
//!   rotated sibling such as `auth.log.1`)
//! - E4 hidden processes: a mount over `/proc/<pid>`; a process the kernel reported (fork/exec, no exit) that still
//!   exists but is missing from the `/proc` listing (userland rootkit)
//! - E5 kernel modules: kernel taint flags for out-of-tree/unsigned modules newly set; module loaded that is not
//!   part of the installed kernel's module tree

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::{DirEntryExt, MetadataExt};

/// Logs whose disappearance or shrinking is a classic trace of an intruder
pub const LOGS: &[&str] = &[
    "/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "/var/log/messages", "/var/log/wtmp", "/var/log/btmp",
    "/var/log/lastlog", "/var/log/faillog", "/var/log/audit/audit.log",
];

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LogState {
    pub ino: u64,
    pub size: u64,
}

/// Snapshot of one log: own state + rotated siblings (`auth.log.1`, `auth.log-20261127.gz` …) with their inode
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LogSnap {
    pub state: Option<LogState>,
    pub siblings: HashMap<String, u64>,
}

pub fn snap(path: &str) -> LogSnap {
    let state = std::fs::metadata(path).ok().filter(|m| m.is_file()).map(|m| LogState { ino: m.ino(), size: m.size() });
    let (dir, name) = path.rsplit_once('/').unwrap_or(("/", path));
    let siblings = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| Some((e.file_name().to_str()?.to_string(), e.ino())))
                .filter(|(n, _)| n != name && n.starts_with(name) && n[name.len()..].starts_with(['.', '-']))
                .collect()
        })
        .unwrap_or_default();
    LogSnap { state, siblings }
}

/// Verdict for one log between two snapshots (None = fine). A new or renewed rotated sibling (new name or new
/// inode under a known name – `rotate 1`, copytruncate) means logrotate or savelog did its job – then deleting,
/// shrinking or replacing is normal. Only deleting a sibling does not count as a rotation.
pub fn log_verdict(prev: &LogSnap, now: &LogSnap) -> Option<&'static str> {
    let rotated = now.siblings.iter().any(|(n, i)| prev.siblings.get(n) != Some(i));
    let (Some(p), now_state) = (prev.state, now.state) else { return None };
    if rotated {
        return None;
    }
    match now_state {
        None => Some("deleted"),
        Some(n) if n.ino != p.ino && n.size < p.size => Some("replaced by a smaller file"),
        Some(n) if n.ino == p.ino && n.size < p.size => Some(if n.size == 0 { "emptied" } else { "shortened" }),
        _ => None,
    }
}

/// E4a: mounts whose target is a process directory in /proc (hides that process from ps/top)
pub fn proc_mounts(mountinfo: &str) -> Vec<String> {
    mountinfo
        .lines()
        .filter_map(|l| l.split_whitespace().nth(4))
        .filter(|t| t.strip_prefix("/proc/").is_some_and(|r| !r.is_empty() && r.split('/').next().is_some_and(|p| p.chars().all(|c| c.is_ascii_digit()))))
        .map(String::from)
        .collect()
}

/// E4b: processes the kernel reported that exist (signal 0 succeeds) but are missing from the /proc listing.
/// Thread ids are not listed in /proc either – so the number must still be a process of its own (Tgid = PID).
pub fn hidden_pids(candidates: &[i32], listed: &HashSet<i32>) -> Vec<i32> {
    candidates
        .iter()
        .copied()
        .filter(|p| *p > 1 && !listed.contains(p))
        // SAFETY: kill with signal 0 only checks existence/permission, sends nothing
        .filter(|p| unsafe { libc::kill(*p, 0) } == 0)
        .filter(|p| tgid(*p) == Some(*p))
        .collect()
}

fn tgid(pid: i32) -> Option<i32> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    s.lines().find(|l| l.starts_with("Tgid:"))?.split_whitespace().nth(1)?.parse().ok()
}

pub fn proc_listing() -> HashSet<i32> {
    std::fs::read_dir("/proc")
        .map(|rd| rd.flatten().filter_map(|e| e.file_name().to_str().and_then(|s| s.parse().ok())).collect())
        .unwrap_or_default()
}

/// E5: kernel taint bits for out-of-tree (O = 4096) and unsigned (E = 8192) modules
pub const TAINT_OOT: u64 = 1 << 12;
pub const TAINT_UNSIGNED: u64 = 1 << 13;

pub fn taint() -> u64 {
    std::fs::read_to_string("/proc/sys/kernel/tainted").ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
}

pub fn modules() -> HashSet<String> {
    std::fs::read_to_string("/proc/modules")
        .map(|s| s.lines().filter_map(|l| l.split_whitespace().next().map(String::from)).collect())
        .unwrap_or_default()
}

/// Module names of the installed kernel's tree (/lib/modules/<release>/**.ko*), `-` and `_` treated alike
pub fn module_tree() -> HashSet<String> {
    let rel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let mut out = HashSet::new();
    let mut stack = vec![std::path::PathBuf::from(format!("/lib/modules/{}", rel.trim()))];
    let mut n = 0;
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            n += 1;
            if n > 200_000 {
                return out;
            }
            let p = e.path();
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                stack.push(p);
            } else if let Some(name) = p.file_name().and_then(|f| f.to_str()) {
                if let Some(base) = name.split(".ko").next().filter(|_| name.contains(".ko")) {
                    out.insert(base.replace('-', "_"));
                }
            }
        }
    }
    out
}

/// State between two rounds of the system watch
#[derive(Default)]
pub struct Watch {
    pub logs: HashMap<String, LogSnap>,
    pub taint: Option<u64>,
    pub modules: Option<HashSet<String>>,
    tree: Option<HashSet<String>>,
    /// suspicion of a hidden process must hold in two rounds (avoids races with exiting processes)
    pub hidden_seen: HashSet<i32>,
}

/// One finding of the system watch: (rule, severity, title, detail, key)
pub type Finding = (&'static str, &'static str, String, String, String);

impl Watch {
    pub fn round(&mut self, candidates: &[i32]) -> Vec<Finding> {
        let mut out = Vec::new();
        // E3
        for l in LOGS {
            let now = snap(l);
            if let Some(prev) = self.logs.get(*l) {
                if let Some(what) = log_verdict(prev, &now) {
                    out.push(("log_tampered", "high", format!("Security log {what}: {l}"),
                        format!("{l} was {what} without a log rotation – intruders often wipe their traces this way\nSize before: {} bytes",
                            prev.state.map(|s| s.size).unwrap_or(0)), l.to_string()));
                }
            }
            self.logs.insert(l.to_string(), now);
        }
        // E4a
        if let Ok(mi) = std::fs::read_to_string("/proc/self/mountinfo") {
            for t in proc_mounts(&mi) {
                out.push(("proc_hidden_mount", "critical", format!("Process hidden by a mount over {t}"),
                    format!("Something is mounted over {t} – the process with this number no longer shows up in ps/top. A known technique to hide malware."), t));
            }
        }
        // E4b
        let listed = proc_listing();
        let hidden = hidden_pids(candidates, &listed);
        for p in &hidden {
            if self.hidden_seen.contains(p) {
                let e = tyrosd_core::proctable::get(*p, None);
                let (comm, exe) = e.map(|e| (e.comm, e.exe)).unwrap_or_default();
                out.push(("process_hidden", "critical", format!("Hidden process: {comm} (PID {p})"),
                    format!("PID {p} exists according to the kernel but is missing from the /proc listing – typical of a rootkit that hides processes\nProgram: {exe}"),
                    format!("{p}|{exe}")));
            }
        }
        self.hidden_seen = hidden.into_iter().collect();
        // E5
        let t = taint();
        if let Some(prev) = self.taint {
            let new = t & !prev & (TAINT_OOT | TAINT_UNSIGNED);
            if new != 0 {
                let kind = if new & TAINT_UNSIGNED != 0 { "unsigned" } else { "out-of-tree" };
                out.push(("kernel_module_tainted", "high", format!("Kernel module loaded: {kind}"),
                    format!("The kernel now reports an {kind} module (taint {prev} → {t}). Legitimate for DKMS drivers (e.g. after a driver update), otherwise typical of a kernel rootkit."),
                    format!("taint|{t}")));
            }
        }
        self.taint = Some(t);
        let mods = modules();
        // first round: modules already loaded before the agent started are checked too
        let empty = HashSet::new();
        let prev = self.modules.as_ref().unwrap_or(&empty);
        let fresh: Vec<&String> = mods.difference(prev).collect();
        if !fresh.is_empty() {
            let tree = self.tree.get_or_insert_with(module_tree);
            // module tree of the running kernel missing or incomplete (kernel updated, old tree removed): no verdict
            let usable = tree.len() >= 100;
            for m in fresh {
                if usable && !tree.contains(&m.replace('-', "_")) {
                    out.push(("kernel_module_unknown", "high", format!("Kernel module loaded that is not part of the kernel: {m}"),
                        format!("Module {m} was loaded and is not in /lib/modules of the running kernel – legitimate for DKMS drivers, otherwise typical of a kernel rootkit."),
                        m.clone()));
                }
            }
        }
        self.modules = Some(mods);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(ino: u64, size: u64, sib: &[(&str, u64)]) -> LogSnap {
        LogSnap { state: Some(LogState { ino, size }), siblings: sib.iter().map(|(n, i)| (n.to_string(), *i)).collect() }
    }

    #[test]
    fn log_tampering_vs_rotation() {
        let before = s(1, 5000, &[("auth.log.1", 7)]);
        assert_eq!(log_verdict(&before, &s(1, 0, &[("auth.log.1", 7)])), Some("emptied"));
        assert_eq!(log_verdict(&before, &s(1, 1200, &[("auth.log.1", 7)])), Some("shortened"));
        assert_eq!(log_verdict(&before, &LogSnap { state: None, siblings: before.siblings.clone() }), Some("deleted"));
        assert_eq!(log_verdict(&before, &s(2, 10, &[("auth.log.1", 7)])), Some("replaced by a smaller file"));
        // deleting the rotated copy as well is no rotation
        assert_eq!(log_verdict(&before, &s(1, 0, &[])), Some("emptied"));
        // rotation: new sibling, renewed sibling (rotate 1: old file becomes auth.log.1), copytruncate, dateext
        assert_eq!(log_verdict(&before, &s(2, 0, &[("auth.log.1", 8), ("auth.log.2.gz", 7)])), None);
        assert_eq!(log_verdict(&before, &s(2, 0, &[("auth.log.1", 1)])), None);
        assert_eq!(log_verdict(&before, &s(1, 0, &[("auth.log.1", 9)])), None);
        assert_eq!(log_verdict(&before, &s(1, 0, &[("auth.log.1", 7), ("auth.log-20261127", 9)])), None);
        // growing, unchanged, never existed: fine
        assert_eq!(log_verdict(&before, &s(1, 6000, &[("auth.log.1", 7)])), None);
        assert_eq!(log_verdict(&LogSnap::default(), &LogSnap::default()), None);
    }

    #[test]
    fn mounts_over_proc_pids() {
        let mi = "22 1 0:5 / /proc rw - proc proc rw\n90 22 0:40 / /proc/1234 rw - tmpfs tmpfs rw\n91 22 0:41 / /proc/sys/fs/binfmt_misc rw - x x rw\n";
        assert_eq!(proc_mounts(mi), vec!["/proc/1234".to_string()]);
    }

    #[test]
    fn hidden_only_when_alive_and_unlisted() {
        let me = std::process::id() as i32;
        let listed = proc_listing();
        assert!(listed.contains(&me));
        assert!(hidden_pids(&[me], &listed).is_empty(), "listed");
        let mut without: HashSet<i32> = listed.clone();
        without.remove(&me);
        assert_eq!(hidden_pids(&[me], &without), vec![me], "alive but unlisted");
        assert!(hidden_pids(&[i32::MAX - 3], &without).is_empty(), "not alive");
    }

    #[test]
    fn watch_round_baseline_then_quiet() {
        let mut w = Watch::default();
        let first = w.round(&[]);
        assert!(first.iter().all(|f| f.0 != "log_tampered" && f.0 != "kernel_module_tainted" && f.0 != "process_hidden"), "first round sets the baseline: {first:?}");
        assert!(w.taint.is_some() && w.modules.is_some());
    }
}
