//! Process attribution via /proc (fanotify only provides the PID).
//! Must be read immediately on the raw event, otherwise short-lived processes
//! are gone (main plan 26.1).

use serde::Serialize;

#[derive(Serialize, Clone, Debug, Default)]
pub struct ProcInfo {
    pub pid: i32,
    pub exe: Option<String>,
    pub comm: Option<String>,
    /// comm names of the parent chain, starting with the process itself.
    pub chain: Vec<String>,
    pub gone: bool,
    /// Process or ancestor is a **verified** package manager (executable, not just the name – see `trust`).
    /// Must be determined on the raw event while the processes still exist.
    #[serde(skip)]
    pub pkg: bool,
}

fn comm(pid: i32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm")).ok().map(|s| s.trim_end().to_string())
}

pub fn ppid(pid: i32) -> Option<i32> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Field 2 (comm) may contain spaces/parentheses → parse after the last ')'
    let rest = &s[s.rfind(')')? + 2..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

pub fn exe(pid: i32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok().map(|p| p.to_string_lossy().into_owned())
}

/// Start time of a process (field 22 in /proc/<pid>/stat) – distinguishes a reused PID
fn start_time(pid: i32) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    s[s.rfind(')')? + 2..].split_whitespace().nth(19)?.parse().ok()
}

/// Short-term memory of verified package management processes: apt starts dozens of very short-lived dpkg processes.
/// If one has exited before its (delayed) events are processed, it still counts as verified –
/// but only within `PKG_MEMORY` and only if the PID has not meanwhile been taken by another process
/// (test run on a fresh VM: libtinfo/libtic “outside of a package update”, dpkg already exited).
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

/// verified package management process with this PID, seen recently, and the PID not reassigned since
fn recall_pkg(pid: i32, start_now: Option<u64>) -> Option<ProcInfo> {
    let g = PKG_SEEN.lock().unwrap();
    let (start, t, info) = g.as_ref()?.get(&pid)?;
    if t.elapsed() >= PKG_MEMORY {
        return None;
    }
    // if another process (different start time) already runs under the PID, the memory does not apply
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
        // already exited: recently verified as package management?
        return recall_pkg(pid, None).unwrap_or(ProcInfo { gone: true, ..info });
    }
    let mut cur = pid;
    for _ in 0..8 {
        match comm(cur) {
            Some(c) => {
                // expensive check (exe, owner) only for names from the list
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
    // exited during the check (or PID reassigned): chain/check incomplete → treat as “exited”
    // (then the package update window applies), otherwise an incompletely read dpkg would be known as unverified
    let now = start_time(pid);
    if now.is_none() || now != start {
        return recall_pkg(pid, None).unwrap_or(ProcInfo { gone: true, ..info });
    }
    // still running, not verified – maybe verified just before (e.g. chain briefly unreadable)
    recall_pkg(pid, start).unwrap_or(info)
}

#[cfg(test)]
mod pkg_memory_tests {
    use super::*;

    #[test]
    fn verified_pkg_is_remembered_only_for_same_process() {
        let info = ProcInfo { pid: 999_001, comm: Some("dpkg".into()), chain: vec!["dpkg".into(), "apt-get".into()], pkg: true, ..Default::default() };
        remember_pkg(&info, Some(4242));
        // exited: still counts as verified, marked as “exited”
        let r = recall_pkg(999_001, None).unwrap();
        assert!(r.pkg && r.gone && r.chain == info.chain);
        // the same process is still running
        assert!(recall_pkg(999_001, Some(4242)).is_some_and(|r| r.pkg && !r.gone));
        // PID reassigned meanwhile → no memory
        assert!(recall_pkg(999_001, Some(9999)).is_none());
        // unknown PID
        assert!(recall_pkg(999_002, None).is_none());
    }

    #[test]
    fn vanished_process_counts_as_gone() {
        // does not exist: exited, no chain, not verified
        let r = lookup(i32::MAX - 7);
        assert!(r.gone && !r.pkg && r.chain.is_empty());
        // own process: running, start time readable
        assert!(start_time(std::process::id() as i32).is_some());
    }
}

/// Does the process (or an ancestor) belong to a package manager? Only via the verified executable
/// (`ProcInfo::pkg`), never via the name (security review H4: symlink “dpkg” → bash).
pub fn is_package_manager(p: Option<&ProcInfo>) -> bool {
    p.is_some_and(|p| p.pkg)
}
