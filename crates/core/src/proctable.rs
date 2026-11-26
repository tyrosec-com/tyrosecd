//! Process memory: what the proc connector reported about processes (fork, exec, exit), kept for a short time after
//! the process has exited. Short-lived processes (a shell started by a web shell, `sh -c` from cron, dpkg helpers) are
//! often gone before their file events or their start are evaluated – reading /proc then yields nothing.
//!
//! Fed by the proc connector thread (`tyrosd-detect`), which reads the cheap values (comm, exe, cmdline, uid, ppid)
//! immediately on exec. Read only; nothing is changed on the system.
//!
//! Correctness with reused PIDs: every fork/exec replaces the entry of that PID, so while no kernel messages are lost
//! the entry always describes the latest process with this PID. Where the start time is known, it is compared too.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long an exited process stays in memory
pub const KEEP_AFTER_EXIT: Duration = Duration::from_secs(120);
/// Hard upper bound of entries (memory: well below 10 MB)
pub const MAX_ENTRIES: usize = 20_000;
const MAX_CMDLINE: usize = 1024;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Entry {
    pub pid: i32,
    pub ppid: i32,
    /// start time (field 22 of /proc/<pid>/stat) if it could be read
    pub start: Option<u64>,
    pub comm: String,
    pub exe: String,
    pub cmdline: String,
    pub uid: Option<u32>,
    /// set on exit
    pub exited: Option<Instant>,
}

#[derive(Default)]
struct Table {
    map: HashMap<i32, (Entry, Instant)>,
}

impl Table {
    fn put(&mut self, e: Entry) {
        prune(self);
        self.map.insert(e.pid, (e, Instant::now()));
    }
}

static TABLE: Mutex<Option<Table>> = Mutex::new(None);
static ACTIVE: AtomicBool = AtomicBool::new(false);
/// kernel messages lost (sequence gaps, ENOBUFS)
pub static LOST: AtomicU64 = AtomicU64::new(0);
/// lookups of exited processes answered from memory
pub static RECALLED: AtomicU64 = AtomicU64::new(0);

/// The proc connector feeds the table (set by the listener once subscribed)
pub fn set_active(on: bool) {
    ACTIVE.store(on, Ordering::Relaxed);
}

pub fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

fn with<R>(f: impl FnOnce(&mut Table) -> R) -> R {
    let mut g = TABLE.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(Table::default))
}

fn prune(t: &mut Table) {
    if t.map.len() < MAX_ENTRIES {
        return;
    }
    t.map.retain(|_, (e, _)| e.exited.is_none_or(|x| x.elapsed() < KEEP_AFTER_EXIT));
    if t.map.len() >= MAX_ENTRIES {
        // still full (fork storm): drop the oldest tenth, exited ones first
        let mut v: Vec<(i32, bool, Instant)> = t.map.iter().map(|(p, (e, at))| (*p, e.exited.is_none(), *at)).collect();
        v.sort_by_key(|(_, running, at)| (*running, *at));
        for (p, _, _) in v.into_iter().take(MAX_ENTRIES / 10) {
            t.map.remove(&p);
        }
    }
}

pub fn insert(e: Entry) {
    with(|t| t.put(e));
}

/// fork: the child inherits name, program and command line of the parent until it calls exec
pub fn on_fork(parent: i32, child: i32) {
    with(|t| {
        prune(t);
        let base = t.map.get(&parent).map(|(e, _)| e.clone());
        let e = match base {
            Some(p) => Entry { pid: child, ppid: parent, start: None, exited: None, ..p },
            None => Entry { pid: child, ppid: parent, ..Default::default() },
        };
        t.map.insert(child, (e, Instant::now()));
    });
}

/// exec: read the cheap values right now (the process may be gone in a few milliseconds)
pub fn on_exec(pid: i32) -> Entry {
    let e = read(pid).unwrap_or_else(|| {
        // already exited: keep what fork told us (parent), mark the program as unknown
        with(|t| t.map.get(&pid).map(|(e, _)| Entry { exe: String::new(), cmdline: String::new(), ..e.clone() }))
            .unwrap_or(Entry { pid, ..Default::default() })
    });
    insert(e.clone());
    e
}

pub fn on_exit(pid: i32) {
    with(|t| {
        if let Some((e, _)) = t.map.get_mut(&pid) {
            e.exited = Some(Instant::now());
        }
    });
}

/// Entry for a PID. `start_now`: start time of the process currently running under this PID (None = no process)
/// – an entry with a different known start time belongs to an earlier process and is not returned.
pub fn get(pid: i32, start_now: Option<u64>) -> Option<Entry> {
    with(|t| {
        let (e, _) = t.map.get(&pid)?;
        if e.exited.is_some_and(|x| x.elapsed() >= KEEP_AFTER_EXIT) {
            return None;
        }
        if let (Some(a), Some(b)) = (e.start, start_now) {
            if a != b {
                return None;
            }
        }
        if e.comm.is_empty() && e.exe.is_empty() {
            return None;
        }
        Some(e.clone())
    })
}

/// Lookup of a process that is no longer in /proc (counts as "recalled")
pub fn recall(pid: i32) -> Option<Entry> {
    let r = get(pid, None)?;
    RECALLED.fetch_add(1, Ordering::Relaxed);
    Some(r)
}

/// Names of the parent chain starting at `pid`, from memory (for parents that have already exited)
pub fn chain(pid: i32, depth: usize) -> Vec<String> {
    with(|t| {
        let mut out = Vec::new();
        let mut cur = pid;
        for _ in 0..depth {
            let Some((e, _)) = t.map.get(&cur) else { break };
            if e.comm.is_empty() {
                break;
            }
            out.push(e.comm.clone());
            if e.ppid <= 1 || e.ppid == cur {
                break;
            }
            cur = e.ppid;
        }
        out
    })
}

pub fn len() -> usize {
    with(|t| t.map.len())
}

/// Read comm, exe, cmdline, uid, ppid and start time of a running process (None if it is gone)
pub fn read(pid: i32) -> Option<Entry> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (l, r) = (stat.find('(')?, stat.rfind(')')?);
    let comm = stat[l + 1..r].to_string();
    let rest: Vec<&str> = stat.get(r + 2..)?.split_whitespace().collect();
    let ppid = rest.get(1)?.parse().ok()?;
    let start = rest.get(19).and_then(|s| s.parse().ok());
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|b| {
            let b = &b[..b.len().min(4096)];
            b.split(|c| *c == 0).filter(|s| !s.is_empty()).map(|s| String::from_utf8_lossy(s).into_owned()).collect::<Vec<_>>().join(" ")
        })
        .unwrap_or_default();
    let uid = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("Uid:")).and_then(|l| l.split_whitespace().nth(1)?.parse().ok()));
    Some(Entry { pid, ppid, start, comm, exe, cmdline: cmdline.chars().take(MAX_CMDLINE).collect(), uid, exited: None })
}

/// After lost kernel messages: take up all running processes that are not yet known (at most every 30 s)
pub fn resync() -> usize {
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    {
        let mut g = LAST.lock().unwrap_or_else(|e| e.into_inner());
        if g.is_some_and(|t| t.elapsed() < Duration::from_secs(30)) {
            return 0;
        }
        *g = Some(Instant::now());
    }
    let Ok(rd) = std::fs::read_dir("/proc") else { return 0 };
    let mut n = 0;
    for d in rd.flatten() {
        let Some(pid) = d.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else { continue };
        let known = with(|t| t.map.get(&pid).is_some_and(|(e, _)| e.exited.is_none() && !e.comm.is_empty()));
        if !known {
            if let Some(e) = read(pid) {
                insert(e);
                n += 1;
            }
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    // tests share the global table: unique PID ranges per test
    fn e(pid: i32, ppid: i32, comm: &str, start: Option<u64>) -> Entry {
        Entry { pid, ppid, start, comm: comm.into(), exe: format!("/usr/bin/{comm}"), cmdline: comm.into(), uid: Some(33), exited: None }
    }

    #[test]
    fn exited_process_is_recalled_with_chain() {
        insert(e(910_001, 910_000, "php-fpm8.3", Some(10)));
        insert(e(910_000, 1, "php-fpm8.3", Some(5)));
        on_fork(910_001, 910_002);
        // child inherits the parent's name until exec
        assert_eq!(get(910_002, None).unwrap().comm, "php-fpm8.3");
        insert(e(910_002, 910_001, "sh", Some(20)));
        on_exit(910_002);
        on_exit(910_001);
        let r = recall(910_002).unwrap();
        assert_eq!(r.comm, "sh");
        assert_eq!(chain(910_002, 6), vec!["sh", "php-fpm8.3", "php-fpm8.3"]);
    }

    #[test]
    fn reused_pid_is_not_confused() {
        insert(e(920_001, 1, "old", Some(100)));
        // another process with a different start time runs under the PID
        assert!(get(920_001, Some(200)).is_none());
        assert!(get(920_001, Some(100)).is_some());
        // a new fork replaces the entry
        insert(e(920_000, 1, "cron", Some(1)));
        on_fork(920_000, 920_001);
        assert_eq!(get(920_001, None).unwrap().comm, "cron");
    }

    #[test]
    fn expired_entries_are_not_returned() {
        let mut x = e(930_001, 1, "gone", None);
        x.exited = Some(Instant::now() - KEEP_AFTER_EXIT - Duration::from_secs(1));
        insert(x);
        assert!(get(930_001, None).is_none());
    }

    #[test]
    fn unknown_fork_without_name_is_not_returned() {
        on_fork(940_000, 940_001);
        assert!(get(940_001, None).is_none());
    }

    #[test]
    fn bounded_size() {
        // fill beyond the limit (own table, the global one is shared by the tests): never more than MAX_ENTRIES,
        // running processes survive while exited ones can be dropped
        let mut t = Table::default();
        t.put(e(5, 1, "init-child", None));
        for i in 0..(MAX_ENTRIES as i32 + 500) {
            let mut x = e(1_000_000 + i, 1, "w", None);
            x.exited = Some(Instant::now());
            t.put(x);
        }
        assert!(t.map.len() <= MAX_ENTRIES);
        assert!(t.map.contains_key(&5));
    }

    #[test]
    fn reads_own_process() {
        let me = read(std::process::id() as i32).unwrap();
        assert!(!me.comm.is_empty() && me.start.is_some() && me.uid.is_some());
    }
}
