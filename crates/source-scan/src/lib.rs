//! Reconciliation scan: finds everything events have missed (downtime,
//! mmap, NFS, timestomping). Compares size/mtime/ctime/inode/mode/uid/gid,
//! hashes on mismatch. Throttled (IO class idle, rate limit), parallel,
//! resumable.
//!
//! Memory: the file list is streamed (no vector of all paths); the
//! state lives in the processor's `State` (embedded database).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use rayon::prelude::*;
use serde::Serialize;
use tyrosd_core::event::{Backend, FileMeta, Op};
use tyrosd_core::policy::ContentMode;
use tyrosd_core::processor::{Input, Processor};

#[derive(Clone, Debug)]
pub struct ScanConfig {
    pub roots: Vec<String>,
    pub threads: usize,
    /// MB/s read limit (None = unlimited)
    pub rate_mb_s: Option<u64>,
    /// IO priority "idle" + nice 10
    pub low_prio: bool,
    pub one_fs: bool,
    /// Rehash all files, not only on metadata mismatch
    pub full_hash: bool,
}

#[derive(Serialize, Debug, Default)]
pub struct ScanReport {
    pub baseline: bool,
    pub files: u64,
    pub hashed: u64,
    pub bytes_hashed: u64,
    pub changes: u64,
    pub deleted: u64,
    pub errors: u64,
    pub duration_ms: u128,
    pub state_bytes: u64,
    pub cache_bytes: u64,
    pub known: u64,
}

fn set_low_prio() {
    // ioprio_set(IOPRIO_WHO_PROCESS, 0 = calling thread, CLASS_IDLE << 13)
    const IOPRIO_CLASS_IDLE: libc::c_long = 3;
    // SAFETY: simple syscalls without pointers.
    unsafe {
        libc::syscall(libc::SYS_ioprio_set, 1 as libc::c_long, 0 as libc::c_long, IOPRIO_CLASS_IDLE << 13);
        libc::setpriority(libc::PRIO_PROCESS, 0, 10);
    }
}

struct RateLimiter {
    start: Instant,
    bytes: AtomicU64,
    rate: u64,
}

impl RateLimiter {
    fn account(&self, n: u64) {
        if self.rate == 0 {
            return;
        }
        let total = self.bytes.fetch_add(n, Ordering::Relaxed) + n;
        let should = Duration::from_secs_f64(total as f64 / self.rate as f64);
        let el = self.start.elapsed();
        if should > el {
            std::thread::sleep(should - el);
        }
    }
}

fn changed(a: &FileMeta, b: &FileMeta) -> bool {
    a.size != b.size
        || a.mtime_ns != b.mtime_ns
        || a.ctime_ns != b.ctime_ns
        || a.ino != b.ino
        || a.mode != b.mode
        || a.uid != b.uid
        || a.gid != b.gid
        || a.caps != b.caps
}

/// Persist the state (e.g. when the agent stops).
pub fn save_state(proc: &Processor, complete: bool) -> Result<u64> {
    if complete {
        proc.state.set_complete(true)?;
    }
    proc.state.flush(true)?;
    Ok(proc.state.file_bytes())
}

pub fn scan(cfg: &ScanConfig, proc: &Processor) -> Result<ScanReport> {
    let t0 = Instant::now();
    let mut rep = ScanReport::default();
    let baseline = !proc.state.is_complete();
    rep.baseline = baseline;
    if cfg.low_prio {
        set_low_prio();
    }

    let limiter = RateLimiter { start: Instant::now(), bytes: AtomicU64::new(0), rate: cfg.rate_mb_s.unwrap_or(0) * 1024 * 1024 };
    let files = AtomicU64::new(0);
    let hashed = AtomicU64::new(0);
    let bytes = AtomicU64::new(0);
    let changes = AtomicU64::new(0);
    let errors = AtomicU64::new(0);

    let low_prio = cfg.low_prio;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(cfg.threads.max(1))
        .start_handler(move |_| {
            if low_prio {
                set_low_prio();
            }
        })
        .build()?;

    let policy = proc.policy.clone();
    for root in &cfg.roots {
        let walker = walkdir::WalkDir::new(root)
            .same_file_system(cfg.one_fs)
            .follow_links(false)
            .into_iter()
            // do not even enter ignored directories
            .filter_entry(|e| {
                !(e.file_type().is_dir()
                    && policy.mode_for(&format!("{}/.x", e.path().to_string_lossy().trim_end_matches('/'))) == ContentMode::Ignore)
            });
        pool.install(|| {
            walker
                .filter_map(|r| match r {
                    Ok(e) => Some(e),
                    Err(_) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                        None
                    }
                })
                .filter(|e| e.file_type().is_file() || e.file_type().is_symlink())
                .par_bridge()
                .for_each(|e| {
                    let p = e.path().to_string_lossy().into_owned();
                    if proc.policy.mode_for(&p) == ContentMode::Ignore {
                        return;
                    }
                    files.fetch_add(1, Ordering::Relaxed);
                    let Some(meta) = FileMeta::from_path(&p) else { return };
                    let prev = proc.entry(&p);
                    let need = match &prev {
                        None => true,
                        Some(en) => cfg.full_hash || changed(&en.meta, &meta),
                    };
                    if !need {
                        return;
                    }
                    if prev.is_none() && baseline {
                        proc.prime(&p); // baseline: record only, no event
                    } else {
                        // Modify vs. Attrib vs. WriteNochange is decided by the processor via the hash;
                        // pure timestamp changes are adopted silently.
                        let op = if prev.is_none() { Op::Create } else { Op::Modify };
                        let emitted = proc.process(Input {
                            ts_ns: tyrosd_core::now_ns(),
                            first_ts_ns: tyrosd_core::now_ns(),
                            backend: Backend::Scan,
                            op,
                            path: p,
                            old_path: None,
                            proc: None,
                            note: None,
                            quiet_nochange: true,
                        });
                        if emitted {
                            changes.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    if meta.mode & libc::S_IFMT == libc::S_IFREG {
                        hashed.fetch_add(1, Ordering::Relaxed);
                        bytes.fetch_add(meta.size, Ordering::Relaxed);
                        limiter.account(meta.size);
                    }
                });
        });
    }

    // Deleted files: known paths under the roots that no longer exist
    if !baseline {
        for root in &cfg.roots {
            for p in proc.state.missing_under(root)? {
                proc.process(Input {
                    ts_ns: tyrosd_core::now_ns(),
                    first_ts_ns: tyrosd_core::now_ns(),
                    backend: Backend::Scan,
                    op: Op::Delete,
                    path: p,
                    old_path: None,
                    proc: None,
                    note: None,
                    quiet_nochange: true,
                });
                rep.deleted += 1;
            }
        }
    }
    rep.state_bytes = save_state(proc, true)?;
    rep.files = files.into_inner();
    rep.hashed = hashed.into_inner();
    rep.bytes_hashed = bytes.into_inner();
    rep.changes = changes.into_inner();
    rep.errors = errors.into_inner();
    rep.cache_bytes = proc.state.blob_bytes();
    rep.known = proc.known();
    rep.duration_ms = t0.elapsed().as_millis();
    Ok(rep)
}
