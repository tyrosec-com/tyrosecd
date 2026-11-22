use serde::Serialize;

use crate::procinfo::ProcInfo;

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Op {
    Create,
    Modify,
    Delete,
    Rename,
    Attrib,
    WriteNochange,
    Overflow,
    /// Program start from a location where enforcing protection would have prevented it (dry run, only reported)
    Exec,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    Fanotify,
    Inotify,
    Scan,
}

/// Raw event from a backend, before debounce and content processing.
#[derive(Clone, Debug)]
pub struct RawEvent {
    pub ts_ns: i64,
    pub backend: Backend,
    pub op: Op,
    pub path: String,
    pub old_path: Option<String>,
    pub proc: Option<ProcInfo>,
    pub note: Option<String>,
}

/// Output event (one JSON line in events.jsonl). The format is aligned with
/// `ci/spike/tests/compare.py`.
#[derive(Serialize, Clone, Debug)]
pub struct Event {
    pub ts_ns: i64,
    /// Time of the first raw event (for latency measurement).
    pub first_ts_ns: i64,
    pub backend: Backend,
    pub op: Op,
    pub path: String,
    pub old_path: Option<String>,
    pub pid: Option<i32>,
    pub exe: Option<String>,
    pub comm: Option<String>,
    pub proc_chain: Vec<String>,
    pub mode: Option<String>,
    pub base_hash: Option<String>,
    pub new_hash: Option<String>,
    pub diff_lines: Option<u32>,
    pub diff_bytes: Option<u32>,
    pub meta: Option<FileMeta>,
    pub note: Option<String>,
    /// Spike only (`--emit-diff`): diff text, truncated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<String>,
    /// For the central server (not in the JSON): patch against `base_hash` …
    #[serde(skip)]
    pub patch: Option<Vec<u8>>,
    /// … or full (possibly masked) content if no base exists
    #[serde(skip)]
    pub content: Option<Vec<u8>>,
    /// Hash of the stored version after the change (hex)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stored_hash: Option<String>,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq, serde::Deserialize, Default)]
pub struct FileMeta {
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub ino: u64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    /// Hex of the xattr `security.capability`, if present.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub caps: Option<String>,
}

impl FileMeta {
    pub fn from_path(path: &str) -> Option<FileMeta> {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::symlink_metadata(path).ok()?;
        Some(FileMeta {
            size: m.size(),
            mode: m.mode(),
            uid: m.uid(),
            gid: m.gid(),
            ino: m.ino(),
            mtime_ns: m.mtime() * 1_000_000_000 + m.mtime_nsec(),
            ctime_ns: m.ctime() * 1_000_000_000 + m.ctime_nsec(),
            caps: if m.file_type().is_file() { read_caps(path) } else { None },
        })
    }

    pub fn is_suid_sgid(&self) -> bool {
        self.mode & 0o6000 != 0
    }
}

/// Reads the xattr `security.capability` (file capabilities).
pub fn read_caps(path: &str) -> Option<String> {
    let c_path = std::ffi::CString::new(path).ok()?;
    let name = c"security.capability";
    let mut buf = [0u8; 64];
    // SAFETY: buffers and strings are valid for the duration of the call.
    let n = unsafe {
        libc::lgetxattr(
            c_path.as_ptr(),
            name.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    if n > 0 {
        Some(hex::encode(&buf[..n as usize]))
    } else {
        None
    }
}
