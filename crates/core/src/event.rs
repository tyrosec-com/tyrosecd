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
    /// Programmstart aus einem Ort, an dem ein scharfer Schutz ihn verhindert hätte (Probelauf, nur gemeldet)
    Exec,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    Fanotify,
    Inotify,
    Scan,
}

/// Rohereignis eines Backends, vor Debounce und Inhaltsverarbeitung.
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

/// Ausgabeereignis (eine JSON-Zeile in events.jsonl). Format ist mit
/// `ci/spike/tests/compare.py` abgestimmt.
#[derive(Serialize, Clone, Debug)]
pub struct Event {
    pub ts_ns: i64,
    /// Zeitpunkt des ersten Rohereignisses (für Latenzmessung).
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
    /// Nur Spike (`--emit-diff`): Diff-Text, gekürzt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<String>,
    /// Für die Zentrale (nicht im JSON): Patch gegen `base_hash` …
    #[serde(skip)]
    pub patch: Option<Vec<u8>>,
    /// … oder voller (ggf. maskierter) Inhalt, wenn keine Basis existiert
    #[serde(skip)]
    pub content: Option<Vec<u8>>,
    /// Hash der gespeicherten Fassung nach der Änderung (Hex)
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
    /// Hex des xattr `security.capability`, falls vorhanden.
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

/// Liest das xattr `security.capability` (File-Capabilities).
pub fn read_caps(path: &str) -> Option<String> {
    let c_path = std::ffi::CString::new(path).ok()?;
    let name = c"security.capability";
    let mut buf = [0u8; 64];
    // SAFETY: Puffer und Strings sind gültig für die Dauer des Aufrufs.
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
