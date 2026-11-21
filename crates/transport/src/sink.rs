//! Ereignisse → Protokoll → Spool.

use std::sync::Arc;

use tyrosd_core::event::{Event, FileMeta};
use tyrosd_core::sink::Sink;
use tyrosd_proto as pb;

use crate::spool::Spool;

pub struct SpoolSink {
    pub spool: Arc<Spool>,
}

fn hexb(h: &Option<String>) -> Vec<u8> {
    h.as_deref().and_then(|s| hex::decode(s).ok()).unwrap_or_default()
}

fn zstd(d: &Option<Vec<u8>>) -> Vec<u8> {
    d.as_ref().and_then(|d| zstd::encode_all(&d[..], 3).ok()).unwrap_or_default()
}

pub fn meta_pb(m: &FileMeta) -> pb::FileMeta {
    pb::FileMeta {
        size: m.size,
        mode: m.mode,
        uid: m.uid,
        gid: m.gid,
        ino: m.ino,
        mtime_ns: m.mtime_ns,
        ctime_ns: m.ctime_ns,
        caps: m.caps.as_deref().and_then(|c| hex::decode(c).ok()).unwrap_or_default(),
    }
}

pub fn op_str(e: &Event) -> String {
    serde_json::to_value(e.op).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

pub fn backend_str(e: &Event) -> String {
    serde_json::to_value(e.backend).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

pub fn to_pb(e: &Event, with_payload: bool) -> pb::FileEvent {
    pb::FileEvent {
        op: op_str(e),
        path: e.path.clone(),
        old_path: e.old_path.clone().unwrap_or_default(),
        backend: backend_str(e),
        first_ts_ns: e.first_ts_ns,
        pid: e.pid.unwrap_or(0),
        exe: e.exe.clone().unwrap_or_default(),
        comm: e.comm.clone().unwrap_or_default(),
        proc_chain: e.proc_chain.clone(),
        mode: e.mode.clone().unwrap_or_default(),
        base_hash: hexb(&e.base_hash),
        raw_hash: hexb(&e.new_hash),
        stored_hash: hexb(&e.stored_hash),
        patch_zstd: if with_payload { zstd(&e.patch) } else { vec![] },
        content_zstd: if with_payload { zstd(&e.content) } else { vec![] },
        meta: e.meta.as_ref().map(meta_pb),
        note: e.note.clone().unwrap_or_default(),
        diff_lines: e.diff_lines.unwrap_or(0),
    }
}

impl Sink for SpoolSink {
    fn emit(&self, e: &Event) {
        let mut fe = to_pb(e, true);
        let payload = fe.patch_zstd.len() + fe.content_zstd.len();
        if payload > 0 && !self.spool.has_room(payload + 512) {
            // Spool voll: Inhalt/Diff weglassen, Metadaten + Hashes behalten (Hauptplan 9)
            fe.patch_zstd.clear();
            fe.content_zstd.clear();
            fe.note = if fe.note.is_empty() { "spool_full".into() } else { format!("{},spool_full", fe.note) };
        }
        if let Err(err) = self.spool.push(e.ts_ns, pb::envelope::Body::File(fe)) {
            eprintln!("[tyrosecd] Spool-Fehler: {err:#}");
        }
    }
}
