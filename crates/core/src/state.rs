//! Persistenter Zustand des Agents (ersetzt Hash-Tabellen im RAM):
//! - `state`: Pfad → Hash (binär), Hash der gespeicherten Fassung, Metadaten
//! - `blobs`: Hash → zstd-komprimierter Inhalt (Diff-Basis), ersetzt die
//!   vielen Einzeldateien des alten Snapshot-Caches
//! - `meta`: Zähler und Flags
//! - `history`: Pfad → zuletzt gesehene Roh-Hashes (SHA-256) – Grundlage für „Wiederherstellen nur auf
//!   eine Fassung, die der Agent selbst gesehen hat“ (Sicherheitsprüfung K1)
//! - `actions`: Aktions-ID → Zeitpunkt, Stand, Meldung – jede Aktion der Zentrale läuft höchstens einmal
//!   (auch über Neustarts), IDs werden `ACTIONS_KEEP` lang behalten
//!
//! Eingebettet (redb, reines Rust, eine Datei, kein Dienst). Im RAM liegen nur
//! der redb-Seiten-Cache (begrenzt) und ein Puffer noch nicht geschriebener
//! Änderungen, der gebündelt geschrieben wird.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use redb::{Database, Durability, ReadableTable, ReadableTableMetadata, TableDefinition};

use crate::event::FileMeta;

const STATE: TableDefinition<&str, &[u8]> = TableDefinition::new("state");
const BLOBS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blobs");
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");
const HISTORY: TableDefinition<&str, &[u8]> = TableDefinition::new("history");

const ACTIONS: TableDefinition<u64, &[u8]> = TableDefinition::new("actions");

/// So viele zuletzt gesehene Fassungen je Pfad merkt sich der Agent.
pub const HISTORY_MAX: usize = 16;
/// so lange bleiben ausgeführte Aktions-IDs gespeichert
pub const ACTIONS_KEEP: Duration = Duration::from_secs(30 * 24 * 3600);

/// Stand einer Aktion der Zentrale
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionRun {
    /// begonnen, Ergebnis (noch) nicht gespeichert – läuft gerade oder wurde durch einen Neustart unterbrochen
    Running { ts_ns: i64 },
    Done { ts_ns: i64, ok: bool, message: String },
}

impl ActionRun {
    fn encode(&self) -> Vec<u8> {
        let (ts, st, msg) = match self {
            ActionRun::Running { ts_ns } => (*ts_ns, 0u8, ""),
            ActionRun::Done { ts_ns, ok, message } => (*ts_ns, if *ok { 1 } else { 2 }, message.as_str()),
        };
        let mut v = ts.to_le_bytes().to_vec();
        v.push(st);
        // Meldung gekürzt (an Zeichengrenze)
        let mut end = msg.len().min(500);
        while !msg.is_char_boundary(end) {
            end -= 1;
        }
        v.extend_from_slice(&msg.as_bytes()[..end]);
        v
    }

    fn decode(b: &[u8]) -> Option<ActionRun> {
        let ts_ns = i64::from_le_bytes(b.get(..8)?.try_into().ok()?);
        Some(match b.get(8)? {
            0 => ActionRun::Running { ts_ns },
            s => ActionRun::Done { ts_ns, ok: *s == 1, message: String::from_utf8_lossy(&b[9..]).into_owned() },
        })
    }
}

/// Zustand einer Datei.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    /// Hash des Rohinhalts (bei Symlinks: Hash des Ziels)
    pub hash: [u8; 32],
    /// Hash der gespeicherten (ggf. maskierten) Fassung = Diff-Basis
    pub stored: Option<[u8; 32]>,
    pub meta: FileMeta,
}

impl Entry {
    fn encode(&self) -> Vec<u8> {
        let caps = self.meta.caps.as_deref().and_then(|c| hex::decode(c).ok()).unwrap_or_default();
        let mut v = Vec::with_capacity(1 + 32 + 32 + 48 + 1 + caps.len());
        let flags = (self.stored.is_some() as u8) | ((!caps.is_empty() as u8) << 1);
        v.push(flags);
        v.extend_from_slice(&self.hash);
        if let Some(s) = &self.stored {
            v.extend_from_slice(s);
        }
        let m = &self.meta;
        v.extend_from_slice(&m.size.to_le_bytes());
        v.extend_from_slice(&m.mode.to_le_bytes());
        v.extend_from_slice(&m.uid.to_le_bytes());
        v.extend_from_slice(&m.gid.to_le_bytes());
        v.extend_from_slice(&m.ino.to_le_bytes());
        v.extend_from_slice(&m.mtime_ns.to_le_bytes());
        v.extend_from_slice(&m.ctime_ns.to_le_bytes());
        if !caps.is_empty() {
            v.push(caps.len().min(255) as u8);
            v.extend_from_slice(&caps[..caps.len().min(255)]);
        }
        v
    }

    fn decode(b: &[u8]) -> Option<Entry> {
        let flags = *b.first()?;
        let mut i = 1;
        let take = |i: &mut usize, n: usize| -> Option<&[u8]> {
            let s = b.get(*i..*i + n)?;
            *i += n;
            Some(s)
        };
        let hash: [u8; 32] = take(&mut i, 32)?.try_into().ok()?;
        let stored = if flags & 1 != 0 { Some(take(&mut i, 32)?.try_into().ok()?) } else { None };
        let u64_ = |s: &[u8]| u64::from_le_bytes(s.try_into().unwrap());
        let u32_ = |s: &[u8]| u32::from_le_bytes(s.try_into().unwrap());
        let size = u64_(take(&mut i, 8)?);
        let mode = u32_(take(&mut i, 4)?);
        let uid = u32_(take(&mut i, 4)?);
        let gid = u32_(take(&mut i, 4)?);
        let ino = u64_(take(&mut i, 8)?);
        let mtime_ns = u64_(take(&mut i, 8)?) as i64;
        let ctime_ns = u64_(take(&mut i, 8)?) as i64;
        let caps = if flags & 2 != 0 {
            let n = *take(&mut i, 1)?.first()? as usize;
            Some(hex::encode(take(&mut i, n)?))
        } else {
            None
        };
        Some(Entry { hash, stored, meta: FileMeta { size, mode, uid, gid, ino, mtime_ns, ctime_ns, caps } })
    }
}

/// Hex-Hash (aus `hash::hash_bytes`) → 32 Byte.
pub fn hash_from_hex(h: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Ok(v) = hex::decode(h) {
        let n = v.len().min(32);
        out[..n].copy_from_slice(&v[..n]);
    }
    out
}

#[derive(Default)]
struct Pending {
    /// None = gelöscht
    state: HashMap<String, Option<Entry>>,
    blobs: HashMap<[u8; 32], Vec<u8>>,
    /// neu gesehene Roh-Hashes je Pfad (älteste zuerst)
    hist: HashMap<String, Vec<[u8; 32]>>,
    bytes: usize,
}

pub struct State {
    db: Database,
    pending: Mutex<Pending>,
    blob_bytes: AtomicU64,
    blob_budget: u64,
    last_durable: Mutex<Instant>,
    path: String,
}

/// Puffer wird geschrieben, wenn er größer als das wird (Einträge bzw. Bytes).
const FLUSH_ENTRIES: usize = 20_000;
const FLUSH_BYTES: usize = 16 * 1024 * 1024;

impl State {
    pub fn open(path: &str, cache_mb: usize, blob_budget: u64) -> Result<Arc<State>> {
        if let Some(d) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(d)?;
        }
        let db = Database::builder().set_cache_size(cache_mb * 1024 * 1024).create(path)?;
        let txn = db.begin_write()?;
        {
            txn.open_table(STATE)?;
            txn.open_table(BLOBS)?;
            txn.open_table(META)?;
            txn.open_table(HISTORY)?;
            txn.open_table(ACTIONS)?;
        }
        txn.commit()?;
        let blob_bytes = {
            let r = db.begin_read()?;
            let m = r.open_table(META)?;
            let v = m.get("blob_bytes")?.map(|g| g.value()).unwrap_or(0);
            v
        };
        let s = Arc::new(State {
            db,
            pending: Mutex::new(Pending::default()),
            blob_bytes: AtomicU64::new(blob_bytes),
            blob_budget,
            last_durable: Mutex::new(Instant::now()),
            path: path.to_string(),
        });
        // Hintergrund: Puffer jede Sekunde schreiben, alle 30 s dauerhaft (fsync)
        let w = Arc::downgrade(&s);
        std::thread::Builder::new()
            .name("state-flush".into())
            .spawn(move || loop {
                std::thread::sleep(Duration::from_secs(1));
                let Some(s) = w.upgrade() else { break };
                let durable = s.last_durable.lock().unwrap().elapsed() >= Duration::from_secs(30);
                let _ = s.flush(durable);
            })?;
        Ok(s)
    }

    pub fn get(&self, path: &str) -> Option<Entry> {
        if let Some(e) = self.pending.lock().unwrap().state.get(path) {
            return e.clone();
        }
        let r = self.db.begin_read().ok()?;
        let t = r.open_table(STATE).ok()?;
        let g = t.get(path).ok()??;
        Entry::decode(g.value())
    }

    pub fn put(&self, path: &str, e: Entry) {
        let full = {
            let mut p = self.pending.lock().unwrap();
            p.bytes += path.len() + 120;
            p.state.insert(path.to_string(), Some(e));
            p.state.len() >= FLUSH_ENTRIES || p.bytes >= FLUSH_BYTES
        };
        if full {
            let _ = self.flush(false);
        }
    }

    pub fn remove(&self, path: &str) {
        let full = {
            let mut p = self.pending.lock().unwrap();
            p.bytes += path.len() + 16;
            p.state.insert(path.to_string(), None);
            p.state.len() >= FLUSH_ENTRIES
        };
        if full {
            let _ = self.flush(false);
        }
    }

    /// Roh-Hash (SHA-256) einer Fassung merken, die der Agent selbst gelesen hat.
    pub fn remember(&self, path: &str, h: &[u8; 32]) {
        let full = {
            let mut p = self.pending.lock().unwrap();
            let v = p.hist.entry(path.to_string()).or_default();
            if v.last() == Some(h) {
                return;
            }
            v.retain(|x| x != h);
            v.push(*h);
            if v.len() > HISTORY_MAX {
                v.remove(0);
            }
            p.bytes += path.len() + 32;
            p.bytes >= FLUSH_BYTES
        };
        if full {
            let _ = self.flush(false);
        }
    }

    /// Hat der Agent für genau diesen Pfad schon einmal eine Fassung mit diesem Roh-Hash gesehen?
    pub fn seen_hash(&self, path: &str, h: &[u8; 32]) -> bool {
        if self.pending.lock().unwrap().hist.get(path).is_some_and(|v| v.contains(h)) {
            return true;
        }
        let Ok(r) = self.db.begin_read() else { return false };
        let Ok(t) = r.open_table(HISTORY) else { return false };
        let Ok(Some(g)) = t.get(path) else { return false };
        let found = g.value().chunks_exact(32).any(|c| c == h.as_slice());
        found
    }

    pub fn blob_exists(&self, h: &[u8; 32]) -> bool {
        if self.pending.lock().unwrap().blobs.contains_key(h) {
            return true;
        }
        self.db
            .begin_read()
            .ok()
            .and_then(|r| r.open_table(BLOBS).ok())
            .and_then(|t| t.get(h.as_slice()).ok().flatten().map(|_| ()))
            .is_some()
    }

    /// Inhalt speichern (zstd). `false`, wenn das Budget erschöpft ist.
    pub fn blob_put(&self, h: &[u8; 32], data: &[u8]) -> bool {
        if self.blob_exists(h) {
            return true;
        }
        let Ok(comp) = zstd::encode_all(data, 3) else { return false };
        if self.blob_bytes.load(Ordering::Relaxed) + comp.len() as u64 > self.blob_budget {
            return false;
        }
        self.blob_bytes.fetch_add(comp.len() as u64, Ordering::Relaxed);
        let full = {
            let mut p = self.pending.lock().unwrap();
            p.bytes += comp.len();
            p.blobs.insert(*h, comp);
            p.bytes >= FLUSH_BYTES
        };
        if full {
            let _ = self.flush(false);
        }
        true
    }

    pub fn blob_get(&self, h: &[u8; 32]) -> Option<Vec<u8>> {
        let comp = {
            let p = self.pending.lock().unwrap();
            p.blobs.get(h).cloned()
        };
        let comp = match comp {
            Some(c) => c,
            None => {
                let r = self.db.begin_read().ok()?;
                let t = r.open_table(BLOBS).ok()?;
                let g = t.get(h.as_slice()).ok()??;
                g.value().to_vec()
            }
        };
        zstd::decode_all(&comp[..]).ok()
    }

    /// Puffer schreiben. `durable` = mit fsync.
    pub fn flush(&self, durable: bool) -> Result<()> {
        let mut p = self.pending.lock().unwrap();
        if p.state.is_empty() && p.blobs.is_empty() && p.hist.is_empty() && !durable {
            return Ok(());
        }
        let mut txn = self.db.begin_write()?;
        txn.set_durability(if durable { Durability::Immediate } else { Durability::None });
        {
            let mut t = txn.open_table(STATE)?;
            for (k, v) in p.state.iter() {
                match v {
                    Some(e) => {
                        t.insert(k.as_str(), e.encode().as_slice())?;
                    }
                    None => {
                        t.remove(k.as_str())?;
                    }
                }
            }
            let mut b = txn.open_table(BLOBS)?;
            for (k, v) in p.blobs.iter() {
                b.insert(k.as_slice(), v.as_slice())?;
            }
            let mut hst = txn.open_table(HISTORY)?;
            for (k, new) in p.hist.iter() {
                let mut v: Vec<[u8; 32]> = match hst.get(k.as_str())? {
                    Some(g) => g.value().chunks_exact(32).map(|c| c.try_into().unwrap()).collect(),
                    None => Vec::new(),
                };
                for h in new {
                    v.retain(|x| x != h);
                    v.push(*h);
                }
                let skip = v.len().saturating_sub(HISTORY_MAX);
                let flat: Vec<u8> = v[skip..].iter().flatten().copied().collect();
                hst.insert(k.as_str(), flat.as_slice())?;
            }
            let mut m = txn.open_table(META)?;
            m.insert("blob_bytes", self.blob_bytes.load(Ordering::Relaxed))?;
        }
        txn.commit()?;
        // Puffer freigeben (inkl. Kapazität, damit RSS wieder sinkt)
        *p = Pending::default();
        if durable {
            *self.last_durable.lock().unwrap() = Instant::now();
        }
        Ok(())
    }

    /// Aktion beginnen: atomar „noch nie gesehen → als laufend vermerken“ (dauerhaft, vor der Ausführung).
    /// `None` = darf jetzt laufen; sonst der bisherige Stand (nicht erneut ausführen). Räumt dabei IDs auf, die älter
    /// als `ACTIONS_KEEP` sind.
    pub fn action_begin(&self, id: u64, now_ns: i64) -> Result<Option<ActionRun>> {
        let mut txn = self.db.begin_write()?;
        txn.set_durability(Durability::Immediate);
        let prev = {
            let mut t = txn.open_table(ACTIONS)?;
            let prev = t.get(id)?.map(|g| ActionRun::decode(g.value()).unwrap_or(ActionRun::Running { ts_ns: 0 }));
            let cutoff = now_ns - ACTIONS_KEEP.as_nanos() as i64;
            let old: Vec<u64> = t
                .iter()?
                .filter_map(|r| r.ok())
                .filter(|(_, v)| v.value().get(..8).and_then(|b| b.try_into().ok()).map(i64::from_le_bytes).is_some_and(|ts| ts < cutoff))
                .map(|(k, _)| k.value())
                .collect();
            for k in old {
                if k != id {
                    t.remove(k)?;
                }
            }
            if prev.is_none() {
                t.insert(id, ActionRun::Running { ts_ns: now_ns }.encode().as_slice())?;
            }
            prev
        };
        txn.commit()?;
        Ok(prev)
    }

    /// Ergebnis einer Aktion speichern (für erneute Meldung bei Wiederholung).
    pub fn action_finish(&self, id: u64, now_ns: i64, ok: bool, message: &str) -> Result<()> {
        let mut txn = self.db.begin_write()?;
        txn.set_durability(Durability::Immediate);
        txn.open_table(ACTIONS)?.insert(id, ActionRun::Done { ts_ns: now_ns, ok, message: message.to_string() }.encode().as_slice())?;
        txn.commit()?;
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.meta_get("complete") == 1
    }

    pub fn set_complete(&self, v: bool) -> Result<()> {
        self.flush(false)?;
        let mut txn = self.db.begin_write()?;
        txn.set_durability(Durability::Immediate);
        txn.open_table(META)?.insert("complete", v as u64)?;
        txn.commit()?;
        Ok(())
    }

    fn meta_get(&self, k: &str) -> u64 {
        self.db
            .begin_read()
            .ok()
            .and_then(|r| r.open_table(META).ok())
            .and_then(|t| t.get(k).ok().flatten().map(|g| g.value()))
            .unwrap_or(0)
    }

    /// Anzahl bekannter Pfade (ohne ungeschriebenen Puffer).
    pub fn count(&self) -> u64 {
        self.db
            .begin_read()
            .ok()
            .and_then(|r| r.open_table(STATE).ok())
            .and_then(|t| t.len().ok())
            .unwrap_or(0)
    }

    /// Bekannte Pfade unterhalb von `root`, deren Datei nicht mehr existiert.
    /// Läuft über die sortierte Tabelle, ohne alle Pfade in den RAM zu laden.
    pub fn missing_under(&self, root: &str) -> Result<Vec<String>> {
        self.flush(false)?;
        let prefix = if root == "/" { "/".to_string() } else { format!("{}/", root.trim_end_matches('/')) };
        let mut out = Vec::new();
        let r = self.db.begin_read()?;
        let t = r.open_table(STATE)?;
        for item in t.range(prefix.as_str()..)? {
            let (k, _) = item?;
            let k = k.value();
            if !k.starts_with(&prefix) {
                break;
            }
            if std::fs::symlink_metadata(k).is_err() {
                out.push(k.to_string());
            }
        }
        Ok(out)
    }

    pub fn blob_bytes(&self) -> u64 {
        self.blob_bytes.load(Ordering::Relaxed)
    }

    pub fn file_bytes(&self) -> u64 {
        std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> FileMeta {
        FileMeta { size: 10, mode: 0o100644, uid: 0, gid: 0, ino: 42, mtime_ns: 1, ctime_ns: 2, caps: Some("0100000200".into()) }
    }

    #[test]
    fn roundtrip_and_persist() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s.redb").to_string_lossy().into_owned();
        {
            let s = State::open(&p, 4, 1 << 20).unwrap();
            let e = Entry { hash: [7; 32], stored: Some([9; 32]), meta: meta() };
            s.put("/etc/passwd", e.clone());
            assert_eq!(s.get("/etc/passwd"), Some(e.clone()));
            assert!(s.blob_put(&[9; 32], b"inhalt"));
            s.flush(true).unwrap();
            assert_eq!(s.get("/etc/passwd"), Some(e));
            s.remove("/etc/passwd");
            assert_eq!(s.get("/etc/passwd"), None);
            s.put("/etc/hosts", Entry { hash: [1; 32], stored: None, meta: meta() });
            s.set_complete(true).unwrap();
            s.flush(true).unwrap();
        }
        let s = State::open(&p, 4, 1 << 20).unwrap();
        assert!(s.is_complete());
        assert_eq!(s.get("/etc/passwd"), None);
        assert_eq!(s.get("/etc/hosts").unwrap().hash, [1; 32]);
        assert_eq!(s.blob_get(&[9; 32]).unwrap(), b"inhalt");
        assert_eq!(s.count(), 1);
        // /etc/hosts existiert auf dem Testsystem evtl.; ein erfundener Pfad nicht
        s.put("/nicht/vorhanden/x", Entry { hash: [2; 32], stored: None, meta: meta() });
        assert_eq!(s.missing_under("/nicht").unwrap(), vec!["/nicht/vorhanden/x".to_string()]);
    }

    #[test]
    fn history_of_seen_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("h.redb").to_string_lossy().into_owned();
        {
            let s = State::open(&p, 4, 1 << 20).unwrap();
            s.remember("/var/www/a.php", &[1; 32]);
            s.remember("/var/www/a.php", &[2; 32]);
            assert!(s.seen_hash("/var/www/a.php", &[1; 32]));
            s.flush(true).unwrap();
            s.remember("/var/www/a.php", &[3; 32]);
            s.flush(true).unwrap();
        }
        let s = State::open(&p, 4, 1 << 20).unwrap();
        for h in [1u8, 2, 3] {
            assert!(s.seen_hash("/var/www/a.php", &[h; 32]), "{h}");
        }
        // nur für genau diesen Pfad
        assert!(!s.seen_hash("/var/www/b.php", &[1; 32]));
        assert!(!s.seen_hash("/var/www/a.php", &[9; 32]));
        // begrenzt: älteste Fassungen fallen heraus
        for i in 10..(10 + HISTORY_MAX as u8) {
            s.remember("/var/www/a.php", &[i; 32]);
        }
        s.flush(false).unwrap();
        assert!(!s.seen_hash("/var/www/a.php", &[1; 32]));
        assert!(s.seen_hash("/var/www/a.php", &[10; 32]));
    }

    #[test]
    fn actions_run_once_and_expire() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.redb").to_string_lossy().into_owned();
        let day = 24 * 3600 * 1_000_000_000i64;
        let t0 = 100 * day;
        {
            let s = State::open(&p, 4, 1 << 20).unwrap();
            assert_eq!(s.action_begin(7, t0).unwrap(), None);
            // läuft noch → nicht erneut
            assert_eq!(s.action_begin(7, t0 + 1).unwrap(), Some(ActionRun::Running { ts_ns: t0 }));
            s.action_finish(7, t0 + 2, true, "1.2.3.4 gesperrt").unwrap();
            assert_eq!(s.action_begin(8, t0 + 3).unwrap(), None); // unterbrochen (kein finish)
        }
        // über Neustart hinweg
        let s = State::open(&p, 4, 1 << 20).unwrap();
        assert_eq!(s.action_begin(7, t0 + 10).unwrap(), Some(ActionRun::Done { ts_ns: t0 + 2, ok: true, message: "1.2.3.4 gesperrt".into() }));
        assert!(matches!(s.action_begin(8, t0 + 10).unwrap(), Some(ActionRun::Running { .. })));
        // nach 30 Tagen vergessen
        assert_eq!(s.action_begin(9, t0 + 31 * day).unwrap(), None);
        assert_eq!(s.action_begin(7, t0 + 31 * day).unwrap(), None);
        // lange Meldung mit Umlauten: gekürzt, gültiges UTF-8
        s.action_finish(10, t0, false, &"ä".repeat(400)).unwrap();
        let Some(ActionRun::Done { message, ok, .. }) = s.action_begin(10, t0).unwrap() else { panic!() };
        assert!(!ok && message.len() <= 500 && message.chars().all(|c| c == 'ä'));
    }

    #[test]
    fn budget() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("b.redb").to_string_lossy().into_owned();
        let s = State::open(&p, 4, 64).unwrap();
        let big: Vec<u8> = (0..10_000u32).flat_map(|i| i.to_le_bytes()).collect();
        assert!(!s.blob_put(&[3; 32], &big), "Budget muss greifen");
    }
}
