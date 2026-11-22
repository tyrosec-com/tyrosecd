//! Persistent queue (spool) with a hash chain.
//!
//! Every message gets a gapless `seq` when enqueued and
//! `prev_hash` = SHA-256 of the encoded predecessor envelope. The chain continues
//! across restarts (state in the same file). Deletion happens only
//! once the central server has acknowledged up to a `seq`.
//!
//! Hard limit: if the central server is unreachable for a long time, the spool does not grow until the disk is full.
//! Above the limit (`spool_max_mb`, at most 10 % of the free space) the **oldest** messages are
//! discarded – file events, contents, metrics and inventory first, only then logins, detections,
//! check reports, action results and heartbeats. The chain stays gapless: everything from the first
//! discarded message on is renumbered and re-chained (never messages currently in flight), and
//! then a lifecycle message `spool_dropped` follows with the number of discarded messages
//! (`detail` = "dropped=N bytes=B total=T limit_mb=L") – so the central server sees the loss.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::Result;
use prost::Message;
use redb::{Database, Durability, ReadableTable, ReadableTableMetadata, TableDefinition};
use sha2::Digest;
use tyrosd_proto::{envelope::Body, Envelope};

const ITEMS: TableDefinition<u64, &[u8]> = TableDefinition::new("items");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

/// default of the hard limit (agent.toml `spool_max_mb`)
pub const DEFAULT_HARD_MAX: u64 = 512 * 1024 * 1024;
/// smallest hard limit (configuration)
const MIN_HARD_MAX: u64 = 64 * 1024;
/// lower bound of the limit derived from free space (otherwise nothing would work on an almost full disk)
const DISK_FLOOR: u64 = 4 * 1024 * 1024;
/// after discarding, the spool is at most this full (percent of the limit) – so that re-chaining is rare
const DROP_TARGET_PCT: u64 = 80;
/// how often the free space is re-determined
const DISK_RECHECK: Duration = Duration::from_secs(60);

struct Chain {
    /// last seq
    seq: u64,
    /// hash of the last envelope
    hash: Vec<u8>,
    /// bytes used (encoded envelopes)
    bytes: u64,
    /// highest seq that the sender has read and the central server has not yet acknowledged – up to it nothing is
    /// discarded or renumbered
    inflight: u64,
    /// effective hard limit and the time it was determined
    cap: u64,
    cap_at: Option<Instant>,
}

pub struct Spool {
    db: Database,
    chain: Mutex<Chain>,
    /// soft limit: above it contents/diffs are omitted
    pub max_bytes: u64,
    /// hard limit (configured); additionally at most 10 % of the free space is effective
    pub hard_max: u64,
    dir: String,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SpoolStats {
    pub items: u64,
    pub bytes: u64,
    pub last_seq: u64,
    /// messages discarded in total because of the hard limit (since the spool was created)
    pub dropped_total: u64,
}

fn u64_from(b: &[u8]) -> u64 {
    b.try_into().map(u64::from_le_bytes).unwrap_or(0)
}

/// Effective hard limit: configured, but at most 10 % of the free space (our own bytes count as free,
/// otherwise the limit would shrink as we grow), and at least `DISK_FLOOR`.
pub fn effective_cap(hard_max: u64, disk_free: Option<u64>, own_bytes: u64) -> u64 {
    match disk_free {
        Some(f) => hard_max.min((f.saturating_add(own_bytes) / 10).max(DISK_FLOOR)),
        None => hard_max,
    }
}

/// free space (available to non-root) on the file system of `dir`
fn disk_free(dir: &str) -> Option<u64> {
    let c = std::ffi::CString::new(dir).ok()?;
    // SAFETY: valid C string and pointer, return value checked
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    Some((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

/// Field number of the content (oneof `body`, tags 10–18) from the encoded envelope, without decoding everything
fn body_tag(raw: &[u8]) -> Option<u32> {
    fn varint(b: &[u8], i: &mut usize) -> Option<u64> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let x = *b.get(*i)?;
            *i += 1;
            v |= u64::from(x & 0x7f) << shift;
            if x & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }
    let mut i = 0;
    while i < raw.len() {
        let key = varint(raw, &mut i)?;
        let (field, wire) = ((key >> 3) as u32, key & 7);
        if field >= 10 {
            return Some(field);
        }
        match wire {
            0 => {
                varint(raw, &mut i)?;
            }
            1 => i += 8,
            2 => {
                let l = varint(raw, &mut i)? as usize;
                i = i.checked_add(l)?;
            }
            5 => i += 4,
            _ => return None,
        }
    }
    None
}

/// Kept longer: heartbeat (13), check (14), login (15), detection (17), action result (18), unknown.
/// Discarded first: file event (10), content (11), metrics (12), inventory (16).
fn important(raw: &[u8]) -> bool {
    !matches!(body_tag(raw), Some(10 | 11 | 12 | 16))
}

impl Spool {
    pub fn open(path: &str, max_bytes: u64) -> Result<Spool> {
        Self::open_limited(path, max_bytes, DEFAULT_HARD_MAX)
    }

    /// `max_bytes` = soft limit (omit contents), `hard_max` = hard limit (discard oldest messages)
    pub fn open_limited(path: &str, max_bytes: u64, hard_max: u64) -> Result<Spool> {
        let dir = match std::path::Path::new(path).parent() {
            Some(d) if !d.as_os_str().is_empty() => {
                std::fs::create_dir_all(d)?;
                d.to_string_lossy().into_owned()
            }
            _ => ".".into(),
        };
        let db = Database::builder().set_cache_size(4 * 1024 * 1024).create(path)?;
        let txn = db.begin_write()?;
        {
            txn.open_table(ITEMS)?;
            txn.open_table(META)?;
        }
        txn.commit()?;
        let (seq, hash, bytes) = {
            let r = db.begin_read()?;
            let m = r.open_table(META)?;
            let seq = m.get("last_seq")?.map(|g| u64_from(g.value())).unwrap_or(0);
            let hash = m.get("last_hash")?.map(|g| g.value().to_vec()).unwrap_or_default();
            let bytes = m.get("bytes")?.map(|g| u64_from(g.value())).unwrap_or(0);
            (seq, hash, bytes)
        };
        let hard_max = hard_max.max(MIN_HARD_MAX);
        let chain = Chain { seq, hash, bytes, inflight: 0, cap: hard_max, cap_at: None };
        Ok(Spool { db, chain: Mutex::new(chain), max_bytes, hard_max, dir })
    }

    /// effective hard limit (free space re-determined at most once per minute)
    fn cap(&self, c: &mut Chain) -> u64 {
        if c.cap_at.is_none_or(|t| t.elapsed() >= DISK_RECHECK) {
            c.cap = effective_cap(self.hard_max, disk_free(&self.dir), c.bytes);
            c.cap_at = Some(Instant::now());
        }
        c.cap
    }

    /// Enqueue a message. Returns the assigned `seq`.
    pub fn push(&self, ts_ns: i64, body: Body) -> Result<u64> {
        let mut c = self.chain.lock().unwrap();
        let mut env = Envelope { seq: 0, prev_hash: c.hash.clone(), ts_ns, body: Some(body) };
        let need = env.encoded_len() as u64 + 16;
        let cap = self.cap(&mut c);
        if c.bytes + need > cap {
            let target = (cap / 100 * DROP_TARGET_PCT).saturating_sub(need + 1024);
            let need_free = c.bytes.saturating_sub(target);
            let (n, freed) = self.drop_oldest(&mut c, need_free)?;
            if n > 0 {
                let total = self.meta_u64("dropped_total") + n;
                eprintln!(
                    "[tyrosecd] spool full (limit {} KB, central service unreachable?): {n} oldest messages ({} KB) dropped",
                    cap >> 10,
                    freed >> 10
                );
                let detail = format!("dropped={n} bytes={freed} total={total} limit_mb={}", cap >> 20);
                let marker = Body::Lifecycle(tyrosd_proto::Lifecycle { kind: "spool_dropped".into(), host: None, detail });
                let mark = Envelope { seq: c.seq + 1, prev_hash: c.hash.clone(), ts_ns, body: Some(marker) };
                self.insert(&mut c, mark, Some(total))?;
            }
        }
        env.seq = c.seq + 1;
        env.prev_hash = c.hash.clone();
        self.insert(&mut c, env, None)
    }

    fn insert(&self, c: &mut Chain, env: Envelope, dropped_total: Option<u64>) -> Result<u64> {
        let enc = env.encode_to_vec();
        let hash = sha2::Sha256::digest(&enc).to_vec();
        let mut txn = self.db.begin_write()?;
        // group commit: durability (fsync) is done by `sync()` in the sender thread (≤ 1 s)
        txn.set_durability(Durability::None);
        {
            let mut t = txn.open_table(ITEMS)?;
            t.insert(env.seq, enc.as_slice())?;
            let mut m = txn.open_table(META)?;
            m.insert("last_seq", env.seq.to_le_bytes().as_slice())?;
            m.insert("last_hash", hash.as_slice())?;
            m.insert("bytes", (c.bytes + enc.len() as u64).to_le_bytes().as_slice())?;
            if let Some(d) = dropped_total {
                m.insert("dropped_total", d.to_le_bytes().as_slice())?;
            }
        }
        txn.commit()?;
        c.seq = env.seq;
        c.hash = hash;
        c.bytes += enc.len() as u64;
        Ok(env.seq)
    }

    /// Free at least `need` bytes by discarding the oldest messages – unimportant ones first, important ones only if
    /// those are not enough. Messages in flight (`inflight`) stay untouched. Everything from the first
    /// discarded message on is renumbered and re-chained without gaps. Returns (count, bytes).
    fn drop_oldest(&self, c: &mut Chain, need: u64) -> Result<(u64, u64)> {
        if need == 0 {
            return Ok((0, 0));
        }
        let from = c.inflight + 1;
        // 1st pass (read-only): how much can be gained from the unimportant ones?
        let low_total = {
            let r = self.db.begin_read()?;
            let t = r.open_table(ITEMS)?;
            let mut low = 0u64;
            for item in t.range(from..)? {
                let (_, v) = item?;
                if !important(v.value()) {
                    low += v.value().len() as u64;
                }
            }
            low
        };
        let need_low = need.min(low_total);
        let need_high = need - need_low;
        let (mut freed_low, mut freed_high, mut n) = (0u64, 0u64, 0u64);
        // new number and predecessor hash (set from the first discarded message on)
        let mut rechain: Option<(u64, Vec<u8>)> = None;
        let mut txn = self.db.begin_write()?;
        txn.set_durability(Durability::None);
        {
            let mut t = txn.open_table(ITEMS)?;
            let mut cursor = from;
            loop {
                // read piece by piece (never the whole spool in memory); new numbers are ≤ old ones,
                // so they lie behind `cursor`
                let chunk: Vec<(u64, Vec<u8>)> =
                    t.range(cursor..)?.take(512).filter_map(|r| r.ok()).map(|(k, v)| (k.value(), v.value().to_vec())).collect();
                let Some(last) = chunk.last().map(|x| x.0) else { break };
                for (k, raw) in chunk {
                    let len = raw.len() as u64;
                    let drop = if important(&raw) {
                        let d = freed_high < need_high;
                        if d {
                            freed_high += len;
                        }
                        d
                    } else {
                        let d = freed_low < need_low;
                        if d {
                            freed_low += len;
                        }
                        d
                    };
                    if drop {
                        if rechain.is_none() {
                            // chain from here: same seq and same predecessor as the first discarded message
                            let e = Envelope::decode(raw.as_slice())?;
                            rechain = Some((k, e.prev_hash));
                        }
                        t.remove(k)?;
                        n += 1;
                        continue;
                    }
                    let Some((next, prev)) = rechain.as_mut() else { continue }; // before the first gap: unchanged
                    t.remove(k)?;
                    let Ok(mut e) = Envelope::decode(raw.as_slice()) else {
                        // unreadable: discard it too instead of breaking the chain
                        freed_low += len;
                        n += 1;
                        continue;
                    };
                    e.seq = *next;
                    e.prev_hash = std::mem::take(prev);
                    let enc = e.encode_to_vec();
                    t.insert(*next, enc.as_slice())?;
                    // size may change slightly (shorter seq varint)
                    freed_low += len;
                    freed_low = freed_low.saturating_sub(enc.len() as u64);
                    *prev = sha2::Sha256::digest(&enc).to_vec();
                    *next += 1;
                }
                cursor = last + 1;
            }
        }
        let Some((next, prev)) = rechain else {
            txn.abort()?;
            return Ok((0, 0));
        };
        let freed = freed_low + freed_high;
        let bytes = c.bytes.saturating_sub(freed);
        let (seq, hash) = (next - 1, prev);
        {
            let mut m = txn.open_table(META)?;
            m.insert("last_seq", seq.to_le_bytes().as_slice())?;
            m.insert("last_hash", hash.as_slice())?;
            m.insert("bytes", bytes.to_le_bytes().as_slice())?;
        }
        txn.commit()?;
        c.seq = seq;
        c.hash = hash;
        c.bytes = bytes;
        Ok((n, freed))
    }

    fn meta_u64(&self, k: &str) -> u64 {
        self.db
            .begin_read()
            .ok()
            .and_then(|r| r.open_table(META).ok())
            .and_then(|m| m.get(k).ok().flatten().map(|g| u64_from(g.value())))
            .unwrap_or(0)
    }

    /// Make everything enqueued so far durable (fsync).
    pub fn sync(&self) -> Result<()> {
        let mut txn = self.db.begin_write()?;
        txn.set_durability(Durability::Immediate);
        txn.commit()?;
        Ok(())
    }

    /// Is there still room for a message of this size (with content/diff)?
    pub fn has_room(&self, n: usize) -> bool {
        let mut c = self.chain.lock().unwrap();
        let cap = self.cap(&mut c);
        c.bytes + n as u64 <= self.max_bytes.min(cap)
    }

    /// Oldest messages (already encoded) up to the limits. They count as in flight until the next `ack`
    /// and are neither discarded nor renumbered until then.
    pub fn peek(&self, max_items: usize, max_bytes: usize) -> Result<Vec<(u64, Vec<u8>)>> {
        let mut c = self.chain.lock().unwrap();
        let r = self.db.begin_read()?;
        let t = r.open_table(ITEMS)?;
        let mut out = Vec::new();
        let mut bytes = 0;
        for item in t.iter()? {
            let (k, v) = item?;
            let v = v.value();
            if !out.is_empty() && (out.len() >= max_items || bytes + v.len() > max_bytes) {
                break;
            }
            bytes += v.len();
            out.push((k.value(), v.to_vec()));
        }
        if let Some((k, _)) = out.last() {
            c.inflight = c.inflight.max(*k);
        }
        Ok(out)
    }

    /// Remove everything up to and including `seq` (acknowledged by the central server).
    pub fn ack(&self, seq: u64) -> Result<u64> {
        let mut c = self.chain.lock().unwrap();
        let mut freed = 0u64;
        let mut n = 0u64;
        let mut txn = self.db.begin_write()?;
        txn.set_durability(Durability::Immediate);
        {
            let mut t = txn.open_table(ITEMS)?;
            let keys: Vec<(u64, usize)> = t
                .range(..=seq)?
                .filter_map(|r| r.ok())
                .map(|(k, v)| (k.value(), v.value().len()))
                .collect();
            for (k, len) in keys {
                t.remove(k)?;
                freed += len as u64;
                n += 1;
            }
            let mut m = txn.open_table(META)?;
            m.insert("bytes", c.bytes.saturating_sub(freed).to_le_bytes().as_slice())?;
        }
        txn.commit()?;
        c.bytes = c.bytes.saturating_sub(freed);
        // the central server's response has arrived: nothing in flight any more
        // (the sender reads again only afterwards)
        c.inflight = 0;
        Ok(n)
    }

    pub fn stats(&self) -> SpoolStats {
        let c = self.chain.lock().unwrap();
        let items = self
            .db
            .begin_read()
            .ok()
            .and_then(|r| r.open_table(ITEMS).ok())
            .and_then(|t| t.len().ok())
            .unwrap_or(0);
        SpoolStats { items, bytes: c.bytes, last_seq: c.seq, dropped_total: self.meta_u64("dropped_total") }
    }
}

/// Verifies a sequence of envelopes (for tests and the ingest).
pub fn verify_chain(prev_seq: u64, prev_hash: &[u8], items: &[Vec<u8>]) -> std::result::Result<(u64, Vec<u8>), String> {
    let mut seq = prev_seq;
    let mut hash = prev_hash.to_vec();
    for raw in items {
        let e = Envelope::decode(raw.as_slice()).map_err(|e| e.to_string())?;
        if e.seq != seq + 1 {
            return Err(format!("gap: expected seq {}, got {}", seq + 1, e.seq));
        }
        if e.prev_hash != hash {
            return Err(format!("chain broken at seq {}", e.seq));
        }
        seq = e.seq;
        hash = sha2::Sha256::digest(raw).to_vec();
    }
    Ok((seq, hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tyrosd_proto::{FileEvent, Lifecycle, LoginEvent};

    fn body(k: &str) -> Body {
        Body::Lifecycle(Lifecycle { kind: k.into(), host: None, detail: String::new() })
    }

    fn file(i: usize) -> Body {
        Body::File(FileEvent { op: "MODIFY".into(), path: format!("/var/www/{i}/{}", "x".repeat(900)), ..Default::default() })
    }

    fn login(ip: &str) -> Body {
        Body::Login(LoginEvent { service: "ssh".into(), success: true, user: "root".into(), ip: ip.into(), count: 1, ..Default::default() })
    }

    fn all(s: &Spool) -> Vec<Vec<u8>> {
        s.peek(usize::MAX, usize::MAX).unwrap().into_iter().map(|(_, v)| v).collect()
    }

    #[test]
    fn chain_survives_restart_and_ack() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("spool.redb").to_string_lossy().into_owned();
        {
            let s = Spool::open(&p, 1 << 20).unwrap();
            assert_eq!(s.push(1, body("start")).unwrap(), 1);
            assert_eq!(s.push(2, body("a")).unwrap(), 2);
        }
        let s = Spool::open(&p, 1 << 20).unwrap();
        assert_eq!(s.push(3, body("b")).unwrap(), 3);
        let items: Vec<Vec<u8>> = s.peek(10, 1 << 20).unwrap().into_iter().map(|(_, v)| v).collect();
        assert_eq!(items.len(), 3);
        let (seq, _) = verify_chain(0, &[], &items).expect("chain valid");
        assert_eq!(seq, 3);
        assert_eq!(s.ack(2).unwrap(), 2);
        assert_eq!(s.stats().items, 1);
        // detect tampering: modify the middle element
        let mut bad = items.clone();
        let last = bad[1].len() - 1;
        bad[1][last] ^= 1;
        assert!(verify_chain(0, &[], &bad).is_err());
    }

    #[test]
    fn cap_limited_by_free_disk() {
        assert_eq!(effective_cap(512 << 20, None, 0), 512 << 20);
        assert_eq!(effective_cap(512 << 20, Some(100 << 30), 0), 512 << 20);
        // 1 GiB free + 0 own → 100 MiB (10 %)
        assert_eq!(effective_cap(512 << 20, Some(1 << 30), 0) >> 20, 102);
        // own bytes count as free
        assert_eq!(effective_cap(512 << 20, Some(900 << 20), 100 << 20), 100 << 20);
        // almost full: lower bound
        assert_eq!(effective_cap(512 << 20, Some(1 << 20), 0), DISK_FLOOR);
    }

    #[test]
    fn body_kind_without_decoding() {
        let raw = |b: Body| Envelope { seq: 300, prev_hash: vec![7; 32], ts_ns: -5, body: Some(b) }.encode_to_vec();
        assert_eq!(body_tag(&raw(file(1))), Some(10));
        assert_eq!(body_tag(&raw(login("203.0.113.1"))), Some(15));
        assert!(!important(&raw(file(1))));
        assert!(important(&raw(login("203.0.113.1"))));
        assert!(important(&raw(body("start"))));
    }

    #[test]
    fn hard_limit_drops_oldest_unimportant_first() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("spool.redb").to_string_lossy().into_owned();
        let s = Spool::open_limited(&p, 1 << 20, 64 * 1024).unwrap();
        s.push(1, login("203.0.113.1")).unwrap();
        for i in 0..200 {
            s.push(2 + i as i64, file(i)).unwrap();
        }
        let st = s.stats();
        assert!(st.bytes <= 64 * 1024, "limit respected: {}", st.bytes);
        assert!(st.dropped_total > 100);
        let items = all(&s);
        // chain gapless from the start (nothing acknowledged) – no chain gap at the central server
        let (seq, _) = verify_chain(0, &[], &items).expect("chain valid");
        assert_eq!(seq, s.stats().last_seq);
        assert_eq!(items.len() as u64, s.stats().items);
        let envs: Vec<Envelope> = items.iter().map(|r| Envelope::decode(r.as_slice()).unwrap()).collect();
        // login (oldest message) survives, oldest file events are gone, the newest remains
        assert!(matches!(&envs[0].body, Some(Body::Login(_))));
        let paths: Vec<&str> = envs.iter().filter_map(|e| if let Some(Body::File(f)) = &e.body { Some(f.path.as_str()) } else { None }).collect();
        assert!(!paths.iter().any(|p| p.starts_with("/var/www/0/")));
        assert!(paths.last().unwrap().starts_with("/var/www/199/"));
        // note(s) with count; sum = total discarded
        let marks: Vec<u64> = envs
            .iter()
            .filter_map(|e| match &e.body {
                Some(Body::Lifecycle(l)) if l.kind == "spool_dropped" => {
                    l.detail.split(' ').find_map(|kv| kv.strip_prefix("dropped=")).and_then(|v| v.parse().ok())
                }
                _ => None,
            })
            .collect();
        assert!(!marks.is_empty());
        assert_eq!(marks.iter().sum::<u64>(), st.dropped_total);
        // still gapless after a restart
        drop(s);
        let s = Spool::open_limited(&p, 1 << 20, 64 * 1024).unwrap();
        s.push(999, body("start")).unwrap();
        verify_chain(0, &[], &all(&s)).expect("chain valid after restart");
    }

    #[test]
    fn important_dropped_only_when_needed_and_inflight_untouched() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("spool.redb").to_string_lossy().into_owned();
        let s = Spool::open_limited(&p, 1 << 20, 64 * 1024).unwrap();
        for i in 0..5 {
            s.push(i, file(i as usize)).unwrap();
        }
        // the sender has read the first 5, response pending
        let sent = s.peek(5, 1 << 20).unwrap();
        // only important messages left → they must give way (oldest first)
        for i in 0..400 {
            s.push(10 + i, Body::Login(LoginEvent { service: "ssh".into(), user: format!("u{i}-{}", "y".repeat(400)), ip: "198.51.100.1".into(), ..Default::default() }))
                .unwrap();
        }
        let now = s.peek(usize::MAX, usize::MAX).unwrap();
        // the 5 in flight are unchanged (same seq, same bytes)
        assert_eq!(&now[..5], &sent[..]);
        let items: Vec<Vec<u8>> = now.into_iter().map(|(_, v)| v).collect();
        verify_chain(0, &[], &items).expect("chain valid");
        assert!(s.stats().bytes <= 64 * 1024 + 8 * 1024);
        // the central server acknowledges the 5 → afterwards the beginning may be discarded too
        s.ack(5).unwrap();
        assert!(s.stats().dropped_total > 0);
    }
}
