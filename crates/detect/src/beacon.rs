//! Beaconing sample: every 30 s read the
//! connection table and record **new** outgoing connections to public addresses per (process, destination, port) as
//! the minute of the current hour (bit field). The completed hour goes with the inventory to the
//! server, which looks for regular contacts there. Read only; mapping socket → process (scan over /proc/*/fd)
//! only when there are new connections.
//!
//! A pure sample would rarely see short connections (typical HTTP beacon: 0.2–2 s). Therefore TIME_WAIT
//! counts too: after the client closes it, the connection stays in the table for 60 s – with a 30 s interval
//! every connection closed by the client is seen. A connection is the tuple (local port, destination, dest. port);
//! TIME_WAIT entries no longer have a socket – the process then comes from an earlier sighting of the same
//! connection or the same destination in this hour, otherwise "?".

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Mutex;

use serde::Serialize;

/// at most this many destinations per hour (the rest is counted but not reported individually)
pub const MAX_KEYS: usize = 500;

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct BeaconItem {
    pub process: String,
    pub exe: String,
    pub remote: String,
    pub port: u16,
    /// Bit m = at least one new connection started in minute m of the hour
    pub minutes: u64,
    /// new connections in the hour
    pub conns: u32,
    /// name of the destination as queried via DNS (since 0.5.5, empty if unknown)
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct BeaconHour {
    /// Start of the hour (Unix seconds, on the full hour)
    pub hour: u64,
    pub items: Vec<BeaconItem>,
    /// Destinations beyond MAX_KEYS (not reported individually)
    pub dropped: u32,
}

/// last completed hour (read by the inventory)
static LAST: Mutex<Option<BeaconHour>> = Mutex::new(None);

pub fn last_hour() -> Option<BeaconHour> {
    LAST.lock().ok()?.clone()
}

/// public address? (private, loopback, link-local, CGNAT, ULA … do not count)
pub fn is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_private() || a.is_loopback() || a.is_link_local() || a.is_unspecified() || a.is_broadcast() || a.is_documentation()
                || (o[0] == 100 && (64..128).contains(&o[1])))
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_public(&IpAddr::V4(v4));
            }
            let s = a.segments();
            !(a.is_loopback() || a.is_unspecified() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// Sampling interval (TIME_WAIT keeps closed connections for 60 s – a 30 s interval sees each one)
pub const INTERVAL_S: u64 = 30;

/// Connection: (local port, destination, destination port)
type Ident = (u16, IpAddr, u16);

#[derive(Default)]
pub struct Sampler {
    /// known connections with their process – only new ones count
    seen: HashMap<Ident, (String, String)>,
    /// destination → last seen process (for TIME_WAIT entries without a socket)
    by_target: HashMap<(IpAddr, u16), (String, String)>,
    hour: u64,
    cur: BTreeMap<(String, String, String, u16), (u64, u32, String)>,
    dropped: u32,
}

/// Connection from the table: (inode – 0 for TIME_WAIT, destination, destination port, local port)
pub type Row = (u64, IpAddr, u16, u16);

impl Sampler {
    /// One sample. `resolve` maps new inodes to processes (name, program) – called only when there are new
    /// connections. Returns the completed hour when a new one has started.
    pub fn observe(&mut self, now: u64, rows: &[Row], listening: &HashSet<u16>, resolve: impl FnOnce(&[u64]) -> HashMap<u64, (String, String)>) -> Option<BeaconHour> {
        let hour = now - now % 3600;
        let mut done = None;
        if self.hour != hour {
            if self.hour != 0 {
                done = Some(self.take());
            }
            self.hour = hour;
        }
        let minute = (now % 3600) / 60;
        let out: Vec<&Row> = rows.iter().filter(|(_, ip, _, lport)| is_public(ip) && !listening.contains(lport)).collect();
        let ident = |r: &Row| -> Ident { (r.3, r.1, r.2) };
        // forget connections that no longer exist (the set stays small; a local port reused later
        // then counts as a new connection)
        let present: HashSet<Ident> = rows.iter().map(ident).collect();
        self.seen.retain(|k, _| present.contains(k));
        let new: Vec<&Row> = out.iter().copied().filter(|r| !self.seen.contains_key(&ident(r))).collect();
        if new.is_empty() {
            return done;
        }
        let inodes: Vec<u64> = new.iter().map(|r| r.0).filter(|i| *i != 0).collect();
        let owners = if inodes.is_empty() { HashMap::new() } else { resolve(&inodes) };
        for r in new {
            let who = owners
                .get(&r.0)
                .filter(|_| r.0 != 0)
                .cloned()
                .or_else(|| self.by_target.get(&(r.1, r.2)).cloned())
                .unwrap_or_else(|| ("?".into(), String::new()));
            if who.0 != "?" {
                self.by_target.insert((r.1, r.2), who.clone());
            }
            self.seen.insert(ident(r), who.clone());
            let key = (who.0, who.1, r.1.to_string(), r.2);
            if !self.cur.contains_key(&key) && self.cur.len() >= MAX_KEYS {
                self.dropped += 1;
                continue;
            }
            let e = self.cur.entry(key).or_insert((0, 0, String::new()));
            e.0 |= 1u64 << minute;
            e.1 += 1;
            if e.2.is_empty() {
                if let Some(n) = crate::dns::name_of(&r.1) {
                    e.2 = n;
                }
            }
        }
        done
    }

    fn take(&mut self) -> BeaconHour {
        self.by_target.clear();
        let items = std::mem::take(&mut self.cur)
            .into_iter()
            .map(|((process, exe, remote, port), (minutes, conns, name))| BeaconItem { process, exe, remote, port, minutes, conns, name })
            .collect();
        let h = BeaconHour { hour: self.hour, items, dropped: self.dropped };
        self.dropped = 0;
        h
    }
}

/// Sample from the real system (connection table + processes)
pub fn sample(s: &mut Sampler, now: u64) {
    // 01 ESTABLISHED, 02 SYN_SENT, 06 TIME_WAIT (closed by the client, visible for 60 s)
    let rows: Vec<Row> = crate::net::with_states(&["01", "02", "06"]).into_iter().map(|c| (c.inode, c.raddr, c.rport, c.lport)).collect();
    let listening = crate::net::listening_ports();
    let done = s.observe(now, &rows, &listening, |new| {
        let owners = crate::net::socket_owners();
        new.iter()
            .filter_map(|i| {
                let pid = owners.get(i)?;
                let info = crate::proc::info(*pid)?;
                Some((*i, (info.comm, info.exe)))
            })
            .collect()
    });
    if let Some(h) = done {
        if let Ok(mut l) = LAST.lock() {
            *l = Some(h);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn public_addresses() {
        assert!(is_public(&ip("91.92.93.10")));
        assert!(!is_public(&ip("10.0.0.5")));
        assert!(!is_public(&ip("192.168.178.63")));
        assert!(!is_public(&ip("100.64.1.1")));
        assert!(!is_public(&ip("127.0.0.1")));
        assert!(!is_public(&ip("::ffff:10.1.1.1")));
        assert!(!is_public(&ip("fd00::1")));
        assert!(is_public(&ip("2a01:4f8::1")));
    }

    #[test]
    fn counts_new_outgoing_connections_per_minute_and_rolls_hours() {
        let mut s = Sampler::default();
        let listen: HashSet<u16> = [443].into();
        let h0 = 1_795_100_400; // full hour
        let who = |new: &[u64]| new.iter().map(|i| (*i, ("curl".to_string(), "/usr/bin/curl".to_string()))).collect();
        // Minute 0: new outgoing connection; incoming (local port 443) and private ones do not count
        let rows = vec![(1, ip("91.92.93.9"), 443, 51000), (2, ip("91.92.93.10"), 51234, 443), (3, ip("10.0.0.2"), 3306, 52000)];
        assert!(s.observe(h0 + 5, &rows, &listen, who).is_none());
        // the same connection 15 s later: not new
        s.observe(h0 + 20, &rows, &listen, |_| panic!("no new connection – nothing to resolve"));
        // Minutes 5 and 10: new connections to the same destination
        s.observe(h0 + 300, &[(4, ip("91.92.93.9"), 443, 51001)], &listen, who);
        s.observe(h0 + 600, &[(5, ip("91.92.93.9"), 443, 51002)], &listen, who);
        // next hour → the completed hour is returned
        let done = s.observe(h0 + 3600 + 1, &[], &listen, who).expect("hour completed");
        assert_eq!(done.hour, h0);
        assert_eq!(done.items.len(), 1);
        let it = &done.items[0];
        assert_eq!((it.process.as_str(), it.remote.as_str(), it.port, it.conns), ("curl", "91.92.93.9", 443, 3));
        assert_eq!(it.minutes, 1 | (1 << 5) | (1 << 10));
    }

    #[test]
    fn carries_dns_name_of_target() {
        let mut s = Sampler::default();
        let h0 = 1_795_100_400;
        crate::dns::remember(ip("91.92.93.77"), "ip-lookup.example");
        let who = |new: &[u64]| new.iter().map(|i| (*i, ("apache2".to_string(), "/usr/sbin/apache2".to_string()))).collect();
        s.observe(h0 + 5, &[(1, ip("91.92.93.77"), 80, 50000), (2, ip("91.92.93.78"), 80, 50001)], &HashSet::new(), who);
        let done = s.observe(h0 + 3600, &[], &HashSet::new(), |_| HashMap::new()).unwrap();
        let named = done.items.iter().find(|i| i.remote == "91.92.93.77").unwrap();
        assert_eq!(named.name, "ip-lookup.example");
        assert_eq!(done.items.iter().find(|i| i.remote == "91.92.93.78").unwrap().name, "");
    }

    #[test]
    fn time_wait_counts_short_connections_and_keeps_process() {
        let mut s = Sampler::default();
        let h0 = 1_795_100_400;
        let none = HashSet::new();
        let who = |new: &[u64]| new.iter().map(|i| (*i, ("curl".to_string(), "/usr/bin/curl".to_string()))).collect();
        // Minute 0: connection seen open (socket 7) → process known
        s.observe(h0, &[(7, ip("91.92.93.9"), 443, 50000)], &none, who);
        // 30 s later: the same connection in TIME_WAIT (socket 0) – not new
        s.observe(h0 + 30, &[(0, ip("91.92.93.9"), 443, 50000)], &none, |_| panic!("not new"));
        // Minute 5: short connection seen only as TIME_WAIT → process from an earlier sighting of the same destination
        s.observe(h0 + 300, &[(0, ip("91.92.93.9"), 443, 50011)], &none, |_| panic!("no socket – nothing to resolve"));
        // unknown destination only as TIME_WAIT → process "?"
        s.observe(h0 + 330, &[(0, ip("91.92.93.50"), 8443, 50012)], &none, |_| panic!("no socket"));
        let done = s.observe(h0 + 3600, &[], &none, |_| HashMap::new()).unwrap();
        let curl = done.items.iter().find(|i| i.remote == "91.92.93.9").unwrap();
        assert_eq!((curl.process.as_str(), curl.conns, curl.minutes), ("curl", 2, 1 | (1 << 5)));
        let unknown = done.items.iter().find(|i| i.remote == "91.92.93.50").unwrap();
        assert_eq!(unknown.process, "?");
    }

    #[test]
    fn caps_number_of_targets() {
        let mut s = Sampler::default();
        let h0 = 1_795_100_400;
        let rows: Vec<Row> = (0..(MAX_KEYS as u64 + 7)).map(|i| (i + 1, IpAddr::V4(std::net::Ipv4Addr::from(0x5b00_0000u32 + i as u32)), 443, 40000)).collect();
        s.observe(h0, &rows, &HashSet::new(), |new| new.iter().map(|i| (*i, ("x".to_string(), String::new()))).collect());
        let done = s.observe(h0 + 3600, &[], &HashSet::new(), |_| HashMap::new()).unwrap();
        assert_eq!(done.items.len(), MAX_KEYS);
        assert_eq!(done.dropped, 7);
    }
}
