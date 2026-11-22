//! Traffic per port (actions plan, item 10): estimated from the TCP connections (`ss -tin`: bytes per connection).
//! Incoming = service port of this server, outgoing = destination port. Limits: no UDP; connections that start and
//! end between two samples (15 s) are missing. No changes to the system (no firewall counters).
use std::collections::{HashMap, HashSet};
use std::process::Command;
use tyrosd_proto::PortTraffic;

#[derive(Default)]
pub struct PortMeter {
    last: HashMap<(String, String), (u64, u64)>,
    acc: HashMap<(u32, &'static str), (u64, u64, HashSet<(String, String)>)>,
    primed: bool,
    ss: Option<Option<&'static str>>,
}

/// listening TCP ports from /proc/net/tcp{,6} (state 0A)
pub fn listening() -> HashSet<u32> {
    let mut s = HashSet::new();
    for f in ["/proc/net/tcp", "/proc/net/tcp6"] {
        for l in std::fs::read_to_string(f).unwrap_or_default().lines().skip(1) {
            let c: Vec<&str> = l.split_whitespace().collect();
            if c.len() > 3 && c[3] == "0A" {
                if let Some(p) = c[1].rsplit(':').next().and_then(|h| u32::from_str_radix(h, 16).ok()) {
                    s.insert(p);
                }
            }
        }
    }
    s
}

fn port_of(addr: &str) -> Option<u32> {
    addr.rsplit(':').next()?.parse().ok()
}

fn field(info: &str, key: &str) -> Option<u64> {
    info.split_whitespace().find_map(|t| t.strip_prefix(key)).and_then(|v| v.parse().ok())
}

/// `ss -tinH` output → [(local, peer, sent, received)]
pub fn parse_ss(out: &str) -> Vec<(String, String, u64, u64)> {
    let mut v = Vec::new();
    let mut head: Option<(String, String)> = None;
    for l in out.lines() {
        if l.starts_with(|c: char| c.is_whitespace()) {
            if let Some((loc, peer)) = head.take() {
                let tx = field(l, "bytes_acked:").or_else(|| field(l, "bytes_sent:")).unwrap_or(0);
                let rx = field(l, "bytes_received:").unwrap_or(0);
                v.push((loc, peer, tx, rx));
            }
        } else {
            let c: Vec<&str> = l.split_whitespace().collect();
            // State Recv-Q Send-Q Local Peer [process]
            head = (c.len() >= 5 && c[0] != "LISTEN").then(|| (c[3].to_string(), c[4].to_string()));
        }
    }
    v
}

impl PortMeter {
    fn ss_path(&mut self) -> Option<&'static str> {
        *self.ss.get_or_insert_with(|| ["/usr/bin/ss", "/bin/ss", "/usr/sbin/ss", "/sbin/ss"].into_iter().find(|p| std::path::Path::new(p).exists()))
    }

    pub fn sample(&mut self) {
        let Some(ss) = self.ss_path() else { return };
        let Ok(o) = Command::new(ss).args(["-tinH"]).output() else { return };
        self.feed(&String::from_utf8_lossy(&o.stdout), &listening());
    }

    pub fn feed(&mut self, out: &str, listen: &HashSet<u32>) {
        let mut cur = HashMap::new();
        for (loc, peer, tx, rx) in parse_ss(out).into_iter().take(20_000) {
            // Connections within the server (localhost) are not network traffic and would be counted twice
            if [&peer, &loc].iter().any(|a| a.starts_with("127.") || a.starts_with("[::1]") || a.starts_with("[::ffff:127.")) {
                continue;
            }
            let (Some(lp), Some(pp)) = (port_of(&loc), port_of(&peer)) else { continue };
            let key = (loc, peer);
            let (dtx, drx) = match self.last.get(&key) {
                Some(&(ltx, lrx)) => (tx.saturating_sub(ltx), rx.saturating_sub(lrx)),
                None if self.primed => (tx, rx), // new connection since the last sample
                None => (0, 0),
            };
            let k = if listen.contains(&lp) { (lp, "in") } else { (pp, "out") };
            let e = self.acc.entry(k).or_default();
            e.0 += drx;
            e.1 += dtx;
            if e.2.len() < 10_000 {
                e.2.insert(key.clone());
            }
            cur.insert(key, (tx, rx));
        }
        self.last = cur;
        self.primed = true;
    }

    /// Close the minute: the 30 ports with the most traffic
    pub fn take(&mut self) -> Vec<PortTraffic> {
        let mut v: Vec<PortTraffic> = self
            .acc
            .drain()
            .filter(|(_, (rx, tx, _))| rx + tx > 0)
            .map(|((port, dir), (rx, tx, c))| PortTraffic { port, dir: dir.into(), rx_bytes: rx, tx_bytes: tx, conns: c.len() as u32 })
            .collect();
        v.sort_by(|a, b| (b.rx_bytes + b.tx_bytes).cmp(&(a.rx_bytes + a.tx_bytes)));
        v.truncate(30);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S1: &str = "ESTAB 0 0 10.0.0.5:443 203.0.113.9:51234\n\t cubic wscale:7,7 rto:204 bytes_sent:5000 bytes_acked:4000 bytes_received:300 segs_out:10\nESTAB 0 0 10.0.0.5:40112 198.51.100.2:25\n\t cubic bytes_acked:100 bytes_received:50\nLISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n";
    const S2: &str = "ESTAB 0 0 127.0.0.1:5222 127.0.0.1:40000\n\t cubic bytes_acked:99999 bytes_received:99999\nESTAB 0 0 10.0.0.5:443 203.0.113.9:51234\n\t cubic bytes_acked:9000 bytes_received:800\nESTAB 0 0 10.0.0.5:40112 198.51.100.2:25\n\t cubic bytes_acked:20100 bytes_received:150\nESTAB 0 0 [2a01:4f8::5]:443 [2001:db8::7]:6000\n\t cubic bytes_acked:700 bytes_received:70\n";

    #[test]
    fn deltas_per_port_and_direction() {
        assert_eq!(parse_ss(S1).len(), 2);
        let listen: HashSet<u32> = [443, 22].into();
        let mut m = PortMeter::default();
        m.feed(S1, &listen); // first sample: only remember
        m.feed(S2, &listen);
        let t = m.take();
        let p443 = t.iter().find(|p| p.port == 443 && p.dir == "in").unwrap();
        assert_eq!((p443.tx_bytes, p443.rx_bytes, p443.conns), (5000 + 700, 500 + 70, 2)); // incl. new IPv6 connection
        let smtp = t.iter().find(|p| p.port == 25 && p.dir == "out").unwrap();
        assert_eq!((smtp.tx_bytes, smtp.rx_bytes), (20000, 100));
        assert_eq!(t[0].port, 25); // most traffic first
        assert!(m.take().is_empty());
    }
}
