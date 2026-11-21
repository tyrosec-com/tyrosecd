//! TCP-Verbindungen aus /proc/net/tcp{,6} und ihre Prozesse (nur lesen).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct Conn {
    pub raddr: IpAddr,
    pub rport: u16,
    pub lport: u16,
    pub inode: u64,
}

impl Conn {
    pub fn remote(&self) -> String {
        match self.raddr {
            IpAddr::V6(a) => format!("[{a}]:{}", self.rport),
            IpAddr::V4(a) => format!("{a}:{}", self.rport),
        }
    }
    pub fn remote_is_local(&self) -> bool {
        match self.raddr {
            IpAddr::V4(a) => a.is_loopback() || a.is_unspecified(),
            IpAddr::V6(a) => a.is_loopback() || a.is_unspecified() || a.to_ipv4_mapped().map(|v| v.is_loopback()).unwrap_or(false),
        }
    }
}

/// Hex-Adresse aus /proc/net/tcp (Netzwerk-Bytefolge je 32-Bit-Wort, little endian gespeichert)
pub fn parse_addr(hex: &str) -> Option<(IpAddr, u16)> {
    let (a, p) = hex.split_once(':')?;
    let port = u16::from_str_radix(p, 16).ok()?;
    let ip = match a.len() {
        8 => IpAddr::V4(Ipv4Addr::from(u32::from_str_radix(a, 16).ok()?.to_le_bytes())),
        32 => {
            let mut b = [0u8; 16];
            for i in 0..4 {
                let w = u32::from_str_radix(&a[i * 8..i * 8 + 8], 16).ok()?.to_le_bytes();
                b[i * 4..i * 4 + 4].copy_from_slice(&w);
            }
            IpAddr::V6(Ipv6Addr::from(b))
        }
        _ => return None,
    };
    Some((ip, port))
}

/// Bestehende TCP-Verbindungen (Zustand 01 = ESTABLISHED)
pub fn established() -> Vec<Conn> {
    with_states(&["01"])
}

/// Lokale Ports, auf denen der Server lauscht (Zustand 0A = LISTEN)
pub fn listening_ports() -> HashSet<u16> {
    with_states(&["0A"]).into_iter().map(|c| c.lport).collect()
}

/// Eingehende Verbindung: der lokale Port ist ein Port, auf dem der Server lauscht
/// (dann ist der entfernte Port nur der zufällige Absender-Port des Clients)
pub fn is_inbound(c: &Conn, listening: &HashSet<u16>) -> bool {
    listening.contains(&c.lport)
}

/// Verbindungen in den angegebenen Zuständen (01 ESTABLISHED, 08 CLOSE_WAIT …)
pub fn with_states(states: &[&str]) -> Vec<Conn> {
    let mut out = Vec::new();
    for f in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(s) = std::fs::read_to_string(f) else { continue };
        for l in s.lines().skip(1) {
            let c: Vec<&str> = l.split_whitespace().collect();
            if c.len() < 10 || !states.contains(&c[3]) {
                continue;
            }
            let (Some((_, lport)), Some((raddr, rport))) = (parse_addr(c[1]), parse_addr(c[2])) else { continue };
            out.push(Conn { raddr, rport, lport, inode: c[9].parse().unwrap_or(0) });
        }
    }
    out
}

/// Socket-Inode → PID (über /proc/*/fd)
pub fn socket_owners() -> HashMap<u64, u32> {
    let mut m = HashMap::new();
    let Ok(rd) = std::fs::read_dir("/proc") else { return m };
    for e in rd.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
        for fd in fds.flatten() {
            if let Some(ino) = socket_inode(&fd.path()) {
                m.entry(ino).or_insert(pid);
            }
        }
    }
    m
}

fn socket_inode(p: &std::path::Path) -> Option<u64> {
    let l = std::fs::read_link(p).ok()?;
    let s = l.to_string_lossy();
    s.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
}

/// Ist stdin oder stdout des Prozesses eine TCP-Verbindung nach außen? → Gegenstelle
pub fn stdio_remote(pid: u32) -> Option<String> {
    let ino0 = socket_inode(std::path::Path::new(&format!("/proc/{pid}/fd/0")));
    let ino1 = socket_inode(std::path::Path::new(&format!("/proc/{pid}/fd/1")));
    if ino0.is_none() && ino1.is_none() {
        return None;
    }
    // auch CLOSE_WAIT: Gegenstelle hat geschlossen, die Shell hängt aber noch am Socket
    with_states(&["01", "08"])
        .into_iter()
        .find(|c| (Some(c.inode) == ino0 || Some(c.inode) == ino1) && !c.remote_is_local())
        .map(|c| c.remote())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_net_addresses() {
        // 127.0.0.1:22 bzw. 1.2.3.4:443
        assert_eq!(parse_addr("0100007F:0016").unwrap(), (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 22));
        assert_eq!(parse_addr("04030201:01BB").unwrap(), (IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443));
        // ::1
        let (a, p) = parse_addr("00000000000000000000000001000000:0050").unwrap();
        assert_eq!((a, p), (IpAddr::V6(Ipv6Addr::LOCALHOST), 80));
    }
}

#[cfg(test)]
mod inbound_tests {
    use super::*;

    #[test]
    fn inbound_ssh_is_not_outbound_to_pool_port() {
        // Praxisfall: SSH-Client mit Absender-Port 45560 galt als „Mining-Pool“
        let listening: HashSet<u16> = [22, 80, 443].into();
        let ssh_in = Conn { raddr: "91.92.94.5".parse().unwrap(), rport: 45560, lport: 22, inode: 1 };
        let pool_out = Conn { raddr: "198.51.100.7".parse().unwrap(), rport: 45560, lport: 51234, inode: 2 };
        assert!(is_inbound(&ssh_in, &listening));
        assert!(!is_inbound(&pool_out, &listening));
    }
}
