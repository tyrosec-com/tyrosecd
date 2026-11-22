//! Domain names for destination addresses (make beaconing findings readable, 2026-11-20): sniff DNS responses on the
//! server and keep "address → queried name" in memory. Real case: three addresses at budget hosters, reverse
//! resolution returns nothing – but the server had asked for "ip-lookup.example".
//!
//! Read only: a packet socket (AF_PACKET, requires CAP_NET_RAW) with a kernel filter that passes only incoming
//! UDP packets from port 53 (IPv4/IPv6, no fragments). Only responses with A/AAAA records are evaluated;
//! per address the most recently queried name is stored (at most `MAX_NAMES`, in memory only). Names are sent
//! to the server only for destinations that appear in the beaconing sample. DNS over TLS/HTTPS stays
//! invisible (then simply no name).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// at most this many addresses in memory (the oldest half is dropped when exceeded)
pub const MAX_NAMES: usize = 8192;

struct Names {
    map: HashMap<IpAddr, (String, u64)>,
    seq: u64,
}

static NAMES: Mutex<Option<Names>> = Mutex::new(None);

/// most recently queried DNS name for an address
pub fn name_of(ip: &IpAddr) -> Option<String> {
    NAMES.lock().ok()?.as_ref()?.map.get(ip).map(|(n, _)| n.clone())
}

pub fn remember(ip: IpAddr, name: &str) {
    let Ok(mut g) = NAMES.lock() else { return };
    let n = g.get_or_insert_with(|| Names { map: HashMap::new(), seq: 0 });
    n.seq += 1;
    let seq = n.seq;
    n.map.insert(ip, (name.to_string(), seq));
    if n.map.len() > MAX_NAMES {
        let cut = seq - (MAX_NAMES as u64 / 2);
        n.map.retain(|_, (_, s)| *s > cut);
    }
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

/// Read a name at `pos` (with compression pointers). Returns (name, position after the name in the original flow).
fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut end = None;
    for _ in 0..64 {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            return Some((out, end.unwrap_or(pos + 1)));
        }
        if len & 0xc0 == 0xc0 {
            let ptr = ((len & 0x3f) << 8) | *msg.get(pos + 1)? as usize;
            end.get_or_insert(pos + 2);
            if ptr >= pos {
                return None; // backwards only (no loops)
            }
            pos = ptr;
            continue;
        }
        if len > 63 {
            return None;
        }
        let label = msg.get(pos + 1..pos + 1 + len)?;
        if !label.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_') {
            return None;
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
        if out.len() > 253 {
            return None;
        }
        pos += 1 + len;
    }
    None
}

/// DNS response (from the DNS header) → (address, queried name) for all A/AAAA records
pub fn parse_dns(msg: &[u8]) -> Vec<(IpAddr, String)> {
    let mut out = Vec::new();
    let (Some(flags), Some(qd), Some(an)) = (u16_at(msg, 2), u16_at(msg, 4), u16_at(msg, 6)) else { return out };
    // response (QR), no error (RCODE 0), exactly one question (usual), at most 64 answers
    if flags & 0x8000 == 0 || flags & 0x000f != 0 || qd != 1 || an == 0 || an > 64 {
        return out;
    }
    let Some((qname, mut pos)) = read_name(msg, 12) else { return out };
    if qname.is_empty() || !qname.contains('.') {
        return out;
    }
    pos += 4; // type, class
    for _ in 0..an {
        let Some((_, p)) = read_name(msg, pos) else { break };
        let (Some(typ), Some(rdlen)) = (u16_at(msg, p), u16_at(msg, p + 8)) else { break };
        let rd = p + 10;
        let Some(data) = msg.get(rd..rd + rdlen as usize) else { break };
        match (typ, data.len()) {
            (1, 4) => out.push((IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])), qname.clone())),
            (28, 16) => {
                let a: [u8; 16] = data.try_into().unwrap_or([0; 16]);
                out.push((IpAddr::V6(Ipv6Addr::from(a)), qname.clone()));
            }
            _ => {}
        }
        pos = rd + rdlen as usize;
    }
    out
}

/// IP packet (from the network header, as delivered by a SOCK_DGRAM packet socket) → DNS answer records
pub fn parse_packet(pkt: &[u8]) -> Vec<(IpAddr, String)> {
    let Some(v) = pkt.first().map(|b| b >> 4) else { return Vec::new() };
    let udp = match v {
        4 if pkt.get(9) == Some(&17) => (pkt[0] & 0x0f) as usize * 4,
        6 if pkt.get(6) == Some(&17) => 40,
        _ => return Vec::new(),
    };
    if u16_at(pkt, udp) != Some(53) {
        return Vec::new();
    }
    pkt.get(udp + 8..).map(parse_dns).unwrap_or_default()
}

/// Kernel filter (classic BPF): only non-outgoing UDP packets with source port 53, IPv4 without fragments or IPv6
/// without extension headers. Nothing else reaches the agent at all.
#[cfg(target_os = "linux")]
fn filter() -> Vec<libc::sock_filter> {
    const LD_W_ABS: u16 = 0x20;
    const LD_H_ABS: u16 = 0x28;
    const LD_B_ABS: u16 = 0x30;
    const LD_H_IND: u16 = 0x48;
    const LDX_B_MSH: u16 = 0xb1;
    const JEQ_K: u16 = 0x15;
    const JSET_K: u16 = 0x45;
    const RET_K: u16 = 0x06;
    const AD_PROTOCOL: u32 = 0xffff_f000; // SKF_AD_OFF + SKF_AD_PROTOCOL
    const AD_PKTTYPE: u32 = 0xffff_f004; // SKF_AD_OFF + SKF_AD_PKTTYPE
    let i = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
    vec![
        i(LD_W_ABS, 0, 0, AD_PKTTYPE), //  0
        i(JEQ_K, 15, 0, 4),            //  1 PACKET_OUTGOING → drop (17)
        i(LD_W_ABS, 0, 0, AD_PROTOCOL), // 2
        i(JEQ_K, 0, 7, 0x0800),        //  3 IPv4? else → 11
        i(LD_B_ABS, 0, 0, 9),          //  4 protocol
        i(JEQ_K, 0, 11, 17),           //  5 UDP? else → 17
        i(LD_H_ABS, 0, 0, 6),          //  6 fragment field
        i(JSET_K, 9, 0, 0x1fff),       //  7 fragment → 17
        i(LDX_B_MSH, 0, 0, 0),         //  8 X = IP header length
        i(LD_H_IND, 0, 0, 0),          //  9 UDP source port
        i(JEQ_K, 5, 6, 53),            // 10 53 → 16, else → 17
        i(JEQ_K, 0, 5, 0x86dd),        // 11 IPv6? else → 17
        i(LD_B_ABS, 0, 0, 6),          // 12 Next Header
        i(JEQ_K, 0, 3, 17),            // 13 UDP? else → 17
        i(LD_H_ABS, 0, 0, 40),         // 14 UDP source port
        i(JEQ_K, 0, 1, 53),            // 15 53 → 16, else → 17
        i(RET_K, 0, 0, 2048),          // 16 accept (max. 2 KiB)
        i(RET_K, 0, 0, 0),             // 17 drop
    ]
}

/// Sniff until `stop`. If the permission is missing (older systemd unit without AF_PACKET/CAP_NET_RAW), this is
/// reported once and the function returns – beaconing then continues without names.
#[cfg(target_os = "linux")]
pub fn run(stop: Arc<AtomicBool>, log: impl Fn(String)) {
    // SAFETY: simple system calls with valid, locally held buffers; the socket is closed at the end.
    unsafe {
        let fd = libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, (libc::ETH_P_ALL as u16).to_be() as i32);
        if fd < 0 {
            log(format!("DNS names for beaconing not available ({}) – systemd unit without AF_PACKET/CAP_NET_RAW; run install.sh again", std::io::Error::last_os_error()));
            return;
        }
        let mut prog = filter();
        let fprog = libc::sock_fprog { len: prog.len() as u16, filter: prog.as_mut_ptr() };
        if libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_ATTACH_FILTER, &fprog as *const _ as *const libc::c_void, std::mem::size_of::<libc::sock_fprog>() as u32) != 0 {
            log(format!("DNS names: filter not set ({}) – off", std::io::Error::last_os_error()));
            libc::close(fd);
            return;
        }
        let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of::<libc::timeval>() as u32);
        log("DNS names for beaconing: active (DNS responses only, read-only)".into());
        let mut buf = [0u8; 2048];
        while !stop.load(Ordering::Relaxed) {
            let n = libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
            if n <= 0 {
                continue;
            }
            for (ip, name) in parse_packet(&buf[..n as usize]) {
                if crate::beacon::is_public(&ip) {
                    remember(ip, &name);
                }
            }
        }
        libc::close(fd);
    }
}

#[cfg(not(target_os = "linux"))]
pub fn run(_stop: Arc<AtomicBool>, _log: impl Fn(String)) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Response to "ip-lookup.example A" with a CNAME-free chain, three A records (names compressed)
    fn answer() -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0];
        for l in ["ip-lookup", "example"] {
            m.push(l.len() as u8);
            m.extend_from_slice(l.as_bytes());
        }
        m.extend_from_slice(&[0, 0, 1, 0, 1]);
        for ip in [[91, 92, 93, 1], [91, 92, 93, 2], [91, 92, 93, 3]] {
            m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
            m.extend_from_slice(&ip);
        }
        m
    }

    #[test]
    fn parses_a_records_with_compression() {
        let r = parse_dns(&answer());
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|(_, n)| n == "ip-lookup.example"));
        assert_eq!(r[0].0, "91.92.93.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parses_ipv4_udp_packet_and_ignores_others() {
        let dns = answer();
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 9, 9, 9, 9, 10, 0, 0, 5];
        p.extend_from_slice(&[0, 53, 0xc3, 0x50, 0, 0, 0, 0]);
        p.extend_from_slice(&dns);
        assert_eq!(parse_packet(&p).len(), 3);
        // source port not 53 → nothing
        let mut q = p.clone();
        q[21] = 54;
        assert!(parse_packet(&q).is_empty());
        // query (QR=0) → nothing
        let mut a = dns.clone();
        a[2] = 0x01;
        assert!(parse_dns(&a).is_empty());
        // error response (NXDOMAIN) → nothing
        let mut e = dns.clone();
        e[3] = 0x83;
        assert!(parse_dns(&e).is_empty());
    }

    #[test]
    fn rejects_garbage_and_pointer_loops() {
        assert!(parse_dns(&[]).is_empty());
        assert!(parse_dns(&[0; 12]).is_empty());
        let mut m = vec![0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 0xc0, 12];
        m.extend_from_slice(&[0; 20]);
        assert!(parse_dns(&m).is_empty(), "pointer to itself");
        // invalid characters in the name
        let mut b = vec![0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 3, b'a', b' ', b'b', 0, 0, 1, 0, 1];
        b.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        assert!(parse_dns(&b).is_empty());
    }

    #[test]
    fn remembers_and_evicts() {
        let ip: IpAddr = "91.92.93.94".parse().unwrap();
        remember(ip, "c2.example.net");
        assert_eq!(name_of(&ip).as_deref(), Some("c2.example.net"));
        for i in 0..(MAX_NAMES as u32 + 10) {
            remember(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i)), "x.example");
        }
        assert!(name_of(&ip).is_none(), "oldest is evicted");
        assert!(NAMES.lock().unwrap().as_ref().unwrap().map.len() <= MAX_NAMES);
    }
}
