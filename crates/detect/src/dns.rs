//! Domainnamen zu Ziel-Adressen (Beaconing-Funde lesbar machen, 20.11.2026): DNS-Antworten am Server mitlesen und
//! „Adresse → angefragter Name“ im Speicher halten. Praxisfall: drei Adressen bei Billig-Hostern, die
//! Rückwärtsauflösung liefert nichts – gefragt hatte der Server aber nach „ip-lookup.example“.
//!
//! Nur lesen: ein Paket-Socket (AF_PACKET, braucht CAP_NET_RAW) mit Kernel-Filter, der ausschließlich eingehende
//! UDP-Pakete von Port 53 durchlässt (IPv4/IPv6, keine Fragmente). Ausgewertet werden nur Antworten mit A/AAAA-
//! Einträgen; gespeichert wird je Adresse der zuletzt erfragte Name (höchstens `MAX_NAMES`, nur im Speicher). An die
//! Zentrale gehen Namen nur für Ziele, die in der Beaconing-Stichprobe auftauchen. DNS über TLS/HTTPS bleibt
//! unsichtbar (dann eben kein Name).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// höchstens so viele Adressen im Speicher (älteste Hälfte fällt beim Überschreiten weg)
pub const MAX_NAMES: usize = 8192;

struct Names {
    map: HashMap<IpAddr, (String, u64)>,
    seq: u64,
}

static NAMES: Mutex<Option<Names>> = Mutex::new(None);

/// zuletzt per DNS erfragter Name für eine Adresse
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

/// Name ab `pos` lesen (mit Kompressionszeigern). Liefert (Name, Position nach dem Namen im ursprünglichen Ablauf).
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
                return None; // nur rückwärts (keine Schleifen)
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

/// DNS-Antwort (ab DNS-Kopf) → (Adresse, erfragter Name) für alle A/AAAA-Einträge
pub fn parse_dns(msg: &[u8]) -> Vec<(IpAddr, String)> {
    let mut out = Vec::new();
    let (Some(flags), Some(qd), Some(an)) = (u16_at(msg, 2), u16_at(msg, 4), u16_at(msg, 6)) else { return out };
    // Antwort (QR), ohne Fehler (RCODE 0), genau eine Frage (üblich), höchstens 64 Antworten
    if flags & 0x8000 == 0 || flags & 0x000f != 0 || qd != 1 || an == 0 || an > 64 {
        return out;
    }
    let Some((qname, mut pos)) = read_name(msg, 12) else { return out };
    if qname.is_empty() || !qname.contains('.') {
        return out;
    }
    pos += 4; // Typ, Klasse
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

/// IP-Paket (ab Netzwerk-Kopf, wie ein SOCK_DGRAM-Paket-Socket es liefert) → DNS-Antwort-Einträge
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

/// Kernel-Filter (klassisches BPF): nur nicht-ausgehende UDP-Pakete mit Quellport 53, IPv4 ohne Fragmente oder IPv6
/// ohne Erweiterungs-Köpfe. Alles andere erreicht den Agent gar nicht.
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
        i(JEQ_K, 15, 0, 4),            //  1 PACKET_OUTGOING → verwerfen (17)
        i(LD_W_ABS, 0, 0, AD_PROTOCOL), // 2
        i(JEQ_K, 0, 7, 0x0800),        //  3 IPv4? sonst → 11
        i(LD_B_ABS, 0, 0, 9),          //  4 Protokoll
        i(JEQ_K, 0, 11, 17),           //  5 UDP? sonst → 17
        i(LD_H_ABS, 0, 0, 6),          //  6 Fragment-Feld
        i(JSET_K, 9, 0, 0x1fff),       //  7 Fragment → 17
        i(LDX_B_MSH, 0, 0, 0),         //  8 X = Länge IP-Kopf
        i(LD_H_IND, 0, 0, 0),          //  9 UDP-Quellport
        i(JEQ_K, 5, 6, 53),            // 10 53 → 16, sonst → 17
        i(JEQ_K, 0, 5, 0x86dd),        // 11 IPv6? sonst → 17
        i(LD_B_ABS, 0, 0, 6),          // 12 Next Header
        i(JEQ_K, 0, 3, 17),            // 13 UDP? sonst → 17
        i(LD_H_ABS, 0, 0, 40),         // 14 UDP-Quellport
        i(JEQ_K, 0, 1, 53),            // 15 53 → 16, sonst → 17
        i(RET_K, 0, 0, 2048),          // 16 annehmen (max. 2 KiB)
        i(RET_K, 0, 0, 0),             // 17 verwerfen
    ]
}

/// Mitlesen bis `stop`. Fehlt die Berechtigung (ältere systemd-Unit ohne AF_PACKET/CAP_NET_RAW), wird das einmal
/// gemeldet und die Funktion endet – Beaconing läuft dann ohne Namen weiter.
#[cfg(target_os = "linux")]
pub fn run(stop: Arc<AtomicBool>, log: impl Fn(String)) {
    // SAFETY: einfache Systemaufrufe mit gültigen, lokal gehaltenen Puffern; der Socket wird am Ende geschlossen.
    unsafe {
        let fd = libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, (libc::ETH_P_ALL as u16).to_be() as i32);
        if fd < 0 {
            log(format!("DNS-Namen für Beaconing nicht verfügbar ({}) – systemd-Unit ohne AF_PACKET/CAP_NET_RAW; install.sh erneut ausführen", std::io::Error::last_os_error()));
            return;
        }
        let mut prog = filter();
        let fprog = libc::sock_fprog { len: prog.len() as u16, filter: prog.as_mut_ptr() };
        if libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_ATTACH_FILTER, &fprog as *const _ as *const libc::c_void, std::mem::size_of::<libc::sock_fprog>() as u32) != 0 {
            log(format!("DNS-Namen: Filter nicht gesetzt ({}) – aus", std::io::Error::last_os_error()));
            libc::close(fd);
            return;
        }
        let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of::<libc::timeval>() as u32);
        log("DNS-Namen für Beaconing: aktiv (nur DNS-Antworten, nur lesen)".into());
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

    /// Antwort auf „ip-lookup.example A“ mit CNAME-freier Kette, drei A-Einträgen (Namen komprimiert)
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
        // Quellport nicht 53 → nichts
        let mut q = p.clone();
        q[21] = 54;
        assert!(parse_packet(&q).is_empty());
        // Anfrage (QR=0) → nichts
        let mut a = dns.clone();
        a[2] = 0x01;
        assert!(parse_dns(&a).is_empty());
        // Fehlerantwort (NXDOMAIN) → nichts
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
        assert!(parse_dns(&m).is_empty(), "Zeiger auf sich selbst");
        // ungültige Zeichen im Namen
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
        assert!(name_of(&ip).is_none(), "älteste fällt weg");
        assert!(NAMES.lock().unwrap().as_ref().unwrap().map.len() <= MAX_NAMES);
    }
}
