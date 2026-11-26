//! Proc connector (netlink, NETLINK_CONNECTOR / CN_IDX_PROC): reports every process start, fork and exit.
//! Requires CAP_NET_ADMIN (present in the systemd unit). No eBPF, no kernel modules – read only.
//!
//! Feeds the process memory (`tyrosd_core::proctable`): on exec the cheap values (comm, exe, cmdline, uid) are read
//! immediately, before a short-lived process is gone. Lost kernel messages (sequence gaps, ENOBUFS) are counted
//! and followed by a resync of the running processes.

use std::sync::atomic::{AtomicBool, Ordering};

use tyrosd_core::proctable;

const NETLINK_CONNECTOR: i32 = 11;
const CN_IDX_PROC: u32 = 1;
const CN_VAL_PROC: u32 = 1;
const PROC_CN_MCAST_LISTEN: u32 = 1;
const PROC_EVENT_FORK: u32 = 0x0000_0001;
const PROC_EVENT_EXEC: u32 = 0x0000_0002;
const PROC_EVENT_EXIT: u32 = 0x8000_0000;
const NLMSG_DONE: u16 = 3;
/// Receive buffer (SO_RCVBUFFORCE, needs CAP_NET_ADMIN): fork storms of builds/cron otherwise overflow the default
const RCVBUF: i32 = 4 << 20;

/// Listens for process events, keeps the process memory up to date and calls `on_exec(pid)` for every process
/// start until `stop` is set.
pub fn listen(stop: &AtomicBool, mut on_exec: impl FnMut(u32)) -> std::io::Result<()> {
    // SAFETY: simple system calls with checked return values
    unsafe {
        let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, NETLINK_CONNECTOR);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let guard = Fd(fd);
        let mut sa: libc::sockaddr_nl = std::mem::zeroed();
        sa.nl_family = libc::AF_NETLINK as u16;
        sa.nl_pid = 0; // assigned by the kernel
        sa.nl_groups = CN_IDX_PROC;
        if libc::bind(fd, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_nl>() as u32) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // subscription: nlmsghdr (16) + cn_msg (20) + op (4)
        let mut msg = [0u8; 40];
        msg[0..4].copy_from_slice(&40u32.to_ne_bytes());
        msg[4..6].copy_from_slice(&NLMSG_DONE.to_ne_bytes());
        msg[12..16].copy_from_slice(&std::process::id().to_ne_bytes());
        msg[16..20].copy_from_slice(&CN_IDX_PROC.to_ne_bytes());
        msg[20..24].copy_from_slice(&CN_VAL_PROC.to_ne_bytes());
        msg[32..34].copy_from_slice(&4u16.to_ne_bytes());
        msg[36..40].copy_from_slice(&PROC_CN_MCAST_LISTEN.to_ne_bytes());
        if libc::send(fd, msg.as_ptr() as *const _, msg.len(), 0) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // receive timeout so that `stop` is checked
        let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const _, std::mem::size_of::<libc::timeval>() as u32);
        // larger receive buffer; if not permitted the default stays (losses are counted below)
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUFFORCE, &RCVBUF as *const _ as *const _, std::mem::size_of::<i32>() as u32);
        proctable::set_active(true);
        // running processes once at the start (their exec happened before the agent)
        proctable::resync();
        let mut buf = vec![0u8; 65536];
        let mut seqs = Seqs::default();
        while !stop.load(Ordering::Relaxed) {
            let n = libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0);
            if n < 0 {
                let e = std::io::Error::last_os_error();
                match e.raw_os_error() {
                    Some(libc::EAGAIN) | Some(libc::EINTR) => continue,
                    Some(libc::ENOBUFS) => {
                        // too many messages at once: some are lost – count, then take up running processes again
                        proctable::LOST.fetch_add(1, Ordering::Relaxed);
                        seqs = Seqs::default();
                        proctable::resync();
                        continue;
                    }
                    _ => {
                        proctable::set_active(false);
                        return Err(e);
                    }
                }
            }
            let mut lost = 0;
            parse(&buf[..n as usize], &mut |ev| match ev {
                Ev::Fork { parent, child } => proctable::on_fork(parent, child),
                Ev::Exec(pid) => {
                    proctable::on_exec(pid as i32);
                    on_exec(pid);
                }
                Ev::Exit(pid) => proctable::on_exit(pid),
                Ev::Seq { cpu, seq } => lost += seqs.gap(cpu, seq),
            });
            if lost > 0 {
                proctable::LOST.fetch_add(lost, Ordering::Relaxed);
                proctable::resync();
            }
        }
        proctable::set_active(false);
        drop(guard);
    }
    Ok(())
}

/// One kernel message
#[derive(Debug, PartialEq)]
pub enum Ev {
    Fork { parent: i32, child: i32 },
    Exec(u32),
    Exit(i32),
    /// sequence number of the message (counted per CPU by the kernel) – gaps mean lost messages
    Seq { cpu: u32, seq: u32 },
}

/// Last sequence number per CPU
#[derive(Default)]
pub struct Seqs(std::collections::HashMap<u32, u32>);

impl Seqs {
    /// Number of messages missing before `seq` on this CPU (0 for the first message of a CPU, for repeats and
    /// for out-of-order delivery)
    pub fn gap(&mut self, cpu: u32, seq: u32) -> u64 {
        match self.0.insert(cpu, seq) {
            Some(p) if seq > p.wrapping_add(1) && seq - p < 1 << 20 => (seq - p - 1) as u64,
            _ => 0,
        }
    }
}

/// Evaluate one or more netlink messages. Layout: nlmsghdr (16) | cn_msg (20: id 8, seq @24, ack 4, len 2, flags 2)
/// | proc_event: what @36, cpu @40, timestamp @44, event_data @52.
/// Threads (pid ≠ tgid) are ignored: only processes count.
pub fn parse(mut b: &[u8], on: &mut impl FnMut(Ev)) {
    let i32_at = |m: &[u8], o: usize| i32::from_ne_bytes(m[o..o + 4].try_into().unwrap());
    let u32_at = |m: &[u8], o: usize| u32::from_ne_bytes(m[o..o + 4].try_into().unwrap());
    while b.len() >= 16 {
        let len = u32::from_ne_bytes(b[0..4].try_into().unwrap()) as usize;
        if len < 16 || len > b.len() {
            return;
        }
        let m = &b[..len];
        if m.len() >= 60 {
            on(Ev::Seq { cpu: u32_at(m, 40), seq: u32_at(m, 24) });
            match u32_at(m, 36) {
                PROC_EVENT_EXEC => {
                    let (pid, tgid) = (i32_at(m, 52), i32_at(m, 56));
                    if tgid > 0 && pid == tgid {
                        on(Ev::Exec(tgid as u32));
                    }
                }
                PROC_EVENT_FORK if m.len() >= 68 => {
                    let (ptgid, cpid, ctgid) = (i32_at(m, 56), i32_at(m, 60), i32_at(m, 64));
                    if ctgid > 0 && cpid == ctgid {
                        on(Ev::Fork { parent: ptgid, child: ctgid });
                    }
                }
                PROC_EVENT_EXIT => {
                    let (pid, tgid) = (i32_at(m, 52), i32_at(m, 56));
                    if tgid > 0 && pid == tgid {
                        on(Ev::Exit(tgid));
                    }
                }
                _ => {}
            }
        }
        let next = (len + 3) & !3;
        if next >= b.len() {
            return;
        }
        b = &b[next..];
    }
}

struct Fd(i32);
impl Drop for Fd {
    fn drop(&mut self) {
        // SAFETY: own fd
        unsafe { libc::close(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(what: u32, cpu: u32, seq: u32, data: &[i32]) -> Vec<u8> {
        let mut m = vec![0u8; 52 + 4 * data.len().max(4)];
        let len = m.len() as u32;
        m[0..4].copy_from_slice(&len.to_ne_bytes());
        m[24..28].copy_from_slice(&seq.to_ne_bytes());
        m[36..40].copy_from_slice(&what.to_ne_bytes());
        m[40..44].copy_from_slice(&cpu.to_ne_bytes());
        for (i, d) in data.iter().enumerate() {
            m[52 + 4 * i..56 + 4 * i].copy_from_slice(&d.to_ne_bytes());
        }
        m
    }

    #[test]
    fn parses_exec_fork_exit() {
        let mut b = msg(PROC_EVENT_EXEC, 0, 1, &[4242, 4242]);
        b.extend(msg(PROC_EVENT_FORK, 0, 2, &[100, 100, 4243, 4243]));
        b.extend(msg(PROC_EVENT_FORK, 0, 3, &[100, 100, 4244, 4243])); // thread: ignored
        b.extend(msg(PROC_EVENT_EXEC, 0, 4, &[4245, 4243])); // exec in a thread: ignored
        b.extend(msg(PROC_EVENT_EXIT, 1, 7, &[4243, 4243, 0, 17]));
        let mut got = vec![];
        parse(&b, &mut |e| got.push(e));
        let ev: Vec<_> = got.into_iter().filter(|e| !matches!(e, Ev::Seq { .. })).collect();
        assert_eq!(ev, vec![Ev::Exec(4242), Ev::Fork { parent: 100, child: 4243 }, Ev::Exit(4243)]);
    }

    #[test]
    fn sequence_gaps_per_cpu() {
        let mut s = Seqs::default();
        assert_eq!(s.gap(0, 10), 0); // first message of the CPU
        assert_eq!(s.gap(0, 11), 0);
        assert_eq!(s.gap(1, 500), 0); // other CPU counts on its own
        assert_eq!(s.gap(0, 15), 3); // 12, 13, 14 missing
        assert_eq!(s.gap(0, 3), 0); // restarted / out of order: no gap
    }
}
