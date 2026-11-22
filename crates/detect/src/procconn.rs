//! Proc connector (netlink, NETLINK_CONNECTOR / CN_IDX_PROC): reports every process start.
//! Requires CAP_NET_ADMIN (present in the systemd unit). No eBPF, no kernel modules.

use std::sync::atomic::{AtomicBool, Ordering};

const NETLINK_CONNECTOR: i32 = 11;
const CN_IDX_PROC: u32 = 1;
const CN_VAL_PROC: u32 = 1;
const PROC_CN_MCAST_LISTEN: u32 = 1;
const PROC_EVENT_EXEC: u32 = 0x0000_0002;
const NLMSG_DONE: u16 = 3;

/// Listens for process starts and calls `on_exec(pid)` until `stop` is set.
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
        let mut buf = vec![0u8; 8192];
        while !stop.load(Ordering::Relaxed) {
            let n = libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0);
            if n < 0 {
                let e = std::io::Error::last_os_error();
                match e.raw_os_error() {
                    Some(libc::EAGAIN) | Some(libc::EINTR) => continue,
                    Some(libc::ENOBUFS) => continue, // too many starts at once: some are lost
                    _ => return Err(e),
                }
            }
            parse(&buf[..n as usize], &mut on_exec);
        }
        drop(guard);
    }
    Ok(())
}

/// Evaluate one or more netlink messages (layout: nlmsghdr | cn_msg | proc_event).
pub fn parse(mut b: &[u8], on_exec: &mut impl FnMut(u32)) {
    while b.len() >= 16 {
        let len = u32::from_ne_bytes(b[0..4].try_into().unwrap()) as usize;
        if len < 16 || len > b.len() {
            return;
        }
        let m = &b[..len];
        // proc_event starts after 16 + 20 bytes; what @0, cpu @4, timestamp @8, event_data @16
        if m.len() >= 36 + 24 {
            let what = u32::from_ne_bytes(m[36..40].try_into().unwrap());
            if what == PROC_EVENT_EXEC {
                let tgid = i32::from_ne_bytes(m[56..60].try_into().unwrap());
                if tgid > 0 {
                    on_exec(tgid as u32);
                }
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
    #[test]
    fn parses_exec_event() {
        let mut m = vec![0u8; 64];
        m[0..4].copy_from_slice(&64u32.to_ne_bytes());
        m[36..40].copy_from_slice(&super::PROC_EVENT_EXEC.to_ne_bytes());
        m[52..56].copy_from_slice(&4242i32.to_ne_bytes()); // pid
        m[56..60].copy_from_slice(&4242i32.to_ne_bytes()); // tgid
        let mut got = vec![];
        super::parse(&m, &mut |p| got.push(p));
        assert_eq!(got, vec![4242]);
    }
}
