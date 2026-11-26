//! Process information from /proc (read only), with the process memory as fallback for processes that have
//! already exited (`tyrosd_core::proctable`, fed by the proc connector).

pub struct Info {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub exe: String,
    pub cmdline: String,
    /// already exited – values from the process memory
    pub gone: bool,
}

pub fn info(pid: u32) -> Option<Info> {
    live(pid).or_else(|| {
        let e = tyrosd_core::proctable::recall(pid as i32)?;
        Some(Info { pid, ppid: e.ppid.max(0) as u32, comm: e.comm, exe: e.exe, cmdline: e.cmdline, gone: true })
    })
}

fn live(pid: u32) -> Option<Info> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (l, r) = (stat.find('(')?, stat.rfind(')')?);
    let comm = stat[l + 1..r].to_string();
    let ppid = stat[r + 2..].split_whitespace().nth(1)?.parse().ok()?;
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|b| b.split(|c| *c == 0).filter(|s| !s.is_empty()).map(|s| String::from_utf8_lossy(s).into_owned()).collect::<Vec<_>>().join(" "))
        .unwrap_or_default();
    Some(Info { pid, ppid, comm, exe, cmdline: cmdline.chars().take(2000).collect(), gone: false })
}

/// Names of the process chain: [process, parent, grandparent, …] – exited links from the process memory
pub fn chain(pid: u32, depth: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = pid;
    while out.len() < depth {
        let Some(i) = live(cur) else {
            out.extend(tyrosd_core::proctable::chain(cur as i32, depth - out.len()));
            break;
        };
        out.push(i.comm);
        if i.ppid <= 1 {
            break;
        }
        cur = i.ppid;
    }
    out
}
