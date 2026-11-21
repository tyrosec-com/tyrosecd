//! Sicherheitsrelevante Server-Gesundheit (Hauptplan 23): CPU, Load, RAM,
//! Swap, Platten (Belegung + Inodes), Netzwerk-Durchsatz. Erfassung alle
//! n Sekunden aus /proc und statvfs, Übertragung als 1-Minuten-Aggregate.
//! Kostet praktisch nichts (wenige Dateien lesen).

pub mod ports;
use std::collections::HashMap;
use std::ffi::CString;
use std::time::{Duration, Instant};

use tyrosd_proto::{DiskUsage, MetricPoint};

#[derive(Clone, Copy, Default)]
struct CpuTimes {
    busy: u64,
    total: u64,
    steal: u64,
}

fn cpu_times() -> Option<CpuTimes> {
    let s = std::fs::read_to_string("/proc/stat").ok()?;
    let l = s.lines().next()?;
    let v: Vec<u64> = l.split_whitespace().skip(1).filter_map(|x| x.parse().ok()).collect();
    // user nice system idle iowait irq softirq steal guest guest_nice
    let idle = v.get(3)? + v.get(4).unwrap_or(&0);
    let steal = *v.get(7).unwrap_or(&0);
    let total: u64 = v.iter().take(8).sum();
    Some(CpuTimes { busy: total - idle, total, steal })
}

fn meminfo() -> HashMap<String, u64> {
    std::fs::read_to_string("/proc/meminfo")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            Some((k.to_string(), v.split_whitespace().next()?.parse::<u64>().ok()? * 1024))
        })
        .collect()
}

fn net_bytes() -> (u64, u64) {
    let s = std::fs::read_to_string("/proc/net/dev").unwrap_or_default();
    let mut rx = 0;
    let mut tx = 0;
    for l in s.lines().skip(2) {
        let Some((iface, rest)) = l.split_once(':') else { continue };
        let iface = iface.trim();
        if iface == "lo" || iface.starts_with("veth") || iface.starts_with("docker") || iface.starts_with("br-") {
            continue;
        }
        let v: Vec<u64> = rest.split_whitespace().filter_map(|x| x.parse().ok()).collect();
        rx += v.first().copied().unwrap_or(0);
        tx += v.get(8).copied().unwrap_or(0);
    }
    (rx, tx)
}

const DISK_FS: &[&str] = &["ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "zfs", "jfs", "reiserfs", "bcachefs", "vfat"];

fn disks() -> Vec<DiskUsage> {
    let s = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for l in s.lines() {
        let f: Vec<&str> = l.split(' ').collect();
        let Some(sep) = f.iter().position(|x| *x == "-") else { continue };
        let (Some(dev), Some(mp), Some(fs)) = (f.get(2), f.get(4), f.get(sep + 1)) else { continue };
        if !DISK_FS.contains(fs) || !seen.insert(dev.to_string()) {
            continue;
        }
        let Ok(c) = CString::new(*mp) else { continue };
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: gültiger Pfad und Puffer
        if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
            continue;
        }
        let bs = st.f_frsize as u64;
        out.push(DiskUsage {
            mount: mp.to_string(),
            total: st.f_blocks as u64 * bs,
            used: (st.f_blocks as u64 - st.f_bfree as u64) * bs,
            inodes_total: st.f_files as u64,
            inodes_used: st.f_files as u64 - st.f_ffree as u64,
        });
    }
    out
}

fn load_and_procs() -> (f32, u32) {
    let s = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
    let f: Vec<&str> = s.split_whitespace().collect();
    let load = f.first().and_then(|x| x.parse().ok()).unwrap_or(0.0);
    let procs = f.get(3).and_then(|x| x.split('/').nth(1)).and_then(|x| x.parse().ok()).unwrap_or(0);
    (load, procs)
}

/// Sammelt Stichproben und liefert pro Minute einen aggregierten Punkt.
pub struct Collector {
    last_cpu: Option<CpuTimes>,
    last_net: Option<((u64, u64), Instant)>,
    samples: Vec<f32>,
    steal: Vec<f32>,
    net_rx_bps: Vec<u64>,
    net_tx_bps: Vec<u64>,
    window_start: Instant,
    pub window: Duration,
    /// CPU-Ticks je Prozess am Fensteranfang (Top-Prozesse)
    proc_ticks: HashMap<u32, u64>,
    proc_at: Option<Instant>,
    /// Verkehr je Port (TCP-Verbindungen)
    ports: ports::PortMeter,
}

impl Default for Collector {
    fn default() -> Self {
        Collector {
            last_cpu: cpu_times(),
            proc_ticks: HashMap::new(),
            proc_at: None,
            ports: ports::PortMeter::default(),
            last_net: Some((net_bytes(), Instant::now())),
            samples: vec![],
            steal: vec![],
            net_rx_bps: vec![],
            net_tx_bps: vec![],
            window_start: Instant::now(),
            window: Duration::from_secs(60),
        }
    }
}

impl Collector {
    /// Eine Stichprobe nehmen. Liefert einen Punkt, wenn das Fenster voll ist.
    pub fn sample(&mut self) -> Option<MetricPoint> {
        if let (Some(prev), Some(cur)) = (self.last_cpu, cpu_times()) {
            let dt = cur.total.saturating_sub(prev.total).max(1) as f32;
            self.samples.push(cur.busy.saturating_sub(prev.busy) as f32 * 100.0 / dt);
            self.steal.push(cur.steal.saturating_sub(prev.steal) as f32 * 100.0 / dt);
            self.last_cpu = Some(cur);
        }
        let now = Instant::now();
        let n = net_bytes();
        if let Some(((rx, tx), t)) = self.last_net {
            let secs = now.duration_since(t).as_secs_f64().max(0.001);
            self.net_rx_bps.push((n.0.saturating_sub(rx) as f64 / secs) as u64);
            self.net_tx_bps.push((n.1.saturating_sub(tx) as f64 / secs) as u64);
        }
        self.last_net = Some((n, now));
        self.ports.sample();
        if now.duration_since(self.window_start) < self.window || self.samples.is_empty() {
            return None;
        }
        let avg = |v: &[f32]| v.iter().sum::<f32>() / v.len().max(1) as f32;
        let avgu = |v: &[u64]| v.iter().sum::<u64>() / v.len().max(1) as u64;
        let m = meminfo();
        let g = |k: &str| *m.get(k).unwrap_or(&0);
        let (load1, procs) = load_and_procs();
        let p = MetricPoint {
            ts_ns: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as i64).unwrap_or(0),
            cpu_pct_avg: avg(&self.samples),
            cpu_pct_max: self.samples.iter().cloned().fold(0.0, f32::max),
            load1,
            mem_total: g("MemTotal"),
            mem_used: g("MemTotal").saturating_sub(g("MemAvailable")),
            swap_total: g("SwapTotal"),
            swap_used: g("SwapTotal").saturating_sub(g("SwapFree")),
            net_rx_bps: avgu(&self.net_rx_bps),
            net_tx_bps: avgu(&self.net_tx_bps),
            disks: disks(),
            steal_pct: avg(&self.steal),
            procs,
            psi_cpu: psi("cpu"),
            psi_mem: psi("memory"),
            psi_io: psi("io"),
            top: self.top_procs(now),
            ports: self.ports.take(),
        };
        self.samples.clear();
        self.steal.clear();
        self.net_rx_bps.clear();
        self.net_tx_bps.clear();
        self.window_start = now;
        Some(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn collects_on_linux() {
        let mut c = Collector { window: Duration::from_millis(0), ..Default::default() };
        std::thread::sleep(Duration::from_millis(50));
        let p = c.sample().expect("Punkt");
        assert!(p.mem_total > 0);
        assert!(p.cpu_pct_avg >= 0.0 && p.cpu_pct_avg <= 100.0);
        assert!(!p.disks.is_empty() || std::path::Path::new("/.dockerenv").exists());
    }
}

/// PSI „some avg60“ in % (Kernel ≥ 4.20 mit CONFIG_PSI); -1 = nicht verfügbar
fn psi(kind: &str) -> f32 {
    std::fs::read_to_string(format!("/proc/pressure/{kind}"))
        .ok()
        .and_then(|s| {
            s.lines().find(|l| l.starts_with("some")).and_then(|l| {
                l.split_whitespace().find_map(|f| f.strip_prefix("avg60=")).and_then(|v| v.parse::<f32>().ok())
            })
        })
        .unwrap_or(-1.0)
}

/// utime+stime (Ticks), comm, RSS (kB) eines Prozesses
fn proc_stat(pid: u32) -> Option<(u64, String, u64)> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (l, r) = (s.find('(')?, s.rfind(')')?);
    let comm = s[l + 1..r].to_string();
    let f: Vec<&str> = s[r + 2..].split_whitespace().collect();
    // nach „)“: state=0 … utime=11, stime=12, rss(Seiten)=21
    let ticks = f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?;
    let rss = f.get(21)?.parse::<u64>().ok()? * 4;
    Some((ticks, comm, rss))
}

impl Collector {
    /// Top 5 nach CPU-Anteil seit dem letzten Fenster (ein Kern = 100 %)
    fn top_procs(&mut self, now: Instant) -> Vec<tyrosd_proto::TopProc> {
        let mut cur = HashMap::new();
        let mut rows = Vec::new();
        let secs = self.proc_at.map(|t| now.duration_since(t).as_secs_f32()).unwrap_or(0.0);
        if let Ok(rd) = std::fs::read_dir("/proc") {
            for e in rd.flatten() {
                let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
                let Some((ticks, comm, rss)) = proc_stat(pid) else { continue };
                cur.insert(pid, ticks);
                if secs > 0.0 {
                    if let Some(prev) = self.proc_ticks.get(&pid) {
                        let pct = ticks.saturating_sub(*prev) as f32 / 100.0 / secs * 100.0;
                        rows.push(tyrosd_proto::TopProc { comm, cpu_pct: pct, rss_kb: rss, pid });
                    }
                }
            }
        }
        self.proc_ticks = cur;
        self.proc_at = Some(now);
        rows.sort_by(|a, b| b.cpu_pct.partial_cmp(&a.cpu_pct).unwrap_or(std::cmp::Ordering::Equal));
        rows.truncate(5);
        rows
    }
}
