//! Local package database: which files belong to packages, plus
//! dpkg md5sums. **Caution:** local and therefore forgeable by a root attacker;
//! in the product the comparison comes from the reference hash database (21.2).

use std::collections::{HashMap, HashSet};

use tyrosd_core::rootfs::{self, FsRoot};

/// at most this many bytes of package database per root (all files combined)
const TOTAL_BUDGET: u64 = 512 << 20;
/// at most this many entries in /var/lib/dpkg/info
const MAX_DPKG_INFO: usize = 200_000;

pub struct PackageDb {
    pub kind: &'static str,
    pub files: HashSet<String>,
    /// absolute path → md5 (dpkg only)
    pub md5: HashMap<String, String>,
    /// path → binary package (from <package>.md5sums), package → installed version (dpkg status)
    pub owner: HashMap<String, String>,
    pub versions: HashMap<String, String>,
    /// RPM: path → (package, EVR "epoch:version-release", architecture, SHA-256 according to the local RPM DB)
    pub rpm: HashMap<String, RpmFile>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RpmFile {
    pub name: String,
    pub evr: String,
    pub arch: String,
    pub sha256: String,
}

/// One line of the rpm query in `PackageDb::load` (path, package, EVR, architecture, digest algorithm, digest;
/// tab-separated)
pub fn parse_rpm_line(l: &str) -> Option<(String, RpmFile)> {
    let f: Vec<&str> = l.split('\t').collect();
    if f.len() < 6 || !f[0].starts_with('/') {
        return None;
    }
    // take the digest only if SHA-256 (algorithm 8); empty digests = directory/symlink
    let sha = if f[4] == "8" && f[5].len() == 64 { f[5].to_string() } else { String::new() };
    Some((f[0].to_string(), RpmFile { name: f[1].to_string(), evr: f[2].to_string(), arch: f[3].to_string(), sha256: sha }))
}

impl PackageDb {
    pub fn load(sysroot: &str) -> PackageDb {
        PackageDb::load_in(&FsRoot::host(sysroot))
    }

    /// Package database under a root; container roots as `FsRoot::Contained` (openat2, regular files only,
    /// size limit per file and in total). rpm only for the own system.
    pub fn load_in(fs: &FsRoot) -> PackageDb {
        let mut budget = TOTAL_BUDGET;
        let mut rd_str = |rel: &str, limit: u64| -> Option<String> {
            if budget == 0 {
                return None;
            }
            let s = fs.read_string(rel, limit.min(budget))?;
            budget = budget.saturating_sub(s.len() as u64);
            Some(s)
        };
        let mut db = PackageDb { kind: "none", files: HashSet::new(), md5: HashMap::new(), owner: HashMap::new(), versions: HashMap::new(), rpm: HashMap::new() };
        if fs.is_dir("/var/lib/dpkg/info") {
            db.kind = "dpkg";
            for (name, _) in fs.read_dir("/var/lib/dpkg/info", MAX_DPKG_INFO) {
                let rel = format!("/var/lib/dpkg/info/{name}");
                if name.ends_with(".list") {
                    if let Some(s) = rd_str(&rel, rootfs::PKG_DB) {
                        db.files.extend(s.lines().filter(|l| !l.is_empty()).map(str::to_string));
                    }
                } else if name.ends_with(".md5sums") {
                    // "libc6:amd64.md5sums" → package "libc6"
                    let pkg = name.trim_end_matches(".md5sums").split(':').next().unwrap_or("").to_string();
                    if let Some(s) = rd_str(&rel, rootfs::PKG_DB) {
                        for l in s.lines() {
                            if let Some((h, p)) = l.split_once("  ") {
                                let path = format!("/{}", p.trim());
                                db.owner.insert(path.clone(), pkg.clone());
                                db.md5.insert(path, h.to_string());
                            }
                        }
                    }
                }
            }
            // config files (/etc/cron.d/certbot …): the md5 is in the dpkg status under "Conffiles:"
            if let Some(s) = rd_str("/var/lib/dpkg/status", rootfs::PKG_DB) {
                let mut in_conf = false;
                let mut cur = String::new();
                for l in s.lines() {
                    // installed version per package (for the reference comparison on the central server)
                    if let Some(p) = l.strip_prefix("Package: ") {
                        cur = p.trim().to_string();
                    } else if let Some(v) = l.strip_prefix("Version: ") {
                        if !cur.is_empty() {
                            db.versions.entry(cur.clone()).or_insert_with(|| v.trim().to_string());
                        }
                    }
                    if l.starts_with("Conffiles:") {
                        in_conf = true;
                    } else if in_conf && l.starts_with(' ') {
                        let mut it = l.split_whitespace();
                        if let (Some(p), Some(h)) = (it.next(), it.next()) {
                            if h.len() == 32 && p.starts_with('/') {
                                db.md5.entry(p.to_string()).or_insert_with(|| h.to_string());
                            }
                        }
                    } else {
                        in_conf = false;
                    }
                }
            }
            return db;
        }
        if let Some(s) = rd_str("/lib/apk/db/installed", rootfs::PKG_DB) {
            db.kind = "apk";
            let mut dir = String::new();
            for l in s.lines() {
                if let Some(d) = l.strip_prefix("F:") {
                    dir = format!("/{d}");
                    db.files.insert(dir.clone());
                } else if let Some(f) = l.strip_prefix("R:") {
                    db.files.insert(format!("{dir}/{f}"));
                }
            }
            return db;
        }
        if fs.is_host_root() && which("rpm") {
            // single values inside the array loop as %{=TAG}
            // (otherwise: "array iterator used with different sized arrays")
            let qf = "[%{FILENAMES}\\t%{=NAME}\\t%{=EPOCHNUM}:%{=VERSION}-%{=RELEASE}\\t%{=ARCH}\\t%{=FILEDIGESTALGO}\\t%{FILEDIGESTS}\\n]";
            if let Ok(out) = std::process::Command::new("rpm").args(["-qa", "--qf", qf]).output() {
                db.kind = "rpm";
                let s = String::from_utf8_lossy(&out.stdout);
                for l in s.lines() {
                    if let Some((path, f)) = parse_rpm_line(l) {
                        db.files.insert(path.clone());
                        db.rpm.insert(path, f);
                    } else if l.starts_with('/') {
                        db.files.insert(l.split('\t').next().unwrap_or(l).to_string());
                    }
                }
            }
        }
        db
    }

    /// Does the path belong to a package? Takes merged /usr into account.
    pub fn owns(&self, p: &str) -> bool {
        if self.files.contains(p) {
            return true;
        }
        if let Some(rest) = p.strip_prefix("/usr") {
            if self.files.contains(rest) {
                return true;
            }
        } else if self.files.contains(&format!("/usr{p}")) {
            return true;
        }
        false
    }

    pub fn md5_for(&self, p: &str) -> Option<&String> {
        self.md5.get(p).or_else(|| match p.strip_prefix("/usr") {
            Some(rest) => self.md5.get(rest),
            None => self.md5.get(&format!("/usr{p}")),
        })
    }

    pub fn available(&self) -> bool {
        !self.files.is_empty()
    }
}

#[cfg(test)]
mod rpm_tests {
    #[test]
    fn rpm_lines() {
        assert!(super::parse_rpm_line("/usr/sbin/sshd	openssh-server").is_none()); // too few columns
        let l = format!("/usr/sbin/sshd	openssh-server	0:8.7p1-38.el9	x86_64	8	{}", "ab".repeat(32));
        let (p, f) = super::parse_rpm_line(&l).unwrap();
        assert_eq!((p.as_str(), f.name.as_str(), f.evr.as_str(), f.arch.as_str()), ("/usr/sbin/sshd", "openssh-server", "0:8.7p1-38.el9", "x86_64"));
        assert_eq!(f.sha256.len(), 64);
        let l = format!("/usr/bin/x	foo	0:1-1.el7	x86_64	1	{}", "ab".repeat(16)); // md5 (EL7) → no SHA-256
        assert!(super::parse_rpm_line(&l).unwrap().1.sha256.is_empty());
        assert!(super::parse_rpm_line("/etc	filesystem	0:3.16-2.el9	x86_64	8	").unwrap().1.sha256.is_empty());
    }
}

pub fn which(bin: &str) -> bool {
    std::env::var("PATH")
        .unwrap_or_else(|_| "/usr/sbin:/usr/bin:/sbin:/bin".into())
        .split(':')
        .any(|d| std::path::Path::new(d).join(bin).is_file())
}
