//! E8 (plan 2026-11-27, package D): reading of credential files – `/etc/shadow`, `/etc/gshadow` and private SSH
//! keys (`~/.ssh/id_*`). Plain open notifications (`FAN_OPEN`), never a permission request: logins must never wait
//! for the agent. Read only, nothing is prevented.
//!
//! Many programs read these files on purpose (login, sudo, cron, backups). Besides a fixed list, the agent learns per
//! file class which programs read them: during the first 7 days silently, afterwards a program that never did is
//! reported once (and learned).

use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Silent learning phase after the first start
pub const LEARN_S: i64 = 7 * 86400;
const MAX_SEEN: usize = 2000;

/// Programs that read the password database or SSH keys as part of their job
const AUTH: &[&str] = &[
    "sshd", "sshd-session", "sshd-auth", "unix_chkpwd", "unix_update", "sudo", "su", "login", "passwd", "chage", "chpasswd", "chfn", "chsh",
    "useradd", "usermod", "userdel", "groupadd", "groupmod", "groupdel", "gpasswd", "newusers", "pwck", "grpck", "pwconv", "pwunconv",
    "grpconv", "grpunconv", "vipw", "vigr", "cron", "crond", "atd", "polkitd", "polkit-agent-helper-1", "pkexec", "systemd", "systemd-logind",
    "systemd-userdbd", "systemd-homed", "dovecot", "auth", "saslauthd", "vsftpd", "proftpd", "pure-ftpd", "cockpit-session", "sssd", "nscd",
    "faillock", "doas", "run0", "accounts-daemon", "ssh", "scp", "sftp", "ssh-add", "ssh-agent", "ssh-keygen", "ssh-copy-id", "tyrosecd",
];

pub fn routine(comm: &str, exe: &str) -> bool {
    let base = exe.rsplit('/').next().unwrap_or(exe);
    AUTH.iter().any(|a| *a == comm || *a == base) || crate::decoy::routine_reader(comm)
}

/// File class for the learned profile and the report
pub fn class(path: &str) -> &'static str {
    if path.starts_with("/etc/") {
        "shadow"
    } else {
        "ssh_key"
    }
}

/// Files to watch: password databases and private SSH keys of root and the users in /home
pub fn targets() -> Vec<String> {
    let mut v: Vec<String> = ["/etc/shadow", "/etc/gshadow"].iter().filter(|p| std::path::Path::new(p).is_file()).map(|p| p.to_string()).collect();
    let mut homes = vec![std::path::PathBuf::from("/root")];
    if let Ok(rd) = std::fs::read_dir("/home") {
        homes.extend(rd.flatten().take(500).map(|e| e.path()));
    }
    for h in homes {
        let Ok(rd) = std::fs::read_dir(h.join(".ssh")) else { continue };
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            // regular files only (no symlinks – never follow a user's link to a root file)
            if n.starts_with("id_") && !n.ends_with(".pub") && e.file_type().is_ok_and(|t| t.is_file()) {
                v.push(e.path().to_string_lossy().into_owned());
            }
        }
        if v.len() >= 500 {
            break;
        }
    }
    v
}

/// Learned readers per file class ("class|program"), persisted in the data directory
pub struct Profile {
    path: String,
    since: i64,
    seen: Vec<String>,
}

impl Profile {
    pub fn load(path: &str, now: i64) -> Profile {
        let v: serde_json::Value = std::fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        let since = v["since"].as_i64().unwrap_or(now);
        let seen = v["seen"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
        let p = Profile { path: path.to_string(), since, seen };
        if v.is_null() {
            p.save();
        }
        p
    }

    fn save(&self) {
        let _ = std::fs::write(&self.path, serde_json::json!({ "since": self.since, "seen": self.seen }).to_string());
    }

    pub fn learning(&self, now: i64) -> bool {
        now - self.since < LEARN_S
    }

    /// Record a reader; true = report it (unknown program after the learning phase)
    pub fn note(&mut self, key: &str, now: i64) -> bool {
        if self.seen.iter().any(|s| s == key) {
            return false;
        }
        if self.seen.len() < MAX_SEEN {
            self.seen.push(key.to_string());
            self.save();
        }
        !self.learning(now)
    }
}

/// Start the watch: `emit(path, pid, info)` for every read by a program that is neither routine nor known.
/// The files are marked again every minute (passwd & co. replace /etc/shadow by a new file).
pub fn start(data_dir: &str, emit: impl Fn(String, tyrosd_core::procinfo::ProcInfo) + Send + 'static) -> Result<usize, String> {
    let w = Arc::new(tyrosd_source_fanotify::decoy::DecoyWatch::notify_only().map_err(|e| format!("{e:#}"))?);
    let files = targets();
    let n = files.iter().filter(|f| w.watch(f).is_ok()).count();
    if n == 0 {
        return Err("no credential files found".into());
    }
    {
        let w = w.clone();
        std::thread::Builder::new()
            .name("cred-remark".into())
            .spawn(move || loop {
                std::thread::sleep(Duration::from_secs(60));
                for f in targets() {
                    let _ = w.watch(&f);
                }
            })
            .map_err(|e| e.to_string())?;
    }
    let profile = Mutex::new(Profile::load(&format!("{data_dir}/credaccess.json"), now_s()));
    std::thread::Builder::new()
        .name("cred-watch".into())
        .spawn(move || {
            let _ = w.run(|path, pid| {
                let p = tyrosd_core::procinfo::lookup(pid);
                let comm = p.comm.clone().unwrap_or_default();
                let exe = p.exe.clone().unwrap_or_default();
                // package management (verified), own process, routine programs: never
                if p.pkg || routine(&comm, &exe) {
                    return;
                }
                let prog = if exe.is_empty() { comm.clone() } else { exe.clone() };
                let key = format!("{}|{prog}", class(&path));
                if profile.lock().unwrap_or_else(|e| e.into_inner()).note(&key, now_s()) {
                    emit(path, p);
                }
            });
        })
        .map_err(|e| e.to_string())?;
    Ok(n)
}

fn now_s() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routine_readers() {
        assert!(routine("unix_chkpwd", "/usr/sbin/unix_chkpwd"));
        assert!(routine("sshd-session", "/usr/lib/openssh/sshd-session"));
        assert!(routine("borg", "/usr/bin/borg"));
        assert!(!routine("cat", "/usr/bin/cat"));
        assert!(!routine("python3", "/usr/bin/python3.12"));
        assert_eq!(class("/etc/shadow"), "shadow");
        assert_eq!(class("/root/.ssh/id_ed25519"), "ssh_key");
    }

    #[test]
    fn profile_learns_silently_then_reports_new_programs_once() {
        let dir = std::env::temp_dir().join(format!("tyrosd-cred-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("p.json").to_string_lossy().into_owned();
        let t0 = 1_800_000_000;
        let mut p = Profile::load(&f, t0);
        assert!(!p.note("shadow|/usr/bin/perl", t0 + 3600), "learning phase");
        let later = t0 + LEARN_S + 1;
        let mut p2 = Profile::load(&f, later);
        assert!(!p2.learning(later));
        assert!(!p2.note("shadow|/usr/bin/perl", later), "learned before");
        assert!(p2.note("shadow|/usr/bin/cat", later), "new program after learning");
        assert!(!p2.note("shadow|/usr/bin/cat", later), "only once");
        drop(p);
        let _ = std::fs::remove_dir_all(dir);
    }
}
