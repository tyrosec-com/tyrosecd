//! Härtungs-relevante Systemangaben für den Sicherheitswert (Plan B2):
//! effektive SSH-Server-Einstellungen und „Neustart nötig“.
//! Nur Dateien lesen – kein `sshd -T`, kein Prozessstart.

use std::path::Path;

use serde::Serialize;

#[derive(Serialize, Debug, Default, Clone, PartialEq)]
pub struct Ssh {
    /// sshd installiert (Konfiguration gefunden)
    pub present: bool,
    /// yes | no | prohibit-password | forced-commands-only (Vorgabe: prohibit-password)
    pub permit_root_login: String,
    pub password_authentication: bool,
    pub kbd_interactive_authentication: bool,
    pub permit_empty_passwords: bool,
    pub ports: Vec<u16>,
}

/// sshd-Konfiguration lesen: erster Wert gewinnt (wie sshd), `Include` an Ort und Stelle,
/// `Match`-Blöcke werden für die globalen Werte ignoriert.
pub fn ssh(root: &str) -> Ssh {
    let main = format!("{}/etc/ssh/sshd_config", root.trim_end_matches('/'));
    if !Path::new(&main).exists() {
        return Ssh::default();
    }
    let mut vals: Vec<(String, String)> = Vec::new();
    read_conf(root, &main, &mut vals, 0);
    let get = |k: &str| vals.iter().find(|(key, _)| key == k).map(|(_, v)| v.to_lowercase());
    let yes = |k: &str, default: bool| get(k).map(|v| v == "yes").unwrap_or(default);
    let mut ports: Vec<u16> = vals.iter().filter(|(k, _)| k == "port").filter_map(|(_, v)| v.parse().ok()).collect();
    if ports.is_empty() {
        ports.push(22);
    }
    ports.dedup();
    // ChallengeResponseAuthentication ist der alte Name von KbdInteractiveAuthentication
    let kbd = get("kbdinteractiveauthentication").or_else(|| get("challengeresponseauthentication"));
    Ssh {
        present: true,
        permit_root_login: get("permitrootlogin").unwrap_or_else(|| "prohibit-password".into()),
        password_authentication: yes("passwordauthentication", true),
        kbd_interactive_authentication: kbd.map(|v| v == "yes").unwrap_or(true),
        permit_empty_passwords: yes("permitemptypasswords", false),
        ports,
    }
}

fn read_conf(root: &str, path: &str, out: &mut Vec<(String, String)>, depth: u8) {
    if depth > 4 {
        return;
    }
    let Ok(s) = std::fs::read_to_string(path) else { return };
    for line in s.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let mut it = l.splitn(2, |c: char| c.is_whitespace() || c == '=');
        let key = it.next().unwrap_or("").to_lowercase();
        let val = it.next().unwrap_or("").trim().trim_start_matches('=').trim().trim_matches('"').to_string();
        if key == "match" {
            return; // ab hier nur bedingte Werte
        }
        if key == "include" {
            for pat in val.split_whitespace() {
                let full = if pat.starts_with('/') { format!("{}{}", root.trim_end_matches('/'), pat) } else { format!("{}/etc/ssh/{}", root.trim_end_matches('/'), pat) };
                let mut files = expand(&full);
                files.sort();
                for f in files {
                    read_conf(root, &f, out, depth + 1);
                }
            }
            continue;
        }
        if key == "port" || !out.iter().any(|(k, _)| *k == key) {
            out.push((key, val));
        }
    }
}

/// einfache Glob-Auflösung für `Include /etc/ssh/sshd_config.d/*.conf`
fn expand(pat: &str) -> Vec<String> {
    let Some(star) = pat.rfind('*') else { return vec![pat.to_string()] };
    let dir_end = pat[..star].rfind('/').unwrap_or(0);
    let (dir, file_pat) = (&pat[..dir_end], &pat[dir_end + 1..]);
    let (pre, suf) = file_pat.split_once('*').unwrap_or((file_pat, ""));
    let Ok(rd) = std::fs::read_dir(dir) else { return vec![] };
    rd.flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(pre) && n.ends_with(suf))
        .map(|n| format!("{dir}/{n}"))
        .collect()
}

#[derive(Serialize, Debug, Default)]
pub struct Reboot {
    pub running_kernel: String,
    pub newest_kernel: String,
    /// /var/run/reboot-required (Debian/Ubuntu) vorhanden
    pub flag_file: bool,
    pub required: bool,
}

pub fn reboot() -> Reboot {
    let running = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default().trim().to_string();
    let newest = std::fs::read_dir("/boot")
        .map(|rd| {
            let mut ks: Vec<String> = rd
                .flatten()
                .filter_map(|e| e.file_name().to_string_lossy().strip_prefix("vmlinuz-").map(str::to_string))
                .filter(|v| !v.contains("rescue"))
                .collect();
            ks.sort_by(|a, b| version_key(a).cmp(&version_key(b)));
            ks.pop().unwrap_or_default()
        })
        .unwrap_or_default();
    let flag = Path::new("/var/run/reboot-required").exists() || Path::new("/run/reboot-required").exists();
    let required = flag || (!newest.is_empty() && !running.is_empty() && newest != running);
    Reboot { running_kernel: running, newest_kernel: newest, flag_file: flag, required }
}

/// Kernel-Versionen numerisch vergleichen: „6.8.0-49-generic“ → [6, 8, 0, 49]
pub fn version_key(v: &str) -> Vec<u64> {
    v.split(|c: char| !c.is_ascii_digit()).filter(|s| !s.is_empty()).filter_map(|s| s.parse().ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sshd_first_value_wins_and_includes() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path().to_str().unwrap();
        std::fs::create_dir_all(format!("{r}/etc/ssh/sshd_config.d")).unwrap();
        std::fs::write(format!("{r}/etc/ssh/sshd_config.d/50-cloud.conf"), "PasswordAuthentication yes\nPermitRootLogin yes\n").unwrap();
        std::fs::write(
            format!("{r}/etc/ssh/sshd_config"),
            "Include /etc/ssh/sshd_config.d/*.conf\nPort 2222\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nMatch User backup\n  PasswordAuthentication yes\n",
        )
        .unwrap();
        let s = ssh(r);
        assert!(s.present);
        assert!(s.password_authentication); // Include steht oben → gewinnt (wie bei Ubuntu-Cloud-Images)
        assert_eq!(s.permit_root_login, "yes");
        assert!(!s.kbd_interactive_authentication);
        assert_eq!(s.ports, vec![2222]);
    }

    #[test]
    fn sshd_defaults() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path().to_str().unwrap();
        std::fs::create_dir_all(format!("{r}/etc/ssh")).unwrap();
        std::fs::write(format!("{r}/etc/ssh/sshd_config"), "# leer\n").unwrap();
        let s = ssh(r);
        assert_eq!(s.permit_root_login, "prohibit-password");
        assert!(s.password_authentication);
        assert_eq!(s.ports, vec![22]);
        assert!(!ssh("/gibt/es/nicht").present);
    }

    #[test]
    fn kernel_order() {
        let mut v = vec!["6.8.0-49-generic", "6.8.0-100-generic", "6.8.0-9-generic"];
        v.sort_by(|a, b| version_key(a).cmp(&version_key(b)));
        assert_eq!(v.last().unwrap(), &"6.8.0-100-generic");
    }
}
