//! Detect the latest backup (plan "quiet", item 5): borg, restic, duplicity, Plesk, typical backup directories.
//! Only timestamps and paths – no contents.
use serde::Serialize;
use std::path::Path;

#[derive(Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Backup {
    pub kind: String,
    pub path: String,
    /// Unix time of the most recent backup
    pub last: i64,
}

fn mtime(p: &Path) -> Option<i64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(p).ok().map(|m| m.mtime())
}

/// most recent modification time of a matching file in `dir` (one level, plus one sublevel)
fn newest(dir: &Path, depth: u8, pred: &dyn Fn(&str) -> bool) -> Option<i64> {
    let mut best = None;
    for e in std::fs::read_dir(dir).ok()?.flatten().take(5000) {
        let name = e.file_name().to_string_lossy().to_string();
        let Ok(ft) = e.file_type() else { continue };
        let t = if ft.is_dir() && depth > 0 {
            newest(&e.path(), depth - 1, pred)
        } else if ft.is_file() && pred(&name) {
            mtime(&e.path())
        } else {
            None
        };
        best = best.max(t);
    }
    best
}

fn homes(root: &str) -> Vec<std::path::PathBuf> {
    let mut v = vec![Path::new(root).join("root")];
    if let Ok(rd) = std::fs::read_dir(Path::new(root).join("home")) {
        v.extend(rd.flatten().map(|e| e.path()).take(200));
    }
    v
}

fn archive(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    // /var/backups contains Debian housekeeping files (dpkg, apt, passwd copies) – that is not a backup
    if ["dpkg.", "apt.", "alternatives.", "passwd", "group", "shadow", "gshadow", "aptitude.", "infodir."].iter().any(|p| n.starts_with(p)) {
        return false;
    }
    [".tar", ".tgz", ".gz", ".zst", ".xz", ".bz2", ".zip", ".sql", ".dump", ".7z", ".borg", ".bak"].iter().any(|e| n.contains(e))
}

pub fn detect(root: &str) -> Vec<Backup> {
    let mut out = Vec::new();
    let r = |p: &str| Path::new(root).join(p.trim_start_matches('/'));
    let mut add = |kind: &str, path: &Path, last: Option<i64>| {
        if let Some(l) = last {
            let shown = path.to_string_lossy().trim_start_matches(root.trim_end_matches('/')).to_string();
            out.push(Backup { kind: kind.into(), path: if shown.is_empty() { "/".into() } else { shown }, last: l });
        }
    };
    for h in homes(root) {
        // borg: security/<repo-id>/manifest-timestamp is written on every backup (also for remote repos)
        let sec = h.join(".config/borg/security");
        if let Ok(rd) = std::fs::read_dir(&sec) {
            for e in rd.flatten().take(50) {
                let ts = e.path().join("manifest-timestamp");
                let loc = std::fs::read_to_string(e.path().join("location")).unwrap_or_default();
                add("borg", Path::new(if loc.trim().is_empty() { sec.to_str().unwrap_or("") } else { loc.trim() }), mtime(&ts));
            }
        }
        // restic: cache per repository, the snapshots directory is updated on every run
        let rc = h.join(".cache/restic");
        if let Ok(rd) = std::fs::read_dir(&rc) {
            for e in rd.flatten().take(50) {
                add("restic", &rc, newest(&e.path().join("snapshots"), 0, &|_| true).or(mtime(&e.path().join("snapshots"))));
            }
        }
        // duplicity: manifests in the cache
        let dc = h.join(".cache/duplicity");
        if dc.is_dir() {
            add("duplicity", &dc, newest(&dc, 1, &|n| n.contains("manifest")));
        }
    }
    // Plesk, ISPConfig, typical directories
    for (kind, dir, depth) in [("plesk", "/var/lib/psa/dumps", 2u8), ("ispconfig", "/var/backup", 2), ("folder", "/backup", 2), ("folder", "/backups", 2),
        ("folder", "/var/backups", 1), ("automysqlbackup", "/var/lib/automysqlbackup", 2), ("folder", "/srv/backup", 2), ("folder", "/home/backup", 2)]
    {
        let p = r(dir);
        if p.is_dir() {
            add(kind, &p, newest(&p, depth, &archive));
        }
    }
    out.sort_by(|a, b| b.last.cmp(&a.last));
    out.dedup_by(|a, b| a.kind == b.kind && a.path == b.path);
    out.truncate(10);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_borg_and_folder_backups_but_not_dpkg() {
        let root = std::env::temp_dir().join(format!("bk-{}", std::process::id()));
        let sec = root.join("root/.config/borg/security/abc");
        std::fs::create_dir_all(&sec).unwrap();
        std::fs::write(sec.join("manifest-timestamp"), "2026-11-16T03:00:00").unwrap();
        std::fs::write(sec.join("location"), "ssh://backup@backup.example:23/./borg").unwrap();
        std::fs::create_dir_all(root.join("var/backups")).unwrap();
        std::fs::write(root.join("var/backups/dpkg.status.0"), "x").unwrap();
        let r = root.to_string_lossy().into_owned();
        let found = detect(&r);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!((found[0].kind.as_str(), found[0].path.as_str()), ("borg", "ssh://backup@backup.example:23/./borg"));
        std::fs::write(root.join("var/backups/www-2026-11-16.tar.gz"), "x").unwrap();
        assert_eq!(detect(&r).len(), 2);
        std::fs::remove_dir_all(&root).ok();
    }
}
