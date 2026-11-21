//! Vorgeschichte über ctime (aus dem Userspace kaum fälschbar): Änderungen
//! pro Tag in den letzten N Tagen, Häufungen, jüngste Änderungen an
//! sensiblen Orten, Hinweise auf Timestomping (mtime ≪ ctime).

use std::os::unix::fs::MetadataExt;

use serde::Serialize;

use crate::{Category, Ctx, Severity};

#[derive(Serialize, Debug, Default)]
pub struct Timeline {
    /// (Tag als YYYY-MM-DD, Anzahl Dateien mit ctime an diesem Tag)
    pub days: Vec<(String, u64)>,
    pub peaks: Vec<(String, u64)>,
    pub recent_sensitive: Vec<(String, String)>,
}

fn ymd(secs: i64) -> String {
    // Tage seit Epoch → Datum (proleptischer Gregorianischer Kalender)
    let z = secs.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{:04}-{:02}-{:02}", if m <= 2 { y + 1 } else { y }, m, d)
}

const SENSITIVE: &[&str] = &["/etc/", "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/local/bin/", "/root/.ssh/", "/var/spool/cron/", "/etc/systemd/", "/lib/systemd/", "/usr/lib/systemd/"];

pub fn check(ctx: &mut Ctx) {
    let now = tyrosd_core::now_ns() / 1_000_000_000;
    let days = ctx.cfg.timeline_days;
    let since = now - days * 86_400;
    let mut roots: Vec<String> = ["/etc", "/usr/bin", "/usr/sbin", "/usr/local", "/root", "/home", "/var/spool/cron", "/opt"].iter().map(|r| ctx.p(r)).collect();
    roots.extend(ctx.cfg.webroots.iter().cloned());
    let mut per_day: std::collections::BTreeMap<String, u64> = Default::default();
    let mut recent: Vec<(i64, String)> = Vec::new();
    let mut stomp = 0usize;
    for r in roots {
        let mut it = walkdir::WalkDir::new(&r).follow_links(false).same_file_system(true).into_iter();
        while let Some(Ok(e)) = it.next() {
            if e.file_type().is_dir() {
                let n = e.file_name().to_string_lossy();
                if matches!(n.as_ref(), "node_modules" | ".git" | "cache" | ".cache") {
                    it.skip_current_dir();
                }
                continue;
            }
            if !e.file_type().is_file() {
                continue;
            }
            let Ok(m) = e.metadata() else { continue };
            let ct = m.ctime();
            if ct < since {
                continue;
            }
            *per_day.entry(ymd(ct)).or_default() += 1;
            let p = e.path().to_string_lossy().into_owned();
            let rel = p.strip_prefix(ctx.cfg.sysroot.trim_end_matches('/')).unwrap_or(&p).to_string();
            if SENSITIVE.iter().any(|s| rel.starts_with(s)) || rel.contains("/.ssh/") {
                recent.push((ct, p.clone()));
            }
            // mtime liegt > 180 Tage vor ctime, ctime in den letzten 30 Tagen, PHP
            if p.ends_with(".php") && ct > now - 30 * 86_400 && m.mtime() < ct - 180 * 86_400 {
                stomp += 1;
                if stomp <= 30 {
                    ctx.add(Severity::Low, Category::History, "mtime_older_than_ctime", "PHP-Datei kürzlich geändert, Zeitstempel aber alt (Deploy mit rsync -a oder Timestomping)", Some(p), Some(format!("mtime {} · ctime {}", ymd(m.mtime()), ymd(ct))));
                }
            }
        }
    }
    let counts: Vec<u64> = per_day.values().cloned().collect();
    let mut sorted = counts.clone();
    sorted.sort();
    let median = sorted.get(sorted.len() / 2).cloned().unwrap_or(0);
    let threshold = (median * 5).max(50);
    let peaks: Vec<(String, u64)> = per_day.iter().filter(|(_, c)| **c >= threshold).map(|(d, c)| (d.clone(), *c)).collect();
    for (d, c) in &peaks {
        ctx.add(Severity::Info, Category::History, "ctime_peak", format!("Häufung von Änderungen am {d}: {c} Dateien"), None, Some("Mit Updates/Deploys an diesem Tag abgleichen".into()));
    }
    recent.sort_by(|a, b| b.0.cmp(&a.0));
    let recent_sensitive: Vec<(String, String)> = recent.into_iter().take(40).map(|(t, p)| (ymd(t), p)).collect();
    ctx.stat("timeline_days_with_changes", per_day.len());
    ctx.report.timeline = Some(Timeline { days: per_day.into_iter().collect(), peaks, recent_sensitive });
}

#[cfg(test)]
mod tests {
    #[test]
    fn date() {
        assert_eq!(super::ymd(0), "1970-01-01");
        assert_eq!(super::ymd(1_731_542_400), "2024-11-14");
    }
}
