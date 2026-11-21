//! Fehlanmeldungen an Datenbanken (Plan „Köder-Zugangsdaten“, Phase 2): PostgreSQL und MySQL/MariaDB.
//!
//! Gemeldet werden nur **fehlgeschlagene** Anmeldungen mit Benutzername – die Zentrale gleicht sie mit den Köder-
//! Benutzern ab (wer einen Köder-Benutzer kennt, hat die Köder-Datei gelesen). Andere Regeln laufen darauf nicht.
//!
//! Quellen: Journal der Datenbank-Units (Feld `_SYSTEMD_UNIT` setzt das Journal selbst) und die üblichen Protokoll-
//! dateien. PostgreSQL protokolliert Fehlanmeldungen standardmäßig; MySQL 8 nur mit `log_error_verbosity = 3`,
//! MariaDB mit `log_warnings ≥ 2` (Standard seit 10.2.4).

use std::sync::OnceLock;

use regex::Regex;
use tyrosd_proto::LoginEvent;

fn re_pg_password() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"password authentication failed for user "([^"]{1,64})""#).unwrap())
}

fn re_pg_role() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"role "([^"]{1,64})" does not exist"#).unwrap())
}

fn re_pg_hba() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"no pg_hba\.conf entry for host "([^"]{1,64})", user "([^"]{1,64})""#).unwrap())
}

fn re_mysql() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"Access denied for user '([^']{1,64})'@'([^']{1,255})'").unwrap())
}

fn event(service: &str, user: &str, host: &str) -> LoginEvent {
    // nur IP-Adressen übernehmen (MySQL meldet auch „localhost“)
    let ip = host.parse::<std::net::IpAddr>().map(|a| a.to_string()).unwrap_or_default();
    LoginEvent { service: service.into(), success: false, user: user.into(), ip, method: "password".into(), count: 1, ..Default::default() }
}

/// Eine Zeile aus dem Protokoll einer Datenbank auswerten (`service`: postgresql | mysql)
pub fn parse_line(service: &str, line: &str) -> Option<LoginEvent> {
    match service {
        "postgresql" => {
            if let Some(c) = re_pg_hba().captures(line) {
                return Some(event(service, &c[2], &c[1]));
            }
            re_pg_password().captures(line).or_else(|| re_pg_role().captures(line)).map(|c| event(service, &c[1], ""))
        }
        "mysql" => re_mysql().captures(line).map(|c| event(service, &c[1], &c[2])),
        _ => None,
    }
}

/// Dienst aus der systemd-Unit (vom Journal gesetzt)
pub fn service_of_unit(unit: &str) -> Option<&'static str> {
    if unit.starts_with("postgresql") {
        Some("postgresql")
    } else if unit.starts_with("mariadb") || unit.starts_with("mysql") {
        Some("mysql")
    } else {
        None
    }
}

/// Protokolldateien (Debian/Ubuntu/RHEL-Standardorte), die es auf diesem Server gibt → (Pfad, Dienst)
pub fn log_files() -> Vec<(String, &'static str)> {
    let mut v = Vec::new();
    for p in ["/var/log/mysql/error.log", "/var/log/mariadb/mariadb.log", "/var/log/mysqld.log", "/var/log/mysql/mysqld.log"] {
        if std::path::Path::new(p).is_file() {
            v.push((p.to_string(), "mysql"));
        }
    }
    // Debian/Ubuntu: /var/log/postgresql/postgresql-<version>-<cluster>.log (feste Namen, Logrotate behält sie)
    if let Ok(rd) = std::fs::read_dir("/var/log/postgresql") {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with("postgresql-") && n.ends_with(".log") {
                v.push((e.path().to_string_lossy().into_owned(), "postgresql"));
            }
        }
    }
    v.sort();
    v.truncate(8);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postgres_lines() {
        let e = parse_line("postgresql", r#"2026-11-19 08:00:01.123 CET [1234] report_ro_x7f3@shop FATAL:  password authentication failed for user "report_ro_x7f3""#).unwrap();
        assert_eq!((e.service.as_str(), e.user.as_str(), e.success), ("postgresql", "report_ro_x7f3", false));
        assert_eq!(parse_line("postgresql", r#"FATAL:  role "backup_x" does not exist"#).unwrap().user, "backup_x");
        let e = parse_line("postgresql", r#"FATAL:  no pg_hba.conf entry for host "203.0.113.9", user "u1", database "shop", SSL off"#).unwrap();
        assert_eq!((e.user.as_str(), e.ip.as_str()), ("u1", "203.0.113.9"));
        assert!(parse_line("postgresql", "LOG:  checkpoint starting: time").is_none());
    }

    #[test]
    fn mysql_lines() {
        let e = parse_line("mysql", "2026-11-19T08:00:01.123456Z 12 [Warning] [MY-010926] [Server] Access denied for user 'backup_x7f3'@'localhost' (using password: YES)").unwrap();
        assert_eq!((e.service.as_str(), e.user.as_str(), e.ip.as_str()), ("mysql", "backup_x7f3", ""));
        let e = parse_line("mysql", "[Warning] Access denied for user 'root'@'198.51.100.7' (using password: YES)").unwrap();
        assert_eq!(e.ip, "198.51.100.7");
        assert!(parse_line("mysql", "[Note] mysqld: ready for connections.").is_none());
        assert_eq!(service_of_unit("postgresql@16-main.service"), Some("postgresql"));
        assert_eq!(service_of_unit("mariadb.service"), Some("mysql"));
    }
}
