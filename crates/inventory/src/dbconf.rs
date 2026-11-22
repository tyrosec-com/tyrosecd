//! MySQL/MariaDB: does the server log failed logins? (plan "decoy credentials", phase 2)
//!
//! Only the values from the configuration – whether MySQL or MariaDB is decided by the server based on the packages:
//! MySQL 8 writes "Access denied" only with `log_error_verbosity = 3`, MariaDB with `log_warnings ≥ 2` (default).
use serde::Serialize;

#[derive(Serialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct MysqlConf {
    /// Configuration found (/etc/mysql, /etc/my.cnf …)
    pub present: bool,
    pub log_error_verbosity: Option<u8>,
    pub log_warnings: Option<u8>,
}

fn files() -> Vec<std::path::PathBuf> {
    let mut v: Vec<std::path::PathBuf> = ["/etc/my.cnf", "/etc/mysql/my.cnf"].iter().map(std::path::PathBuf::from).filter(|p| p.is_file()).collect();
    for d in ["/etc/mysql", "/etc/mysql/conf.d", "/etc/mysql/mysql.conf.d", "/etc/mysql/mariadb.conf.d", "/etc/my.cnf.d"] {
        if let Ok(rd) = std::fs::read_dir(d) {
            let mut fs: Vec<_> = rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "cnf") && p.is_file()).collect();
            fs.sort();
            v.extend(fs);
        }
    }
    v.dedup();
    v.truncate(60);
    v
}

/// Values from configuration text (later lines override earlier ones, as in MySQL)
pub fn parse(text: &str, c: &mut MysqlConf) {
    for l in text.lines() {
        let l = l.trim();
        if l.starts_with('#') || l.starts_with(';') {
            continue;
        }
        let Some((k, v)) = l.split_once('=') else { continue };
        let k = k.trim().replace('-', "_").to_ascii_lowercase();
        let v = v.trim().parse::<u8>().ok();
        match k.as_str() {
            "log_error_verbosity" => c.log_error_verbosity = v.or(c.log_error_verbosity),
            "log_warnings" => c.log_warnings = v.or(c.log_warnings),
            _ => {}
        }
    }
}

pub fn mysql() -> MysqlConf {
    let fs = files();
    let mut c = MysqlConf { present: !fs.is_empty(), ..Default::default() };
    for f in fs {
        if let Ok(t) = std::fs::read_to_string(&f) {
            parse(&t, &mut c);
        }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_settings() {
        let mut c = MysqlConf::default();
        parse("[mysqld]\n# log_error_verbosity = 1\nlog_error_verbosity = 3\nlog-warnings=2\n", &mut c);
        assert_eq!((c.log_error_verbosity, c.log_warnings), (Some(3), Some(2)));
    }
}
