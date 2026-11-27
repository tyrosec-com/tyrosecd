//! Package E 5.1 (plan 2026-11-27): hardening findings – read only. Each finding names the setting, the file and
//! a ready-made snippet; nothing is changed (an optional "harden" action exists only with all three keys).
//! Severity low/medium: shown in the check report, no alert (exception: `.env` inside the web root).

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;

use crate::app::{read_small, App, SMALL};
use crate::apphard::{strip_php_comments, AppFinding};
use crate::Severity;

fn s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// Hardening findings of one application
pub fn findings(a: &App, web_conf: &str) -> Vec<AppFinding> {
    let root = Path::new(&a.root);
    let mut out = Vec::new();
    match a.kind.as_str() {
        "WordPress" | "WooCommerce" => {
            if let Some(cfg) = crate::apphard::wp_config_path(root) {
                if let Some(text) = read_small(&cfg, SMALL) {
                    if !wp_file_edit_disabled(&text) {
                        out.push(AppFinding {
                            severity: Severity::Low,
                            check: "wp_file_edit_enabled",
                            title: "WordPress file editor enabled".into(),
                            path: s(&cfg),
                            detail: format!("DISALLOW_FILE_EDIT is not set in {}\nWhoever gets an admin login can change PHP code of plugins and themes in the browser.\nFix (above the line \"That's all, stop editing!\"): define('DISALLOW_FILE_EDIT', true);", cfg.display()),
                        });
                    }
                }
            }
            if let Some(up) = a.media.iter().map(|m| root.join(m)).find(|m| m.ends_with("wp-content/uploads")) {
                if !uploads_php_blocked(&up, web_conf) {
                    out.push(AppFinding {
                        severity: Severity::Medium,
                        check: "uploads_php_allowed",
                        title: "PHP execution not blocked in the upload folder".into(),
                        path: s(&up),
                        detail: format!("Neither a .htaccess rule nor an nginx location blocks PHP files in {}\nA PHP file planted there (web shell) can be run from the browser.\nFix Apache – file {}/.htaccess:\n<FilesMatch \"\\.(php|phtml|phar)$\">\n  Require all denied\n</FilesMatch>\nFix nginx – in the server block:\nlocation ~* /wp-content/uploads/.*\\.(php|phtml|phar)$ {{ deny all; }}", up.display(), up.display()),
                    });
                }
            }
        }
        "Magento" => {
            let env = root.join("app/etc/env.php");
            let env = if env.is_file() { env } else { root.parent().map(|p| p.join("app/etc/env.php")).unwrap_or(env) };
            if let Some(text) = read_small(&env, SMALL) {
                if magento_admin_default(&text) {
                    out.push(AppFinding {
                        severity: Severity::Medium,
                        check: "magento_admin_default_path",
                        title: "Magento admin at the default address /admin".into(),
                        path: s(&env),
                        detail: format!("backend frontName is 'admin' in {}\nBots try logins on /admin of every Magento shop.\nFix: bin/magento setup:config:set --backend-frontname=\"<own name>\"", env.display()),
                    });
                }
            }
        }
        "Laravel" => {
            for p in laravel_public_env(root) {
                out.push(AppFinding {
                    severity: Severity::High,
                    check: "env_in_webroot",
                    title: "Environment file inside the public web folder: Laravel".into(),
                    path: s(&p),
                    detail: format!("{} is inside the public folder – depending on the web server configuration it can be downloaded with all credentials.\nFix: move it to the project folder (one level above public/) and change the credentials it contains.", p.display()),
                });
            }
        }
        "Nextcloud" => {
            use std::os::unix::fs::PermissionsExt;
            let p = root.join("config/config.php");
            if let Ok(m) = std::fs::metadata(&p) {
                let mode = m.permissions().mode() & 0o7777;
                if m.is_file() && mode & 0o004 != 0 {
                    out.push(AppFinding {
                        severity: Severity::Medium,
                        check: "nextcloud_config_readable",
                        title: "Nextcloud configuration readable by all users".into(),
                        path: s(&p),
                        detail: format!("Mode {mode:04o} on {} – every user and every process on the server can read the database password and the secret.\nFix: chmod 0640 {} (owner: web server user)", p.display(), p.display()),
                    });
                }
            }
        }
        _ => {}
    }
    out
}

fn file_edit_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"(?i)\bdefine\s*\(\s*['"](DISALLOW_FILE_EDIT|DISALLOW_FILE_MODS)['"]\s*,\s*(true|1|'1'|"1")\s*\)"#).unwrap())
}

/// DISALLOW_FILE_EDIT (or the stricter DISALLOW_FILE_MODS) set to true
pub fn wp_file_edit_disabled(cfg: &str) -> bool {
    file_edit_re().is_match(&strip_php_comments(cfg))
}

/// Magento `'backend' => ['frontName' => 'admin']`
pub fn magento_admin_default(env_php: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    let r = R.get_or_init(|| Regex::new(r#"(?is)['"]backend['"]\s*=>\s*(?:\[|array\s*\()\s*['"]frontName['"]\s*=>\s*['"]([^'"]*)['"]"#).unwrap());
    r.captures(&strip_php_comments(env_php)).is_some_and(|c| c[1].eq_ignore_ascii_case("admin"))
}

/// `.env` files of a Laravel app inside its public folder
fn laravel_public_env(root: &Path) -> Vec<PathBuf> {
    let mut v = vec![root.join("public/.env")];
    if root.ends_with("public") {
        v.push(root.join(".env"));
    }
    v.into_iter().filter(|p| p.is_file()).collect()
}

/// Is PHP execution in the upload folder blocked – Apache `.htaccess` in the folder, or an nginx/Apache rule in the
/// web server configuration?
pub fn uploads_php_blocked(dir: &Path, web_conf: &str) -> bool {
    let ht = read_small(&dir.join(".htaccess"), SMALL).unwrap_or_default().to_ascii_lowercase();
    if htaccess_blocks_php(&ht) {
        return true;
    }
    conf_blocks_uploads_php(web_conf)
}

pub fn htaccess_blocks_php(ht: &str) -> bool {
    let ht = ht.to_ascii_lowercase();
    (ht.contains("php_flag engine off") || ht.contains("php_admin_flag engine off") || ht.contains("removehandler") || ht.contains("sethandler none") || ht.contains("removetype"))
        || (ht.contains("php") && (ht.contains("require all denied") || ht.contains("deny from all")))
}

/// nginx `location ~* …uploads….php { deny all; }` (or return 403/404) or Apache `<Directory …uploads>` with a PHP block
pub fn conf_blocks_uploads_php(conf: &str) -> bool {
    static N: OnceLock<Regex> = OnceLock::new();
    static A: OnceLock<Regex> = OnceLock::new();
    let n = N.get_or_init(|| Regex::new(r#"(?is)location\s+~\*?\s+[^{]*uploads[^{]*php[^{]*\{[^}]*(deny\s+all|return\s+40[34])"#).unwrap());
    let a = A.get_or_init(|| Regex::new(r#"(?is)<Directory(Match)?\s+[^>]*uploads[^>]*>.*?(php_admin_flag\s+engine\s+off|php_flag\s+engine\s+off|Require\s+all\s+denied|SetHandler\s+none|RemoveHandler).*?</Directory"#).unwrap());
    n.is_match(conf) || a.is_match(conf)
}

/// Web server configuration as one text (nginx, Apache; at most 500 files / 4 MB) for the rule search
pub fn web_conf() -> String {
    let mut out = String::new();
    let mut stack: Vec<PathBuf> = ["/etc/nginx", "/etc/apache2", "/etc/httpd", "/etc/openlitespeed", "/usr/local/lsws/conf"].iter().map(PathBuf::from).collect();
    let mut n = 0;
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(t) = e.file_type() else { continue };
            if t.is_dir() {
                stack.push(p);
            } else if n < 500 && out.len() < 4 << 20 {
                if let Some(s) = read_small(&p, SMALL) {
                    out.push_str(&s);
                    out.push('\n');
                    n += 1;
                }
            }
        }
    }
    out
}

/// PHP settings of the web PHP (FPM/Apache module): display_errors, expose_php, functions that start programs.
/// Returns (check, severity, title, file, detail).
pub fn php_ini() -> Vec<(&'static str, Severity, String, String, String)> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir("/etc/php") else { return out };
    let mut versions: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
    versions.sort();
    for v in versions {
        for sapi in ["fpm", "apache2"] {
            let ini = v.join(sapi).join("php.ini");
            let Some(main) = read_small(&ini, SMALL) else { continue };
            let mut texts = vec![main];
            if let Ok(rd) = std::fs::read_dir(v.join(sapi).join("conf.d")) {
                let mut f: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
                f.sort();
                texts.extend(f.iter().filter_map(|p| read_small(p, SMALL)));
            }
            let val = |key: &str| texts.iter().filter_map(|t| ini_value(t, key)).last();
            let ver = v.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
            let label = format!("PHP {ver} ({sapi})");
            if val("display_errors").is_some_and(|x| on(&x)) {
                out.push(("php_display_errors", Severity::Low, format!("PHP shows errors to visitors: {label}"), s(&ini),
                    format!("display_errors = On in {} (or conf.d)\nError messages reveal paths, versions and sometimes credentials.\nFix: display_errors = Off (log errors instead: log_errors = On)", ini.display())));
            }
            if val("expose_php").is_some_and(|x| on(&x)) {
                out.push(("php_expose", Severity::Low, format!("PHP reveals its version: {label}"), s(&ini),
                    format!("expose_php = On in {}\nEvery response carries the header X-Powered-By with the exact PHP version – scanners look for it.\nFix: expose_php = Off", ini.display())));
            }
            let disabled = val("disable_functions").unwrap_or_default().to_ascii_lowercase();
            let open: Vec<&str> = ["exec", "system", "shell_exec", "passthru", "proc_open", "popen"]
                .into_iter()
                .filter(|f| !disabled.split(',').any(|d| d.trim() == *f))
                .collect();
            if open.len() == 6 {
                out.push(("php_exec_functions", Severity::Low, format!("PHP may start programs: {label}"), s(&ini),
                    format!("disable_functions does not block {} in {}\nA web shell uses exactly these functions to run commands on the server.\nFix (check first whether a plugin needs them, e.g. backup or image tools): disable_functions = exec,system,shell_exec,passthru,proc_open,popen\nPossible side effect: plugins that call programs (backups, PDF/image tools) stop working.", open.join(", "), ini.display())));
            }
        }
    }
    out
}

fn on(v: &str) -> bool {
    matches!(v.trim().trim_matches('"').to_ascii_lowercase().as_str(), "on" | "1" | "true" | "yes" | "stdout" | "stderr")
}

/// Last value of `key = value` in an ini text (comments with `;`)
pub fn ini_value(text: &str, key: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with(';') && !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .filter(|(k, _)| k.trim().eq_ignore_ascii_case(key))
        .map(|(_, v)| v.split(';').next().unwrap_or("").trim().to_string())
        .last()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordpress_file_edit() {
        assert!(!wp_file_edit_disabled("<?php\ndefine('DB_NAME','x');\n"));
        assert!(!wp_file_edit_disabled("<?php\n// define('DISALLOW_FILE_EDIT', true);\n"));
        assert!(!wp_file_edit_disabled("<?php\ndefine('DISALLOW_FILE_EDIT', false);\n"));
        assert!(wp_file_edit_disabled("<?php\ndefine( 'DISALLOW_FILE_EDIT', true );\n"));
        assert!(wp_file_edit_disabled("<?php\ndefine(\"DISALLOW_FILE_MODS\", 1);\n"));
    }

    #[test]
    fn magento_admin_path() {
        assert!(magento_admin_default("<?php return ['backend' => ['frontName' => 'admin'], 'db' => []];"));
        assert!(!magento_admin_default("<?php return ['backend' => ['frontName' => 'admin_x7k2']];"));
        assert!(magento_admin_default("<?php return array('backend' => array('frontName' => 'Admin'));"));
    }

    #[test]
    fn upload_php_rules() {
        assert!(htaccess_blocks_php("<FilesMatch \"\\.(php|phtml)$\">\nRequire all denied\n</FilesMatch>"));
        assert!(htaccess_blocks_php("php_flag engine off"));
        assert!(!htaccess_blocks_php("# BEGIN WebP Express\nRewriteEngine On\n"));
        assert!(conf_blocks_uploads_php("server {\n location ~* /(?:uploads|files)/.*\\.php$ {\n   deny all;\n }\n}"));
        assert!(conf_blocks_uploads_php("location ~* ^/wp-content/uploads/.*\\.php$ { return 403; }"));
        assert!(!conf_blocks_uploads_php("location ~ \\.php$ { fastcgi_pass unix:/run/php/php8.3-fpm.sock; }"));
        assert!(conf_blocks_uploads_php("<Directory /var/www/wp/wp-content/uploads>\n  php_admin_flag engine off\n</Directory>"));
    }

    #[test]
    fn ini_values() {
        let t = "; display_errors = On\ndisplay_errors = Off\nexpose_php = On ; comment\ndisable_functions =\n";
        assert_eq!(ini_value(t, "display_errors").as_deref(), Some("Off"));
        assert_eq!(ini_value(t, "expose_php").as_deref(), Some("On"));
        assert_eq!(ini_value(t, "disable_functions").as_deref(), Some(""));
        assert!(on("On") && !on("Off"));
    }
}
