//! Deploy activity (`deploy_activity`, info): a deploy/update command started inside a known app root
//! (composer, bin/magento, artisan, bin/console, wp-cli, Deployer, git). The app roots come from the
//! inventory (`set_app_roots`, refreshed with every inventory run). Read only.

use std::path::Path;
use std::sync::RwLock;

static ROOTS: RwLock<Vec<String>> = RwLock::new(Vec::new());

/// Maximum number of app roots kept
const MAX_ROOTS: usize = 400;

/// Replace the known app roots (the canonical path is added as well, e.g. for `current` → `releases/N`)
pub fn set_app_roots(roots: Vec<String>) {
    let mut v: Vec<String> = Vec::new();
    for r in roots {
        let r = r.trim_end_matches('/').to_string();
        if r.is_empty() {
            continue;
        }
        if let Ok(c) = std::fs::canonicalize(&r) {
            let c = c.to_string_lossy().into_owned();
            if c != r && c != "/" {
                v.push(c);
            }
        }
        v.push(r);
    }
    v.sort();
    v.dedup();
    v.truncate(MAX_ROOTS);
    if let Ok(mut g) = ROOTS.write() {
        *g = v;
    }
}

pub fn app_roots() -> Vec<String> {
    ROOTS.read().map(|g| g.clone()).unwrap_or_default()
}

fn base(s: &str) -> &str {
    s.rsplit('/').next().unwrap_or(s)
}

/// Wrapper programs in front of the actual command
fn wrapper(b: &str) -> bool {
    matches!(b, "sudo" | "env" | "nice" | "ionice" | "nohup" | "time" | "doas" | "runuser")
        || (b.starts_with("php") && b[3..].chars().all(|c| c.is_ascii_digit() || c == '.'))
}

/// Options of wrappers that take a value (`sudo -u www-data`, `php -d x=y` has the value attached via `=`)
fn takes_value(opt: &str) -> bool {
    matches!(opt, "-u" | "-g" | "-c" | "-C" | "-d" | "--user" | "--group")
}

/// Short form of a deploy command (`composer install`, `bin/magento setup:upgrade` …) or `None`
pub fn deploy_command(cmdline: &str) -> Option<String> {
    let t: Vec<&str> = cmdline.split_whitespace().collect();
    let mut i = 0;
    while i < t.len() {
        let w = t[i];
        // wrapper, environment assignment (`APP_ENV=prod`) or a numeric wrapper value (`nice -n 10`)
        if wrapper(base(w)) || (w.contains('=') && !w.starts_with('-') && !w.contains('/')) || w.bytes().all(|c| c.is_ascii_digit()) {
            i += 1;
        } else if w.starts_with('-') {
            // wrapper option; skip its value, too
            i += if takes_value(w) { 2 } else { 1 };
        } else {
            break;
        }
    }
    let prog = *t.get(i)?;
    // first two positional arguments after the program (git: `-C <dir>` skipped)
    let mut args: Vec<&str> = Vec::new();
    let mut j = i + 1;
    while j < t.len() && args.len() < 2 {
        let a = t[j];
        if a == "-C" || a == "-d" || a == "--working-dir" {
            j += 2;
            continue;
        }
        if !a.starts_with('-') {
            args.push(a);
        }
        j += 1;
    }
    let a0 = args.first().copied().unwrap_or("");
    let a1 = args.get(1).copied().unwrap_or("");
    let b = base(prog);
    let hit = match b {
        "composer" | "composer.phar" | "composer2" if matches!(a0, "install" | "update" | "i" | "u" | "upgrade") => format!("composer {a0}"),
        "magento" if prog.ends_with("bin/magento") && matches!(a0, "setup:upgrade" | "setup:di:compile" | "setup:static-content:deploy" | "deploy:mode:set") => format!("bin/magento {a0}"),
        "artisan" if a0.starts_with("migrate") || a0.starts_with("optimize") => format!("artisan {a0}"),
        "console" if prog.ends_with("bin/console")
            && (a0.starts_with("system:update") || a0.starts_with("plugin:update") || a0 == "cache:clear" || a0 == "sw:cache:clear" || a0.starts_with("doctrine:migrations:migrate")) =>
        {
            format!("bin/console {a0}")
        }
        "wp" | "wp-cli" | "wp-cli.phar" if matches!(a0, "core" | "plugin" | "theme") && a1.starts_with("update") => format!("wp {a0} {a1}"),
        "dep" | "deployer.phar" if a0.starts_with("deploy") => format!("dep {a0}"),
        "git" if matches!(a0, "pull" | "checkout" | "reset") => format!("git {a0}"),
        _ => return None,
    };
    Some(hit)
}

/// Paths in the command line: absolute arguments and `--opt=/path` values
fn arg_paths(cmdline: &str) -> Vec<&str> {
    cmdline
        .split_whitespace()
        .filter_map(|w| if w.starts_with('/') { Some(w) } else { w.split_once('=').map(|(_, v)| v).filter(|v| v.starts_with('/')) })
        .collect()
}

fn inside<'a>(p: &str, roots: &'a [String]) -> Option<&'a String> {
    let p = p.trim_end_matches('/');
    roots.iter().filter(|r| p == r.as_str() || p.starts_with(&format!("{r}/"))).max_by_key(|r| r.len())
}

/// Deploy command inside an app root: (short command, app root)
pub fn deploy_match(cmdline: &str, cwd: Option<&str>, roots: &[String]) -> Option<(String, String)> {
    if roots.is_empty() {
        return None;
    }
    let cmd = deploy_command(cmdline)?;
    let root = cwd.and_then(|c| inside(c, roots)).or_else(|| arg_paths(cmdline).into_iter().find_map(|p| inside(p, roots)))?;
    Some((cmd, root.clone()))
}

/// Working directory of a process
pub fn cwd(pid: u32) -> Option<String> {
    std::fs::read_link(Path::new(&format!("/proc/{pid}/cwd"))).ok().map(|p| p.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands() {
        let ok = [
            ("composer install --no-dev -o", "composer install"),
            ("php /usr/local/bin/composer update", "composer update"),
            ("/usr/bin/php8.3 -d memory_limit=-1 /usr/bin/composer.phar install", "composer install"),
            ("sudo -u www-data php bin/magento setup:upgrade", "bin/magento setup:upgrade"),
            ("php bin/magento setup:static-content:deploy de_DE en_US", "bin/magento setup:static-content:deploy"),
            ("php bin/magento deploy:mode:set production", "bin/magento deploy:mode:set"),
            ("php artisan migrate --force", "artisan migrate"),
            ("php artisan optimize", "artisan optimize"),
            ("php bin/console system:update:finish", "bin/console system:update:finish"),
            ("bin/console plugin:update SwagPayPal", "bin/console plugin:update"),
            ("php bin/console cache:clear", "bin/console cache:clear"),
            ("wp plugin update --all", "wp plugin update"),
            ("php /usr/local/bin/wp --path=/var/www/site core update", "wp core update"),
            ("dep deploy production", "dep deploy"),
            ("git pull origin main", "git pull"),
            ("git -C /var/www/site reset --hard origin/main", "git reset"),
            ("/usr/bin/env php artisan migrate:fresh", "artisan migrate:fresh"),
            ("nice -n 10 composer install", "composer install"),
            ("APP_ENV=prod php83 bin/console cache:clear", "bin/console cache:clear"),
        ];
        for (c, want) in ok {
            assert_eq!(deploy_command(c).as_deref(), Some(want), "{c}");
        }
        for c in ["composer show", "php artisan queue:work", "php bin/console messenger:consume async", "php bin/magento cron:run", "wp plugin list",
            "git status", "git log", "grep composer install", "vim composer.json", "php bin/console scheduled-task:run", "dep list", "php artisan schedule:run", ""] {
            assert_eq!(deploy_command(c), None, "{c}");
        }
    }

    #[test]
    fn only_inside_app_roots() {
        let roots = vec!["/var/www/shop".to_string(), "/var/www/shop/blog".to_string(), "/srv/app".to_string()];
        assert_eq!(deploy_match("composer install", Some("/var/www/shop"), &roots), Some(("composer install".into(), "/var/www/shop".into())));
        // longest matching root
        assert_eq!(deploy_match("wp plugin update --all", Some("/var/www/shop/blog/wp-admin"), &roots).map(|x| x.1), Some("/var/www/shop/blog".into()));
        // working directory elsewhere, path in the arguments
        assert_eq!(deploy_match("php /srv/app/bin/magento setup:upgrade", Some("/root"), &roots).map(|x| x.1), Some("/srv/app".into()));
        assert_eq!(deploy_match("git -C /srv/app pull", Some("/root"), &roots).map(|x| x.1), Some("/srv/app".into()));
        assert_eq!(deploy_match("php /usr/local/bin/wp --path=/var/www/shop/blog core update", None, &roots).map(|x| x.1), Some("/var/www/shop/blog".into()));
        // outside every app root, prefix only, or no roots known
        assert_eq!(deploy_match("composer install", Some("/home/dev/project"), &roots), None);
        assert_eq!(deploy_match("composer install", Some("/var/www/shop-old"), &roots), None);
        assert_eq!(deploy_match("composer install", Some("/var/www/shop"), &[]), None);
        // not a deploy command
        assert_eq!(deploy_match("php artisan queue:work", Some("/srv/app"), &roots), None);
    }

    #[test]
    fn roots_are_canonicalised() {
        let t = std::env::temp_dir().join(format!("deploy-roots-{}", std::process::id()));
        let rel = t.join("releases/5");
        std::fs::create_dir_all(&rel).unwrap();
        let cur = t.join("current");
        let _ = std::fs::remove_file(&cur);
        std::os::unix::fs::symlink(&rel, &cur).unwrap();
        set_app_roots(vec![cur.to_string_lossy().into_owned()]);
        let r = app_roots();
        let canon = std::fs::canonicalize(&rel).unwrap().to_string_lossy().into_owned();
        assert!(r.contains(&canon) && r.contains(&cur.to_string_lossy().into_owned()), "{r:?}");
        set_app_roots(vec![]);
        std::fs::remove_dir_all(&t).ok();
    }
}
