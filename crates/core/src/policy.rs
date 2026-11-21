//! Policy: Pfad → Inhaltsmodus. Zusätzlich eine **fest eingebaute, lokale
//! Obergrenze** (Hauptplan 27.1, A1): Geheimnisse werden nie als Inhalt
//! übertragen, egal was eine (ggf. kompromittierte) Zentrale schickt.

use globset::{Glob, GlobBuilder, GlobSet, GlobSetBuilder};
use serde::Deserialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContentMode {
    Ignore = 0,
    Meta = 1,
    Hash = 2,
    Redacted = 3,
    Full = 4,
}

impl ContentMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ContentMode::Ignore => "ignore",
            ContentMode::Meta => "meta",
            ContentMode::Hash => "hash",
            ContentMode::Redacted => "redacted",
            ContentMode::Full => "full",
        }
    }
}

#[derive(Deserialize, Clone, Debug)]
pub struct Rule {
    pub glob: String,
    pub mode: ContentMode,
}

#[derive(Deserialize, Clone, Debug, Default)]
pub struct PolicyFile {
    #[serde(default)]
    pub rules: Vec<Rule>,
    pub diff_limit_bytes: Option<u64>,
    /// Texte im Modus „full“ trotzdem maskieren (Standard: ja, Sicherheitsprüfung H6)
    pub redact_full: Option<bool>,
}

pub struct Policy {
    rules: Vec<ContentMode>,
    set: GlobSet,
    caps: Vec<ContentMode>,
    cap_set: GlobSet,
    pub default_mode: ContentMode,
    pub diff_limit_bytes: u64,
    /// Geheimnisse auch in „full“-Dateien maskieren, bevor Inhalt/Diff den Server verlässt
    pub redact_full: bool,
}

fn glob(p: &str) -> Glob {
    GlobBuilder::new(p).literal_separator(true).build().expect("Glob")
}

/// Standardprofile „Linux Basis“ + „Webserver“ (Hauptplan Abschnitt 6),
/// Spike-Fassung. Spätere Regeln überschreiben frühere.
pub fn default_rules() -> Vec<(&'static str, ContentMode)> {
    use ContentMode::*;
    vec![
        // Binaries, Bibliotheken, Kernel
        ("/usr/**", Hash),
        ("/bin/**", Hash),
        ("/sbin/**", Hash),
        ("/lib/**", Hash),
        ("/lib64/**", Hash),
        ("/boot/**", Hash),
        ("/opt/**", Hash),
        ("/usr/lib/systemd/**", Full),
        ("/lib/systemd/system/**", Full),
        ("/usr/local/etc/**", Full),
        // Konfiguration, Persistenz, SSH
        ("/etc/**", Full),
        ("/var/spool/cron/**", Full),
        ("/root/.ssh/**", Full),
        ("/home/*/.ssh/**", Full),
        ("/root/.*rc", Full),
        ("/root/.profile", Full),
        ("/home/*/.*rc", Full),
        ("/home/*/.profile", Full),
        ("/root/.config/systemd/**", Full),
        ("/home/*/.config/systemd/**", Full),
        // Webroots
        ("/var/www/**", Full),
        ("/srv/**", Full),
        ("/home/*/public_html/**", Full),
        ("/var/www/vhosts/**", Full),
        // App-Konfigurationen mit Geheimnissen
        ("**/.env", Redacted),
        ("**/.env.*", Redacted),
        ("**/wp-config.php", Redacted),
        ("**/app/etc/env.php", Redacted),
        ("**/.my.cnf", Redacted),
        ("/etc/mysql/**", Redacted),
        // /dev nur Gerätedateien (/dev/null, /dev/pts …) – reines Rauschen; /dev/shm unten wieder an
        ("/dev/**", Ignore),
        // Malware-Ablageorte
        ("/tmp/**", Hash),
        ("/var/tmp/**", Hash),
        ("/dev/shm/**", Hash),
        // Rauschen
        ("/proc/**", Ignore),
        ("/sys/**", Ignore),
        ("/run/**", Ignore),
        ("/var/log/**", Ignore),
        ("/var/cache/**", Ignore),
        ("/var/lib/apt/lists/**", Ignore),
        ("/var/lib/mysql/**", Ignore),
        // Datenverzeichnisse von Diensten (ändern sich ständig; Integrität ist dort nicht FIM-Sache)
        ("/var/lib/mariadb/**", Ignore),
        ("/var/lib/postgresql/**", Ignore),
        ("/var/lib/pgsql/**", Ignore),
        ("/var/lib/redis/**", Ignore),
        ("/var/lib/mongodb/**", Ignore),
        ("/var/lib/elasticsearch/**", Ignore),
        ("/var/lib/opensearch/**", Ignore),
        ("/var/lib/clickhouse/**", Ignore),
        ("/var/lib/influxdb/**", Ignore),
        // Monitoring-Daten (Praxisfall: 33 000 Prometheus-WAL-Ereignisse am Tag auf einem Server)
        ("/var/lib/prometheus/**", Ignore),
        ("/var/lib/grafana/**", Ignore),
        ("/var/lib/loki/**", Ignore),
        // systemd-timesyncd schreibt jede Minute einen Zeitstempel (je Server ~1 300 Ereignisse am Tag)
        ("/var/lib/systemd/timesync/**", Ignore),
        // runc legt je „docker exec“ eine Prozessdatei an und löscht sie wieder (Praxisfall auf einem Mailserver: 23 000 am Tag)
        ("/tmp/runc-process*", Ignore),
        // Protokolle von Anwendungen (Laravel storage/logs, Symfony/Shopware var/log) – kein Code
        ("**/storage/logs/**", Ignore),
        ("**/var/log/**", Ignore),
        ("/var/lib/rabbitmq/**", Ignore),
        ("/var/lib/memcached/**", Ignore),
        ("/var/lib/php/**", Ignore),
        ("/var/lib/nginx/**", Ignore),
        ("/var/lib/systemd/timers/**", Ignore),
        ("/var/lib/systemd/coredump/**", Ignore),
        ("/var/lib/fail2ban/**", Ignore),
        ("/var/lib/crowdsec/**", Ignore),
        ("/var/spool/postfix/**", Ignore),
        ("/var/spool/exim4/**", Ignore),
        ("/var/lib/snapd/**", Ignore),
        ("/var/lib/tyrosec-ingest/**", Ignore),
        ("/var/lib/tyrosd-ingest/**", Ignore),
        ("/var/lib/docker/**", Ignore),
        ("/var/lib/containerd/**", Ignore),
        ("/var/lib/php/sessions/**", Ignore),
        ("/var/lib/tyrosecd/**", Ignore),
        ("/var/lib/tyrosd/**", Ignore), // Altinstallationen vor der Umbenennung
        ("/var/lib/tyrosd-spike/**", Ignore),
        ("**/wp-content/cache/**", Ignore),
        ("**/var/cache/**", Ignore),
        ("**/node_modules/.cache/**", Ignore),
        // Praxisfall (Entwickler- und Testserver): Build-Cache von Next.js, V8-Compile-Cache von Node,
        // Browser-Caches von Puppeteer/Playwright-Profilen in /tmp und Testartefakte von Playwright – kein ausgeführter
        // Servercode, je Lauf Tausende Dateien. Ausführen aus /tmp erkennt weiterhin die Prozess-Überwachung.
        ("**/.next/cache/**", Ignore),
        ("/tmp/node-compile-cache/**", Ignore),
        ("/tmp/*/Default/Cache/**", Ignore),
        ("/tmp/*/Default/Code Cache/**", Ignore),
        ("/tmp/*/Default/GPUCache/**", Ignore),
        ("/tmp/*/Default/Service Worker/CacheStorage/**", Ignore),
        ("**/.playwright-artifacts-*/**", Ignore),
        // Nextcloud-Vorschaubilder (appdata_<instanz>/preview): reiner Cache, oft Zehntausende Ordner
        // (Praxisfall bei einer Installation: 53 000 von 137 000 Ordnern) – kein Code, wird neu erzeugt
        ("**/appdata_*/preview/**", Ignore),
        // Bytecode-Caches (schreibt der Interpreter selbst, z. B. Python beim Start von ufw)
        ("**/__pycache__/**", Ignore),
        ("**/*.pyc", Ignore),
        ("/tmp/systemd-private-*/**", Ignore),
        // Hilfsdateien von Datenbanken, die bei jeder Schreibtransaktion entstehen: PostgreSQL-
        // Shared-Memory-Segmente, SQLite-Journal und -WAL – kein Code, nicht ausführbar, Inhalt ist die Datenbank selbst
        ("/dev/shm/PostgreSQL.*", Ignore),
        ("**/*.db-wal", Ignore),
        ("**/*.db-shm", Ignore),
        ("**/*.db-journal", Ignore),
        ("**/*.sqlite-wal", Ignore),
        ("**/*.sqlite-shm", Ignore),
        ("**/*.sqlite-journal", Ignore),
        ("**/*.sqlite3-wal", Ignore),
        ("**/*.sqlite3-shm", Ignore),
        ("**/*.sqlite3-journal", Ignore),
        ("/etc/ld.so.cache", Hash),
    ]
}

/// Feste Obergrenzen. Nicht per Policy lockerbar.
pub fn hard_caps() -> Vec<(&'static str, ContentMode)> {
    use ContentMode::*;
    vec![
        ("/etc/shadow", Hash),
        ("/etc/shadow-", Hash),
        ("/etc/gshadow", Hash),
        ("/etc/gshadow-", Hash),
        ("/etc/security/opasswd", Hash),
        ("/etc/ssh/ssh_host_*_key", Hash),
        ("**/.ssh/id_*", Hash),
        ("**/.ssh/*_key", Hash),
        ("**/*.key", Hash),
        ("**/*.pem", Hash),
        ("**/*.p12", Hash),
        ("**/*.pfx", Hash),
        ("**/.gnupg/**", Hash),
        ("**/.aws/credentials", Hash),
        ("**/.kube/config", Hash),
        ("**/.docker/config.json", Hash),
        ("/etc/letsencrypt/archive/**", Hash),
        ("/etc/letsencrypt/live/**", Hash),
        ("/etc/letsencrypt/keys/**", Hash),
        ("**/.env", Redacted),
        ("**/.env.*", Redacted),
        ("**/wp-config.php", Redacted),
        ("**/app/etc/env.php", Redacted),
        ("**/.my.cnf", Redacted),
        ("**/.pgpass", Hash),
        ("**/.netrc", Hash),
        ("**/.git-credentials", Hash),
        // Sicherheitsprüfung H6: Dateien, die fast nur aus Geheimnissen bestehen – nie Inhalt, nur Hash/Metadaten
        ("/etc/wireguard/**", Hash),
        ("**/wg*.conf", Hash),
        ("/etc/kubernetes/**", Hash),
        ("**/.kube/**", Hash),
        ("**/kubeconfig", Hash),
        ("**/*.kubeconfig", Hash),
        ("/etc/rancher/**", Hash),
        ("/var/lib/kubelet/**", Hash),
        ("**/*.sql", Hash),
        ("**/.htpasswd", Hash),
        ("**/*.htpasswd", Hash),
        // Web-Anwendungen mit Datenbank-Passwörtern/Schlüsseln in PHP-Konfigurationen
        ("**/config/config.php", Hash),           // Nextcloud/ownCloud
        ("**/configuration.php", Hash),           // Joomla
        ("**/settings.php", Hash),                // Drupal (sites/*/settings.php), TYPO3 ≥ 12 (config/system/settings.php)
        ("**/settings.local.php", Hash),          // Drupal
        ("**/LocalConfiguration.php", Hash),      // TYPO3 ≤ 11
        ("**/AdditionalConfiguration.php", Hash), // TYPO3
        ("**/parameters.php", Hash),              // PrestaShop 1.7+ (app/config/parameters.php)
        ("**/settings.inc.php", Hash),            // PrestaShop 1.6
    ]
}

impl Policy {
    pub fn new(rules: &[(String, ContentMode)]) -> Policy {
        let mut b = GlobSetBuilder::new();
        let mut modes = Vec::new();
        for (g, m) in rules {
            b.add(glob(g));
            modes.push(*m);
        }
        let mut cb = GlobSetBuilder::new();
        let mut caps = Vec::new();
        for (g, m) in hard_caps() {
            cb.add(glob(g));
            caps.push(m);
        }
        Policy {
            rules: modes,
            set: b.build().expect("GlobSet"),
            caps,
            cap_set: cb.build().expect("GlobSet"),
            default_mode: ContentMode::Hash,
            diff_limit_bytes: 2 * 1024 * 1024,
            redact_full: true,
        }
    }

    /// Ist ein unveränderter Schreibzugriff (WRITE_NOCHANGE) hier von Bedeutung? Nur für Zugänge, Rechte, Anmeldung und
    /// Autostart – dieselbe Liste, für die die Zentrale alarmiert. Sonst kein Ereignis (Praxisfall: 30 % aller
    /// Datei-Ereignisse waren unveränderte Schreibzugriffe auf Datenbanken, Logs, Sperrdateien).
    pub fn nochange_relevant(path: &str) -> bool {
        let p = crate::container::effective(path);
        matches!(p, "/etc/passwd" | "/etc/shadow" | "/etc/group" | "/etc/gshadow" | "/etc/sudoers" | "/etc/ld.so.preload" | "/etc/crontab"
            | "/etc/ssh/sshd_config" | "/etc/rc.local" | "/etc/environment" | "/etc/profile" | "/etc/bash.bashrc")
            || ["/etc/sudoers.d/", "/etc/ssh/sshd_config.d/", "/etc/pam.d/", "/etc/cron.d/", "/etc/systemd/system/", "/etc/profile.d/", "/etc/security/",
                "/var/spool/cron/"]
                .iter()
                .any(|d| p.starts_with(d))
            || p.contains("/.ssh/")
    }

    pub fn default_policy() -> Policy {
        let r: Vec<(String, ContentMode)> =
            default_rules().into_iter().map(|(g, m)| (g.to_string(), m)).collect();
        Policy::new(&r)
    }

    /// Standardregeln + Regeln aus einer JSON-Datei (werden angehängt).
    pub fn from_file(path: &str) -> anyhow::Result<Policy> {
        let f: PolicyFile = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        let mut r: Vec<(String, ContentMode)> =
            default_rules().into_iter().map(|(g, m)| (g.to_string(), m)).collect();
        r.extend(f.rules.into_iter().map(|x| (x.glob, x.mode)));
        let mut p = Policy::new(&r);
        if let Some(l) = f.diff_limit_bytes {
            p.diff_limit_bytes = l;
        }
        if let Some(r) = f.redact_full {
            p.redact_full = r;
        }
        Ok(p)
    }

    /// Modus für einen Pfad, nach Anwendung der festen Obergrenze.
    pub fn mode_for(&self, path: &str) -> ContentMode {
        // Container: Docker-/Podman-Speicher bleibt ausgenommen, außer der Schreibschicht (Laufzeit-Änderungen);
        // in Container-Wurzeln gelten die Regeln für den Pfad im Container
        if let Some(c) = crate::container::container_path(path) {
            return self.mode_for_plain(c.rel);
        }
        self.mode_for_plain(path)
    }

    fn mode_for_plain(&self, path: &str) -> ContentMode {
        let m = self
            .set
            .matches(path)
            .into_iter()
            .max()
            .map(|i| self.rules[i])
            .unwrap_or(self.default_mode);
        if m == ContentMode::Ignore {
            return m;
        }
        let cap = self.cap_set.matches(path).into_iter().map(|i| self.caps[i]).min();
        match cap {
            Some(c) if c < m => c,
            _ => m,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ContentMode::*;

    #[test]
    fn noise_rules_20_11() {
        let p = Policy::default_policy();
        for x in ["/var/lib/prometheus/metrics2/wal/00001234", "/var/lib/grafana/grafana.db", "/var/lib/systemd/timesync/clock",
            "/tmp/runc-process123456", "/users/www/app/storage/logs/laravel.log", "/users/www/shop/var/log/prod.log",
            "/users/www/appfrontend/.next/cache/webpack/server/0.pack", "/tmp/node-compile-cache/v22.16.0-x64-efe9a9df-1000/abc",
            "/tmp/puppeteer_dev_chrome_profile-W6xvAi/Default/Cache/Cache_Data/f_000001",
            "/tmp/ff_prof_hk_1795180678107/Default/Code Cache/js/index",
            "/opt/app-tests/e2e/.run/product/output/.playwright-artifacts-2/traces/resources/x.png"] {
            assert_eq!(p.mode_for(x), Ignore, "{x}");
        }
        assert_ne!(p.mode_for("/tmp/x.sh"), Ignore);
        // Build-Ausgabe selbst (ausführbarer Servercode) und Profil-Wurzel in /tmp bleiben überwacht
        assert_ne!(p.mode_for("/users/www/appfrontend/.next/server/app/page.js"), Ignore);
        assert_ne!(p.mode_for("/tmp/puppeteer_dev_chrome_profile-W6xvAi/x.sh"), Ignore);
        assert!(Policy::nochange_relevant("/etc/sudoers.d/90-admin"));
        assert!(Policy::nochange_relevant("/root/.ssh/authorized_keys"));
        assert!(Policy::nochange_relevant("/var/lib/machines/app/etc/shadow"));
        assert!(!Policy::nochange_relevant("/users/www/poc3/daten/dienst.sqlite3"));
        assert!(!Policy::nochange_relevant("/etc/nginx/nginx.conf"));
    }

    #[test]
    fn containers_use_inner_rules() {
        let p = Policy::default_policy();
        assert_eq!(p.mode_for("/var/lib/machines/app/var/log/syslog"), Ignore);
        assert_eq!(p.mode_for("/var/lib/machines/app/var/lib/postgresql/16/main/base/1"), Ignore);
        assert_eq!(p.mode_for("/var/lib/machines/app/var/www/shop/index.php"), Full);
        assert_eq!(p.mode_for("/var/lib/machines/app/etc/shadow"), Hash);
        assert_eq!(p.mode_for("/var/lib/docker/overlay2/abc/diff/var/www/html/x.php"), Full);
        assert_eq!(p.mode_for("/var/lib/docker/overlay2/abc/merged/var/www/html/x.php"), Ignore);
        assert_eq!(p.mode_for("/var/lib/docker/image/overlay2/repositories.json"), Ignore);
    }

    #[test]
    fn database_side_files_ignored() {
        let p = Policy::default_policy();
        assert_eq!(p.mode_for("/dev/shm/PostgreSQL.1234567"), Ignore);
        assert_eq!(p.mode_for("/var/www/app/storage/database.sqlite-journal"), Ignore);
        assert_eq!(p.mode_for("/var/www/app/data/app.db-wal"), Ignore);
        assert_ne!(p.mode_for("/var/www/app/data/app.db"), Ignore);
        assert_ne!(p.mode_for("/dev/shm/x.sh"), Ignore);
    }

    #[test]
    fn nextcloud_preview_cache_ignored() {
        let p = Policy::default_policy();
        assert_eq!(p.mode_for("/users/www/site/nextcloud/data/appdata_oce1u9kp4jmo/preview/8/6/2/3/x.jpg"), ContentMode::Ignore);
        assert_eq!(p.mode_for("/var/www/nc/data/appdata_abc/preview/1/.x"), ContentMode::Ignore);
        // Code der Nextcloud und andere appdata-Ordner bleiben überwacht
        assert_ne!(p.mode_for("/var/www/nc/apps/files/lib/App.php"), ContentMode::Ignore);
        assert_ne!(p.mode_for("/var/www/nc/data/appdata_abc/theming/x.php"), ContentMode::Ignore);
    }

    #[test]
    fn defaults() {
        let p = Policy::default_policy();
        assert_eq!(p.mode_for("/etc/passwd"), Full);
        assert_eq!(p.mode_for("/etc/shadow"), Hash);
        assert_eq!(p.mode_for("/root/.ssh/authorized_keys"), Full);
        assert_eq!(p.mode_for("/root/.ssh/id_ed25519"), Hash);
        assert_eq!(p.mode_for("/var/www/html/wp-config.php"), Redacted);
        assert_eq!(p.mode_for("/var/www/html/index.php"), Full);
        assert_eq!(p.mode_for("/usr/bin/ls"), Hash);
        assert_eq!(p.mode_for("/var/log/syslog"), Ignore);
        assert_eq!(p.mode_for("/proc/1/status"), Ignore);
        assert_eq!(p.mode_for("/dev/null"), Ignore);
        assert_eq!(p.mode_for("/dev/pts/0"), Ignore);
        assert_eq!(p.mode_for("/dev/shm/x.sh"), Hash);
        assert_eq!(p.mode_for("/etc/ssh/ssh_host_ed25519_key"), Hash);
        assert_eq!(p.mode_for("/etc/ssh/ssh_host_ed25519_key.pub"), Full);
    }

    #[test]
    fn policy_cannot_lift_caps() {
        // Simuliert eine kompromittierte Zentrale, die Geheimnisse anfordert.
        let mut r: Vec<(String, ContentMode)> =
            default_rules().into_iter().map(|(g, m)| (g.to_string(), m)).collect();
        r.push(("/etc/shadow".into(), Full));
        r.push(("/root/.ssh/**".into(), Full));
        r.push(("**".into(), Full));
        let p = Policy::new(&r);
        assert_eq!(p.mode_for("/etc/shadow"), Hash);
        assert_eq!(p.mode_for("/root/.ssh/id_rsa"), Hash);
        assert_eq!(p.mode_for("/srv/app/.env"), Redacted);
    }

    #[test]
    fn secret_files_only_hash() {
        let p = Policy::default_policy();
        assert!(p.redact_full, "Standard: auch „full“ wird maskiert");
        for f in [
            "/etc/wireguard/wg0.conf",
            "/etc/kubernetes/admin.conf",
            "/root/.kube/config",
            "/home/a/.kube/cache/x",
            "/etc/rancher/k3s/k3s.yaml",
            "/var/www/shop/backup.sql",
            "/var/www/html/.htpasswd",
            "/var/www/nextcloud/config/config.php",
            "/var/www/joomla/configuration.php",
            "/var/www/drupal/sites/default/settings.php",
            "/var/www/typo3/typo3conf/LocalConfiguration.php",
            "/var/www/typo3/config/system/settings.php",
            "/var/www/presta/app/config/parameters.php",
        ] {
            assert_eq!(p.mode_for(f), Hash, "{f}");
        }
        assert_eq!(p.mode_for("/var/www/html/index.php"), Full);
    }
}
