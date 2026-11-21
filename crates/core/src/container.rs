//! Pfade in Container-Wurzeln erkennen (systemd-nspawn, LXC/LXD/Incus, Docker- und Podman-Schreibschicht).
//! Regeln und Erkennungen werten dann den Pfad *im* Container aus – dieselben Ausnahmen (Logs, Datenbanken)
//! und dieselben Schutzregeln (Web-Ordner, /etc) wie auf dem Server.

/// (Wurzel-Präfix ohne abschließenden Schrägstrich, Bezeichnung) – Bezeichnung z. B. „app“ oder „docker:3f2a9c1b7d4e“
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerPath<'a> {
    pub root: &'a str,
    pub label: String,
    /// Pfad im Container, beginnt mit „/“
    pub rel: &'a str,
}

/// Bekannte Container-Wurzeln: (Präfix, Anzahl Namensteile, Suffix nach dem Namen)
const ROOTS: &[(&str, &str, &str)] = &[
    ("/var/lib/machines/", "", ""),
    ("/var/lib/lxc/", "", "/rootfs"),
    ("/var/lib/lxd/containers/", "", "/rootfs"),
    ("/var/snap/lxd/common/lxd/containers/", "", "/rootfs"),
    ("/var/lib/incus/containers/", "", "/rootfs"),
    ("/var/lib/docker/overlay2/", "docker", "/diff"),
    ("/var/lib/containers/storage/overlay/", "podman", "/diff"),
];

pub fn container_path(path: &str) -> Option<ContainerPath<'_>> {
    for (prefix, kind, suffix) in ROOTS {
        let Some(rest) = path.strip_prefix(prefix) else { continue };
        let (name, after) = rest.split_once('/').unwrap_or((rest, ""));
        if name.is_empty() || name.starts_with('.') {
            return None;
        }
        let tail = format!("/{after}");
        let rel_start = if suffix.is_empty() {
            prefix.len() + name.len()
        } else {
            // Name gefolgt von /rootfs bzw. /diff – sonst ist es kein Dateisystem des Containers
            if !tail.starts_with(&format!("{suffix}/")) && tail != *suffix {
                return None;
            }
            prefix.len() + name.len() + suffix.len()
        };
        let rel = if rel_start >= path.len() { "/" } else { &path[rel_start..] };
        let label = if kind.is_empty() { name.to_string() } else { format!("{kind}:{}", &name[..name.len().min(12)]) };
        return Some(ContainerPath { root: &path[..rel_start], label, rel });
    }
    None
}

/// Pfad, an dem Regeln ausgewertet werden (im Container der Pfad dort, sonst unverändert)
pub fn effective(path: &str) -> &str {
    container_path(path).map(|c| c.rel).unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roots() {
        let c = container_path("/var/lib/machines/app/var/www/shop/index.php").unwrap();
        assert_eq!((c.root, c.label.as_str(), c.rel), ("/var/lib/machines/app", "app", "/var/www/shop/index.php"));
        let d = container_path("/var/lib/docker/overlay2/3f2a9c1b7d4e5f60718293a4b5c6d7e8/diff/var/www/html/x.php").unwrap();
        assert_eq!((d.label.as_str(), d.rel), ("docker:3f2a9c1b7d4e", "/var/www/html/x.php"));
        assert!(container_path("/var/lib/docker/overlay2/3f2a9c1b7d4e/merged/etc/passwd").is_none()); // nur die Schreibschicht
        assert_eq!(container_path("/var/lib/lxc/web1/rootfs/etc/passwd").unwrap().rel, "/etc/passwd");
        assert!(container_path("/var/lib/lxc/web1/config").is_none());
        assert!(container_path("/var/www/shop/index.php").is_none());
        assert_eq!(effective("/var/lib/machines/app/etc/shadow"), "/etc/shadow");
    }
}
