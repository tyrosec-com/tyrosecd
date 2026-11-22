//! Detect paths inside container roots (systemd-nspawn, LXC/LXD/Incus, Docker and Podman writable layer).
//! Rules and detections then evaluate the path *inside* the container – the same exceptions (logs, databases)
//! and the same protection rules (web folders, /etc) as on the host.

/// (root prefix without trailing slash, label) – label e.g. "app" or "docker:3f2a9c1b7d4e"
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerPath<'a> {
    pub root: &'a str,
    pub label: String,
    /// Path inside the container, starts with "/"
    pub rel: &'a str,
}

/// Known container roots: (prefix, number of name components, suffix after the name)
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
            // name followed by /rootfs or /diff – otherwise it is not a filesystem of the container
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

/// Path at which rules are evaluated (for a container the path inside it, otherwise unchanged)
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
        assert!(container_path("/var/lib/docker/overlay2/3f2a9c1b7d4e/merged/etc/passwd").is_none()); // only the writable layer
        assert_eq!(container_path("/var/lib/lxc/web1/rootfs/etc/passwd").unwrap().rel, "/etc/passwd");
        assert!(container_path("/var/lib/lxc/web1/config").is_none());
        assert!(container_path("/var/www/shop/index.php").is_none());
        assert_eq!(effective("/var/lib/machines/app/etc/shadow"), "/etc/shadow");
    }
}
