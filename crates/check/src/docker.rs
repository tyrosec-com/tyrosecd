//! E9 (plan 2026-11-27, package D): risky settings of running Docker containers – read only from the container
//! configuration below /var/lib/docker/containers (no access to the Docker API, nothing is changed).
//! - privileged containers (or SYS_ADMIN/SYS_MODULE/ALL capabilities): a break-out to the host is trivial
//! - the Docker socket mounted into a container: whoever controls the container controls the host
//! - host system folders (/, /etc, /root, /boot, /usr) mounted writable

use crate::{Category, Ctx, Severity};

#[derive(Debug, PartialEq)]
pub struct Risk {
    pub check: &'static str,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
}

const SOCKETS: &[&str] = &["docker.sock", "containerd.sock", "podman.sock", "crio.sock"];
const HOST_DIRS: &[&str] = &["/", "/etc", "/root", "/boot", "/usr", "/var/lib/docker"];

/// Evaluate one container from config.v2.json and hostconfig.json
pub fn risks(config: &serde_json::Value, host: &serde_json::Value) -> Vec<Risk> {
    let mut out = Vec::new();
    if config["State"]["Running"].as_bool() != Some(true) {
        return out;
    }
    let name = config["Name"].as_str().unwrap_or("?").trim_start_matches('/').to_string();
    let image = config["Config"]["Image"].as_str().unwrap_or("?").to_string();
    let caps: Vec<String> = host["CapAdd"].as_array().map(|a| a.iter().filter_map(|c| c.as_str().map(|s| s.to_ascii_uppercase())).collect()).unwrap_or_default();
    let strong: Vec<&String> = caps.iter().filter(|c| matches!(c.trim_start_matches("CAP_"), "SYS_ADMIN" | "SYS_MODULE" | "ALL")).collect();
    if host["Privileged"].as_bool() == Some(true) || !strong.is_empty() {
        let how = if host["Privileged"].as_bool() == Some(true) { "--privileged".to_string() } else { format!("capabilities {}", strong.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")) };
        out.push(Risk {
            check: "container_privileged",
            severity: Severity::High,
            title: format!("Container runs privileged: {name}"),
            detail: format!("Image: {image}\nSetting: {how}\nA privileged container has full access to the host's devices and kernel – whoever takes over the container can take over the server."),
        });
    }
    let mounts = config["MountPoints"].as_object().cloned().unwrap_or_default();
    let mut list: Vec<(String, String, bool)> = mounts
        .values()
        .map(|m| (m["Source"].as_str().unwrap_or("").to_string(), m["Destination"].as_str().unwrap_or("").to_string(), m["RW"].as_bool().unwrap_or(true)))
        .filter(|(s, _, _)| !s.is_empty())
        .collect();
    list.sort();
    for (src, dst, rw) in list {
        let base = src.rsplit('/').next().unwrap_or("");
        if SOCKETS.contains(&base) {
            out.push(Risk {
                check: "container_docker_socket",
                severity: Severity::Medium,
                title: format!("Docker socket mounted into container: {name}"),
                detail: format!("Image: {image}\nMount: {src} → {dst}\nThe socket gives full control over Docker and thus over the host (even when mounted read-only) – legitimate for tools like Traefik, Portainer or Watchtower, but a break-in into that container is a break-in into the server."),
            });
        } else if rw && HOST_DIRS.contains(&host_dir(&src)) {
            out.push(Risk {
                check: "container_host_mount",
                severity: Severity::High,
                title: format!("Host system folder mounted writable into container: {name}"),
                detail: format!("Image: {image}\nMount: {src} → {dst} (writable)\nThe container can change system files of the host (users, SSH keys, services) – a break-in into the container is a break-in into the server."),
            });
        }
    }
    out
}

fn host_dir(src: &str) -> &str {
    let s = src.trim_end_matches('/');
    if s.is_empty() {
        "/"
    } else {
        s
    }
}

pub fn check(ctx: &mut Ctx) {
    let Ok(rd) = std::fs::read_dir("/var/lib/docker/containers") else { return };
    let mut n = 0;
    for e in rd.flatten().take(500) {
        let dir = e.path();
        let read = |f: &str| -> serde_json::Value {
            std::fs::read(dir.join(f)).ok().filter(|b| b.len() < 4 << 20).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
        };
        let (cfg, host) = (read("config.v2.json"), read("hostconfig.json"));
        if cfg.is_null() {
            continue;
        }
        n += 1;
        for r in risks(&cfg, &host) {
            match r.check {
                "container_privileged" => ctx.add(r.severity, Category::Runtime, "container_privileged", r.title, None, Some(r.detail)),
                "container_docker_socket" => ctx.add(r.severity, Category::Runtime, "container_docker_socket", r.title, None, Some(r.detail)),
                _ => ctx.add(r.severity, Category::Runtime, "container_host_mount", r.title, None, Some(r.detail)),
            }
        }
    }
    ctx.stat("docker_containers", n);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg(running: bool, mounts: serde_json::Value) -> serde_json::Value {
        json!({ "Name": "/web", "State": { "Running": running }, "Config": { "Image": "nginx:1.27" }, "MountPoints": mounts })
    }

    #[test]
    fn container_risks() {
        let host = json!({ "Privileged": false, "CapAdd": null });
        assert!(risks(&cfg(true, json!({})), &host).is_empty(), "harmless container");
        assert!(risks(&cfg(false, json!({})), &json!({ "Privileged": true })).is_empty(), "stopped");
        let r = risks(&cfg(true, json!({})), &json!({ "Privileged": true }));
        assert_eq!((r[0].check, r[0].severity), ("container_privileged", Severity::High));
        assert_eq!(r[0].title, "Container runs privileged: web");
        let r = risks(&cfg(true, json!({})), &json!({ "CapAdd": ["SYS_ADMIN", "NET_ADMIN"] }));
        assert_eq!(r[0].check, "container_privileged");
        assert!(risks(&cfg(true, json!({})), &json!({ "CapAdd": ["NET_ADMIN"] })).is_empty());
        let m = json!({
            "/var/run/docker.sock": { "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock", "RW": false },
            "/host": { "Source": "/", "Destination": "/host", "RW": false },
            "/hostetc": { "Source": "/etc", "Destination": "/hostetc", "RW": true },
            "/data": { "Source": "/srv/app/data", "Destination": "/data", "RW": true },
        });
        let r = risks(&cfg(true, m), &host);
        let checks: Vec<_> = r.iter().map(|x| x.check).collect();
        assert_eq!(checks, vec!["container_host_mount", "container_docker_socket"], "read-only / and app data are fine: {r:?}");
    }
}
