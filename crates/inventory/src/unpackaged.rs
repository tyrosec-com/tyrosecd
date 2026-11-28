//! Running programs that do not come from the package manager (self-compiled Apache/PHP/MySQL under /opt or
//! /users, Node via nvm, snaps …) with product and version – for vulnerability matching in the central server
//! (NVD). Read only, **never executes** a program: the version comes from
//! 1. the version string compiled into the program (`Apache/2.4.41`, `nginx/1.25.3`, `X-Powered-By: PHP/8.4.27`,
//!    the Node.js release URL),
//! 2. the install path (`/users/apache2.4.41/bin/httpd`, `/opt/php-8.4.27/sbin/php-fpm`, `…/node/v20.19.5/bin/node`),
//! 3. for snaps: `meta/snap.yaml` of the snap revision.
//!
//! Go programs (Grafana plugins, Traefik, MinIO, own tools …) additionally report their modules and Go version from the
//! build information compiled into every Go binary (ecosystem `Go`, matched by OSV).
//!
//! Results are cached per (path, size, modification time): a program is read at most once while it is unchanged.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::sync::Mutex;

use crate::software::Package;

/// Ecosystem name of these entries in the inventory (matched against NVD by the central server)
pub const ECOSYSTEM: &str = "Binary";
/// Largest program that is searched for a version string
const MAX_READ: u64 = 160 << 20;
const MAX_ENTRIES: usize = 200;

/// Products recognised by program name: (names of the program file, product, marker before the version in the binary)
const PRODUCTS: &[(&[&str], &str, &[&str])] = &[
    (&["httpd", "apache2"], "apache-httpd", &["Apache/"]),
    (&["nginx"], "nginx", &["nginx/"]),
    (&["php-fpm", "php", "php-cgi", "lsphp", "frankenphp"], "php", &["X-Powered-By: PHP/"]),
    (&["mysqld"], "mysql", &[]),
    (&["mariadbd"], "mariadb", &[]),
    (&["memcached"], "memcached", &[]),
    (&["redis-server"], "redis", &[]),
    (&["valkey-server"], "valkey", &[]),
    (&["node", "nodejs"], "nodejs", &["nodejs.org/download/release/v"]),
    (&["postgres", "postmaster"], "postgresql", &[]),
    (&["haproxy"], "haproxy", &[]),
    (&["squid"], "squid", &[]),
    (&["exim", "exim4"], "exim", &[]),
    (&["dovecot"], "dovecot", &[]),
    (&["traefik"], "traefik", &[]),
    (&["caddy"], "caddy", &[]),
    (&["grafana", "grafana-server"], "grafana", &[]),
    (&["prometheus"], "prometheus", &[]),
    (&["minio"], "minio", &[]),
    (&["gitea"], "gitea", &[]),
    (&["jenkins"], "jenkins", &[]),
];

/// Snaps with a known product (snap name → product)
const SNAPS: &[(&str, &str)] = &[("cups", "cups"), ("lxd", "lxd"), ("snapd", "snapd"), ("nextcloud", "nextcloud"), ("microk8s", "kubernetes"), ("certbot", "certbot")];

fn base(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// Product for a program name; also `php8.3-fpm`, `php-fpm8.4`, `httpd.worker`
pub fn product_of(exe: &str) -> Option<(&'static str, &'static [&'static str])> {
    let b = base(exe);
    let norm: String = b.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.').to_string();
    let norm = norm.replace(|c: char| c.is_ascii_digit() || c == '.', "");
    for (names, prod, markers) in PRODUCTS {
        if names.iter().any(|n| *n == b || *n == norm || b.split('.').next() == Some(n)) {
            return Some((prod, markers));
        }
    }
    None
}

/// x.y.z (each part digits, at least three parts) at the start of `s`
fn version_at(s: &str) -> Option<String> {
    let v: String = s.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    let v = v.trim_end_matches('.');
    let parts: Vec<&str> = v.split('.').collect();
    (parts.len() >= 3 && parts.len() <= 4 && parts.iter().all(|p| !p.is_empty() && p.len() <= 5)).then(|| v.to_string())
}

/// Version from the install path: a directory component that contains x.y.z (`apache2.4.41`, `php-8.4.27`, `v20.19.5`)
pub fn version_from_path(exe: &str) -> Option<String> {
    let dir = exe.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
    for comp in dir.split('/').rev() {
        // first digit sequence that forms x.y.z; "apache2.4.41" → "2.4.41"
        for (i, _) in comp.char_indices().filter(|(_, c)| c.is_ascii_digit()) {
            if i > 0 && comp.as_bytes()[i - 1].is_ascii_digit() {
                continue;
            }
            if let Some(v) = version_at(&comp[i..]) {
                return Some(v);
            }
        }
    }
    None
}

/// Version string compiled into the program after one of the markers
pub fn version_in_bytes(data: &[u8], markers: &[&str]) -> Option<String> {
    for m in markers {
        let mb = m.as_bytes();
        let mut start = 0;
        while let Some(pos) = find(&data[start..], mb) {
            let at = start + pos + mb.len();
            let tail = &data[at..data.len().min(at + 24)];
            if let Some(v) = std::str::from_utf8(&tail[..tail.iter().position(|b| !(b.is_ascii_digit() || *b == b'.')).unwrap_or(tail.len())]).ok().and_then(version_at) {
                return Some(v);
            }
            start = at;
        }
    }
    None
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    if n.is_empty() || h.len() < n.len() {
        return None;
    }
    h.windows(n.len()).position(|w| w == n)
}

fn read_file(path: &str) -> Option<Vec<u8>> {
    let f = std::fs::File::open(path).ok()?;
    if f.metadata().ok()?.len() > MAX_READ {
        return None;
    }
    let mut data = Vec::new();
    f.take(MAX_READ).read_to_end(&mut data).ok()?;
    Some(data)
}

fn uvarint(b: &[u8]) -> Option<(usize, usize)> {
    let mut v: usize = 0;
    for (i, x) in b.iter().enumerate().take(9) {
        v |= ((x & 0x7f) as usize) << (7 * i);
        if x & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

/// Go build information (Go ≥ 1.18, inline strings): (Go version, [(module, version)]) – the main module is left
/// out, replacements (`=>`) win
pub fn go_buildinfo(data: &[u8]) -> Option<(String, Vec<(String, String)>)> {
    let pos = find(data, b"\xff Go buildinf:")?;
    let h = &data[pos..];
    if h.len() < 34 || h[15] & 2 == 0 {
        return None;
    }
    let mut i = 32;
    let (vl, n) = uvarint(&h[i..])?;
    i += n;
    let ver = std::str::from_utf8(h.get(i..i + vl)?).ok()?.to_string();
    i += vl;
    let (ml, n) = uvarint(&h[i..])?;
    i += n;
    let mut mi = h.get(i..i + ml)?;
    // 16-byte sentinels before and after the module text
    if mi.len() >= 33 && mi[mi.len() - 17] == b'\n' {
        mi = &mi[16..mi.len() - 16];
    }
    let text = String::from_utf8_lossy(mi);
    let mut deps: Vec<(String, String)> = Vec::new();
    for l in text.lines() {
        let f: Vec<&str> = l.split('\t').collect();
        match f.first() {
            Some(&"dep") if f.len() >= 3 => deps.push((f[1].to_string(), f[2].to_string())),
            Some(&"=>") if f.len() >= 3 && !deps.is_empty() && f[2].starts_with('v') => {
                let last = deps.len() - 1;
                deps[last] = (f[1].to_string(), f[2].to_string());
            }
            _ => {}
        }
    }
    let gov = ver.split_whitespace().next()?.strip_prefix("go")?.to_string();
    Some((gov, deps))
}

/// Go version + modules of a program as packages (ecosystem `Go`)
pub fn go_packages(data: &[u8], exe: &str) -> Vec<Package> {
    let Some((gov, deps)) = go_buildinfo(data) else { return Vec::new() };
    let mut out = Vec::new();
    if gov.split('.').count() >= 2 && gov.chars().all(|c| c.is_ascii_digit() || c == '.') {
        out.push(Package { ecosystem: "Go".into(), name: "stdlib".into(), version: gov, source: "go-binary".into(), location: exe.into() });
    }
    for (m, v) in deps.into_iter().take(500) {
        out.push(Package { ecosystem: "Go".into(), name: m, version: v.trim_start_matches('v').to_string(), source: "go-binary".into(), location: exe.into() });
    }
    out
}

/// Snap: /snap/<name>/<revision>/… → (product, version from meta/snap.yaml)
pub fn snap_of(exe: &str) -> Option<(String, String)> {
    let rest = exe.strip_prefix("/snap/")?;
    let mut it = rest.split('/');
    let (name, rev) = (it.next()?, it.next()?);
    let prod = SNAPS.iter().find(|(s, _)| *s == name)?.1;
    let yaml = std::fs::read_to_string(format!("/snap/{name}/{rev}/meta/snap.yaml")).ok()?;
    let v = yaml.lines().find_map(|l| l.strip_prefix("version:"))?.trim().trim_matches(['\'', '"']).to_string();
    (!v.is_empty() && v.len() < 40).then(|| (prod.to_string(), v))
}

/// Files owned by the package manager (dpkg file lists, apk database); rpm via `rpm -qf` is avoided – on rpm systems
/// only paths outside the system folders count as unpackaged
fn packaged_files() -> HashSet<String> {
    let mut s = HashSet::new();
    if let Ok(rd) = std::fs::read_dir("/var/lib/dpkg/info") {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().ends_with(".list") {
                if let Ok(t) = std::fs::read_to_string(e.path()) {
                    s.extend(t.lines().filter(|l| l.contains("/bin/") || l.contains("/sbin/") || l.contains("/lib")).map(String::from));
                }
            }
        }
    }
    if let Ok(t) = std::fs::read_to_string("/lib/apk/db/installed") {
        let mut dir = String::new();
        for l in t.lines() {
            if let Some(d) = l.strip_prefix("F:") {
                dir = format!("/{d}");
            } else if let Some(f) = l.strip_prefix("R:") {
                s.insert(format!("{dir}/{f}"));
            }
        }
    }
    s
}

/// System folders whose programs come from the package manager on rpm systems (no file list read)
fn system_path(p: &str) -> bool {
    ["/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/lib64/", "/usr/libexec/", "/bin/", "/sbin/", "/lib/", "/lib64/"].iter().any(|d| p.starts_with(d))
}

type Found = (Option<(String, String, String)>, Vec<Package>);
static CACHE: Mutex<Option<HashMap<(String, u64, i64), Found>>> = Mutex::new(None);

/// (product, version, how) and Go modules for one program file
fn identify(exe: &str) -> Found {
    if let Some((p, v)) = snap_of(exe) {
        return (Some((p, v, "snap".into())), Vec::new());
    }
    let data = read_file(exe);
    let go = data.as_deref().map(|d| go_packages(d, exe)).unwrap_or_default();
    let Some((prod, markers)) = product_of(exe) else { return (None, go) };
    if let Some(v) = data.as_deref().filter(|_| !markers.is_empty()).and_then(|d| version_in_bytes(d, markers)) {
        return (Some((prod.into(), v, "binary".into())), go);
    }
    (version_from_path(exe).map(|v| (prod.into(), v, "path".into())), go)
}

/// Running programs without a package, with product and version
pub fn collect() -> Vec<Package> {
    let mut exes: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.flatten() {
            if !e.file_name().to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let Ok(exe) = std::fs::read_link(e.path().join("exe")) else { continue };
            let exe = exe.to_string_lossy().into_owned();
            if exe.ends_with(" (deleted)") || exe.starts_with("/opt/tyrosecd/") || exe.starts_with("/proc/") || exe.starts_with("/memfd:") {
                continue;
            }
            if seen.insert(exe.clone()) {
                exes.push(exe);
            }
        }
    }
    let rpm = std::path::Path::new("/var/lib/rpm").is_dir() || std::path::Path::new("/usr/lib/sysimage/rpm").is_dir();
    let owned = packaged_files();
    let mut out = Vec::new();
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let cache = cache.get_or_insert_with(HashMap::new);
    for exe in exes {
        // programs of the package manager are covered by the distribution's advisories
        if owned.contains(&exe) || (owned.is_empty() && rpm && system_path(&exe)) {
            continue;
        }
        let Ok(m) = std::fs::metadata(&exe) else { continue };
        let key = (exe.clone(), m.size(), m.mtime());
        let (hit, go) = cache.entry(key).or_insert_with(|| identify(&exe)).clone();
        if let Some((p, v, how)) = hit {
            out.push(Package { ecosystem: ECOSYSTEM.into(), name: p, version: v, source: how, location: exe.clone() });
        }
        out.extend(go);
        if out.len() >= MAX_ENTRIES * 20 {
            break;
        }
    }
    if cache.len() > 2000 {
        cache.clear();
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn products_and_paths() {
        assert_eq!(product_of("/users/apache2.4.41/bin/httpd").unwrap().0, "apache-httpd");
        assert_eq!(product_of("/opt/php-8.4.27/sbin/php-fpm").unwrap().0, "php");
        assert_eq!(product_of("/usr/sbin/php-fpm8.3").unwrap().0, "php");
        assert_eq!(product_of("/root/.nvm/versions/node/v20.19.5/bin/node").unwrap().0, "nodejs");
        assert!(product_of("/opt/vendor/bin/some-daemon").is_none());
        assert_eq!(version_from_path("/users/apache2.4.41/bin/httpd").as_deref(), Some("2.4.41"));
        assert_eq!(version_from_path("/opt/php-8.4.27/sbin/php-fpm").as_deref(), Some("8.4.27"));
        assert_eq!(version_from_path("/root/.nvm/versions/node/v20.19.5/bin/node").as_deref(), Some("20.19.5"));
        assert_eq!(version_from_path("/users/mysql8.0.18/bin/mysqld").as_deref(), Some("8.0.18"));
        assert_eq!(version_from_path("/opt/php84/sbin/php-fpm"), None, "major only is not enough");
        assert_eq!(version_from_path("/opt/vendor/node-v22/bin/node"), None);
    }

    #[test]
    fn version_strings_in_binaries() {
        let bin = b"\x00\x01Server: Apache/2.4.41 (Unix)\x00X-Powered-By: PHP/8.4.27\x00https://nodejs.org/download/release/v20.19.5/node-v20.19.5.tar.gz\x00";
        assert_eq!(version_in_bytes(bin, &["Apache/"]).as_deref(), Some("2.4.41"));
        assert_eq!(version_in_bytes(bin, &["X-Powered-By: PHP/"]).as_deref(), Some("8.4.27"));
        assert_eq!(version_in_bytes(bin, &["nodejs.org/download/release/v"]).as_deref(), Some("20.19.5"));
        // marker without a full version first, real one later
        assert_eq!(version_in_bytes(b"nginx/%s\x00nginx/1.25.3\x00", &["nginx/"]).as_deref(), Some("1.25.3"));
        assert_eq!(version_in_bytes(b"nginx/\x00", &["nginx/"]), None);
    }

    #[test]
    fn go_build_info() {
        // header: magic (14) + ptr size + flags (2 = inline strings), padded to 32, then varint strings
        let mut b = vec![0u8; 7];
        let mut h = b"\xff Go buildinf:".to_vec();
        h.push(8);
        h.push(2);
        h.resize(32, 0);
        let ver = b"go1.21.5";
        let sentinel = [0x30u8; 16];
        let text = "path\tgithub.com/acme/tool\nmod\tgithub.com/acme/tool\t(devel)\t\ndep\tgolang.org/x/net\tv0.17.0\th1:x=\ndep\tgithub.com/old/lib\tv1.0.0\th1:y=\n=>\tgithub.com/new/lib\tv1.2.3\th1:z=\nbuild\t-compiler=gc\n";
        let mut mi = sentinel.to_vec();
        mi.extend_from_slice(text.as_bytes());
        mi.extend_from_slice(&sentinel);
        h.push(ver.len() as u8);
        h.extend_from_slice(ver);
        h.push((mi.len() & 0x7f) as u8 | 0x80);
        h.push((mi.len() >> 7) as u8);
        h.extend_from_slice(&mi);
        b.extend_from_slice(&h);
        let p = go_packages(&b, "/opt/tool");
        let got: Vec<_> = p.iter().map(|x| (x.name.as_str(), x.version.as_str())).collect();
        assert_eq!(got, vec![("stdlib", "1.21.5"), ("golang.org/x/net", "0.17.0"), ("github.com/new/lib", "1.2.3")]);
        assert!(go_packages(b"no go here", "/x").is_empty());
    }

    #[test]
    fn collect_runs() {
        // test environment: own test binary is not a known product → nothing, no panic
        let v = collect();
        assert!(v.iter().all(|p| p.ecosystem == ECOSYSTEM && !p.version.is_empty()));
    }
}
