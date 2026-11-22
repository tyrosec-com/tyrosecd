//! Stage C: shop detection in the webroots and outgoing connections (egress inventory).

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Shop {
    /// Magento | Shopware | WooCommerce | PrestaShop | JTL-Shop
    pub kind: String,
    pub root: String,
    pub version: String,
}

fn composer_version(root: &Path, pkgs: &[&str]) -> String {
    let Ok(s) = std::fs::read_to_string(root.join("composer.lock")) else { return String::new() };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) else { return String::new() };
    for p in v["packages"].as_array().into_iter().flatten() {
        if pkgs.contains(&p["name"].as_str().unwrap_or("")) {
            return p["version"].as_str().unwrap_or("").trim_start_matches('v').to_string();
        }
    }
    String::new()
}

fn grep_version(file: &Path, re: &str) -> String {
    let Ok(s) = std::fs::read_to_string(file) else { return String::new() };
    regex_lite(&s, re)
}

/// very small search without a regex dependency: text after `marker` up to the next quotation mark
fn regex_lite(s: &str, marker: &str) -> String {
    s.find(marker)
        .map(|i| s[i + marker.len()..].trim_start_matches([' ', '=', '\'', '"', ',', '(']).chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect())
        .unwrap_or_default()
}

pub fn shops(webroots: &[String]) -> Vec<Shop> {
    let mut out = Vec::new();
    for w in webroots {
        let mut it = walkdir::WalkDir::new(w).max_depth(3).follow_links(false).into_iter();
        while let Some(Ok(e)) = it.next() {
            if !e.file_type().is_dir() {
                continue;
            }
            let n = e.file_name().to_string_lossy();
            if matches!(n.as_ref(), "vendor" | "node_modules" | ".git" | "var" | "cache" | "uploads" | "media" | "pub") {
                it.skip_current_dir();
                continue;
            }
            let p = e.path();
            let root = p.to_string_lossy().into_owned();
            let found = if p.join("app/etc/env.php").is_file() && p.join("bin/magento").is_file() {
                Some(("Magento", composer_version(p, &["magento/product-community-edition", "magento/magento2-base"])))
            } else if p.join("vendor/shopware/core").is_dir() || p.join("vendor/shopware/platform").is_dir() {
                Some(("Shopware", composer_version(p, &["shopware/core", "shopware/platform"])))
            } else if p.join("engine/Shopware/Application.php").is_file() {
                Some(("Shopware 5", grep_version(&p.join("engine/Shopware/Application.php"), "VERSION")))
            } else if p.join("wp-content/plugins/woocommerce/woocommerce.php").is_file() {
                Some(("WooCommerce", grep_version(&p.join("wp-content/plugins/woocommerce/woocommerce.php"), "Version:")))
            } else if p.join("classes/PrestaShopAutoload.php").is_file() || p.join("config/settings.inc.php").is_file() && p.join("classes").is_dir() {
                Some(("PrestaShop", grep_version(&p.join("app/AppKernel.php"), "VERSION")))
            } else if p.join("includes/config.JTL-Shop.ini.php").is_file() || p.join("includes/defines_inc.php").is_file() {
                Some(("JTL-Shop", String::new()))
            } else {
                None
            };
            if let Some((kind, version)) = found {
                out.push(Shop { kind: kind.into(), root, version });
                it.skip_current_dir();
            }
        }
    }
    out
}

#[derive(Serialize, Debug, Clone)]
pub struct Egress {
    pub process: String,
    pub exe: String,
    pub remote: String,
    pub port: u16,
    pub count: u32,
}

/// Outgoing TCP connections by process and destination (without local ones and without incoming ones on open ports)
pub fn egress(listen_ports: &[u16]) -> Vec<Egress> {
    let conns = tyrosd_detect::net::established();
    if conns.is_empty() {
        return vec![];
    }
    let owners = tyrosd_detect::net::socket_owners();
    let mut agg: BTreeMap<(String, String, u16), (String, u32)> = BTreeMap::new();
    for c in conns {
        if c.remote_is_local() || listen_ports.contains(&c.lport) {
            continue; // incoming connection to a service
        }
        let (comm, exe) = owners
            .get(&c.inode)
            .and_then(|pid| tyrosd_detect::proc::info(*pid))
            .map(|i| (i.comm, i.exe))
            .unwrap_or_else(|| ("?".into(), String::new()));
        let ip = c.remote().rsplit_once(':').map(|(a, _)| a.to_string()).unwrap_or_default();
        let e = agg.entry((comm, ip, c.rport)).or_insert((exe, 0));
        e.1 += 1;
    }
    let mut out: Vec<Egress> = agg.into_iter().map(|((process, remote, port), (exe, count))| Egress { process, exe, remote, port, count }).collect();
    out.sort_by(|a, b| b.count.cmp(&a.count));
    out.truncate(200);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_magento_and_woocommerce() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        std::fs::create_dir_all(r.join("shop/app/etc")).unwrap();
        std::fs::create_dir_all(r.join("shop/bin")).unwrap();
        std::fs::write(r.join("shop/app/etc/env.php"), "<?php return [];").unwrap();
        std::fs::write(r.join("shop/bin/magento"), "#!/usr/bin/env php").unwrap();
        std::fs::write(r.join("shop/composer.lock"), r#"{"packages":[{"name":"magento/product-community-edition","version":"2.4.7-p3"}]}"#).unwrap();
        std::fs::create_dir_all(r.join("wp/wp-content/plugins/woocommerce")).unwrap();
        std::fs::write(r.join("wp/wp-content/plugins/woocommerce/woocommerce.php"), "/**\n * Plugin Name: WooCommerce\n * Version: 9.4.2\n */").unwrap();
        let s = shops(&[r.to_string_lossy().into_owned()]);
        assert!(s.iter().any(|x| x.kind == "Magento" && x.version == "2.4.7-p3"), "{s:?}");
        assert!(s.iter().any(|x| x.kind == "WooCommerce" && x.version == "9.4.2"), "{s:?}");
    }
}
