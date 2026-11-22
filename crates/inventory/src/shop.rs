//! Stage C: shop detection in the webroots and outgoing connections (egress inventory).

use std::collections::BTreeMap;

use serde::Serialize;

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Shop {
    /// Magento | Shopware | WooCommerce | PrestaShop | JTL-Shop
    pub kind: String,
    pub root: String,
    pub version: String,
}

/// Shop kinds among the detected apps
const SHOP_KINDS: &[&str] = &["Magento", "Shopware", "Shopware 5", "WooCommerce", "PrestaShop", "JTL-Shop"];

/// Shops among the detected apps (same detection as `apps` in the inventory)
pub fn from_apps(apps: &[crate::app::App]) -> Vec<Shop> {
    apps.iter().filter(|a| SHOP_KINDS.contains(&a.kind.as_str())).map(|a| Shop { kind: a.kind.clone(), root: a.root.clone(), version: a.version.clone() }).collect()
}

pub fn shops(webroots: &[String]) -> Vec<Shop> {
    from_apps(&crate::app::detect(webroots))
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
        std::fs::create_dir_all(r.join("wp/wp-includes")).unwrap();
        std::fs::write(r.join("wp/wp-includes/version.php"), "<?php $wp_version = '6.7.1';").unwrap();
        std::fs::write(r.join("wp/wp-settings.php"), "<?php").unwrap();
        std::fs::write(r.join("wp/wp-content/plugins/woocommerce/woocommerce.php"), "/**\n * Plugin Name: WooCommerce\n * Version: 9.4.2\n */").unwrap();
        let s = shops(&[r.to_string_lossy().into_owned()]);
        assert!(s.iter().any(|x| x.kind == "Magento" && x.version == "2.4.7-p3"), "{s:?}");
        assert!(s.iter().any(|x| x.kind == "WooCommerce" && x.version == "9.4.2"), "{s:?}");
        assert_eq!(s.len(), 2, "WordPress itself is not a shop: {s:?}");
    }
}
