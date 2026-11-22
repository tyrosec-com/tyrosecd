//! Plugins, modules and themes of detected apps (inventory field `apps[].plugins`):
//! WordPress plugins and themes, Magento `app/code/<Vendor>/<Module>`, Shopware `custom/plugins/*`,
//! PrestaShop `modules/*`. Read only and bounded (one folder level, small file heads).
//!
//! The WooCommerce entry of a WordPress root carries no plugins (they are listed once, under WordPress).

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::app::{read_head, read_small, SMALL};

/// Maximum plugins per app
const MAX_PLUGINS: usize = 1000;
/// Maximum folder entries read per plugin folder
const MAX_ENTRIES: usize = 5000;
/// Bytes read from a file head (plugin headers)
const HEAD: u64 = 8192;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct Plugin {
    /// slug (WordPress, PrestaShop), Composer name or `Vendor_Module` (Magento), Composer name (Shopware)
    pub name: String,
    #[serde(default)]
    pub version: String,
    /// author / vendor, if known
    #[serde(default)]
    pub vendor: String,
    /// absolute folder of the plugin
    pub path: String,
    /// wp-plugin | wp-theme | magento-appcode | shopware-custom | prestashop-module
    pub source: String,
}

fn cap(s: &str) -> String {
    s.trim().chars().filter(|c| !c.is_control()).take(128).collect()
}

/// Sub folders (no symbolic links), sorted
fn subdirs(dir: &Path) -> Vec<(String, std::path::PathBuf)> {
    let Ok(rd) = std::fs::read_dir(dir) else { return vec![] };
    let mut v: Vec<(String, std::path::PathBuf)> = rd
        .flatten()
        .take(MAX_ENTRIES)
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| (e.file_name().to_string_lossy().into_owned(), e.path()))
        .filter(|(n, _)| !n.starts_with('.'))
        .collect();
    v.sort();
    v
}

/// Value of a WordPress-style header line (`Version: 1.2`, ` * Author: X`)
pub fn header(head: &str, key: &str) -> Option<String> {
    head.lines().find_map(|l| {
        let t = l.trim_start_matches([' ', '\t', '*', '/', '#', '@']);
        let (k, v) = t.split_once(':')?;
        (k.trim().eq_ignore_ascii_case(key)).then(|| cap(v.trim_end_matches("*/")))
    })
}

fn wp_plugin(slug: &str, dir: &Path) -> Option<Plugin> {
    let Ok(rd) = std::fs::read_dir(dir) else { return None };
    let mut php: Vec<String> = rd.flatten().take(MAX_ENTRIES).map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| n.ends_with(".php")).collect();
    php.sort();
    for n in php.iter().take(100) {
        let Some(h) = read_head(&dir.join(n), HEAD) else { continue };
        if header(&h, "Plugin Name").is_some() {
            return Some(Plugin {
                name: slug.into(),
                version: header(&h, "Version").unwrap_or_default(),
                vendor: header(&h, "Author").unwrap_or_default(),
                path: dir.to_string_lossy().into_owned(),
                source: "wp-plugin".into(),
            });
        }
    }
    None
}

fn wp_theme(slug: &str, dir: &Path) -> Option<Plugin> {
    let h = read_head(&dir.join("style.css"), HEAD)?;
    Some(Plugin {
        name: slug.into(),
        version: header(&h, "Version").unwrap_or_default(),
        vendor: header(&h, "Author").unwrap_or_default(),
        path: dir.to_string_lossy().into_owned(),
        source: "wp-theme".into(),
    })
}

fn composer_json(dir: &Path) -> Option<serde_json::Value> {
    serde_json::from_str(&read_small(&dir.join("composer.json"), SMALL)?).ok()
}

/// Attribute value `attr="…"` in an XML fragment
fn xml_attr(s: &str, attr: &str) -> Option<String> {
    let i = s.find(&format!("{attr}=\""))? + attr.len() + 2;
    s[i..].split('"').next().map(cap)
}

/// Text of `<tag>…</tag>` (CDATA removed)
fn xml_text(s: &str, tag: &str) -> Option<String> {
    let i = s.find(&format!("<{tag}>"))? + tag.len() + 2;
    let v = s[i..].split(&format!("</{tag}>")).next()?;
    Some(cap(v.trim().trim_start_matches("<![CDATA[").trim_end_matches("]]>")))
}

fn magento_module(vendor: &str, module: &str, dir: &Path) -> Plugin {
    let xml = read_small(&dir.join("etc/module.xml"), SMALL).unwrap_or_default();
    let cj = composer_json(dir);
    let name = cj.as_ref().and_then(|c| c["name"].as_str().map(cap)).or_else(|| xml_attr(&xml, "name")).unwrap_or_else(|| format!("{vendor}_{module}"));
    let version = cj.as_ref().and_then(|c| c["version"].as_str().map(cap)).or_else(|| xml_attr(&xml, "setup_version")).unwrap_or_default();
    Plugin { name, version, vendor: vendor.into(), path: dir.to_string_lossy().into_owned(), source: "magento-appcode".into() }
}

fn shopware_plugin(slug: &str, dir: &Path) -> Plugin {
    let cj = composer_json(dir);
    let name = cj.as_ref().and_then(|c| c["name"].as_str().map(cap)).unwrap_or_else(|| slug.to_string());
    let mut version = cj.as_ref().and_then(|c| c["version"].as_str().map(cap)).unwrap_or_default();
    if version.is_empty() {
        // Shopware 5 plugins: plugin.xml
        version = read_small(&dir.join("plugin.xml"), SMALL).and_then(|x| xml_text(&x, "version")).unwrap_or_default();
    }
    let vendor = name.split_once('/').map(|(v, _)| v.to_string()).unwrap_or_default();
    Plugin { name, version, vendor, path: dir.to_string_lossy().into_owned(), source: "shopware-custom".into() }
}

/// `$this->prop = '…';` (first assignment with a string literal)
fn php_prop(src: &str, prop: &str) -> Option<String> {
    let pat = format!("$this->{prop}");
    src.match_indices(&pat).find_map(|(i, _)| {
        let r = src[i + pat.len()..].trim_start().strip_prefix('=')?.trim_start();
        let q = r.chars().next().filter(|c| *c == '\'' || *c == '"')?;
        r[1..].split(q).next().map(cap)
    })
}

fn prestashop_module(slug: &str, dir: &Path) -> Option<Plugin> {
    let main = read_small(&dir.join(format!("{slug}.php")), 2 * SMALL);
    let xml = read_small(&dir.join("config.xml"), SMALL);
    if main.is_none() && xml.is_none() {
        return None;
    }
    let src = main.unwrap_or_default();
    let xml = xml.unwrap_or_default();
    Some(Plugin {
        name: slug.into(),
        version: php_prop(&src, "version").or_else(|| xml_text(&xml, "version")).unwrap_or_default(),
        vendor: php_prop(&src, "author").or_else(|| xml_text(&xml, "author")).unwrap_or_default(),
        path: dir.to_string_lossy().into_owned(),
        source: "prestashop-module".into(),
    })
}

/// Plugins of an app of `kind` at `root`
pub fn collect(kind: &str, root: &Path) -> Vec<Plugin> {
    let mut out = Vec::new();
    match kind {
        "WordPress" => {
            for (slug, dir) in subdirs(&root.join("wp-content/plugins")) {
                out.extend(wp_plugin(&slug, &dir));
            }
            for (slug, dir) in subdirs(&root.join("wp-content/themes")) {
                out.extend(wp_theme(&slug, &dir));
            }
        }
        "Magento" => {
            for (vendor, vdir) in subdirs(&root.join("app/code")) {
                for (module, mdir) in subdirs(&vdir) {
                    if mdir.join("etc/module.xml").is_file() || mdir.join("registration.php").is_file() {
                        out.push(magento_module(&vendor, &module, &mdir));
                    }
                    if out.len() >= MAX_PLUGINS {
                        break;
                    }
                }
            }
        }
        "Shopware" | "Shopware 5" => {
            for (slug, dir) in subdirs(&root.join("custom/plugins")) {
                out.push(shopware_plugin(&slug, &dir));
            }
        }
        "PrestaShop" => {
            for (slug, dir) in subdirs(&root.join("modules")) {
                out.extend(prestashop_module(&slug, &dir));
            }
        }
        _ => {}
    }
    out.truncate(MAX_PLUGINS);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(root: &Path, rel: &str, content: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }
    fn short(v: &[Plugin]) -> Vec<(String, String, String, String)> {
        v.iter().map(|p| (p.source.clone(), p.name.clone(), p.version.clone(), p.vendor.clone())).collect()
    }

    #[test]
    fn wordpress_plugins_and_themes() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        w(r, "wp-content/plugins/akismet/akismet.php", "<?php\n/**\n * Plugin Name: Akismet Anti-spam\n * Version: 5.3.5\n * Author: Automattic\n */");
        w(r, "wp-content/plugins/akismet/class.akismet.php", "<?php");
        w(r, "wp-content/plugins/empty/readme.txt", "x");
        w(r, "wp-content/themes/twentytwentyfour/style.css", "/*\nTheme Name: Twenty Twenty-Four\nAuthor: the WordPress team\nVersion: 1.3\n*/");
        let v = collect("WordPress", r);
        assert_eq!(short(&v), vec![
            ("wp-plugin".into(), "akismet".into(), "5.3.5".into(), "Automattic".into()),
            ("wp-theme".into(), "twentytwentyfour".into(), "1.3".into(), "the WordPress team".into()),
        ]);
        assert_eq!(v[0].path, r.join("wp-content/plugins/akismet").to_string_lossy());
        assert!(collect("WooCommerce", r).is_empty());
    }

    #[test]
    fn magento_app_code() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        w(r, "app/code/Acme/Payment/etc/module.xml", r#"<config><module name="Acme_Payment" setup_version="2.1.0"/></config>"#);
        w(r, "app/code/Acme/Search/registration.php", "<?php");
        w(r, "app/code/Acme/Search/composer.json", r#"{"name":"acme/module-search","version":"1.4.2"}"#);
        let v = collect("Magento", r);
        assert_eq!(short(&v), vec![
            ("magento-appcode".into(), "Acme_Payment".into(), "2.1.0".into(), "Acme".into()),
            ("magento-appcode".into(), "acme/module-search".into(), "1.4.2".into(), "Acme".into()),
        ]);
    }

    #[test]
    fn shopware_and_prestashop() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        w(r, "custom/plugins/AcmeTheme/composer.json", r#"{"name":"acme/theme","version":"3.0.1","type":"shopware-platform-plugin"}"#);
        w(r, "custom/plugins/OldPlugin/plugin.xml", "<plugin><label>Old</label><version>1.2.0</version></plugin>");
        assert_eq!(short(&collect("Shopware", r)), vec![
            ("shopware-custom".into(), "acme/theme".into(), "3.0.1".into(), "acme".into()),
            ("shopware-custom".into(), "OldPlugin".into(), "1.2.0".into(), "".into()),
        ]);
        w(r, "modules/ps_banner/ps_banner.php", "<?php class Ps_Banner extends Module { public function __construct() {\n $this->name = 'ps_banner';\n $this->version = '2.1.2';\n $this->author = 'PrestaShop';\n } }");
        w(r, "modules/legacy/config.xml", "<module><name>legacy</name><version><![CDATA[1.0.4]]></version><author><![CDATA[Acme]]></author></module>");
        w(r, "modules/not_a_module/readme.md", "x");
        assert_eq!(short(&collect("PrestaShop", r)), vec![
            ("prestashop-module".into(), "legacy".into(), "1.0.4".into(), "Acme".into()),
            ("prestashop-module".into(), "ps_banner".into(), "2.1.2".into(), "PrestaShop".into()),
        ]);
    }
}
