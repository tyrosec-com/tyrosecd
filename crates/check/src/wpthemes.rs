//! Hashes of the WordPress themes per installation (check report field `wp_themes`) for the comparison
//! with the original theme packages on the central server. Sent when the installed theme versions
//! changed since the last report, otherwise at most every 7 days. Read only, bounded.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

use crate::app::App;
use crate::composer::{hash_dir, Budget, SentState};

/// Maximum hashed theme files per report
pub const MAX_THEME_FILES: usize = 30_000;
/// Budget for the uncompressed JSON of the `wp_themes` section (1.5 MiB)
pub const MAX_THEME_JSON: usize = 3 << 19;

#[derive(Serialize, Debug, Clone, Default)]
pub struct WpThemes {
    /// WordPress root
    pub root: String,
    pub themes: Vec<ThemeFiles>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

#[derive(Serialize, Debug, Clone, Default)]
pub struct ThemeFiles {
    pub slug: String,
    pub version: String,
    /// path relative to the theme folder → SHA-256 (hex)
    pub files: BTreeMap<String, String>,
    /// files larger than 5 MiB: path → size in bytes
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub large: BTreeMap<String, u64>,
}

/// Theme hashes of the WordPress installations among `apps` that are due (see module description)
pub fn hashes(apps: &[App], state: &Path, force: bool) -> Vec<WpThemes> {
    let mut st = SentState::load(state);
    let mut b = Budget::new(MAX_THEME_FILES, MAX_THEME_JSON);
    let mut out = Vec::new();
    for a in apps.iter().filter(|a| a.kind == "WordPress") {
        if b.exhausted() {
            break;
        }
        let themes: Vec<&crate::plugins::Plugin> = a.plugins.iter().filter(|p| p.source == "wp-theme").collect();
        if themes.is_empty() {
            continue;
        }
        let fp = themes.iter().map(|t| format!("{}:{}", t.name, t.version)).collect::<Vec<_>>().join(",");
        if !force && !st.due(&a.root, &fp) {
            continue;
        }
        let mut w = WpThemes { root: a.root.clone(), ..Default::default() };
        for t in themes {
            let mut tf = ThemeFiles { slug: t.name.clone(), version: t.version.clone(), ..Default::default() };
            b.bytes += tf.slug.len() + tf.version.len() + 48;
            let complete = hash_dir(Path::new(&t.path), &mut tf.files, &mut tf.large, &mut b);
            w.themes.push(tf);
            if !complete {
                w.truncated = true;
                break;
            }
        }
        st.mark(&a.root, fp);
        out.push(w);
    }
    st.save(|k| Path::new(k).join("wp-content/themes").is_dir());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_hashes_and_state() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path().join("wp");
        let w = |rel: &str, c: &str| {
            let p = r.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, c).unwrap();
        };
        w("wp-includes/version.php", "<?php $wp_version = '6.7.1';");
        w("wp-settings.php", "<?php");
        w("wp-content/themes/twentytwentyfour/style.css", "/*\nTheme Name: Twenty Twenty-Four\nVersion: 1.3\n*/");
        w("wp-content/themes/twentytwentyfour/functions.php", "<?php");
        let apps = crate::app::detect(&[r.to_string_lossy().into_owned()]);
        assert_eq!(apps[0].kind, "WordPress");
        let state = t.path().join("wp_themes_sent.json");
        let v = hashes(&apps, &state, false);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].root, r.to_string_lossy());
        assert_eq!((v[0].themes[0].slug.as_str(), v[0].themes[0].version.as_str()), ("twentytwentyfour", "1.3"));
        assert_eq!(v[0].themes[0].files.keys().collect::<Vec<_>>(), vec!["functions.php", "style.css"]);
        assert!(hashes(&apps, &state, false).is_empty(), "unchanged versions are not sent again");
        w("wp-content/themes/twentytwentyfour/style.css", "/*\nTheme Name: Twenty Twenty-Four\nVersion: 1.4\n*/");
        let apps = crate::app::detect(&[r.to_string_lossy().into_owned()]);
        assert_eq!(hashes(&apps, &state, false).len(), 1);
    }
}
