//! Load the YARA rule package and scan files.
//!
//! The package (`rules.yar.zst`, `rules.json`) is fetched and verified by `tyrosd_transport::rules`; here it is
//! compiled (boreal, pure Rust) and kept ready for scans. Rules are never embedded in the binary (antivirus
//! scanners flag signature source text as malware), and on disk they are stored only compressed.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};

/// external variables that some rules expect (file name etc.) – pre-set to empty
const EXTERNALS: &[&str] = &["filename", "filepath", "extension", "filetype", "owner"];

/// Time limit per file
pub const SCAN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Default, serde::Deserialize)]
pub struct Meta {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub reference: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub score: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Hit {
    pub rule: String,
    pub score: i64,
    pub category: String,
    pub author: String,
    pub description: String,
    pub source: String,
}

pub struct Engine {
    scanner: boreal::Scanner,
    pub version: String,
    pub count: usize,
    pub compile_ms: u64,
    meta: HashMap<String, Meta>,
}

#[derive(serde::Deserialize)]
struct MetaFile {
    #[serde(default)]
    rules: Vec<Meta>,
}

impl Engine {
    /// Compile the package from `dir` (rules.yar.zst + rules.json)
    pub fn load(dir: &Path, version: &str) -> Result<Engine> {
        let t = Instant::now();
        let zst = std::fs::read(dir.join("rules.yar.zst")).with_context(|| format!("{}", dir.display()))?;
        let src = String::from_utf8(zstd::decode_all(zst.as_slice()).context("unpack rules.yar.zst")?).context("rules are not UTF-8")?;
        let meta: MetaFile = serde_json::from_slice(&std::fs::read(dir.join("rules.json"))?).context("rules.json")?;
        let e = Self::compile(&src, version, meta.rules)?;
        Ok(Engine { compile_ms: t.elapsed().as_millis() as u64, ..e })
    }

    /// Rules from source text (also for tests)
    pub fn compile(src: &str, version: &str, meta: Vec<Meta>) -> Result<Engine> {
        let mut c = boreal::Compiler::new();
        for x in EXTERNALS {
            let _ = c.define_symbol(*x, "");
        }
        c.add_rules_str(src).map_err(|e| anyhow!("rules do not compile: {}", format!("{e:?}").chars().take(300).collect::<String>()))?;
        let mut scanner = c.finalize();
        scanner.set_scan_params(boreal::scanner::ScanParams::default().timeout_duration(Some(SCAN_TIMEOUT)));
        let count = src.lines().filter(|l| { let t = l.trim_start(); t.starts_with("rule ") || t.starts_with("private rule ") }).count();
        Ok(Engine { scanner, version: version.to_string(), count, compile_ms: 0, meta: meta.into_iter().map(|m| (m.name.clone(), m)).collect() })
    }

    /// Matches in `data`; private helper rules (without an entry in rules.json) do not count
    pub fn scan(&self, data: &[u8]) -> Vec<Hit> {
        let rules = match self.scanner.scan_mem(data) {
            Ok(r) => r.rules,
            // time limit: matches found up to that point are kept
            Err((_, r)) => r.rules,
        };
        let mut hits: Vec<Hit> = rules
            .iter()
            .filter_map(|r| {
                let m = self.meta.get(r.name)?;
                Some(Hit {
                    rule: r.name.to_string(),
                    score: if m.score > 0 { m.score } else { 70 },
                    category: m.category.clone(),
                    author: m.author.clone(),
                    description: m.description.clone(),
                    source: m.source.clone(),
                })
            })
            .collect();
        hits.sort_by(|a, b| b.score.cmp(&a.score).then(a.rule.cmp(&b.rule)));
        hits
    }
}

/// Severity from the highest score: ≥ 80 critical, ≥ 60 high, otherwise medium
pub fn severity(hits: &[Hit]) -> &'static str {
    match hits.iter().map(|h| h.score).max().unwrap_or(0) {
        s if s >= 80 => "critical",
        s if s >= 60 => "high",
        _ => "medium",
    }
}

/// Evidence for the central server: per rule name, kind, author (DRL 1.1 requires attribution), source,
/// description
pub fn detail(path: &str, hits: &[Hit]) -> String {
    let mut s = format!("{path}\nYARA rules:");
    for h in hits.iter().take(8) {
        s += &format!("\n- {} ({}; author: {}; source: {})", h.rule, if h.category.is_empty() { "-" } else { &h.category }, if h.author.is_empty() { "-" } else { &h.author }, h.source);
        if !h.description.is_empty() {
            s += &format!(": {}", h.description.chars().take(160).collect::<String>());
        }
    }
    if hits.len() > 8 {
        s += &format!("\n… and {} more", hits.len() - 8);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = r#"
import "pe"
private rule is_php { strings: $a = "<?php" condition: $a }
rule t_eval { meta: score = 85 strings: $r = /eval\s*\(\s*base64_decode/ condition: is_php and $r }
rule t_weak { strings: $a = "c99shell" condition: $a }
"#;

    fn meta() -> Vec<Meta> {
        vec![
            Meta { name: "t_eval".into(), score: 85, category: "webshell".into(), author: "tyrosec".into(), source: "tyrosec".into(), ..Default::default() },
            Meta { name: "t_weak".into(), score: 50, category: "webshell".into(), source: "x/y".into(), ..Default::default() },
        ]
    }

    #[test]
    fn scan_and_severity() {
        let e = Engine::compile(SRC, "r1", meta()).unwrap();
        assert_eq!(e.count, 3);
        let h = e.scan(b"<?php eval(base64_decode($x)); // c99shell");
        assert_eq!(h.iter().map(|x| x.rule.as_str()).collect::<Vec<_>>(), vec!["t_eval", "t_weak"]);
        assert_eq!(severity(&h), "critical");
        assert!(detail("/var/www/x.php", &h).contains("t_eval (webshell; author: tyrosec; source: tyrosec)"));
        assert!(e.scan(b"harmless").is_empty());
        // a private helper rule never appears as a match
        assert!(e.scan(b"<?php echo 1;").is_empty());
        assert_eq!(severity(&e.scan(b"c99shell")), "medium");
    }

    #[test]
    fn load_package_from_dir() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("rules.yar.zst"), zstd::encode_all(SRC.as_bytes(), 3).unwrap()).unwrap();
        std::fs::write(d.path().join("rules.json"), serde_json::to_vec(&serde_json::json!({"version": "r1", "rules": [{"name": "t_eval", "score": 85}]})).unwrap()).unwrap();
        let e = Engine::load(d.path(), "r1").unwrap();
        assert_eq!(e.version, "r1");
        assert_eq!(e.scan(b"<?php eval( base64_decode(1)").len(), 1);
        // broken package → error (agent keeps the old version)
        std::fs::write(d.path().join("rules.yar.zst"), zstd::encode_all(&b"rule x { condition: nope }"[..], 3).unwrap()).unwrap();
        assert!(Engine::load(d.path(), "r1").is_err());
    }
}
