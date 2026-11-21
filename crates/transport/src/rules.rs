//! YARA-Regelpaket laden.
//!
//! Wie das Agent-Update: Manifest mit einem eingebauten Release-Schlüssel signiert (Epoche ≥ bekannte), Produkt
//! `tyrosecd-rules`, nicht abgelaufen, Version höher als die geladene, nur von einer erlaubten Quelle. Jede Datei mit
//! Größenlimit und SHA-256 aus dem Manifest. Abgelegt unter `<data_dir>/rules/<version>/` (0700/0600), danach
//! `<data_dir>/rules/current` mit der Version. Der Agent lädt die Regeln erst danach (eigener Baustein `tyrosd-yara`).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use sha2::Digest;

use crate::update::{fetch_limited, known_epoch, release_keys, Manifest};

pub const PRODUCT: &str = "tyrosecd-rules";

/// Stand des geladenen Pakets für den Heartbeat (setzt der Agent nach dem Laden)
#[derive(Clone, Debug, Default)]
pub struct Status {
    pub version: String,
    pub count: u32,
    pub rss_kb: u64,
    pub error: String,
}

pub static STATUS: std::sync::Mutex<Status> = std::sync::Mutex::new(Status { version: String::new(), count: 0, rss_kb: 0, error: String::new() });

pub fn status() -> Status {
    STATUS.lock().map(|s| s.clone()).unwrap_or_default()
}
/// Dateien eines Pakets mit Höchstgröße
pub const FILES: &[(&str, u64)] = &[("rules.yar.zst", 16 << 20), ("rules.json", 16 << 20), ("NOTICE", 4 << 20)];

/// „r12“ → 12
pub fn number(v: &str) -> Option<u64> {
    let n = v.strip_prefix('r')?;
    if n.is_empty() || n.len() > 6 || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    n.parse().ok()
}

/// geladene Version (Datei `current`), sofern das Verzeichnis vollständig ist
pub fn current(data_dir: &str) -> Option<String> {
    let v = std::fs::read_to_string(format!("{data_dir}/rules/current")).ok()?.trim().to_string();
    number(&v)?;
    FILES.iter().all(|(f, _)| Path::new(&format!("{data_dir}/rules/{v}/{f}")).is_file()).then_some(v)
}

pub fn dir(data_dir: &str, version: &str) -> PathBuf {
    PathBuf::from(format!("{data_dir}/rules/{version}"))
}

/// Manifest prüfen (Signatur, widerrufene Schlüssel, Produkt, Ablauf); Versionsvergleich übernimmt der Aufrufer
pub fn verify(raw: &[u8], sig: &[u8], keys: &[(&[u8; 32], u32)], min_epoch: u32) -> Result<Manifest> {
    let valid = |k: &[u8; 32]| ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &k[..]).verify(raw, sig).is_ok();
    let Some((_, epoch)) = keys.iter().filter(|(k, _)| valid(k)).max_by_key(|(_, e)| *e).copied() else {
        bail!("Signatur des Regelpakets ungültig – abgelehnt");
    };
    if epoch < min_epoch {
        bail!("Regelpaket mit widerrufenem Schlüssel (Epoche {epoch} < {min_epoch}) – abgelehnt");
    }
    let m: Manifest = serde_json::from_slice(raw).context("Manifest")?;
    if m.product != PRODUCT {
        bail!("Manifest für falsches Produkt: {}", m.product);
    }
    if let Some(d) = m.key_epoch {
        if d != epoch {
            bail!("Schlüssel-Epoche im Manifest ({d}) passt nicht zum Signierschlüssel ({epoch})");
        }
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if m.expires == 0 || m.expires < now {
        bail!("Regelpaket {} ist abgelaufen oder ohne Ablaufdatum", m.version);
    }
    number(&m.version).ok_or_else(|| anyhow!("Regelpaket: Version „{}“ ungültig", m.version))?;
    for (f, _) in FILES {
        if !m.files.contains_key(*f) {
            bail!("Regelpaket {}: Datei {f} fehlt im Manifest", m.version);
        }
    }
    Ok(m)
}

/// Paket von `base` (…/rules/<version>) holen, wenn es höher ist als `have`. Ok(Some(version)) nach dem Ablegen.
pub fn fetch_newer(base: &str, data_dir: &str, have: Option<&str>) -> Result<Option<String>> {
    let base = base.trim_end_matches('/');
    let raw = fetch_limited(&format!("{base}/manifest.json"), 1 << 20)?;
    let sig = fetch_limited(&format!("{base}/manifest.json.sig"), 1024)?;
    let m = verify(&raw, &sig, &release_keys(), known_epoch(data_dir))?;
    let new = number(&m.version).unwrap_or(0);
    if have.and_then(number).is_some_and(|h| h >= new) {
        return Ok(None);
    }
    let target = dir(data_dir, &m.version);
    let tmp = PathBuf::from(format!("{data_dir}/rules/.neu-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    create_private_dir(&tmp)?;
    let res = (|| -> Result<()> {
        for (f, limit) in FILES {
            let info = &m.files[*f];
            if info.size > *limit {
                bail!("{f}: {} Bytes über dem Limit", info.size);
            }
            let data = fetch_limited(&format!("{base}/{f}"), info.size + 1)?;
            if data.len() as u64 != info.size || hex::encode(sha2::Sha256::digest(&data)) != info.sha256 {
                bail!("{f}: Größe oder Prüfsumme passt nicht zum Manifest");
            }
            write_private(&tmp.join(f), &data)?;
        }
        write_private(&tmp.join("manifest.json"), &raw)?;
        Ok(())
    })();
    if let Err(e) = res {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(e);
    }
    let _ = std::fs::remove_dir_all(&target);
    std::fs::rename(&tmp, &target).with_context(|| format!("{}", target.display()))?;
    write_private(Path::new(&format!("{data_dir}/rules/current")), m.version.as_bytes())?;
    // ältere Pakete aufräumen (nur gültige Versionsordner, das vorige bleibt als Rückfall)
    if let Ok(rd) = std::fs::read_dir(format!("{data_dir}/rules")) {
        let mut olds: Vec<(u64, PathBuf)> = rd
            .flatten()
            .filter_map(|e| number(&e.file_name().to_string_lossy()).map(|n| (n, e.path())))
            .filter(|(n, _)| *n < new)
            .collect();
        olds.sort();
        for (_, p) in olds.iter().rev().skip(1) {
            let _ = std::fs::remove_dir_all(p);
        }
    }
    Ok(Some(m.version))
}

/// vorige Version als Rückfall (wenn die neue nicht lädt)
pub fn fall_back(data_dir: &str, bad: &str) -> Option<String> {
    let bad_n = number(bad)?;
    let prev = std::fs::read_dir(format!("{data_dir}/rules"))
        .ok()?
        .flatten()
        .filter_map(|e| number(&e.file_name().to_string_lossy()))
        .filter(|n| *n < bad_n)
        .max()?;
    let v = format!("r{prev}");
    write_private(Path::new(&format!("{data_dir}/rules/current")), v.as_bytes()).ok()?;
    let _ = std::fs::remove_dir_all(dir(data_dir, bad));
    Some(v)
}

fn create_private_dir(p: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if let Some(parent) = p.parent() {
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(parent)?;
    }
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(p)?;
    Ok(())
}

fn write_private(p: &Path, data: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = p.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, p)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn key() -> Ed25519KeyPair {
        let rng = ring::rand::SystemRandom::new();
        Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref()).unwrap()
    }

    fn manifest(product: &str, version: &str, expires: u64, files: &[(&str, &[u8])]) -> Vec<u8> {
        let f: serde_json::Map<String, serde_json::Value> = files
            .iter()
            .map(|(n, d)| (n.to_string(), serde_json::json!({"sha256": hex::encode(sha2::Sha256::digest(d)), "size": d.len()})))
            .collect();
        serde_json::to_vec(&serde_json::json!({"product": product, "version": version, "expires": expires, "files": f})).unwrap()
    }

    fn later() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 3600
    }

    #[test]
    fn versions() {
        assert_eq!(number("r12"), Some(12));
        assert_eq!(number("12"), None);
        assert_eq!(number("r"), None);
        assert_eq!(number("r1x"), None);
        assert_eq!(number("r1234567"), None);
    }

    #[test]
    fn verify_rejects_wrong_product_key_and_expiry() {
        let k = key();
        let pubk: [u8; 32] = k.public_key().as_ref().try_into().unwrap();
        let keys = [(&pubk, 0u32)];
        let files: Vec<(&str, &[u8])> = vec![("rules.yar.zst", b"a"), ("rules.json", b"b"), ("NOTICE", b"c")];
        let ok = manifest(PRODUCT, "r3", later(), &files);
        assert_eq!(verify(&ok, k.sign(&ok).as_ref(), &keys, 0).unwrap().version, "r3");
        // Agent-Manifest ist kein Regelpaket (und umgekehrt prüft der Agent-Updater das Produkt)
        let agent = manifest("tyrosecd-agent", "r3", later(), &files);
        assert!(verify(&agent, k.sign(&agent).as_ref(), &keys, 0).is_err());
        // fremder Schlüssel
        let other = key();
        assert!(verify(&ok, other.sign(&ok).as_ref(), &keys, 0).is_err());
        // widerrufene Epoche
        assert!(verify(&ok, k.sign(&ok).as_ref(), &keys, 1).is_err());
        // abgelaufen
        let old = manifest(PRODUCT, "r3", 1, &files);
        assert!(verify(&old, k.sign(&old).as_ref(), &keys, 0).is_err());
        // Datei fehlt
        let short = manifest(PRODUCT, "r3", later(), &files[..2]);
        assert!(verify(&short, k.sign(&short).as_ref(), &keys, 0).is_err());
    }

    #[test]
    fn fallback_to_previous() {
        let d = tempfile::tempdir().unwrap();
        let dd = d.path().to_str().unwrap();
        for v in ["r1", "r2"] {
            create_private_dir(&dir(dd, v)).unwrap();
            for (f, _) in FILES {
                write_private(&dir(dd, v).join(f), b"x").unwrap();
            }
        }
        write_private(Path::new(&format!("{dd}/rules/current")), b"r2").unwrap();
        assert_eq!(current(dd).as_deref(), Some("r2"));
        assert_eq!(fall_back(dd, "r2").as_deref(), Some("r1"));
        assert_eq!(current(dd).as_deref(), Some("r1"));
        assert!(!dir(dd, "r2").exists());
    }
}
