//! Load the YARA rule package.
//!
//! Like the agent update: manifest signed with a built-in release key (epoch ≥ known), product
//! `tyrosecd-rules`, not expired, version higher than the loaded one, only from an allowed source. Every file with
//! a size limit and SHA-256 from the manifest. Stored under `<data_dir>/rules/<version>/` (0700/0600), then
//! `<data_dir>/rules/current` with the version. The agent loads the rules only afterwards
//! (separate crate `tyrosd-yara`).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use sha2::Digest;

use crate::update::{fetch_limited, known_epoch, release_keys, Manifest};

pub const PRODUCT: &str = "tyrosecd-rules";

/// State of the loaded package for the heartbeat (set by the agent after loading)
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
/// Files of a package with maximum size
pub const FILES: &[(&str, u64)] = &[("rules.yar.zst", 16 << 20), ("rules.json", 16 << 20), ("NOTICE", 4 << 20)];

/// "r12" → 12
pub fn number(v: &str) -> Option<u64> {
    let n = v.strip_prefix('r')?;
    if n.is_empty() || n.len() > 6 || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    n.parse().ok()
}

/// loaded version (file `current`), provided the directory is complete
pub fn current(data_dir: &str) -> Option<String> {
    let v = std::fs::read_to_string(format!("{data_dir}/rules/current")).ok()?.trim().to_string();
    number(&v)?;
    FILES.iter().all(|(f, _)| Path::new(&format!("{data_dir}/rules/{v}/{f}")).is_file()).then_some(v)
}

pub fn dir(data_dir: &str, version: &str) -> PathBuf {
    PathBuf::from(format!("{data_dir}/rules/{version}"))
}

/// Verify the manifest (signature, revoked keys, product, expiry); the version comparison is done by the caller
pub fn verify(raw: &[u8], sig: &[u8], keys: &[(&[u8; 32], u32)], min_epoch: u32) -> Result<Manifest> {
    let valid = |k: &[u8; 32]| ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &k[..]).verify(raw, sig).is_ok();
    let Some((_, epoch)) = keys.iter().filter(|(k, _)| valid(k)).max_by_key(|(_, e)| *e).copied() else {
        bail!("rule package signature invalid – rejected");
    };
    if epoch < min_epoch {
        bail!("rule package with revoked key (epoch {epoch} < {min_epoch}) – rejected");
    }
    let m: Manifest = serde_json::from_slice(raw).context("Manifest")?;
    if m.product != PRODUCT {
        bail!("manifest for the wrong product: {}", m.product);
    }
    if let Some(d) = m.key_epoch {
        if d != epoch {
            bail!("key epoch in the manifest ({d}) does not match the signing key ({epoch})");
        }
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if m.expires == 0 || m.expires < now {
        bail!("rule package {} has expired or has no expiry date", m.version);
    }
    number(&m.version).ok_or_else(|| anyhow!("rule package: version “{}” invalid", m.version))?;
    for (f, _) in FILES {
        if !m.files.contains_key(*f) {
            bail!("rule package {}: file {f} missing from the manifest", m.version);
        }
    }
    Ok(m)
}

/// Fetch the package from `base` (…/rules/<version>) if it is higher than `have`. Ok(Some(version)) after storing it.
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
                bail!("{f}: {} bytes over the limit", info.size);
            }
            let data = fetch_limited(&format!("{base}/{f}"), info.size + 1)?;
            if data.len() as u64 != info.size || hex::encode(sha2::Sha256::digest(&data)) != info.sha256 {
                bail!("{f}: size or checksum does not match the manifest");
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
    // clean up older packages (only valid version directories; the previous one stays as a fallback)
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

/// previous version as a fallback (if the new one does not load)
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
        // an agent manifest is not a rule package (and conversely the agent updater checks the product)
        let agent = manifest("tyrosecd-agent", "r3", later(), &files);
        assert!(verify(&agent, k.sign(&agent).as_ref(), &keys, 0).is_err());
        // foreign key
        let other = key();
        assert!(verify(&ok, other.sign(&ok).as_ref(), &keys, 0).is_err());
        // revoked epoch
        assert!(verify(&ok, k.sign(&ok).as_ref(), &keys, 1).is_err());
        // expired
        let old = manifest(PRODUCT, "r3", 1, &files);
        assert!(verify(&old, k.sign(&old).as_ref(), &keys, 0).is_err());
        // file missing
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
