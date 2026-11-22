//! Self-update (main plan 12.4, launch package 25.3).
//!
//! Security:
//! - Only what is signed with the **release key** is installed. The
//!   public key is embedded in the binary; the private one is kept offline.
//!   The central server can only report "there is version X at URL Y".
//! - Only higher versions (no downgrade to a vulnerable version), and only in
//!   small steps (same major version, at most one minor version ahead) –
//!   a "999.0.0" manifest cannot pin the agent permanently.
//! - Key epoch: a key with a lower epoch than the highest ever accepted
//!   counts as revoked (rotation).
//! - The SHA-256 of every file is in the signed manifest; the downloaded program must
//!   itself report the manifest's version.
//! - Atomic exchange; on repeated failed starts, return to the old version.

use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::Digest;

/// Public release key (Ed25519, 694e09f0…852e). The private key is kept offline by the publisher.
pub const RELEASE_PUBKEY: &[u8; 32] = include_bytes!("../release.pub");
/// Trusted release keys (rotation 2026-11-16): the previous key (only for the transition –
/// running agents only know this one), the new main key 2026 and a reserve key kept offline.
/// From the next version on, signing uses only "2026"; after that the old key is dropped.
pub const RELEASE_PUBKEYS: [&[u8; 32]; 3] =
    [RELEASE_PUBKEY, include_bytes!("../release-2026.pub"), include_bytes!("../release-reserve.pub")];

/// Key epoch per built-in key (same order as `RELEASE_PUBKEYS`): old = 0, 2026 = 1,
/// reserve = 2. The agent remembers the highest epoch it has ever accepted
/// (`EPOCH_FILE` in the data directory) and afterwards rejects manifests signed with a key of a lower epoch
/// – an exposed old key is thus revoked as soon as the agent has seen a manifest of the newer
/// one.
pub const RELEASE_KEY_EPOCHS: [u32; 3] = [0, 1, 2];

/// Lower bound of the key epoch, fixed in the binary (raise it once the old key is no longer used for signing)
pub const MIN_KEY_EPOCH: u32 = 0;

/// File in the data directory with the highest key epoch ever accepted
pub const EPOCH_FILE: &str = "release-epoch";

/// At most this many patch versions of jump (within the same minor version, or from x.(y+1).0)
pub const MAX_PATCH_JUMP: u64 = 50;

/// Version of this binary (can be overridden at build time via TYROSD_VERSION for testing updates)
pub const AGENT_VERSION: &str = match option_env!("TYROSD_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Deserialize, Debug, Clone)]
pub struct FileInfo {
    pub sha256: String,
    pub size: u64,
}

/// Release manifest. Unknown fields are ignored (no `deny_unknown_fields`) – so new fields like `key_epoch`
/// stay readable for older agents.
#[derive(Deserialize, Debug, Clone)]
pub struct Manifest {
    pub product: String,
    pub version: String,
    pub files: std::collections::HashMap<String, FileInfo>,
    /// Unix seconds; after that the manifest is invalid (protection against "freezing"
    /// by a source that permanently serves an old, validly signed manifest)
    #[serde(default)]
    pub expires: u64,
    /// Epoch of the signing key (optional, written by the signing tool since 0.4.10). If set, it must
    /// match the key that actually verifies.
    #[serde(default)]
    pub key_epoch: Option<u32>,
}

/// Default list of allowed update sources (prefixes). A source reported by the
/// central server outside this list is ignored.
pub const DEFAULT_UPDATE_SOURCES: &[&str] = &["https://get.tyrosec.com/"];

/// Is `base` an allowed update source?
pub fn source_allowed(base: &str, allowed: &[String]) -> bool {
    let b = base.trim();
    // no tricks like https://get.tyrosec.com.evil.tld or user@host
    if b.contains('@') || b.contains("..") {
        return false;
    }
    allowed.iter().any(|p| {
        let p = if p.ends_with('/') { p.clone() } else { format!("{p}/") };
        b.starts_with(&p) || format!("{b}/") == p
    })
}

#[derive(Serialize, Deserialize, Debug)]
struct Marker {
    from: String,
    to: String,
    ts: u64,
    attempts: u32,
}

/// a > b for versions of the form 1.2.3 (missing parts = 0, non-numeric parts = 0)
pub fn version_gt(a: &str, b: &str) -> bool {
    let p = |s: &str| -> Vec<u64> { s.split(['.', '-', '+']).take(3).map(|x| x.parse().unwrap_or(0)).collect() };
    let (mut x, mut y) = (p(a), p(b));
    x.resize(3, 0);
    y.resize(3, 0);
    x > y
}

/// Strictly "x.y.z" (digits only, at most 9 digits per part)
fn parse_version(s: &str) -> Option<[u64; 3]> {
    let v: Vec<&str> = s.split('.').collect();
    if v.len() != 3 || v.iter().any(|x| x.is_empty() || x.len() > 9 || !x.bytes().all(|b| b.is_ascii_digit())) {
        return None;
    }
    Some([v[0].parse().ok()?, v[1].parse().ok()?, v[2].parse().ok()?])
}

/// May we jump from `current` to `target`? Same major version, minor at most +1, patch at most
/// `MAX_PATCH_JUMP` ahead (or ≤ `MAX_PATCH_JUMP` in the next minor version). A change of the major version
/// first requires an agent release that adjusts this rule.
pub fn version_jump_ok(target: &str, current: &str) -> bool {
    let (Some(t), Some(c)) = (parse_version(target), parse_version(current)) else { return false };
    if t[0] != c[0] {
        return false;
    }
    if t[1] == c[1] {
        t[2] <= c[2].saturating_add(MAX_PATCH_JUMP)
    } else {
        t[1] == c[1] + 1 && t[2] <= MAX_PATCH_JUMP
    }
}

/// Highest key epoch ever accepted (if the file is missing: `MIN_KEY_EPOCH`)
#[allow(clippy::unnecessary_min_or_max)] // MIN_KEY_EPOCH is currently 0, will be raised after the rotation
pub fn known_epoch(data_dir: &str) -> u32 {
    std::fs::read_to_string(format!("{data_dir}/{EPOCH_FILE}"))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0)
        .max(MIN_KEY_EPOCH)
}

/// Record the key epoch – only upwards, atomically (temporary file + rename)
pub fn store_epoch(data_dir: &str, epoch: u32) -> Result<()> {
    if epoch <= known_epoch(data_dir) && std::path::Path::new(&format!("{data_dir}/{EPOCH_FILE}")).exists() {
        return Ok(());
    }
    let tmp = format!("{data_dir}/{EPOCH_FILE}.tmp");
    let _ = std::fs::remove_file(&tmp);
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&tmp)?;
        f.write_all(format!("{epoch}\n").as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, format!("{data_dir}/{EPOCH_FILE}"))?;
    Ok(())
}

/// Download with a size limit (also for the YARA rule package, `rules.rs`)
pub fn fetch_limited(url: &str, limit: u64) -> Result<Vec<u8>> {
    fetch(url, limit)
}

fn fetch(url: &str, limit: u64) -> Result<Vec<u8>> {
    if let Some(path) = url.strip_prefix("file://") {
        return Ok(std::fs::read(path).with_context(|| path.to_string())?);
    }
    // integrity comes from the signature; transport via HTTPS with Web PKI (or local)
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(120)).try_proxy_from_env(true).build();
    let resp = agent.get(url).call().map_err(|e| anyhow!("{url}: {e}"))?;
    let mut v = Vec::new();
    resp.into_reader().take(limit).read_to_end(&mut v)?;
    Ok(v)
}

pub fn arch_file() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "tyrosecd-aarch64",
        _ => "tyrosecd-x86_64",
    }
}

/// built-in keys with their epochs
pub fn release_keys() -> Vec<(&'static [u8; 32], u32)> {
    RELEASE_PUBKEYS.iter().copied().zip(RELEASE_KEY_EPOCHS).collect()
}

/// Download and verify the manifest. `Ok(None)` if no higher version is available. The key epoch of a valid
/// manifest is recorded in `data_dir` (only upwards).
pub fn check(base: &str, data_dir: &str) -> Result<Option<Manifest>> {
    let base = base.trim_end_matches('/');
    let raw = fetch(&format!("{base}/manifest.json"), 1 << 20)?;
    let sig = fetch(&format!("{base}/manifest.json.sig"), 1024)?;
    let (m, epoch) = verify_manifest_any(&raw, &sig, &release_keys(), known_epoch(data_dir), AGENT_VERSION)?;
    if let Err(e) = store_epoch(data_dir, epoch) {
        eprintln!("key epoch {epoch} not saved: {e:#}");
    }
    Ok(m)
}

/// Like `verify_manifest`, valid with one of the trusted keys `(key, epoch)`; keys with an
/// epoch below `min_epoch` count as revoked. Additionally returns the epoch of the verifying key.
pub fn verify_manifest_any(raw: &[u8], sig: &[u8], keys: &[(&[u8; 32], u32)], min_epoch: u32, current: &str) -> Result<(Option<Manifest>, u32)> {
    let valid = |k: &[u8; 32]| ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &k[..]).verify(raw, sig).is_ok();
    // highest matching epoch (in case a key were listed more than once)
    let Some((key, epoch)) = keys.iter().filter(|(k, _)| valid(k)).max_by_key(|(_, e)| *e).copied() else {
        bail!("release manifest signature invalid – update rejected");
    };
    if epoch < min_epoch {
        bail!("release manifest signed with a revoked key (epoch {epoch} < {min_epoch}) – update rejected");
    }
    let m = verify_manifest(raw, sig, key, current)?;
    let declared: Manifest = serde_json::from_slice(raw).context("Manifest")?;
    if let Some(d) = declared.key_epoch {
        if d != epoch {
            bail!("key epoch in the manifest ({d}) does not match the signing key ({epoch}) – update rejected");
        }
    }
    Ok((m, epoch))
}

/// Verify signature, product, expiry date and version (key-parameterized for tests).
pub fn verify_manifest(raw: &[u8], sig: &[u8], pubkey: &[u8], current: &str) -> Result<Option<Manifest>> {
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pubkey)
        .verify(raw, sig)
        .map_err(|_| anyhow!("release manifest signature invalid – update rejected"))?;
    let m: Manifest = serde_json::from_slice(raw).context("Manifest")?;
    if m.product != "tyrosecd-agent" {
        bail!("manifest for the wrong product: {}", m.product);
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if m.expires == 0 || m.expires < now {
        bail!("release manifest {} has expired or has no expiry date – update rejected", m.version);
    }
    if !version_gt(&m.version, current) {
        return Ok(None);
    }
    if !version_jump_ok(&m.version, current) {
        bail!("release manifest {} is an invalid version jump from {current} – update rejected", m.version);
    }
    Ok(Some(m))
}

/// Does the program at `path` report exactly `tyrosecd <version>` with `--version`? Run without environment, without
/// input and with a time limit (at this point the program is already confirmed by the checksum in the signed manifest
/// – it is exactly the program that is about to run as root anyway).
pub fn binary_version_matches(path: &std::path::Path, version: &str) -> Result<()> {
    use std::process::{Command, Stdio};
    let mut child = Command::new(path)
        .arg("--version")
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("{} --version", path.display()))?;
    let t0 = std::time::Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if t0.elapsed() > Duration::from_secs(15) {
            let _ = child.kill();
            let _ = child.wait();
            bail!("new program does not respond to --version – update rejected");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut out = String::new();
    child.stdout.take().map(|mut s| (&mut s).take(4096).read_to_string(&mut out));
    let got = out.trim();
    if got != format!("tyrosecd {version}") {
        bail!("new program reports “{}” instead of version {version} – update rejected", got.chars().take(80).collect::<String>());
    }
    Ok(())
}

/// Download the new binary, verify it and atomically put it in place of the running one.
/// Afterwards the process must restart (systemd: exit code ≠ 0).
pub fn apply(base: &str, m: &Manifest, data_dir: &str) -> Result<()> {
    let base = base.trim_end_matches('/');
    let name = arch_file();
    let info = m.files.get(name).ok_or_else(|| anyhow!("release does not contain {name}"))?;
    let bin = fetch(&format!("{base}/{name}"), info.size + 1)?;
    if bin.len() as u64 != info.size || hex::encode(sha2::Sha256::digest(&bin)) != info.sha256 {
        bail!("checksum of {name} does not match – update rejected");
    }
    let exe = std::env::current_exe()?.canonicalize()?;
    let dir = exe.parent().ok_or_else(|| anyhow!("program directory"))?;
    let new = dir.join("tyrosecd.new");
    let prev = dir.join("tyrosecd.prev");
    std::fs::write(&new, &bin)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755))?;
    }
    // the program must itself report the manifest's version (no old program under a new version number)
    if let Err(e) = binary_version_matches(&new, &m.version) {
        let _ = std::fs::remove_file(&new);
        return Err(e);
    }
    std::fs::copy(&exe, &prev)?;
    let marker = Marker {
        from: AGENT_VERSION.into(),
        to: m.version.clone(),
        ts: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        attempts: 0,
    };
    std::fs::write(format!("{data_dir}/update.json"), serde_json::to_vec(&marker)?)?;
    std::fs::rename(&new, &exe)?; // atomic within the same directory
    Ok(())
}

/// Fallback for systems without the systemd guard: if the new binary repeatedly fails to start
/// stably, the previous version is restored. Under systemd this is handled by the unit's
/// `ExecStartPre` (also kicks in if the new binary crashes immediately).
pub fn startup_check(data_dir: &str) -> Option<String> {
    let path = format!("{data_dir}/update.json");
    let mut mk: Marker = serde_json::from_slice(&std::fs::read(&path).ok()?).ok()?;
    mk.attempts += 1;
    if mk.attempts >= 2 {
        let exe = std::env::current_exe().ok()?.canonicalize().ok()?;
        let prev = exe.parent()?.join("tyrosecd.prev");
        let _ = std::fs::remove_file(&path);
        if prev.exists() && std::fs::rename(&prev, &exe).is_ok() {
            return Some(format!("update {} → {} does not start stably – reverting to {}", mk.from, mk.to, mk.from));
        }
        return None;
    }
    let _ = std::fs::write(&path, serde_json::to_vec(&mk).unwrap_or_default());
    None
}

/// Version whose update was rolled back (stored by the systemd guard as update.failed).
/// This version is not installed again, otherwise a loop would result.
pub fn failed_version(data_dir: &str) -> Option<String> {
    let mk: Marker = serde_json::from_slice(&std::fs::read(format!("{data_dir}/update.failed")).ok()?).ok()?;
    Some(mk.to)
}

/// Call after a stable run time: update confirmed. Returns (from, to).
pub fn confirm(data_dir: &str) -> Option<(String, String)> {
    let path = format!("{data_dir}/update.json");
    let mk: Marker = serde_json::from_slice(&std::fs::read(&path).ok()?).ok()?;
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{data_dir}/update.attempts")); // counter of the systemd guard
    Some((mk.from, mk.to))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert!(version_gt("0.0.2", "0.0.1"));
        assert!(version_gt("1.0", "0.9.9"));
        assert!(!version_gt("0.0.1", "0.0.1"));
        assert!(!version_gt("0.0.1", "0.1.0"));
    }

    #[test]
    fn version_jumps_are_capped() {
        assert!(version_jump_ok("0.4.10", "0.4.9"));
        assert!(version_jump_ok("0.4.59", "0.4.9"));
        assert!(!version_jump_ok("0.4.60", "0.4.9"));
        assert!(version_jump_ok("0.5.0", "0.4.10"));
        assert!(version_jump_ok("0.5.50", "0.4.10"));
        assert!(!version_jump_ok("0.5.51", "0.4.10"));
        assert!(!version_jump_ok("0.6.0", "0.4.10"));
        assert!(!version_jump_ok("1.0.0", "0.4.10"));
        assert!(!version_jump_ok("999.0.0", "0.4.10"));
        assert!(!version_jump_ok("0.4.10-evil", "0.4.9"));
        assert!(!version_jump_ok("0.4.1234567890", "0.4.9"));
        assert!(!version_jump_ok("0.4", "0.4.9"));
    }

    #[test]
    fn rejects_unsigned_manifest() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("manifest.json"), br#"{"product":"tyrosecd-agent","version":"99.0.0","files":{}}"#).unwrap();
        std::fs::write(d.path().join("manifest.json.sig"), [0u8; 64]).unwrap();
        let base = format!("file://{}", d.path().display());
        let err = check(&base, &d.path().to_string_lossy()).unwrap_err().to_string();
        assert!(err.contains("signature"), "{err}");
    }

    #[test]
    fn epoch_store_only_goes_up() {
        let d = tempfile::tempdir().unwrap();
        let dd = d.path().to_string_lossy().into_owned();
        assert_eq!(known_epoch(&dd), 0);
        store_epoch(&dd, 1).unwrap();
        assert_eq!(known_epoch(&dd), 1);
        store_epoch(&dd, 0).unwrap();
        assert_eq!(known_epoch(&dd), 1);
        store_epoch(&dd, 2).unwrap();
        assert_eq!(known_epoch(&dd), 2);
        // broken file → lower bound
        std::fs::write(d.path().join(EPOCH_FILE), "x").unwrap();
        assert_eq!(known_epoch(&dd), MIN_KEY_EPOCH);
    }

    #[test]
    fn built_in_epochs() {
        let k = release_keys();
        assert_eq!(k.len(), 3);
        assert_eq!(k.iter().map(|(_, e)| *e).collect::<Vec<_>>(), vec![0, 1, 2]);
        assert!(std::ptr::eq(k[0].0, RELEASE_PUBKEY));
    }

    #[test]
    fn binary_must_report_manifest_version() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let script = |name: &str, body: &str| {
            let p = d.path().join(name);
            std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            p
        };
        let ok = script("ok", r#"[ "$1" = "--version" ] && echo "tyrosecd 0.4.10""#);
        assert!(binary_version_matches(&ok, "0.4.10").is_ok());
        // old program under a new version number
        assert!(binary_version_matches(&ok, "0.4.11").is_err());
        let old = script("old", r#"echo "tyrosecd 0.4.9""#);
        assert!(binary_version_matches(&old, "0.4.10").unwrap_err().to_string().contains("0.4.9"));
        let junk = script("junk", r#"echo "tyrosecd 0.4.10 extra""#);
        assert!(binary_version_matches(&junk, "0.4.10").is_err());
        let fail = script("fail", "exit 1");
        assert!(binary_version_matches(&fail, "0.4.10").is_err());
        assert!(binary_version_matches(&d.path().join("missing"), "0.4.10").is_err());
    }
}

#[cfg(test)]
mod hardening_tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn keypair() -> Ed25519KeyPair {
        let rng = ring::rand::SystemRandom::new();
        Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref()).unwrap()
    }

    fn manifest(version: &str, expires: u64) -> Vec<u8> {
        format!(r#"{{"product":"tyrosecd-agent","version":"{version}","expires":{expires},"files":{{}}}}"#).into_bytes()
    }

    fn manifest_epoch(version: &str, expires: u64, epoch: u32) -> Vec<u8> {
        format!(r#"{{"product":"tyrosecd-agent","version":"{version}","expires":{expires},"key_epoch":{epoch},"created":1,"files":{{}}}}"#).into_bytes()
    }

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    fn pk(kp: &Ed25519KeyPair) -> [u8; 32] {
        kp.public_key().as_ref().try_into().unwrap()
    }

    #[test]
    fn any_trusted_key_is_accepted_others_not() {
        // rotation: manifest signed with the new key, agent knows old + new + reserve
        let (old, new, foreign) = (keypair(), keypair(), keypair());
        let (ko, kn) = (pk(&old), pk(&new));
        let raw = manifest("0.0.2", now() + 3600);
        let sig = new.sign(&raw);
        let (m, e) = verify_manifest_any(&raw, sig.as_ref(), &[(&ko, 0), (&kn, 1)], 0, "0.0.1").unwrap();
        assert!(m.is_some());
        assert_eq!(e, 1);
        assert!(verify_manifest_any(&raw, sig.as_ref(), &[(&ko, 0)], 0, "0.0.1").is_err());
        assert!(verify_manifest_any(&raw, foreign.sign(&raw).as_ref(), &[(&ko, 0), (&kn, 1)], 0, "0.0.1").is_err());
        // built-in keys: three different ones
        assert_ne!(RELEASE_PUBKEYS[0], RELEASE_PUBKEYS[1]);
        assert_ne!(RELEASE_PUBKEYS[1], RELEASE_PUBKEYS[2]);
    }

    #[test]
    fn lower_key_epoch_is_revoked() {
        let (old, new) = (keypair(), keypair());
        let (ko, kn) = (pk(&old), pk(&new));
        let keys = [(&ko, 0), (&kn, 1)];
        let raw = manifest("0.0.2", now() + 3600);
        // no newer key seen yet: the old one is valid
        assert!(verify_manifest_any(&raw, old.sign(&raw).as_ref(), &keys, 0, "0.0.1").unwrap().0.is_some());
        // after epoch 1 was accepted: old key revoked, new one still valid
        let e = verify_manifest_any(&raw, old.sign(&raw).as_ref(), &keys, 1, "0.0.1").unwrap_err();
        assert!(e.to_string().contains("revoked"), "{e}");
        assert!(verify_manifest_any(&raw, new.sign(&raw).as_ref(), &keys, 1, "0.0.1").is_ok());
        // even "no newer version" with the old key is rejected (no silent pass-through)
        let same = manifest("0.0.1", now() + 3600);
        assert!(verify_manifest_any(&same, old.sign(&same).as_ref(), &keys, 1, "0.0.1").is_err());
    }

    #[test]
    fn declared_key_epoch_must_match_signing_key() {
        let (old, new) = (keypair(), keypair());
        let (ko, kn) = (pk(&old), pk(&new));
        let keys = [(&ko, 0), (&kn, 1)];
        let good = manifest_epoch("0.0.2", now() + 3600, 1);
        assert_eq!(verify_manifest_any(&good, new.sign(&good).as_ref(), &keys, 0, "0.0.1").unwrap().1, 1);
        // signed with the old key, but claims to be epoch 1
        let e = verify_manifest_any(&good, old.sign(&good).as_ref(), &keys, 0, "0.0.1").unwrap_err();
        assert!(e.to_string().contains("does not match"), "{e}");
        // without the field (manifests up to 0.4.9) still valid
        let plain = manifest("0.0.2", now() + 3600);
        assert!(verify_manifest_any(&plain, old.sign(&plain).as_ref(), &keys, 0, "0.0.1").is_ok());
    }

    #[test]
    fn check_persists_epoch_and_then_rejects_old_key() {
        // end to end via files, with test keys instead of the built-in ones
        let (old, new) = (keypair(), keypair());
        let (ko, kn) = (pk(&old), pk(&new));
        let keys = [(&ko, 0u32), (&kn, 1u32)];
        let d = tempfile::tempdir().unwrap();
        let dd = d.path().to_string_lossy().into_owned();
        let raw = manifest_epoch("0.0.2", now() + 3600, 1);
        let (_, e) = verify_manifest_any(&raw, new.sign(&raw).as_ref(), &keys, known_epoch(&dd), "0.0.1").unwrap();
        store_epoch(&dd, e).unwrap();
        let raw = manifest("0.0.3", now() + 3600);
        assert!(verify_manifest_any(&raw, old.sign(&raw).as_ref(), &keys, known_epoch(&dd), "0.0.1").is_err());
    }

    #[test]
    fn manifest_with_new_fields_parses_like_before() {
        // agent ≤ 0.4.9 reads the same structure without `key_epoch` – unknown fields must not interfere
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct OldManifest {
            product: String,
            version: String,
            files: std::collections::HashMap<String, FileInfo>,
            #[serde(default)]
            expires: u64,
        }
        let raw = manifest_epoch("0.4.10", now() + 3600, 1);
        let m: OldManifest = serde_json::from_slice(&raw).unwrap();
        assert_eq!(m.version, "0.4.10");
        let m: Manifest = serde_json::from_slice(&raw).unwrap();
        assert_eq!(m.key_epoch, Some(1));
    }

    #[test]
    fn valid_newer_manifest_is_accepted() {
        let kp = keypair();
        let raw = manifest("0.0.9", now() + 3600);
        let m = verify_manifest(&raw, kp.sign(&raw).as_ref(), kp.public_key().as_ref(), "0.0.1").unwrap();
        assert_eq!(m.unwrap().version, "0.0.9");
    }

    #[test]
    fn huge_version_is_rejected() {
        let kp = keypair();
        for v in ["999.0.0", "0.9.0", "0.0.999"] {
            let raw = manifest(v, now() + 3600);
            let e = verify_manifest(&raw, kp.sign(&raw).as_ref(), kp.public_key().as_ref(), "0.0.1").unwrap_err();
            assert!(e.to_string().contains("version jump"), "{v}: {e}");
        }
    }

    #[test]
    fn expired_or_undated_manifest_is_rejected() {
        let kp = keypair();
        for raw in [manifest("0.0.2", now() - 1), manifest("0.0.2", 0)] {
            let e = verify_manifest(&raw, kp.sign(&raw).as_ref(), kp.public_key().as_ref(), "0.0.1").unwrap_err();
            assert!(e.to_string().contains("expired"), "{e}");
        }
    }

    #[test]
    fn downgrade_and_foreign_key_are_rejected() {
        let kp = keypair();
        let raw = manifest("0.0.1", now() + 3600);
        assert!(verify_manifest(&raw, kp.sign(&raw).as_ref(), kp.public_key().as_ref(), "0.0.2").unwrap().is_none());
        let other = keypair();
        let raw = manifest("0.0.9", now() + 3600);
        assert!(verify_manifest(&raw, other.sign(&raw).as_ref(), kp.public_key().as_ref(), "0.0.1").is_err());
        // manifest modified after signing
        let mut tampered = raw.clone();
        let sig = kp.sign(&raw);
        tampered[40] ^= 1;
        assert!(verify_manifest(&tampered, sig.as_ref(), kp.public_key().as_ref(), "0.0.1").is_err());
    }

    #[test]
    fn update_sources() {
        let allowed = vec!["https://get.tyrosec.com/".to_string(), "file:///root/rel".to_string()];
        assert!(source_allowed("https://get.tyrosec.com/releases/0.0.2", &allowed));
        assert!(source_allowed("file:///root/rel/x", &allowed));
        assert!(!source_allowed("https://get.tyrosec.com.evil.tld/x", &allowed));
        assert!(!source_allowed("https://evil.tld/https://get.tyrosec.com/", &allowed));
        assert!(!source_allowed("https://user@get.tyrosec.com/x", &allowed));
        assert!(!source_allowed("https://get.tyrosec.com/../../etc", &allowed));
        assert!(!source_allowed("http://169.254.169.254/latest", &allowed));
    }
}
