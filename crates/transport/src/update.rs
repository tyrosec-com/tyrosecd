//! Selbst-Update (Hauptplan 12.4, Launch-Paket 25.3).
//!
//! Sicherheit:
//! - Installiert wird nur, was mit dem **Release-Schlüssel** signiert ist. Der
//!   öffentliche Schlüssel ist im Binary eingebettet; der private liegt offline.
//!   Die Zentrale kann nur „es gibt Version X unter URL Y“ melden.
//! - Nur höhere Versionen (kein Downgrade auf eine verwundbare Version), und nur in
//!   kleinen Schritten (gleiche Major-Version, höchstens eine Minor-Version weiter) –
//!   ein Manifest „999.0.0“ kann den Agenten nicht dauerhaft festnageln.
//! - Schlüssel-Epoche: ein Schlüssel niedrigerer Epoche als die höchste je angenommene
//!   gilt als widerrufen (Rotation).
//! - SHA-256 jeder Datei steht im signierten Manifest; das geladene Programm muss
//!   selbst die Version des Manifests melden.
//! - Atomarer Austausch; bei wiederholtem Fehlstart Rückkehr zur alten Version.

use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::Digest;

/// Öffentlicher Release-Schlüssel (Ed25519, 694e09f0…852e). Der private Schlüssel liegt offline beim Herausgeber.
pub const RELEASE_PUBKEY: &[u8; 32] = include_bytes!("../release.pub");
/// Vertrauenswürdige Release-Schlüssel (Rotation 16.11.2026): bisheriger Schlüssel (nur noch für den Übergang –
/// laufende Agenten kennen nur ihn), neuer Hauptschlüssel 2026 und ein offline verwahrter Reserve-Schlüssel.
/// Ab der nächsten Version wird nur noch mit „2026“ signiert; danach fällt der alte Schlüssel heraus.
pub const RELEASE_PUBKEYS: [&[u8; 32]; 3] =
    [RELEASE_PUBKEY, include_bytes!("../release-2026.pub"), include_bytes!("../release-reserve.pub")];

/// Schlüssel-Epoche je eingebautem Schlüssel (gleiche Reihenfolge wie `RELEASE_PUBKEYS`): alt = 0, 2026 = 1,
/// Reserve = 2. Der Agent merkt sich die höchste Epoche, die er je angenommen hat
/// (`EPOCH_FILE` im Datenverzeichnis), und lehnt danach Manifeste ab, die mit einem Schlüssel niedrigerer Epoche
/// signiert sind – ein exponierter alter Schlüssel ist damit widerrufen, sobald der Agent ein Manifest des neueren
/// gesehen hat.
pub const RELEASE_KEY_EPOCHS: [u32; 3] = [0, 1, 2];

/// Untergrenze der Schlüssel-Epoche, fest im Binary (anheben, sobald mit dem alten Schlüssel nicht mehr signiert wird)
pub const MIN_KEY_EPOCH: u32 = 0;

/// Datei im Datenverzeichnis mit der höchsten je angenommenen Schlüssel-Epoche
pub const EPOCH_FILE: &str = "release-epoch";

/// Höchstens so viele Patch-Versionen Sprung (innerhalb derselben Minor-Version bzw. ab x.(y+1).0)
pub const MAX_PATCH_JUMP: u64 = 50;

/// Version dieses Binaries (zum Testen von Updates per TYROSD_VERSION beim Bauen überschreibbar)
pub const AGENT_VERSION: &str = match option_env!("TYROSD_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Deserialize, Debug, Clone)]
pub struct FileInfo {
    pub sha256: String,
    pub size: u64,
}

/// Release-Manifest. Unbekannte Felder werden ignoriert (kein `deny_unknown_fields`) – neue Felder wie `key_epoch`
/// bleiben so für ältere Agenten lesbar.
#[derive(Deserialize, Debug, Clone)]
pub struct Manifest {
    pub product: String,
    pub version: String,
    pub files: std::collections::HashMap<String, FileInfo>,
    /// Unix-Sekunden; danach ist das Manifest ungültig (Schutz vor „Einfrieren“
    /// durch eine Quelle, die dauerhaft ein altes, gültig signiertes Manifest liefert)
    #[serde(default)]
    pub expires: u64,
    /// Epoche des Signierschlüssels (optional, ab 0.4.10 vom Signierwerkzeug geschrieben). Ist sie gesetzt, muss sie
    /// zum tatsächlich prüfenden Schlüssel passen.
    #[serde(default)]
    pub key_epoch: Option<u32>,
}

/// Standard-Liste erlaubter Update-Quellen (Präfixe). Eine von der Zentrale
/// gemeldete Quelle außerhalb dieser Liste wird ignoriert.
pub const DEFAULT_UPDATE_SOURCES: &[&str] = &["https://get.tyrosec.com/"];

/// Ist `base` eine erlaubte Update-Quelle?
pub fn source_allowed(base: &str, allowed: &[String]) -> bool {
    let b = base.trim();
    // keine Tricks wie https://get.tyrosec.com.evil.tld oder Benutzer@Host
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

/// a > b für Versionen der Form 1.2.3 (fehlende Teile = 0, nicht-numerische Teile = 0)
pub fn version_gt(a: &str, b: &str) -> bool {
    let p = |s: &str| -> Vec<u64> { s.split(['.', '-', '+']).take(3).map(|x| x.parse().unwrap_or(0)).collect() };
    let (mut x, mut y) = (p(a), p(b));
    x.resize(3, 0);
    y.resize(3, 0);
    x > y
}

/// Streng „x.y.z“ (nur Ziffern, je Teil höchstens 9 Stellen)
fn parse_version(s: &str) -> Option<[u64; 3]> {
    let v: Vec<&str> = s.split('.').collect();
    if v.len() != 3 || v.iter().any(|x| x.is_empty() || x.len() > 9 || !x.bytes().all(|b| b.is_ascii_digit())) {
        return None;
    }
    Some([v[0].parse().ok()?, v[1].parse().ok()?, v[2].parse().ok()?])
}

/// Darf von `current` auf `target` gesprungen werden? Gleiche Major-Version, Minor höchstens +1, Patch höchstens
/// `MAX_PATCH_JUMP` weiter (bzw. ≤ `MAX_PATCH_JUMP` in der nächsten Minor-Version). Ein Wechsel der Major-Version
/// braucht vorher ein Agent-Release, das diese Regel anpasst.
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

/// Höchste je angenommene Schlüssel-Epoche (fehlt die Datei: `MIN_KEY_EPOCH`)
#[allow(clippy::unnecessary_min_or_max)] // MIN_KEY_EPOCH ist derzeit 0, wird nach der Rotation angehoben
pub fn known_epoch(data_dir: &str) -> u32 {
    std::fs::read_to_string(format!("{data_dir}/{EPOCH_FILE}"))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0)
        .max(MIN_KEY_EPOCH)
}

/// Schlüssel-Epoche vermerken – nur nach oben, atomar (temporäre Datei + rename)
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

/// Laden mit Größenlimit (auch für das YARA-Regelpaket, `rules.rs`)
pub fn fetch_limited(url: &str, limit: u64) -> Result<Vec<u8>> {
    fetch(url, limit)
}

fn fetch(url: &str, limit: u64) -> Result<Vec<u8>> {
    if let Some(path) = url.strip_prefix("file://") {
        return Ok(std::fs::read(path).with_context(|| path.to_string())?);
    }
    // Integrität kommt aus der Signatur; Transport über HTTPS mit Web-PKI (oder lokal)
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

/// eingebaute Schlüssel mit ihren Epochen
pub fn release_keys() -> Vec<(&'static [u8; 32], u32)> {
    RELEASE_PUBKEYS.iter().copied().zip(RELEASE_KEY_EPOCHS).collect()
}

/// Manifest laden und prüfen. `Ok(None)`, wenn keine höhere Version vorliegt. Die Schlüssel-Epoche eines gültigen
/// Manifests wird in `data_dir` vermerkt (nur nach oben).
pub fn check(base: &str, data_dir: &str) -> Result<Option<Manifest>> {
    let base = base.trim_end_matches('/');
    let raw = fetch(&format!("{base}/manifest.json"), 1 << 20)?;
    let sig = fetch(&format!("{base}/manifest.json.sig"), 1024)?;
    let (m, epoch) = verify_manifest_any(&raw, &sig, &release_keys(), known_epoch(data_dir), AGENT_VERSION)?;
    if let Err(e) = store_epoch(data_dir, epoch) {
        eprintln!("Schlüssel-Epoche {epoch} nicht gespeichert: {e:#}");
    }
    Ok(m)
}

/// Wie `verify_manifest`, gültig mit einem der vertrauenswürdigen Schlüssel `(Schlüssel, Epoche)`; Schlüssel mit einer
/// Epoche unter `min_epoch` gelten als widerrufen. Liefert zusätzlich die Epoche des prüfenden Schlüssels.
pub fn verify_manifest_any(raw: &[u8], sig: &[u8], keys: &[(&[u8; 32], u32)], min_epoch: u32, current: &str) -> Result<(Option<Manifest>, u32)> {
    let valid = |k: &[u8; 32]| ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &k[..]).verify(raw, sig).is_ok();
    // höchste passende Epoche (falls ein Schlüssel mehrfach eingetragen wäre)
    let Some((key, epoch)) = keys.iter().filter(|(k, _)| valid(k)).max_by_key(|(_, e)| *e).copied() else {
        bail!("Signatur des Release-Manifests ungültig – Update abgelehnt");
    };
    if epoch < min_epoch {
        bail!("Release-Manifest mit widerrufenem Schlüssel (Epoche {epoch} < {min_epoch}) signiert – Update abgelehnt");
    }
    let m = verify_manifest(raw, sig, key, current)?;
    let declared: Manifest = serde_json::from_slice(raw).context("Manifest")?;
    if let Some(d) = declared.key_epoch {
        if d != epoch {
            bail!("Schlüssel-Epoche im Manifest ({d}) passt nicht zum Signierschlüssel ({epoch}) – Update abgelehnt");
        }
    }
    Ok((m, epoch))
}

/// Signatur, Produkt, Ablaufdatum und Version prüfen (schlüssel-parametrisch für Tests).
pub fn verify_manifest(raw: &[u8], sig: &[u8], pubkey: &[u8], current: &str) -> Result<Option<Manifest>> {
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pubkey)
        .verify(raw, sig)
        .map_err(|_| anyhow!("Signatur des Release-Manifests ungültig – Update abgelehnt"))?;
    let m: Manifest = serde_json::from_slice(raw).context("Manifest")?;
    if m.product != "tyrosecd-agent" {
        bail!("Manifest für falsches Produkt: {}", m.product);
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if m.expires == 0 || m.expires < now {
        bail!("Release-Manifest {} ist abgelaufen oder ohne Ablaufdatum – Update abgelehnt", m.version);
    }
    if !version_gt(&m.version, current) {
        return Ok(None);
    }
    if !version_jump_ok(&m.version, current) {
        bail!("Release-Manifest {} ist ein unzulässiger Versionssprung von {current} – Update abgelehnt", m.version);
    }
    Ok(Some(m))
}

/// Meldet das Programm unter `path` mit `--version` genau `tyrosecd <version>`? Ausgeführt ohne Umgebung, ohne
/// Eingabe und mit Zeitlimit (das Programm ist zu diesem Zeitpunkt bereits über die Prüfsumme im signierten Manifest
/// bestätigt – es ist genau das Programm, das gleich ohnehin als root läuft).
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
            bail!("neues Programm antwortet nicht auf --version – Update abgelehnt");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut out = String::new();
    child.stdout.take().map(|mut s| (&mut s).take(4096).read_to_string(&mut out));
    let got = out.trim();
    if got != format!("tyrosecd {version}") {
        bail!("neues Programm meldet „{}“ statt Version {version} – Update abgelehnt", got.chars().take(80).collect::<String>());
    }
    Ok(())
}

/// Neues Binary laden, prüfen und atomar an die Stelle des laufenden setzen.
/// Danach muss der Prozess neu starten (systemd: Exit-Code ≠ 0).
pub fn apply(base: &str, m: &Manifest, data_dir: &str) -> Result<()> {
    let base = base.trim_end_matches('/');
    let name = arch_file();
    let info = m.files.get(name).ok_or_else(|| anyhow!("Release enthält kein {name}"))?;
    let bin = fetch(&format!("{base}/{name}"), info.size + 1)?;
    if bin.len() as u64 != info.size || hex::encode(sha2::Sha256::digest(&bin)) != info.sha256 {
        bail!("Prüfsumme von {name} stimmt nicht – Update abgelehnt");
    }
    let exe = std::env::current_exe()?.canonicalize()?;
    let dir = exe.parent().ok_or_else(|| anyhow!("Programmverzeichnis"))?;
    let new = dir.join("tyrosecd.new");
    let prev = dir.join("tyrosecd.prev");
    std::fs::write(&new, &bin)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755))?;
    }
    // Programm muss selbst die Version des Manifests melden (kein altes Programm unter neuer Versionsnummer)
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
    std::fs::rename(&new, &exe)?; // atomar im selben Verzeichnis
    Ok(())
}

/// Rückfall für Systeme ohne systemd-Guard: Startet das neue Binary wiederholt nicht
/// stabil, wird die vorherige Version zurückgesetzt. Unter systemd übernimmt das
/// `ExecStartPre` der Unit (greift auch, wenn das neue Binary sofort abstürzt).
pub fn startup_check(data_dir: &str) -> Option<String> {
    let path = format!("{data_dir}/update.json");
    let mut mk: Marker = serde_json::from_slice(&std::fs::read(&path).ok()?).ok()?;
    mk.attempts += 1;
    if mk.attempts >= 2 {
        let exe = std::env::current_exe().ok()?.canonicalize().ok()?;
        let prev = exe.parent()?.join("tyrosecd.prev");
        let _ = std::fs::remove_file(&path);
        if prev.exists() && std::fs::rename(&prev, &exe).is_ok() {
            return Some(format!("Update {} → {} startet nicht stabil – zurück auf {}", mk.from, mk.to, mk.from));
        }
        return None;
    }
    let _ = std::fs::write(&path, serde_json::to_vec(&mk).unwrap_or_default());
    None
}

/// Version, deren Update zurückgerollt wurde (vom systemd-Wächter als update.failed
/// abgelegt). Diese Version wird nicht erneut installiert, sonst entstünde eine Schleife.
pub fn failed_version(data_dir: &str) -> Option<String> {
    let mk: Marker = serde_json::from_slice(&std::fs::read(format!("{data_dir}/update.failed")).ok()?).ok()?;
    Some(mk.to)
}

/// Nach stabiler Laufzeit aufrufen: Update bestätigt. Liefert (von, nach).
pub fn confirm(data_dir: &str) -> Option<(String, String)> {
    let path = format!("{data_dir}/update.json");
    let mk: Marker = serde_json::from_slice(&std::fs::read(&path).ok()?).ok()?;
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{data_dir}/update.attempts")); // Zähler des systemd-Guards
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
        assert!(err.contains("Signatur"), "{err}");
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
        // kaputte Datei → Untergrenze
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
        // altes Programm unter neuer Versionsnummer
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
        // Rotation: Manifest mit dem neuen Schlüssel signiert, Agent kennt alt + neu + Reserve
        let (old, new, foreign) = (keypair(), keypair(), keypair());
        let (ko, kn) = (pk(&old), pk(&new));
        let raw = manifest("0.0.2", now() + 3600);
        let sig = new.sign(&raw);
        let (m, e) = verify_manifest_any(&raw, sig.as_ref(), &[(&ko, 0), (&kn, 1)], 0, "0.0.1").unwrap();
        assert!(m.is_some());
        assert_eq!(e, 1);
        assert!(verify_manifest_any(&raw, sig.as_ref(), &[(&ko, 0)], 0, "0.0.1").is_err());
        assert!(verify_manifest_any(&raw, foreign.sign(&raw).as_ref(), &[(&ko, 0), (&kn, 1)], 0, "0.0.1").is_err());
        // eingebaute Schlüssel: drei verschiedene
        assert_ne!(RELEASE_PUBKEYS[0], RELEASE_PUBKEYS[1]);
        assert_ne!(RELEASE_PUBKEYS[1], RELEASE_PUBKEYS[2]);
    }

    #[test]
    fn lower_key_epoch_is_revoked() {
        let (old, new) = (keypair(), keypair());
        let (ko, kn) = (pk(&old), pk(&new));
        let keys = [(&ko, 0), (&kn, 1)];
        let raw = manifest("0.0.2", now() + 3600);
        // noch kein neuerer Schlüssel gesehen: alter gilt
        assert!(verify_manifest_any(&raw, old.sign(&raw).as_ref(), &keys, 0, "0.0.1").unwrap().0.is_some());
        // nachdem Epoche 1 angenommen wurde: alter Schlüssel widerrufen, neuer weiter gültig
        let e = verify_manifest_any(&raw, old.sign(&raw).as_ref(), &keys, 1, "0.0.1").unwrap_err();
        assert!(e.to_string().contains("widerrufen"), "{e}");
        assert!(verify_manifest_any(&raw, new.sign(&raw).as_ref(), &keys, 1, "0.0.1").is_ok());
        // auch „keine neuere Version“ mit altem Schlüssel wird abgelehnt (kein stilles Durchwinken)
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
        // mit dem alten Schlüssel signiert, gibt sich aber als Epoche 1 aus
        let e = verify_manifest_any(&good, old.sign(&good).as_ref(), &keys, 0, "0.0.1").unwrap_err();
        assert!(e.to_string().contains("passt nicht"), "{e}");
        // ohne Feld (Manifeste bis 0.4.9) weiterhin gültig
        let plain = manifest("0.0.2", now() + 3600);
        assert!(verify_manifest_any(&plain, old.sign(&plain).as_ref(), &keys, 0, "0.0.1").is_ok());
    }

    #[test]
    fn check_persists_epoch_and_then_rejects_old_key() {
        // Ende-zu-Ende über Dateien, mit Testschlüsseln statt der eingebauten
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
        // Agent ≤ 0.4.9 liest dieselbe Struktur ohne `key_epoch` – unbekannte Felder dürfen nicht stören
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
            assert!(e.to_string().contains("Versionssprung"), "{v}: {e}");
        }
    }

    #[test]
    fn expired_or_undated_manifest_is_rejected() {
        let kp = keypair();
        for raw in [manifest("0.0.2", now() - 1), manifest("0.0.2", 0)] {
            let e = verify_manifest(&raw, kp.sign(&raw).as_ref(), kp.public_key().as_ref(), "0.0.1").unwrap_err();
            assert!(e.to_string().contains("abgelaufen"), "{e}");
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
        // Manifest nach dem Signieren verändert
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
