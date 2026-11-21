//! Erneuerung des Client-Zertifikats (Sicherheitsprüfung K4): Agent-Zertifikate laufen nach wenigen Wochen ab.
//! Täglich prüfen; ab weniger als `RENEW_BEFORE_DAYS` Tagen Restlaufzeit neues Schlüsselpaar + CSR (wie beim
//! Enrollment) über die **bestehende** mTLS-Verbindung an `POST /v1/renew` (`{"csr": "<PEM>"}` → `{"cert": "<PEM>"}`).
//! Das neue Zertifikat muss zum neuen Schlüssel passen und denselben CN (Host-ID) und Aussteller haben wie das alte.
//! Austausch atomar mit Wiederaufnahme nach Absturz (`recover_pending`).

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

use crate::client::Client;
use crate::config::AgentConfig;

/// Ab dieser Restlaufzeit wird erneuert
pub const RENEW_BEFORE_DAYS: i64 = 14;

/// Angaben aus einem Zertifikat
#[derive(Debug, Clone, PartialEq)]
pub struct CertInfo {
    pub cn: String,
    pub issuer: String,
    pub not_after: i64,
    /// öffentlicher Schlüssel (subjectPublicKey, roh)
    pub public_key: Vec<u8>,
}

pub fn cert_info(pem: &str) -> Result<CertInfo> {
    let mut r = std::io::BufReader::new(pem.as_bytes());
    let der = rustls_pemfile::certs(&mut r).next().context("kein Zertifikat im PEM")??;
    let (_, c) = x509_parser::parse_x509_certificate(der.as_ref()).map_err(|e| anyhow::anyhow!("Zertifikat nicht lesbar: {e}"))?;
    let cn = c.subject().iter_common_name().next().and_then(|n| n.as_str().ok()).unwrap_or("").to_string();
    Ok(CertInfo {
        cn,
        issuer: c.issuer().to_string(),
        not_after: c.validity().not_after.timestamp(),
        public_key: c.public_key().subject_public_key.data.to_vec(),
    })
}

fn now_s() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Resttage des aktuellen Client-Zertifikats
pub fn days_left(cfg: &AgentConfig) -> Result<i64> {
    let pem = std::fs::read_to_string(cfg.cert_path()).with_context(|| cfg.cert_path())?;
    Ok((cert_info(&pem)?.not_after - now_s()) / 86400)
}

fn pending_key(cfg: &AgentConfig) -> String {
    format!("{}/agent.key.renew", cfg.data_dir)
}
fn pending_crt(cfg: &AgentConfig) -> String {
    format!("{}/agent.crt.renew", cfg.data_dir)
}

fn write_file(path: &str, data: &[u8], mode: u32) -> Result<()> {
    let _ = std::fs::remove_file(path);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(mode).custom_flags(libc::O_NOFOLLOW).open(path).with_context(|| path.to_string())?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

/// Unterbrochenen Austausch abschließen: `agent.crt.renew` ist der Festschreibe-Punkt (erst danach wird umbenannt).
pub fn recover_pending(cfg: &AgentConfig) {
    let (pk, pc) = (pending_key(cfg), pending_crt(cfg));
    if std::path::Path::new(&pc).exists() {
        if std::path::Path::new(&pk).exists() {
            let _ = std::fs::rename(&pk, cfg.key_path());
        }
        let _ = std::fs::rename(&pc, cfg.cert_path());
        eprintln!("[tyrosecd] unterbrochene Zertifikats-Erneuerung abgeschlossen");
    } else {
        let _ = std::fs::remove_file(&pk);
    }
    let _ = std::fs::remove_file(format!("{pc}.tmp"));
}

/// Neues Zertifikat gegen alten Stand und neuen Schlüssel prüfen
pub fn check_new(old: &CertInfo, new: &CertInfo, new_public_key: &[u8]) -> Result<()> {
    if new.public_key != new_public_key {
        bail!("neues Zertifikat passt nicht zum neuen Schlüssel");
    }
    if new.cn.is_empty() || new.cn != old.cn {
        bail!("neues Zertifikat für anderen Host ({} statt {})", new.cn, old.cn);
    }
    if new.issuer != old.issuer {
        bail!("neues Zertifikat von anderem Aussteller ({})", new.issuer);
    }
    if new.not_after <= now_s() || new.not_after <= old.not_after {
        bail!("neues Zertifikat läuft nicht später ab als das bisherige");
    }
    Ok(())
}

/// Schlüssel + Zertifikat atomar ersetzen (Schlüssel 0600)
pub fn install(cfg: &AgentConfig, key_pem: &str, cert_pem: &str) -> Result<()> {
    let (pk, pc) = (pending_key(cfg), pending_crt(cfg));
    write_file(&pk, key_pem.as_bytes(), 0o600)?;
    let tmp = format!("{pc}.tmp");
    write_file(&tmp, cert_pem.as_bytes(), 0o644)?;
    std::fs::rename(&tmp, &pc)?; // Festschreibe-Punkt
    std::fs::rename(&pk, cfg.key_path())?;
    std::fs::rename(&pc, cfg.cert_path())?;
    if let Ok(d) = std::fs::File::open(&cfg.data_dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Zertifikat jetzt erneuern (über die bestehende mTLS-Verbindung `client`). Liefert das neue Ablaufdatum.
pub fn renew(cfg: &AgentConfig, client: &Client) -> Result<i64> {
    let old = cert_info(&std::fs::read_to_string(cfg.cert_path()).with_context(|| cfg.cert_path())?)?;
    // wie beim Enrollment: ECDSA P-256, Schlüssel verlässt den Server nie
    let key = rcgen::KeyPair::generate().context("Schlüssel erzeugen")?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name.push(rcgen::DnType::CommonName, "tyrosecd-agent");
    let csr = params.serialize_request(&key)?.pem()?;
    let resp = client.post_json("/v1/renew", &serde_json::json!({ "csr": csr })).context("Erneuerung")?;
    let cert_pem = resp.get("cert").and_then(|c| c.as_str()).context("Antwort ohne Zertifikat")?;
    let new = cert_info(cert_pem)?;
    check_new(&old, &new, key.public_key_raw())?;
    install(cfg, &key.serialize_pem(), cert_pem)?;
    crate::client::reload_all();
    Ok(new.not_after)
}

/// Täglich aufrufen: erneuert bei Bedarf. `Ok(None)` = noch nicht nötig.
pub fn maybe_renew(cfg: &AgentConfig, client: &Client) -> Result<Option<i64>> {
    if days_left(cfg)? >= RENEW_BEFORE_DAYS {
        return Ok(None);
    }
    renew(cfg, client).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ca() -> (rcgen::Certificate, rcgen::KeyPair) {
        let k = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name.push(rcgen::DnType::CommonName, "tyrosec agent CA");
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        (p.self_signed(&k).unwrap(), k)
    }

    fn issue(ca: &(rcgen::Certificate, rcgen::KeyPair), key: &rcgen::KeyPair, cn: &str, days: i64) -> String {
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name.push(rcgen::DnType::CommonName, cn);
        p.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        p.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(days);
        p.signed_by(key, &ca.0, &ca.1).unwrap().pem()
    }

    #[test]
    fn new_cert_must_match_key_host_and_issuer() {
        let ca1 = ca();
        let (k_old, k_new, k_other) = (rcgen::KeyPair::generate().unwrap(), rcgen::KeyPair::generate().unwrap(), rcgen::KeyPair::generate().unwrap());
        let old = cert_info(&issue(&ca1, &k_old, "host-1", 5)).unwrap();
        assert_eq!(old.cn, "host-1");
        assert!((old.not_after - now_s()) / 86400 < RENEW_BEFORE_DAYS);
        let good = cert_info(&issue(&ca1, &k_new, "host-1", 90)).unwrap();
        assert!(check_new(&old, &good, k_new.public_key_raw()).is_ok());
        // falscher Schlüssel
        assert!(check_new(&old, &cert_info(&issue(&ca1, &k_other, "host-1", 90)).unwrap(), k_new.public_key_raw()).is_err());
        // anderer Host
        assert!(check_new(&old, &cert_info(&issue(&ca1, &k_new, "host-2", 90)).unwrap(), k_new.public_key_raw()).is_err());
        // anderer Aussteller
        let ca2 = ca();
        let mut other_ca = cert_info(&issue(&ca2, &k_new, "host-1", 90)).unwrap();
        other_ca.issuer.push('x');
        assert!(check_new(&old, &other_ca, k_new.public_key_raw()).is_err());
        // nicht länger gültig
        assert!(check_new(&old, &cert_info(&issue(&ca1, &k_new, "host-1", 2)).unwrap(), k_new.public_key_raw()).is_err());
    }

    #[test]
    fn install_is_atomic_and_recoverable() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let cfg: AgentConfig = toml::from_str(&format!("server = \"https://x\"\ndata_dir = {:?}", d.path().to_string_lossy())).unwrap();
        std::fs::write(cfg.key_path(), "alt-key").unwrap();
        std::fs::write(cfg.cert_path(), "alt-crt").unwrap();
        install(&cfg, "neu-key", "neu-crt").unwrap();
        assert_eq!(std::fs::read_to_string(cfg.key_path()).unwrap(), "neu-key");
        assert_eq!(std::fs::read_to_string(cfg.cert_path()).unwrap(), "neu-crt");
        assert_eq!(std::fs::metadata(cfg.key_path()).unwrap().permissions().mode() & 0o777, 0o600);
        // Absturz nach dem Festschreiben, vor dem Umbenennen → beim Start abgeschlossen
        std::fs::write(pending_key(&cfg), "k3").unwrap();
        std::fs::write(pending_crt(&cfg), "c3").unwrap();
        recover_pending(&cfg);
        assert_eq!(std::fs::read_to_string(cfg.key_path()).unwrap(), "k3");
        assert_eq!(std::fs::read_to_string(cfg.cert_path()).unwrap(), "c3");
        // Absturz vor dem Festschreiben → alter Stand bleibt
        std::fs::write(pending_key(&cfg), "k4").unwrap();
        recover_pending(&cfg);
        assert_eq!(std::fs::read_to_string(cfg.key_path()).unwrap(), "k3");
        assert!(!std::path::Path::new(&pending_key(&cfg)).exists());
    }
}
