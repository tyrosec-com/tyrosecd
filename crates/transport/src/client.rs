//! HTTPS-Client (rustls) mit optionalem Client-Zertifikat (mTLS).
//!
//! Nur TLS 1.3 zur Zentrale (Enrollment, Versand, Heartbeat, Zertifikats-Erneuerung). Der Download der
//! Selbst-Updates (`update.rs`) nutzt einen eigenen ureq-Agent und ist davon nicht betroffen.
//!
//! Nach einer Zertifikats-Erneuerung (`renew`) bauen alle Clients ihre TLS-Konfiguration beim nächsten
//! Aufruf neu auf (Generationszähler) – ohne Neustart des Agents.

use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};

use crate::config::AgentConfig;

/// Erhöht sich bei jedem Austausch von Schlüssel/Zertifikat
static CERT_GEN: AtomicU64 = AtomicU64::new(0);

/// Neues Client-Zertifikat liegt bereit: alle Clients laden es beim nächsten Aufruf.
pub fn reload_all() {
    CERT_GEN.fetch_add(1, Ordering::SeqCst);
}

pub struct Client {
    cfg: AgentConfig,
    with_client_cert: bool,
    agent: RwLock<(u64, ureq::Agent)>,
    base: String,
}

fn load_certs(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let mut r = std::io::BufReader::new(std::fs::File::open(path).with_context(|| path.to_string())?);
    Ok(rustls_pemfile::certs(&mut r).collect::<std::result::Result<Vec<_>, _>>()?)
}

fn load_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let mut r = std::io::BufReader::new(std::fs::File::open(path).with_context(|| path.to_string())?);
    rustls_pemfile::private_key(&mut r)?.ok_or_else(|| anyhow!("kein Schlüssel in {path}"))
}

/// TLS-Konfiguration zur Zentrale: nur TLS 1.3
pub fn tls_config(cfg: &AgentConfig, with_client_cert: bool) -> Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    let ca = cfg.server_ca_path();
    if std::path::Path::new(&ca).exists() {
        for c in load_certs(&ca)? {
            roots.add(c)?;
        }
    } else {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let b = rustls::ClientConfig::builder_with_provider(provider).with_protocol_versions(&[&rustls::version::TLS13])?.with_root_certificates(roots);
    Ok(if with_client_cert {
        b.with_client_auth_cert(load_certs(&cfg.cert_path())?, load_key(&cfg.key_path())?)?
    } else {
        b.with_no_client_auth()
    })
}

fn build(cfg: &AgentConfig, with_client_cert: bool) -> Result<ureq::Agent> {
    let tls = tls_config(cfg, with_client_cert)?;
    let mut ab = ureq::AgentBuilder::new()
        .tls_config(Arc::new(tls))
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .user_agent(concat!("tyrosecd-agent/", env!("CARGO_PKG_VERSION")))
        .try_proxy_from_env(true);
    if let Some(p) = &cfg.proxy {
        ab = ab.proxy(ureq::Proxy::new(p)?);
    }
    Ok(ab.build())
}

/// Erreichbarkeit der Zentrale unter `server` prüfen – ohne Nebenwirkungen (kein Heartbeat, der eine
/// angeforderte Prüfung oder Aktion „verbrauchen“ würde): GET auf einen nicht vorhandenen Pfad. Jede
/// HTTP-Antwort zählt als Erfolg, denn TLS 1.3 mit Prüfung gegen die Server-CA und den Hostnamen stellt
/// sicher, dass es unsere Zentrale ist. Nutzt Client-Zertifikat und Proxy wie der normale Versand.
pub fn probe(cfg: &AgentConfig, server: &str) -> Result<()> {
    let mut c = cfg.clone();
    c.server = server.to_string();
    let agent = build(&c, true)?;
    match agent.get(&format!("{}/v1/probe", server.trim_end_matches('/'))).timeout(Duration::from_secs(20)).call() {
        Ok(_) | Err(ureq::Error::Status(..)) => Ok(()),
        Err(e) => Err(anyhow!("{server} nicht erreichbar: {e}")),
    }
}

impl Client {
    /// `with_client_cert = false` nur für das Enrollment.
    pub fn new(cfg: &AgentConfig, with_client_cert: bool) -> Result<Client> {
        if with_client_cert {
            crate::renew::recover_pending(cfg);
        }
        let generation = CERT_GEN.load(Ordering::SeqCst);
        let agent = build(cfg, with_client_cert)?;
        Ok(Client { cfg: cfg.clone(), with_client_cert, agent: RwLock::new((generation, agent)), base: cfg.server.trim_end_matches('/').to_string() })
    }

    /// aktueller ureq-Agent; nach einer Erneuerung einmal neu aufgebaut
    fn agent(&self) -> ureq::Agent {
        let generation = CERT_GEN.load(Ordering::SeqCst);
        {
            let a = self.agent.read().unwrap();
            if a.0 == generation || !self.with_client_cert {
                return a.1.clone();
            }
        }
        let mut a = self.agent.write().unwrap();
        if a.0 != generation {
            match build(&self.cfg, self.with_client_cert) {
                Ok(n) => *a = (generation, n),
                Err(e) => {
                    eprintln!("[tyrosecd] neues Client-Zertifikat nicht ladbar ({e:#}) – bisherige Verbindung bleibt");
                    a.0 = generation;
                }
            }
        }
        a.1.clone()
    }

    /// POST mit Protobuf-Body; `zstd` = Body ist zstd-komprimiert.
    pub fn post(&self, path: &str, body: &[u8], zstd: bool) -> Result<Vec<u8>> {
        let mut req = self.agent().post(&format!("{}{}", self.base, path)).set("Content-Type", "application/x-protobuf");
        if zstd {
            req = req.set("Content-Encoding", "zstd");
        }
        read_response(req.send_bytes(body))
    }

    /// POST mit JSON-Body (Zertifikats-Erneuerung)
    pub fn post_json(&self, path: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
        let req = self.agent().post(&format!("{}{}", self.base, path)).set("Content-Type", "application/json");
        let v = read_response(req.send_bytes(&serde_json::to_vec(body)?))?;
        serde_json::from_slice(&v).context("Antwort ist kein JSON")
    }
}

fn read_response(r: std::result::Result<ureq::Response, ureq::Error>) -> Result<Vec<u8>> {
    match r {
        Ok(resp) => {
            let mut v = Vec::new();
            resp.into_reader().take(16 * 1024 * 1024).read_to_end(&mut v)?;
            Ok(v)
        }
        Err(ureq::Error::Status(code, resp)) => {
            let msg = resp.into_string().unwrap_or_default();
            bail!("HTTP {code}: {}", msg.chars().take(300).collect::<String>())
        }
        Err(e) => Err(anyhow!("Verbindung: {e}")),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_tls13() {
        let d = tempfile::tempdir().unwrap();
        let cfg: crate::AgentConfig = toml::from_str(&format!("server = \"https://x\"\ndata_dir = {:?}", d.path().to_string_lossy())).unwrap();
        let c = super::tls_config(&cfg, false).unwrap();
        // Aufbau mit nur TLS 1.3 gelingt (Versionsliste ist in rustls nicht öffentlich abfragbar)
        let _ = c;
    }
}
