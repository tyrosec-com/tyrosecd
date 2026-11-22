//! Enrollment: generate the key locally, send CSR + host info with a one-time token to
//! the central server, store the client certificate. The private key never leaves
//! the server.

use anyhow::{Context, Result};
use prost::Message;
use tyrosd_proto as pb;

use crate::client::Client;
use crate::config::{set_mode, AgentConfig};

pub fn host_info(backend: &str) -> pb::HostInfo {
    let rd = |p: &str| std::fs::read_to_string(p).map(|s| s.trim().to_string()).unwrap_or_default();
    let os = rd("/etc/os-release")
        .lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME=").map(|v| v.trim_matches('"').to_string()))
        .unwrap_or_default();
    pb::HostInfo {
        hostname: rd("/proc/sys/kernel/hostname"),
        os,
        kernel: rd("/proc/sys/kernel/osrelease"),
        arch: std::env::consts::ARCH.into(),
        agent_version: crate::update::AGENT_VERSION.into(),
        backend: backend.into(),
    }
}

/// `server_ca_pem`: optional (self-hosted/test), otherwise Web PKI.
pub fn enroll(cfg: &mut AgentConfig, token: &str, server_ca_pem: Option<String>, config_path: &str) -> Result<()> {
    std::fs::create_dir_all(&cfg.data_dir)?;
    set_mode(&cfg.data_dir, 0o700);
    if let Some(ca) = server_ca_pem {
        std::fs::write(cfg.server_ca_path(), ca)?;
    }
    // key generated locally (ECDSA P-256)
    let key = rcgen::KeyPair::generate().context("generate key")?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name.push(rcgen::DnType::CommonName, "tyrosecd-agent");
    let csr = params.serialize_request(&key)?.pem()?;

    let req = pb::EnrollRequest { token: token.into(), csr_pem: csr, host: Some(host_info("")), protocol: tyrosd_proto::PROTOCOL_VERSION };
    let client = Client::new(cfg, false)?;
    let resp = client.post("/v1/enroll", &req.encode_to_vec(), false).context("enrolment")?;
    let resp = pb::EnrollResponse::decode(resp.as_slice())?;

    let kp = cfg.key_path();
    std::fs::write(&kp, key.serialize_pem())?;
    set_mode(&kp, 0o600);
    std::fs::write(cfg.cert_path(), &resp.cert_pem)?;
    if !resp.server_ca_pem.is_empty() && !std::path::Path::new(&cfg.server_ca_path()).exists() {
        std::fs::write(cfg.server_ca_path(), &resp.server_ca_pem)?;
    }
    cfg.host_id = resp.host_id;
    cfg.save(config_path)?;
    eprintln!("[tyrosecd] enrolled: Host {} (tenant {})", cfg.host_id, resp.tenant);
    Ok(())
}
