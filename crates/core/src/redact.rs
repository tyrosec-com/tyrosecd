//! Redaction: masks secret values before a diff is produced.
//! Works line by line on bytes (Latin-1 safe).
//!
//! Security review H6: default for all uploaded texts; assignments of the form `NAME=…`/`name: …` whose name
//! looks like a key/password/token (`APP_KEY`, `PrivateKey`, `client-key-data`, `PASSPHRASE` …) are masked up
//! to the end of the line – not just up to the first space.

use regex::bytes::Regex;
use std::sync::OnceLock;

pub const MASK: &[u8] = b"***REDACTED***";

/// Line is an assignment to a secret name → mask the value up to the end of the line.
/// Group 1 = everything up to and including the separator; the rest is replaced.
fn assignment() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r#"(?i)^(\s*(?:export\s+|set\s+|-\s+)?["']?[A-Za-z0-9_.\-]*(?:key|passphrase|password|passwd|pwd|bindpw|authtok|secret|token|psk|credentials?|auth)(?:[_.\-][A-Za-z0-9_.\-]*)?["']?\s*(?:=>|=|:)\s*)\S.*$"#,
        )
        .expect("Redaction-Regex")
    })
}

/// Configurations of the form "keyword whitespace value" (without `=`/`:`) – redis
/// (`requirepass`, `masterauth`), msmtp (`password`), keepalived (`auth_pass`), ldap.conf/nslcd (`bindpw`, `rootpwmodpw`),
/// sssd (`ldap_default_authtok`). Lowercase only (as they appear in the files) – prose like "Password …" is kept.
fn keyword_value() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"^(\s*(?:requirepass|masterauth|password|passwd|auth_pass|bindpw|rootbindpw|rootpwmodpw|ldap_default_authtok|tls_key_pass|sasl_password|smtp_pass|secret)[ \t]+)\S.*$"#)
            .expect("Redaction-Regex")
    })
}

/// redis ACL: `user name on >plaintext #sha256 …` → mask passwords (`>…`, `<…`) and hashes (`#…`, `!…`)
fn redis_user() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"(\s)([><#!])(\S+)"#).expect("Redaction-Regex"))
}

/// strongSwan/libreswan `ipsec.secrets`: `[ids] : PSK|RSA|ECDSA|EAP|XAUTH|… secret` → mask everything after the `:`
fn ipsec_secret() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"^([^#]*?(?:^|\s):\s*)(?:PSK|RSA|ECDSA|BLISS|EAP|XAUTH|NTLM|P12|PKCS8|PKCS12|PIN|PPK)\b.*$"#).expect("Redaction-Regex")
    })
}

/// OpenVPN inline blocks with keys/credentials (`<key>`, `<tls-auth>`, `<tls-crypt>`, `<tls-crypt-v2>`,
/// `<secret>`, `<pkcs12>`, `<auth-user-pass>`, `<http-proxy-user-pass>`): replace the content entirely
const OVPN_BLOCKS: &[&str] = &["key", "tls-auth", "tls-crypt", "tls-crypt-v2", "secret", "pkcs12", "auth-user-pass", "http-proxy-user-pass"];

fn ovpn_open(body: &[u8]) -> Option<&'static str> {
    let t = trim(body);
    OVPN_BLOCKS.iter().copied().find(|b| t.len() == b.len() + 2 && t[0] == b'<' && &t[1..t.len() - 1] == b.as_bytes() && t[t.len() - 1] == b'>')
}

fn trim(b: &[u8]) -> &[u8] {
    let s = b.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(b.len());
    let e = b.iter().rposition(|c| !c.is_ascii_whitespace()).map(|i| i + 1).unwrap_or(s);
    &b[s..e.max(s)]
}

fn rules() -> &'static [Regex] {
    static R: OnceLock<Vec<Regex>> = OnceLock::new();
    R.get_or_init(|| {
        [
            // PHP define('DB_PASSWORD', 'value');  WordPress salts likewise
            r#"(?i)(define\(\s*['"][A-Z_]*(PASSWORD|_KEY|_SALT|SECRET|TOKEN|PASSPHRASE)['"]\s*,\s*['"])([^'"]*)(['"])"#,
            // KEY=value, key: value, "key" => "value" (in the middle of a line, e.g. PHP arrays)
            r#"(?i)((?:password|passwd|pwd|passphrase|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth_?(?:token|key|pass)|[a-z0-9]*_key)[A-Za-z0-9_\-]*['"]?\s*(?:=>|=|:)\s*['"]?)([^'"\s,;]+)(['"]?)"#,
            // URLs with credentials: scheme://user:pass@host
            r#"([a-z][a-z0-9+.\-]*://[^:/\s]+:)([^@/\s]+)(@)"#,
        ]
        .iter()
        .map(|r| Regex::new(r).expect("Redaction-Regex"))
        .collect()
    })
}

/// Masks secrets. PEM private key blocks are replaced entirely.
pub fn redact(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut in_pem = false;
    let mut in_ovpn: Option<&'static str> = None;
    for line in data.split_inclusive(|b| *b == b'\n') {
        if let Some(tag) = in_ovpn {
            let t = trim(line);
            if t.len() == tag.len() + 3 && t.starts_with(b"</") && &t[2..t.len() - 1] == tag.as_bytes() && t.ends_with(b">") {
                in_ovpn = None;
                out.extend_from_slice(line);
            }
            continue;
        }
        if let Some(tag) = ovpn_open(line) {
            in_ovpn = Some(tag);
            out.extend_from_slice(line);
            out.extend_from_slice(MASK);
            out.push(b'\n');
            continue;
        }
        if contains(line, b"-----BEGIN") && contains(line, b"PRIVATE KEY") {
            // "-----BEGIN (RSA|EC|OPENSSH|ENCRYPTED|PGP) PRIVATE KEY( BLOCK)-----"; if the end is on the same line
            // (e.g. JSON with \n), replace only this line
            in_pem = !contains(line, b"-----END");
            out.extend_from_slice(b"-----BEGIN PRIVATE KEY (REDACTED)-----\n");
            continue;
        }
        if in_pem {
            if contains(line, b"-----END") {
                in_pem = false;
            }
            continue;
        }
        // Split off the line ending (regex works on the line without \r\n)
        let body_len = line.len() - line.iter().rev().take_while(|b| **b == b'\n' || **b == b'\r').count();
        let (body, eol) = line.split_at(body_len);
        let is_comment = body.iter().find(|b| !b.is_ascii_whitespace()).is_some_and(|b| *b == b'#' || *b == b';');
        if !is_comment {
            if let Some(c) = assignment().captures(body).or_else(|| keyword_value().captures(body)).or_else(|| ipsec_secret().captures(body)) {
                out.extend_from_slice(&c[1]);
                out.extend_from_slice(MASK);
                out.extend_from_slice(eol);
                continue;
            }
            if is_redis_acl(body) {
                // redis ACL (`user name on >pw`): mask passwords/hashes, permissions stay readable
                let l = redis_user().replace_all(body, |c: &regex::bytes::Captures| {
                    let mut v = c[1].to_vec();
                    v.extend_from_slice(&c[2]);
                    v.extend_from_slice(MASK);
                    v
                });
                out.extend_from_slice(&l);
                out.extend_from_slice(eol);
                continue;
            }
        }
        let mut l = body.to_vec();
        for (i, re) in rules().iter().enumerate() {
            l = re
                .replace_all(&l, |c: &regex::bytes::Captures| {
                    let mut v = Vec::new();
                    v.extend_from_slice(&c[1]);
                    v.extend_from_slice(MASK);
                    // last group = closing character
                    let last = if i == 0 { 4 } else { 3 };
                    if let Some(m) = c.get(last) {
                        v.extend_from_slice(m.as_bytes());
                    }
                    v
                })
                .into_owned();
        }
        out.extend_from_slice(&l);
        out.extend_from_slice(eol);
    }
    out
}

/// `user <name> on|off … >pw` (redis.conf / users.acl) – not every line starting with "user" (nginx: `user www-data;`)
fn is_redis_acl(body: &[u8]) -> bool {
    let mut t = body.split(|b| b.is_ascii_whitespace()).filter(|t| !t.is_empty());
    t.next() == Some(b"user".as_slice())
        && t.next().is_some()
        && t.any(|w| matches!(w, b"on" | b"off" | b"nopass" | b"resetpass" | b"reset") || w.starts_with(b"+") || w.starts_with(b"~"))
}

/// Masking with knowledge of the file name: formats whose secret is at a fixed position
/// without a recognizable name before it – `chap-secrets`/`pap-secrets` (3rd column), Postfix `sasl_passwd`
/// (`host user:password`), OpenVPN `auth-user-pass` files (user, password). Always followed by `redact`.
/// For container paths only the file name/folder is considered – the prefix does not interfere.
pub fn redact_path(path: &str, data: &[u8]) -> Vec<u8> {
    let name = path.rsplit('/').next().unwrap_or(path);
    let pre = if name == "chap-secrets" || name == "pap-secrets" || name == "srp-secrets" {
        Some(map_lines(data, |body| mask_from_field(body, 2)))
    } else if name.starts_with("sasl_passwd") && !name.ends_with(".db") && !name.ends_with(".lmdb") && !name.ends_with(".cdb") {
        Some(map_lines(data, mask_sasl))
    } else if is_ovpn_credentials(path, data) {
        let mut first = true;
        Some(map_lines(data, |body| {
            if trim(body).is_empty() || body.starts_with(b"#") {
                return None;
            }
            if std::mem::take(&mut first) {
                None
            } else {
                Some(MASK.to_vec())
            }
        }))
    } else {
        None
    };
    match pre {
        Some(p) => redact(&p),
        None => redact(data),
    }
}

/// File next to an OpenVPN configuration consisting only of user and password (`auth-user-pass file`):
/// folder `openvpn`, not a configuration (.conf/.ovpn), 2 non-empty lines without spaces
fn is_ovpn_credentials(path: &str, data: &[u8]) -> bool {
    if !path.split('/').any(|c| c == "openvpn") || path.ends_with(".conf") || path.ends_with(".ovpn") || data.len() > 4096 {
        return false;
    }
    let lines: Vec<&[u8]> = data.split(|b| *b == b'\n').map(trim).filter(|l| !l.is_empty() && !l.starts_with(b"#")).collect();
    lines.len() == 2 && lines.iter().all(|l| !l.iter().any(|b| *b == b' ' || *b == b'\t'))
}

/// Rewrite line by line (`f` returns a replacement for the line content without line ending, or None = unchanged)
fn map_lines(data: &[u8], mut f: impl FnMut(&[u8]) -> Option<Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for line in data.split_inclusive(|b| *b == b'\n') {
        let body_len = line.len() - line.iter().rev().take_while(|b| **b == b'\n' || **b == b'\r').count();
        let (body, eol) = line.split_at(body_len);
        match f(body) {
            Some(r) => out.extend_from_slice(&r),
            None => out.extend_from_slice(body),
        }
        out.extend_from_slice(eol);
    }
    out
}

/// Mask from column `n` (0-based, separated by whitespace; quotes keep a field together) to the end of the line;
/// comments and shorter lines are kept
fn mask_from_field(body: &[u8], n: usize) -> Option<Vec<u8>> {
    if trim(body).is_empty() || trim(body).starts_with(b"#") {
        return None;
    }
    let mut i = 0;
    let mut field = 0;
    while i < body.len() {
        while i < body.len() && body[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= body.len() {
            return None;
        }
        if field == n {
            let mut v = body[..i].to_vec();
            v.extend_from_slice(MASK);
            return Some(v);
        }
        if body[i] == b'"' {
            i += 1;
            while i < body.len() && body[i] != b'"' {
                i += 1;
            }
            i += 1;
        } else {
            while i < body.len() && !body[i].is_ascii_whitespace() {
                i += 1;
            }
        }
        field += 1;
    }
    None
}

/// Postfix `sasl_passwd`: `[smtp.example.com]:587 user:password` → password after the first `:` of the 2nd column
fn mask_sasl(body: &[u8]) -> Option<Vec<u8>> {
    let t = trim(body);
    if t.is_empty() || t.starts_with(b"#") {
        return None;
    }
    let start = body.iter().position(|b| !b.is_ascii_whitespace())?;
    let end_host = start + body[start..].iter().position(|b| b.is_ascii_whitespace())?;
    let cred = end_host + body[end_host..].iter().position(|b| !b.is_ascii_whitespace())?;
    let colon = cred + body[cred..].iter().position(|b| *b == b':')?;
    let mut v = body[..=colon].to_vec();
    v.extend_from_slice(MASK);
    Some(v)
}

fn contains(h: &[u8], n: &[u8]) -> bool {
    h.windows(n.len()).any(|w| w == n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(b: Vec<u8>) -> String {
        String::from_utf8_lossy(&b).into_owned()
    }

    #[test]
    fn wp_config() {
        let r = s(redact(b"define( 'DB_PASSWORD', 'geheim123' );\ndefine('DB_NAME', 'wp');\n"));
        assert!(r.contains("DB_PASSWORD', '***REDACTED***'"), "{r}");
        assert!(r.contains("'wp'"));
    }
    #[test]
    fn env() {
        let r = s(redact(b"APP_KEY=base64:abc\nDB_PASSWORD=xyz\nAPP_NAME=Shop\n"));
        assert!(!r.contains("xyz"), "{r}");
        assert!(r.contains("APP_NAME=Shop"));
    }
    #[test]
    fn app_key_is_masked() {
        let r = s(redact(b"APP_KEY=base64:Zm9vYmFyYmF6cXV4\nAPP_ENV=production\nSTRIPE_SECRET_KEY = sk_live abc def\nexport AWS_SECRET_ACCESS_KEY=AKIA/xyz\n"));
        assert!(!r.contains("Zm9vYmFy"), "{r}");
        assert!(!r.contains("sk_live") && !r.contains("abc def"), "{r}");
        assert!(!r.contains("AKIA"), "{r}");
        assert!(r.contains("APP_KEY=***REDACTED***\n"), "{r}");
        assert!(r.contains("APP_ENV=production"));
    }
    #[test]
    fn wireguard_private_key_is_masked() {
        let r = s(redact(b"[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.0.0.1/24\n[Peer]\nPresharedKey = FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=\nPublicKey = abc\n"));
        assert!(!r.contains("yAnz5TF"), "{r}");
        assert!(!r.contains("FpCyhws9"), "{r}");
        assert!(r.contains("Address = 10.0.0.1/24"));
    }
    #[test]
    fn kube_client_key_is_masked() {
        let r = s(redact(b"users:\n- name: admin\n  user:\n    client-certificate-data: LS0tQ0VSVA==\n    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ==\n    token: eyJhbGciOi.payload.sig\n"));
        assert!(!r.contains("LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ"), "{r}");
        assert!(!r.contains("eyJhbGciOi"), "{r}");
        assert!(r.contains("- name: admin"));
    }
    #[test]
    fn passphrase_to_end_of_line() {
        let r = s(redact(b"SSL_PASSPHRASE=correct horse battery staple\nwpa_passphrase=my hidden wlan\n"));
        assert!(!r.contains("horse") && !r.contains("hidden"), "{r}");
    }
    #[test]
    fn url_creds() {
        let r = s(redact(b"DATABASE_URL=mysql://user:pass@db/x\n"));
        assert!(!r.contains(":pass@"), "{r}");
        let r = s(redact(b"$dsn = 'pgsql://app:s3cr3t@localhost/db';\n"));
        assert!(!r.contains("s3cr3t"), "{r}");
    }
    #[test]
    fn pem() {
        let r = s(redact(b"a\n-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\nb\n"));
        assert!(!r.contains("MIIabc"));
        assert!(r.starts_with("a\n") && r.ends_with("b\n"));
        let r = s(redact(b"x\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA\n-----END OPENSSH PRIVATE KEY-----\n-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBF\n-----END PGP PRIVATE KEY BLOCK-----\ny\n"));
        assert!(!r.contains("b3BlbnNzaA") && !r.contains("lQOYBF"), "{r}");
        assert!(r.ends_with("y\n"));
        // Key on a single line (JSON): only that line, not the rest of the file
        let r = s(redact(b"{\"private_key\": \"-----BEGIN PRIVATE KEY-----\\nMIIE\\n-----END PRIVATE KEY-----\\n\",\n\"ok\": 1}\n"));
        assert!(!r.contains("MIIE") && r.contains("\"ok\": 1"), "{r}");
    }
    #[test]
    fn redis() {
        let r = s(redact_path("/etc/redis/redis.conf", b"bind 127.0.0.1\nrequirepass Sup3rGeheim\n  masterauth  Repl1ka pw\n# requirepass foobared\nport 6379\n"));
        assert!(!r.contains("Sup3rGeheim") && !r.contains("Repl1ka"), "{r}");
        assert!(r.contains("requirepass ***REDACTED***\n") && r.contains("port 6379") && r.contains("bind 127.0.0.1"), "{r}");
        let r = s(redact(b"user alice on >AlicePw #5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 ~cache:* +get\nuser default off nopass\n"));
        assert!(!r.contains("AlicePw") && !r.contains("5e884898"), "{r}");
        assert!(r.contains("~cache:* +get") && r.contains("user default off nopass"), "{r}");
        // nginx "user" is kept
        assert_eq!(s(redact(b"user www-data;\n")), "user www-data;\n");
    }
    #[test]
    fn msmtp_and_keepalived() {
        let r = s(redact_path("/etc/msmtprc", b"account default\nhost smtp.example.com\nuser info@example.com\npassword M41lPw!\npasswordeval \"pass show mail\"\n"));
        assert!(!r.contains("M41lPw"), "{r}");
        assert!(r.contains("host smtp.example.com") && r.contains("passwordeval"), "{r}");
        let r = s(redact(b"vrrp_instance VI_1 {\n    authentication {\n        auth_type PASS\n        auth_pass k33p4l1v\n    }\n}\n"));
        assert!(!r.contains("k33p4l1v") && r.contains("auth_type PASS"), "{r}");
    }
    #[test]
    fn ipsec_secrets() {
        let r = s(redact_path("/etc/ipsec.secrets", b"# ipsec.secrets\n: PSK \"v3ryS3cret\"\nmoon.strongswan.org : RSA moonKey.pem \"KeyPass\"\n2001:db8::1 192.0.2.1 : PSK 0sFpZAZqEN6Ti9sqt4ZP5EWcqx\ncarol : EAP \"Ar3etTnp\"\ninclude /var/lib/strongswan/ipsec.secrets.inc\n"));
        for x in ["v3ryS3cret", "KeyPass", "moonKey.pem", "0sFpZAZqEN6", "Ar3etTnp"] {
            assert!(!r.contains(x), "{x}: {r}");
        }
        assert!(r.contains("moon.strongswan.org : ***REDACTED***") && r.contains("2001:db8::1 192.0.2.1 : ***REDACTED***"), "{r}");
        assert!(r.contains("include /var/lib/strongswan/ipsec.secrets.inc"), "{r}");
        // swanctl.conf: secret = …
        assert!(!s(redact(b"secrets {\n  ike-1 {\n    secret = \"0sv+NkxY9LLZvwj4qCC2o/gGrWDF2d21jL\"\n  }\n}\n")).contains("0sv+Nkx"));
    }
    #[test]
    fn ppp_secrets() {
        let data = b"# Secrets for authentication using CHAP\n# client\tserver\tsecret\t\t\tIP addresses\n\"alice\" * \"pa ss w0rd\" *\nbob\tpptpd\tB0bS3cret\t10.0.0.2\n";
        for p in ["/etc/ppp/chap-secrets", "/etc/ppp/pap-secrets", "/var/lib/machines/vpn/etc/ppp/chap-secrets"] {
            let r = s(redact_path(p, data));
            assert!(!r.contains("pa ss w0rd") && !r.contains("B0bS3cret"), "{p}: {r}");
            assert!(r.contains("\"alice\" * ***REDACTED***\n") && r.contains("bob\tpptpd\t***REDACTED***\n"), "{r}");
            assert!(r.contains("# client\tserver\tsecret"), "{r}");
        }
    }
    #[test]
    fn postfix_sasl_passwd() {
        let r = s(redact_path("/etc/postfix/sasl_passwd", b"[smtp.example.com]:587 relay@example.com:Rel4yPw:x\n# kommentar a:b\n"));
        assert!(!r.contains("Rel4yPw"), "{r}");
        assert!(r.contains("[smtp.example.com]:587 relay@example.com:***REDACTED***\n") && r.contains("# kommentar a:b"), "{r}");
    }
    #[test]
    fn ldap_and_sssd() {
        let r = s(redact_path("/etc/ldap/ldap.conf", b"BASE dc=example,dc=com\nbinddn cn=admin,dc=example,dc=com\nbindpw LdapB1nd\n"));
        assert!(!r.contains("LdapB1nd") && r.contains("binddn cn=admin"), "{r}");
        let r = s(redact_path("/etc/nslcd.conf", b"bindpw   N5lcdPw\nrootpwmodpw R00tMod\n"));
        assert!(!r.contains("N5lcdPw") && !r.contains("R00tMod"), "{r}");
        let r = s(redact_path("/etc/sssd/sssd.conf", b"[domain/x]\nldap_default_bind_dn = cn=svc\nldap_default_authtok = Sss4uth\nldap_default_authtok_type = password\n"));
        assert!(!r.contains("Sss4uth") && r.contains("ldap_default_bind_dn = cn=svc"), "{r}");
    }
    #[test]
    fn openvpn() {
        let conf = b"client\nremote vpn.example.com 1194\n<ca>\n-----BEGIN CERTIFICATE-----\nMIIca\n-----END CERTIFICATE-----\n</ca>\n<key>\nMIIkeydata\n</key>\n<tls-auth>\n-----BEGIN OpenVPN Static key V1-----\n6acef03f62675b4b1bbd03e53b187727\n-----END OpenVPN Static key V1-----\n</tls-auth>\n<tls-crypt>\nc0ffee\n</tls-crypt>\n<auth-user-pass>\nvpnuser\nVpnPassw0rd\n</auth-user-pass>\nverb 3\n";
        let r = s(redact_path("/etc/openvpn/client/office.conf", conf));
        for x in ["MIIkeydata", "6acef03f6267", "c0ffee", "VpnPassw0rd", "vpnuser"] {
            assert!(!r.contains(x), "{x}: {r}");
        }
        assert!(r.contains("MIIca") && r.contains("verb 3") && r.contains("</tls-auth>\n<tls-crypt>"), "{r}");
        // auth-user-pass file: user is kept, password masked
        let r = s(redact_path("/etc/openvpn/client/office.auth", b"vpnuser\nVpnPassw0rd\n"));
        assert_eq!(r, "vpnuser\n***REDACTED***\n");
        let r = s(redact_path("/etc/openvpn/creds.txt", b"vpnuser\r\nVpnPassw0rd\r\n"));
        assert!(!r.contains("VpnPassw0rd"), "{r}");
        // outside of openvpn/ a two-line file stays unchanged
        assert_eq!(s(redact_path("/var/www/a/b.txt", b"hello\nworld\n")), "hello\nworld\n");
    }
    #[test]
    fn code_stays_readable() {
        // normal code without secrets stays unchanged (webroot diffs)
        let code = b"<?php\n$title = 'Shop';\necho htmlspecialchars($title);\n# key: just a comment\n";
        assert_eq!(redact(code), code.to_vec());
    }
}
