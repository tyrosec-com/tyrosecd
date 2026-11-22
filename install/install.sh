#!/bin/sh
# tyrosecd – one-line installation (main plan 12)
#
#   curl -fsSL https://get.tyrosec.com/install.sh | sudo TYROSD_TOKEN=ENR_xxx sh
#
# Review first, then run (recommended):
#   curl -fsSLo install.sh https://get.tyrosec.com/install.sh && less install.sh
#   umask 077; printf '%s\n' ENR_xxx > /root/tyrosec.token; sudo sh install.sh --token-file=/root/tyrosec.token
#
# Options:
#   --token-file=…   file containing the one-time token from the web interface (or environment TYROSD_TOKEN)
#   --token=…        deprecated: token as argument (visible in the process list) – still works, with a warning
#   --allow-downgrade allow a version older than the installed one
#   --server=…       central server (default: https://ingest.tyrosec.com)
#   --server-ca=…    CA file of the server (self-hosted/testing only)
#   --base-url=…     download source of the binaries (default: https://get.tyrosec.com/releases)
#   --version=…      version (default: latest)
#   --no-start       only install and enrol, do not start the service
#   --skip-signature testing only: do not verify the release signature (use SHA256SUMS instead)
#   --uninstall      remove the agent (data is kept; with --purge data is removed as well)
#
# The script installs only: /usr/local/bin/tyrosecd, /etc/systemd/system/tyrosecd.service,
# /etc/tyrosecd/agent.toml, /var/lib/tyrosecd/. No packages, no dependencies.
set -eu

main() {
    TOKEN="${TYROSD_TOKEN:-}"
    SERVER="https://ingest.tyrosec.com"
    SERVER_CA=""
    SERVER_CA_URL="https://get.tyrosec.com/server-ca.crt"
    BASE_URL="https://get.tyrosec.com/releases"
    VERSION="latest"
    START=1
    MODE=install
    PURGE=0
    SKIP_SIG=0
    ALLOW_DOWNGRADE=0
    for a in "$@"; do
        case "$a" in
            --token=*) TOKEN="${a#*=}"; warn "--token=… is visible in the process list – prefer --token-file=… or TYROSD_TOKEN" ;;
            --token-file=*) [ -r "${a#*=}" ] || die "token file not readable: ${a#*=}"; TOKEN="$(tr -d ' \r\n' < "${a#*=}")" ;;
            --allow-downgrade) ALLOW_DOWNGRADE=1 ;;
            --server=*) SERVER="${a#*=}" ;;
            --server-ca=*) SERVER_CA="${a#*=}" ;;
            --server-ca-url=*) SERVER_CA_URL="${a#*=}" ;;
            --base-url=*) BASE_URL="${a#*=}" ;;
            --version=*) VERSION="${a#*=}" ;;
            --no-start) START=0 ;;
            --skip-signature) SKIP_SIG=1 ;;
            --uninstall) MODE=uninstall ;;
            --purge) PURGE=1 ;;
            -h|--help) sed -n '2,20p' "$0" 2>/dev/null || true; exit 0 ;;
            *) die "unknown option: $a" ;;
        esac
    done

    [ "$(id -u)" = 0 ] || die "please run as root (sudo)"
    if [ "$MODE" = uninstall ]; then uninstall; return; fi

    migrate_old
    fix_update_source
    [ -n "$TOKEN" ] || [ -f /etc/tyrosecd/agent.toml ] || die "token missing: --token-file=… or TYROSD_TOKEN (token from the web interface)"
    ARCH="$(detect_arch)"
    INIT="$(detect_init)"
    info "system: $(os_name), kernel $(uname -r), architecture $ARCH, init $INIT"

    # Upgrade (agent already running): do not download to /tmp – the running agent reported the new binary there as
    # "executable in temporary directory" (test run on a fresh VM). It does not monitor its own data directory;
    # no hidden directory name (a program in a hidden directory would be a finding of its own).
    if [ -d /var/lib/tyrosecd ]; then
        TMP="$(mktemp -d /var/lib/tyrosecd/install-tmp.XXXXXX)"
    else
        TMP="$(mktemp -d)"
    fi
    trap 'rm -rf "$TMP"' EXIT
    info "downloading tyrosecd ($VERSION, $ARCH) …"
    fetch "$BASE_URL/$VERSION/tyrosecd-$ARCH" "$TMP/tyrosecd"
    if [ "$SKIP_SIG" = 1 ]; then
        # only for local tests without a signed release
        warn "signature verification disabled (--skip-signature) – testing only"
        fetch "$BASE_URL/$VERSION/SHA256SUMS" "$TMP/SHA256SUMS"
        verify "$TMP/tyrosecd" "tyrosecd-$ARCH" "$TMP/SHA256SUMS"
    else
        # The release manifest is signed with the release key (Ed25519); the checksum of the
        # binary comes from the signed manifest – not from a file on the same server.
        fetch "$BASE_URL/$VERSION/manifest.json" "$TMP/manifest.json"
        fetch "$BASE_URL/$VERSION/manifest.json.sig" "$TMP/manifest.json.sig"
        verify_signature "$TMP/manifest.json" "$TMP/manifest.json.sig" "$BASE_URL/$VERSION/manifest.json.sig.p256"
        want="$(tr -d ' \n' < "$TMP/manifest.json" | sed -n "s/.*\"tyrosecd-$ARCH\":{[^}]*\"sha256\":\"\([0-9a-f]\{64\}\)\".*/\1/p")"
        [ -n "$want" ] || die "manifest contains no binary for $ARCH"
        printf '%s  tyrosecd-%s\n' "$want" "$ARCH" > "$TMP/SHA256SUMS"
        verify "$TMP/tyrosecd" "tyrosecd-$ARCH" "$TMP/SHA256SUMS"
        check_manifest "$TMP/manifest.json" "$TMP/tyrosecd"
    fi

    # Binary in /opt/tyrosecd/bin (writable for self-updates), symlink in /usr/local/bin
    install -d -m 0755 /opt/tyrosecd/bin /usr/local/bin
    install -m 0755 "$TMP/tyrosecd" /opt/tyrosecd/bin/tyrosecd.new
    mv -f /opt/tyrosecd/bin/tyrosecd.new /opt/tyrosecd/bin/tyrosecd    # atomic
    ln -sfn /opt/tyrosecd/bin/tyrosecd /usr/local/bin/tyrosecd
    install -d -m 0700 /etc/tyrosecd /var/lib/tyrosecd
    install -d -m 0750 /var/log/tyrosecd
    info "installed: $(/usr/local/bin/tyrosecd --version)"

    if ! grep -q '^host_id = "[^"]' /etc/tyrosecd/agent.toml 2>/dev/null; then
        info "enrolling with the central server ($SERVER) …"
        # The central server uses its own CA for the agent connection. Without --server-ca it is downloaded from
        # get.tyrosec.com (protected by HTTPS with a public certificate).
        if [ -z "$SERVER_CA" ] && [ -n "$SERVER_CA_URL" ]; then
            fetch "$SERVER_CA_URL" "$TMP/server-ca.crt"
            grep -q "BEGIN CERTIFICATE" "$TMP/server-ca.crt" || die "server CA invalid: $SERVER_CA_URL"
            SERVER_CA="$TMP/server-ca.crt"
        fi
        set -- --server "$SERVER" --config /etc/tyrosecd/agent.toml
        [ -n "$SERVER_CA" ] && set -- "$@" --server-ca "$SERVER_CA"
        # Token via the environment (readable by root only: /proc/<pid>/environ), not as an argument (process list).
        # Older agent versions (before 0.4.9) only support --token.
        if /usr/local/bin/tyrosecd enroll --help 2>/dev/null | grep -q -- '--token-file'; then
            TYROSD_TOKEN="$TOKEN" /usr/local/bin/tyrosecd enroll "$@" </dev/null
        else
            warn "older agent version: passing the token as an argument"
            /usr/local/bin/tyrosecd enroll "$@" --token "$TOKEN"
        fi
    else
        info "already enrolled – upgrade"
    fi

    case "$INIT" in
        systemd)
            write_unit
            # Rewrite the write permissions for locally enabled actions (drop-in actions.conf) to match agent.toml –
            # only via the local program, never from the central server. Older versions lack "refresh".
            if /usr/local/bin/tyrosecd actions --help 2>/dev/null | grep -q refresh; then
                /usr/local/bin/tyrosecd actions --config /etc/tyrosecd/agent.toml refresh </dev/null >/dev/null 2>&1 \
                    || warn "write permissions for actions not refreshed: tyrosecd actions refresh"
            fi
            systemctl daemon-reload
            if [ "$START" = 1 ]; then
                systemctl enable tyrosecd >/dev/null 2>&1
                systemctl restart tyrosecd
                sleep 2
                systemctl is-active -q tyrosecd && info "service running: systemctl status tyrosecd" || warn "service not started: journalctl -u tyrosecd"
            fi
            ;;
        *)
            warn "no systemd detected ($INIT): please set up /usr/local/bin/tyrosecd run --config /etc/tyrosecd/agent.toml as a service yourself (OpenRC/SysV to follow)"
            ;;
    esac
    info "done. First results (compromise check) appear in the web interface after the initial scan."
}

info() { printf '[tyrosecd] %s\n' "$*"; }
warn() { printf '[tyrosecd] WARNING: %s\n' "$*" >&2; }
die()  { printf '[tyrosecd] ERROR: %s\n' "$*" >&2; exit 1; }

os_name() { . /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-unknown}" || printf 'unknown'; }

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo x86_64 ;;
        aarch64|arm64) echo aarch64 ;;
        *) die "architecture $(uname -m) is not supported yet (x86_64, aarch64)" ;;
    esac
}

detect_init() {
    if [ -d /run/systemd/system ]; then echo systemd
    elif command -v rc-service >/dev/null 2>&1; then echo openrc
    else echo unknown; fi
}

# Public Let's Encrypt root (ISRG Root X1, SHA-256 96:BC:EC:06:26:49:76:F3:74:60:77:9A:CF:28:C5:A7:CF:E8:A3:C0:AA:E1:1A:8F:FC:EE:05:C0:BD:DF:08:C6,
# valid until 2035) – only as a fallback if the system's certificate store is outdated (e.g. openSUSE Leap 15.0 from 2019,
# package repositories disabled). The authenticity of the binaries is ensured independently by the signature check.
ISRG_ROOT_X1='-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----'

fetch() {   # fetch <url> <target>
    if command -v curl >/dev/null 2>&1; then
        rc=0; curl -fsSL --proto '=https,file' --retry 3 -o "$2" "$1" 2>/dev/null || rc=$?
        if [ "$rc" = 60 ] || [ "$rc" = 77 ]; then   # 60/77: certificate chain or CA store
            ca=$(mktemp); printf '%s\n' "$ISRG_ROOT_X1" > "$ca"
            warn "system certificate store outdated – using bundled Let's Encrypt root for $1"
            rc=0; curl -fsSL --proto '=https,file' --retry 3 --cacert "$ca" -o "$2" "$1" || rc=$?; rm -f "$ca"
        fi
        [ "$rc" = 0 ] || die "download failed: $1"
    elif command -v wget >/dev/null 2>&1; then
        if ! wget -q -O "$2" "$1"; then
            ca=$(mktemp); printf '%s\n' "$ISRG_ROOT_X1" > "$ca"
            wget -q --ca-certificate="$ca" -O "$2" "$1" || { rm -f "$ca"; die "download failed: $1"; }; rm -f "$ca"
        fi
    else
        die "curl or wget required"
    fi
}

# Public release keys. The manifest is signed twice:
#  - Ed25519 (fingerprint 694e09f0…852e, identical to the one in the agent for self-updates)
#  - ECDSA P-256 for older openssl versions (1.1.x cannot verify Ed25519 on the command line)
# Trusted release keys (rotation 2026-11-16): previous, new (2026) and reserve key.
RELEASE_ED25519_ALT='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAaU4J8IrHVbdn6mgBy3YSLxXpwkdzyJA1tlWov81hhS4=
-----END PUBLIC KEY-----'
RELEASE_ED25519_2026='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAB/OJaBMewG9/9nyKI0NRexLhJsXTU1DkWIMpz7UvlYo=
-----END PUBLIC KEY-----'
RELEASE_ED25519_RESERVE='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA9U4locxNg92JjVtvQcpbLyqLfJ7aB0hSCYjDCbN/DcM=
-----END PUBLIC KEY-----'
RELEASE_P256_ALT='-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDvG4et7rf/DZDPGNGulsgySr9c8O
P+wY3MVRrStBb+98fMVkj2ZsqQHuwveHmbNFtIUK6FpnX4q08Eijead6tQ==
-----END PUBLIC KEY-----'
RELEASE_P256_2026='-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEevooJmFsZ79aDvj5QNW2Tuth+4cx
9Ke8MZIV3OKAkwZSMphsTdiIBX7y87UZlFQuITjJvmjtOmdrD99LiL4g3Q==
-----END PUBLIC KEY-----'
RELEASE_P256_RESERVE='-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcVuJjiqAdEZtAVdpPl1DtDAZ84nk
qQHTOJsjSZnQYibkmGdE5kcPYHwZOvL9a35dzcvAx5XTpF9acG6zjF3ISQ==
-----END PUBLIC KEY-----'

verify_signature() {   # verify_signature <manifest> <ed25519-sig>  (P-256 signature: <sig>.p256 alongside)
    command -v openssl >/dev/null 2>&1 || die "openssl missing – required to verify the release signature (install the openssl package)"
    ok=""
    if openssl pkeyutl -help 2>&1 | grep -q -- '-rawin'; then
        for k in "$RELEASE_ED25519_ALT" "$RELEASE_ED25519_2026" "$RELEASE_ED25519_RESERVE"; do
            printf '%s\n' "$k" > "$TMP/release.pem"
            if openssl pkeyutl -verify -pubin -inkey "$TMP/release.pem" -rawin -in "$1" -sigfile "$2" >/dev/null 2>&1; then ok=1; break; fi
        done
        how="Ed25519"
    else
        fetch "$3" "$TMP/manifest.json.sig.p256"
        for k in "$RELEASE_P256_ALT" "$RELEASE_P256_2026" "$RELEASE_P256_RESERVE"; do
            printf '%s\n' "$k" > "$TMP/release-p256.pem"
            if openssl dgst -sha256 -verify "$TMP/release-p256.pem" -signature "$TMP/manifest.json.sig.p256" "$1" >/dev/null 2>&1; then ok=1; break; fi
        done
        how="ECDSA P-256"
    fi
    [ -n "$ok" ] || die "release manifest signature invalid – installation aborted"
    tr -d ' \n' < "$1" | grep -q '"product":"tyrosecd-agent"' || die "manifest does not belong to tyrosecd"
    info "release signature ok ($how)"
}

verify() {   # verify <file> <name> <sums>
    want="$(grep " $2\$" "$3" | awk '{print $1}')"
    [ -n "$want" ] || die "no checksum for $2"
    if command -v sha256sum >/dev/null 2>&1; then have="$(sha256sum "$1" | awk '{print $1}')"
    else have="$(shasum -a 256 "$1" | awk '{print $1}')"; fi
    [ "$want" = "$have" ] || die "checksum mismatch for $2 (expected $want, got $have)"
    info "checksum ok"
}

# a > b for versions of the form 1.2.3 (like the agent: missing/non-numeric parts = 0)
version_gt() {
    awk -v a="$1" -v b="$2" 'BEGIN {
        na = split(a, x, /[.+-]/); nb = split(b, y, /[.+-]/)
        for (i = 1; i <= 3; i++) { p = (i <= na) ? x[i] + 0 : 0; q = (i <= nb) ? y[i] + 0 : 0
            if (p > q) exit 0; if (p < q) exit 1 }
        exit 1 }'
}

check_manifest() {   # check_manifest <manifest> <binary>  – expiry, version, no downgrade
    m="$(tr -d ' \n\r\t' < "$1")"
    expires="$(printf '%s' "$m" | sed -n 's/.*"expires":\([0-9][0-9]*\).*/\1/p')"
    mver="$(printf '%s' "$m" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"
    now="$(date +%s)"
    [ -n "$expires" ] || die "manifest has no expiry date – installation aborted"
    [ "$expires" -gt "$now" ] || die "release manifest $mver has expired – installation aborted (stale or withheld source?)"
    [ -n "$mver" ] || die "manifest has no version"
    if [ "$VERSION" != latest ] && [ "${VERSION#v}" != "$mver" ]; then
        die "manifest belongs to version $mver, but $VERSION was requested – installation aborted"
    fi
    chmod 0755 "$2"
    bver="$("$2" --version 2>/dev/null | awk '{print $NF}')"
    [ "$bver" = "$mver" ] || die "binary reports version ${bver:-?}, manifest $mver – installation aborted"
    if [ -x /opt/tyrosecd/bin/tyrosecd ] && [ "$ALLOW_DOWNGRADE" != 1 ]; then
        cur="$(/opt/tyrosecd/bin/tyrosecd --version 2>/dev/null | awk '{print $NF}')"
        if [ -n "$cur" ] && version_gt "$cur" "$mver"; then
            die "installed is $cur, offered $mver – no downgrade (force with --allow-downgrade)"
        fi
    fi
    info "manifest ok (version $mver, valid until $(date -d "@$expires" '+%d.%m.%Y' 2>/dev/null || echo "$expires"))"
}

write_unit() {
    # write to a work file first, then only take it over if the content differs – otherwise the running agent reported
    # a "write access without change" on its own unit when re-run (test run on a fresh VM)
    u="$TMP/tyrosecd.service"
    cat > "$u" <<'UNIT'
# tyrosecd agent – hard limits: even a faulty agent cannot slow the server down.
[Unit]
Description=tyrosecd agent (file, login and metric monitoring)
After=network-online.target local-fs.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Type=simple
# Rollback guard: after a self-update, 2 failed starts → on the 3rd start restore the old version
ExecStartPre=/bin/sh -c 'f=/var/lib/tyrosecd/update.json; c=/var/lib/tyrosecd/update.attempts; [ -f $$f ] || exit 0; n=$$(($$(cat $$c 2>/dev/null || echo 0)+1)); echo $$n > $$c; if [ $$n -gt 2 ] && [ -f /opt/tyrosecd/bin/tyrosecd.prev ]; then mv -f /opt/tyrosecd/bin/tyrosecd.prev /opt/tyrosecd/bin/tyrosecd; cp -f $$f /var/lib/tyrosecd/update.failed; rm -f $$f $$c; echo "tyrosecd: Update-Rollback"; fi'
ExecStart=/opt/tyrosecd/bin/tyrosecd run --config /etc/tyrosecd/agent.toml
Restart=on-failure
RestartSec=5
MemoryMax=256M
MemoryHigh=128M
CPUQuota=50%
CPUWeight=20
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
TasksMax=64
LimitNOFILE=65536
NoNewPrivileges=yes
ProtectSystem=strict
# /proc/sys/fs/inotify: agent raises max_user_watches (inotify hosts); stays writable despite ProtectKernelTunables
# /proc/sys/fs/fanotify (kernel ≥ 5.13, "-": if missing, the service still starts): larger queue against overflows
ReadWritePaths=/var/lib/tyrosecd /var/log/tyrosecd /etc/tyrosecd /opt/tyrosecd/bin /proc/sys/fs/inotify -/proc/sys/fs/fanotify
ProtectHome=read-only
# No PrivateTmp: the agent must see the server's real /tmp, /var/tmp and /dev/shm (typical malware drop locations);
# with PrivateTmp it would only see an empty private directory. Likewise no PrivateDevices (/dev/shm).
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
# AF_PACKET (since 0.5.5): read DNS responses so beaconing findings show the target's domain name (kernel filter:
# incoming UDP packets from port 53 only; read only, never send)
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET
SystemCallArchitectures=native
# @system-service + what fanotify (real-time) and resolving file handles need; disallowed calls
# return EPERM instead of killing the service (child processes such as nft, iptables, journalctl inherit the filter)
SystemCallFilter=@system-service fanotify_init fanotify_mark name_to_handle_at open_by_handle_at inotify_init1 inotify_add_watch inotify_rm_watch ioprio_set
SystemCallErrorNumber=EPERM
# Capabilities:
#  CAP_SYS_ADMIN        fanotify with filesystem marks (FAN_MARK_FILESYSTEM, FAN_REPORT_DFID_NAME) – without it inotify only
#  CAP_DAC_READ_SEARCH  open_by_handle_at (fanotify handles → path) and reading all files for hashes
#  CAP_DAC_OVERRIDE     restore/quarantine in other users' directories (only if enabled via "tyrosecd actions enable";
#                       write access to the webroots and CAP_CHOWN/CAP_FOWNER then come from the drop-in
#                       tyrosecd.service.d/actions.conf, written locally only by "tyrosecd actions enable|disable|refresh")
#  CAP_SYS_PTRACE       /proc/<pid>/exe, cwd, fd of other processes (process attribution, reverse shell detection)
#  CAP_SYS_RESOURCE     raise the inotify limit
#  CAP_AUDIT_READ       read journal/audit (SSH logins)
#  CAP_NET_ADMIN        proc connector (netlink, process starts) and – only if block_ip is enabled –
#                       write firewall blocks (nft/iptables); the inventory also reads rules through it
#  CAP_NET_RAW          packet socket for DNS responses (domain names for beaconing, read only)
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_SYS_RESOURCE CAP_AUDIT_READ CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
UNIT
    # The system call group @system-service exists only since systemd 239. Older versions (e.g. openSUSE Leap 15.0
    # with 234) silently skip it – leaving a list of only a few calls with which the agent cannot
    # run. There, no system call filter; the remaining hardening settings stay (systemd ignores unknown ones).
    sdv=$(systemctl --version 2>/dev/null | awk 'NR==1{print $2}' | tr -cd '0-9')
    if [ -n "$sdv" ] && [ "$sdv" -lt 239 ]; then
        sed -i 's/^SystemCallFilter=/# (systemd '"$sdv"' < 239, filter off) SystemCallFilter=/; s/^SystemCallErrorNumber=/# SystemCallErrorNumber=/' "$u"
        warn "systemd $sdv is older than 239 – system call filter of the service disabled (other hardening active)"
    fi
    if cmp -s "$u" /etc/systemd/system/tyrosecd.service; then
        info "systemd unit unchanged"
    else
        cat "$u" > /etc/systemd/system/tyrosecd.service
        chmod 0644 /etc/systemd/system/tyrosecd.service
        info "systemd unit updated"
    fi
}

# Take over an installation under the old name "tyrosd" (before 2026-11-15):
# identity, certificates and state are preserved – no re-enrolment needed.
migrate_old() {
    [ -f /etc/tyrosd/agent.toml ] && [ ! -f /etc/tyrosecd/agent.toml ] || return 0
    info "taking over existing installation (tyrosd → tyrosecd)"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop tyrosd 2>/dev/null || true
        systemctl disable tyrosd 2>/dev/null || true
        rm -f /etc/systemd/system/tyrosd.service; systemctl daemon-reload 2>/dev/null || true
    fi
    install -d -m 0700 /etc/tyrosecd /var/lib/tyrosecd
    [ -d /var/lib/tyrosd ] && cp -a /var/lib/tyrosd/. /var/lib/tyrosecd/
    sed -e 's#/var/lib/tyrosd#/var/lib/tyrosecd#g' -e 's#/etc/tyrosd#/etc/tyrosecd#g' /etc/tyrosd/agent.toml > /etc/tyrosecd/agent.toml
    chmod 0600 /etc/tyrosecd/agent.toml
    rm -rf /etc/tyrosd /var/lib/tyrosd /opt/tyrosd /var/log/tyrosd
    rm -f /usr/local/bin/tyrosd
}

uninstall() {
    info "removing tyrosecd …"
    if [ -d /run/systemd/system ]; then
        systemctl disable --now tyrosecd >/dev/null 2>&1 || true   # sends a stop event to the central server
        rm -f /etc/systemd/system/tyrosecd.service /etc/systemd/system/tyrosecd.service.d/actions.conf
        rmdir /etc/systemd/system/tyrosecd.service.d 2>/dev/null || true
        systemctl daemon-reload || true
    fi
    rm -f /usr/local/bin/tyrosecd
    rm -rf /opt/tyrosecd
    if [ "$PURGE" = 1 ]; then rm -rf /etc/tyrosecd /var/lib/tyrosecd /var/log/tyrosecd; info "data removed"
    else info "data kept in /etc/tyrosecd and /var/lib/tyrosecd (remove with --uninstall --purge)"; fi
    info "done. Please also remove the server in the web interface."
}

# Early installations: placeholder as update source → self-update fails ("not allowed")
fix_update_source() {
    [ -f /etc/tyrosecd/agent.toml ] || return 0
    grep -q 'get\.tyrosd\.example' /etc/tyrosecd/agent.toml || return 0
    sed -i 's#https://get\.tyrosd\.example/#https://get.tyrosec.com/#g' /etc/tyrosecd/agent.toml
    info "update source corrected to https://get.tyrosec.com/"
}

main "$@"
