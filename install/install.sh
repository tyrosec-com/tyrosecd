#!/bin/sh
# tyrosecd – Installation per Einzeiler (Hauptplan 12)
#
#   curl -fsSL https://get.tyrosec.com/install.sh | sudo TYROSD_TOKEN=ENR_xxx sh
#
# Erst ansehen, dann ausführen (empfohlen):
#   curl -fsSLo install.sh https://get.tyrosec.com/install.sh && less install.sh
#   umask 077; printf '%s\n' ENR_xxx > /root/tyrosec.token; sudo sh install.sh --token-file=/root/tyrosec.token
#
# Optionen:
#   --token-file=…   Datei mit dem Einmal-Token aus der Web-Oberfläche (oder Umgebung TYROSD_TOKEN)
#   --token=…        veraltet: Token als Argument (in der Prozessliste sichtbar) – funktioniert weiter, mit Warnung
#   --allow-downgrade ältere Version als die installierte zulassen
#   --server=…       Zentrale (Standard: https://ingest.tyrosec.com)
#   --server-ca=…    CA-Datei des Servers (nur Self-hosted/Test)
#   --base-url=…     Download-Quelle der Binaries (Standard: https://get.tyrosec.com/releases)
#   --version=…      Version (Standard: latest)
#   --no-start       nur installieren und anmelden, Dienst nicht starten
#   --skip-signature nur für Tests: Release-Signatur nicht prüfen (dann SHA256SUMS)
#   --uninstall      Agent entfernen (Daten bleiben; mit --purge auch Daten)
#
# Das Skript installiert ausschließlich: /usr/local/bin/tyrosecd, /etc/systemd/system/tyrosecd.service,
# /etc/tyrosecd/agent.toml, /var/lib/tyrosecd/. Keine Pakete, keine Abhängigkeiten.
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
            --token=*) TOKEN="${a#*=}"; warn "--token=… ist in der Prozessliste sichtbar – besser --token-file=… oder TYROSD_TOKEN" ;;
            --token-file=*) [ -r "${a#*=}" ] || die "Token-Datei nicht lesbar: ${a#*=}"; TOKEN="$(tr -d ' \r\n' < "${a#*=}")" ;;
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
            *) die "unbekannte Option: $a" ;;
        esac
    done

    [ "$(id -u)" = 0 ] || die "bitte als root ausführen (sudo)"
    if [ "$MODE" = uninstall ]; then uninstall; return; fi

    migrate_old
    fix_update_source
    [ -n "$TOKEN" ] || [ -f /etc/tyrosecd/agent.toml ] || die "Token fehlt: --token-file=… oder TYROSD_TOKEN (Token aus der Web-Oberfläche)"
    ARCH="$(detect_arch)"
    INIT="$(detect_init)"
    info "System: $(os_name), Kernel $(uname -r), Architektur $ARCH, Init $INIT"

    # Upgrade (Agent läuft schon): nicht nach /tmp laden – der laufende Agent meldete die neue Programmdatei dort als
    # „ausführbare Datei in temporärem Verzeichnis“ (Testlauf auf frischer VM). Das eigene Datenverzeichnis überwacht er nicht;
    # kein versteckter Ordnername (Programm aus verstecktem Ordner wäre ein eigener Fund).
    if [ -d /var/lib/tyrosecd ]; then
        TMP="$(mktemp -d /var/lib/tyrosecd/install-tmp.XXXXXX)"
    else
        TMP="$(mktemp -d)"
    fi
    trap 'rm -rf "$TMP"' EXIT
    info "lade tyrosecd ($VERSION, $ARCH) …"
    fetch "$BASE_URL/$VERSION/tyrosecd-$ARCH" "$TMP/tyrosecd"
    if [ "$SKIP_SIG" = 1 ]; then
        # nur für lokale Tests ohne signiertes Release
        warn "Signaturprüfung abgeschaltet (--skip-signature) – nur für Tests"
        fetch "$BASE_URL/$VERSION/SHA256SUMS" "$TMP/SHA256SUMS"
        verify "$TMP/tyrosecd" "tyrosecd-$ARCH" "$TMP/SHA256SUMS"
    else
        # Release-Manifest ist mit dem Release-Schlüssel (Ed25519) signiert; die Prüfsumme des
        # Programms kommt aus dem signierten Manifest – nicht aus einer Datei desselben Servers.
        fetch "$BASE_URL/$VERSION/manifest.json" "$TMP/manifest.json"
        fetch "$BASE_URL/$VERSION/manifest.json.sig" "$TMP/manifest.json.sig"
        verify_signature "$TMP/manifest.json" "$TMP/manifest.json.sig" "$BASE_URL/$VERSION/manifest.json.sig.p256"
        want="$(tr -d ' \n' < "$TMP/manifest.json" | sed -n "s/.*\"tyrosecd-$ARCH\":{[^}]*\"sha256\":\"\([0-9a-f]\{64\}\)\".*/\1/p")"
        [ -n "$want" ] || die "Manifest enthält kein Programm für $ARCH"
        printf '%s  tyrosecd-%s\n' "$want" "$ARCH" > "$TMP/SHA256SUMS"
        verify "$TMP/tyrosecd" "tyrosecd-$ARCH" "$TMP/SHA256SUMS"
        check_manifest "$TMP/manifest.json" "$TMP/tyrosecd"
    fi

    # Binary unter /opt/tyrosecd/bin (für Selbst-Updates beschreibbar), Symlink in /usr/local/bin
    install -d -m 0755 /opt/tyrosecd/bin /usr/local/bin
    install -m 0755 "$TMP/tyrosecd" /opt/tyrosecd/bin/tyrosecd.new
    mv -f /opt/tyrosecd/bin/tyrosecd.new /opt/tyrosecd/bin/tyrosecd    # atomar
    ln -sfn /opt/tyrosecd/bin/tyrosecd /usr/local/bin/tyrosecd
    install -d -m 0700 /etc/tyrosecd /var/lib/tyrosecd
    install -d -m 0750 /var/log/tyrosecd
    info "installiert: $(/usr/local/bin/tyrosecd --version)"

    if ! grep -q '^host_id = "[^"]' /etc/tyrosecd/agent.toml 2>/dev/null; then
        info "melde bei der Zentrale an ($SERVER) …"
        # Die Zentrale nutzt eine eigene CA für die Agent-Verbindung. Ohne --server-ca wird sie von
        # get.tyrosec.com geladen (abgesichert über HTTPS mit öffentlichem Zertifikat).
        if [ -z "$SERVER_CA" ] && [ -n "$SERVER_CA_URL" ]; then
            fetch "$SERVER_CA_URL" "$TMP/server-ca.crt"
            grep -q "BEGIN CERTIFICATE" "$TMP/server-ca.crt" || die "Server-CA ungültig: $SERVER_CA_URL"
            SERVER_CA="$TMP/server-ca.crt"
        fi
        set -- --server "$SERVER" --config /etc/tyrosecd/agent.toml
        [ -n "$SERVER_CA" ] && set -- "$@" --server-ca "$SERVER_CA"
        # Token über die Umgebung (nur für root lesbar: /proc/<pid>/environ), nicht als Argument (Prozessliste).
        # Ältere Agent-Versionen (vor 0.4.9) kennen nur --token.
        if /usr/local/bin/tyrosecd enroll --help 2>/dev/null | grep -q -- '--token-file'; then
            TYROSD_TOKEN="$TOKEN" /usr/local/bin/tyrosecd enroll "$@" </dev/null
        else
            warn "ältere Agent-Version: Token wird als Argument übergeben"
            /usr/local/bin/tyrosecd enroll "$@" --token "$TOKEN"
        fi
    else
        info "bereits angemeldet – Upgrade"
    fi

    case "$INIT" in
        systemd)
            write_unit
            # Schreibfreigabe für lokal freigeschaltete Aktionen (Drop-in actions.conf) passend zu agent.toml neu
            # schreiben – nur über das lokale Programm, nie von der Zentrale. Ältere Versionen kennen „refresh“ nicht.
            if /usr/local/bin/tyrosecd actions --help 2>/dev/null | grep -q refresh; then
                /usr/local/bin/tyrosecd actions --config /etc/tyrosecd/agent.toml refresh </dev/null >/dev/null 2>&1 \
                    || warn "Schreibfreigabe für Aktionen nicht erneuert: tyrosecd actions refresh"
            fi
            systemctl daemon-reload
            if [ "$START" = 1 ]; then
                systemctl enable tyrosecd >/dev/null 2>&1
                systemctl restart tyrosecd
                sleep 2
                systemctl is-active -q tyrosecd && info "Dienst läuft: systemctl status tyrosecd" || warn "Dienst nicht gestartet: journalctl -u tyrosecd"
            fi
            ;;
        *)
            warn "kein systemd erkannt ($INIT): bitte /usr/local/bin/tyrosecd run --config /etc/tyrosecd/agent.toml selbst als Dienst einrichten (OpenRC/SysV folgen)"
            ;;
    esac
    info "fertig. Erste Ergebnisse (Kompromittierungs-Check) erscheinen nach der Erst-Erfassung in der Web-Oberfläche."
}

info() { printf '[tyrosecd] %s\n' "$*"; }
warn() { printf '[tyrosecd] WARNUNG: %s\n' "$*" >&2; }
die()  { printf '[tyrosecd] FEHLER: %s\n' "$*" >&2; exit 1; }

os_name() { . /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-unbekannt}" || printf 'unbekannt'; }

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo x86_64 ;;
        aarch64|arm64) echo aarch64 ;;
        *) die "Architektur $(uname -m) wird noch nicht unterstützt (x86_64, aarch64)" ;;
    esac
}

detect_init() {
    if [ -d /run/systemd/system ]; then echo systemd
    elif command -v rc-service >/dev/null 2>&1; then echo openrc
    else echo unbekannt; fi
}

# Öffentliche Wurzel von Let's Encrypt (ISRG Root X1, SHA-256 96:BC:EC:06:26:49:76:F3:74:60:77:9A:CF:28:C5:A7:CF:E8:A3:C0:AA:E1:1A:8F:FC:EE:05:C0:BD:DF:08:C6,
# gültig bis 2035) – nur als Ersatz, wenn die Zertifikatsliste des Systems veraltet ist (z. B. openSUSE Leap 15.0 von 2019,
# Paketquellen abgeschaltet). Die Echtheit der Programmdateien sichert unabhängig davon die Signaturprüfung.
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

fetch() {   # fetch <url> <ziel>
    if command -v curl >/dev/null 2>&1; then
        rc=0; curl -fsSL --proto '=https,file' --retry 3 -o "$2" "$1" 2>/dev/null || rc=$?
        if [ "$rc" = 60 ] || [ "$rc" = 77 ]; then   # 60/77: Zertifikatskette bzw. CA-Liste
            ca=$(mktemp); printf '%s\n' "$ISRG_ROOT_X1" > "$ca"
            warn "Zertifikatsliste des Systems veraltet – nutze mitgelieferte Let's-Encrypt-Wurzel für $1"
            rc=0; curl -fsSL --proto '=https,file' --retry 3 --cacert "$ca" -o "$2" "$1" || rc=$?; rm -f "$ca"
        fi
        [ "$rc" = 0 ] || die "Download fehlgeschlagen: $1"
    elif command -v wget >/dev/null 2>&1; then
        if ! wget -q -O "$2" "$1"; then
            ca=$(mktemp); printf '%s\n' "$ISRG_ROOT_X1" > "$ca"
            wget -q --ca-certificate="$ca" -O "$2" "$1" || { rm -f "$ca"; die "Download fehlgeschlagen: $1"; }; rm -f "$ca"
        fi
    else
        die "curl oder wget nötig"
    fi
}

# Öffentliche Release-Schlüssel. Das Manifest ist doppelt signiert:
#  - Ed25519 (Fingerabdruck 694e09f0…852e, identisch mit dem im Agent für Selbst-Updates)
#  - ECDSA P-256 für ältere openssl-Versionen (1.1.x kann Ed25519 auf der Kommandozeile nicht prüfen)
# Vertrauenswürdige Release-Schlüssel (Rotation 16.11.2026): bisheriger, neuer (2026) und Reserve-Schlüssel.
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

verify_signature() {   # verify_signature <manifest> <ed25519-sig>  (P-256-Signatur: <sig>.p256 daneben)
    command -v openssl >/dev/null 2>&1 || die "openssl fehlt – zur Prüfung der Release-Signatur nötig (Paket openssl installieren)"
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
    [ -n "$ok" ] || die "Signatur des Release-Manifests ungültig – Installation abgebrochen"
    tr -d ' \n' < "$1" | grep -q '"product":"tyrosecd-agent"' || die "Manifest gehört nicht zu tyrosecd"
    info "Release-Signatur ok ($how)"
}

verify() {   # verify <datei> <name> <sums>
    want="$(grep " $2\$" "$3" | awk '{print $1}')"
    [ -n "$want" ] || die "keine Prüfsumme für $2"
    if command -v sha256sum >/dev/null 2>&1; then have="$(sha256sum "$1" | awk '{print $1}')"
    else have="$(shasum -a 256 "$1" | awk '{print $1}')"; fi
    [ "$want" = "$have" ] || die "Prüfsumme stimmt nicht für $2 (erwartet $want, erhalten $have)"
    info "Prüfsumme ok"
}

# a > b für Versionen der Form 1.2.3 (wie der Agent: fehlende/nicht-numerische Teile = 0)
version_gt() {
    awk -v a="$1" -v b="$2" 'BEGIN {
        na = split(a, x, /[.+-]/); nb = split(b, y, /[.+-]/)
        for (i = 1; i <= 3; i++) { p = (i <= na) ? x[i] + 0 : 0; q = (i <= nb) ? y[i] + 0 : 0
            if (p > q) exit 0; if (p < q) exit 1 }
        exit 1 }'
}

check_manifest() {   # check_manifest <manifest> <programm>  – Ablauf, Version, kein Downgrade
    m="$(tr -d ' \n\r\t' < "$1")"
    expires="$(printf '%s' "$m" | sed -n 's/.*"expires":\([0-9][0-9]*\).*/\1/p')"
    mver="$(printf '%s' "$m" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"
    now="$(date +%s)"
    [ -n "$expires" ] || die "Manifest ohne Ablaufdatum – Installation abgebrochen"
    [ "$expires" -gt "$now" ] || die "Release-Manifest $mver ist abgelaufen – Installation abgebrochen (veraltete oder zurückgehaltene Quelle?)"
    [ -n "$mver" ] || die "Manifest ohne Version"
    if [ "$VERSION" != latest ] && [ "${VERSION#v}" != "$mver" ]; then
        die "Manifest gehört zu Version $mver, angefordert war $VERSION – Installation abgebrochen"
    fi
    chmod 0755 "$2"
    bver="$("$2" --version 2>/dev/null | awk '{print $NF}')"
    [ "$bver" = "$mver" ] || die "Programm meldet Version ${bver:-?}, Manifest $mver – Installation abgebrochen"
    if [ -x /opt/tyrosecd/bin/tyrosecd ] && [ "$ALLOW_DOWNGRADE" != 1 ]; then
        cur="$(/opt/tyrosecd/bin/tyrosecd --version 2>/dev/null | awk '{print $NF}')"
        if [ -n "$cur" ] && version_gt "$cur" "$mver"; then
            die "installiert ist $cur, angeboten $mver – kein Downgrade (mit --allow-downgrade erzwingen)"
        fi
    fi
    info "Manifest ok (Version $mver, gültig bis $(date -d "@$expires" '+%d.%m.%Y' 2>/dev/null || echo "$expires"))"
}

write_unit() {
    # erst in eine Arbeitsdatei, dann nur bei abweichendem Inhalt übernehmen – sonst meldete der laufende Agent beim
    # erneuten Ausführen einen „Schreibzugriff ohne Änderung“ auf seine eigene Unit (Testlauf auf frischer VM)
    u="$TMP/tyrosecd.service"
    cat > "$u" <<'UNIT'
# tyrosecd Agent – harte Grenzen: selbst ein fehlerhafter Agent bremst den Server nicht aus.
[Unit]
Description=tyrosecd Agent (Datei-, Login- und Metrik-Überwachung)
After=network-online.target local-fs.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Type=simple
# Rollback-Wächter: nach einem Selbst-Update 2 Fehlstarts → beim 3. Start alte Version zurück
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
# /proc/sys/fs/inotify: Agent erhöht max_user_watches (inotify-Hosts); bleibt trotz ProtectKernelTunables beschreibbar
# /proc/sys/fs/fanotify (Kernel ≥ 5.13, „-“: fehlt sie, startet der Dienst trotzdem): größere Warteschlange gegen Überläufe
ReadWritePaths=/var/lib/tyrosecd /var/log/tyrosecd /etc/tyrosecd /opt/tyrosecd/bin /proc/sys/fs/inotify -/proc/sys/fs/fanotify
ProtectHome=read-only
# Kein PrivateTmp: der Agent muss das echte /tmp, /var/tmp und /dev/shm des Servers sehen (typische Malware-Ablage);
# mit PrivateTmp sähe er nur einen leeren eigenen Ordner. Ebenso kein PrivateDevices (/dev/shm).
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
# AF_PACKET (ab 0.5.5): DNS-Antworten mitlesen, damit Beaconing-Funde den Domainnamen des Ziels zeigen (Kernel-Filter:
# nur eingehende UDP-Pakete von Port 53; nur lesen, nichts senden)
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET
SystemCallArchitectures=native
# @system-service + was fanotify (Echtzeit) und das Auflösen der Datei-Handles brauchen; nicht erlaubte Aufrufe
# liefern EPERM statt den Dienst zu beenden (Kindprozesse wie nft, iptables, journalctl erben den Filter)
SystemCallFilter=@system-service fanotify_init fanotify_mark name_to_handle_at open_by_handle_at inotify_init1 inotify_add_watch inotify_rm_watch ioprio_set
SystemCallErrorNumber=EPERM
# Fähigkeiten:
#  CAP_SYS_ADMIN        fanotify mit Dateisystem-Markierung (FAN_MARK_FILESYSTEM, FAN_REPORT_DFID_NAME) – ohne sie nur inotify
#  CAP_DAC_READ_SEARCH  open_by_handle_at (fanotify-Handles → Pfad) und Lesen aller Dateien für Hashes
#  CAP_DAC_OVERRIDE     Wiederherstellen/Quarantäne in fremden Ordnern (nur wenn per „tyrosecd actions enable“ freigeschaltet;
#                       Schreibrechte für die Webroots sowie CAP_CHOWN/CAP_FOWNER kommen dann aus dem Drop-in
#                       tyrosecd.service.d/actions.conf, das nur „tyrosecd actions enable|disable|refresh“ lokal schreibt)
#  CAP_SYS_PTRACE       /proc/<pid>/exe, cwd, fd anderer Prozesse (Prozess-Zuordnung, Reverse-Shell-Erkennung)
#  CAP_SYS_RESOURCE     inotify-Grenze anheben
#  CAP_AUDIT_READ       Journal/Audit lesen (SSH-Anmeldungen)
#  CAP_NET_ADMIN        Proc-Connector (netlink, Prozessstarts) und – nur wenn block_ip freigeschaltet ist –
#                       Firewall-Sperren schreiben (nft/iptables); auch das Inventar liest Regeln darüber
#  CAP_NET_RAW          Paket-Socket für DNS-Antworten (Domainnamen bei Beaconing, nur lesen)
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_SYS_RESOURCE CAP_AUDIT_READ CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
UNIT
    # Die Systemaufruf-Gruppe @system-service gibt es erst ab systemd 239. Ältere Versionen (z. B. openSUSE Leap 15.0
    # mit 234) überspringen sie stillschweigend – übrig bliebe eine Liste weniger Aufrufe, mit der der Agent nicht
    # läuft. Dort ohne Systemaufruf-Filter; die übrigen Schutzeinstellungen bleiben (unbekannte ignoriert systemd).
    sdv=$(systemctl --version 2>/dev/null | awk 'NR==1{print $2}' | tr -cd '0-9')
    if [ -n "$sdv" ] && [ "$sdv" -lt 239 ]; then
        sed -i 's/^SystemCallFilter=/# (systemd '"$sdv"' < 239, Filter aus) SystemCallFilter=/; s/^SystemCallErrorNumber=/# SystemCallErrorNumber=/' "$u"
        warn "systemd $sdv ist älter als 239 – Systemaufruf-Filter des Dienstes abgeschaltet (übrige Härtung aktiv)"
    fi
    if cmp -s "$u" /etc/systemd/system/tyrosecd.service; then
        info "systemd-Unit unverändert"
    else
        cat "$u" > /etc/systemd/system/tyrosecd.service
        chmod 0644 /etc/systemd/system/tyrosecd.service
        info "systemd-Unit aktualisiert"
    fi
}

# Übernahme einer Installation unter dem alten Namen „tyrosd“ (vor 2026-11-15):
# Identität, Zertifikate und Zustand bleiben erhalten – keine Neuanmeldung nötig.
migrate_old() {
    [ -f /etc/tyrosd/agent.toml ] && [ ! -f /etc/tyrosecd/agent.toml ] || return 0
    info "übernehme bestehende Installation (tyrosd → tyrosecd)"
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
    info "entferne tyrosecd …"
    if [ -d /run/systemd/system ]; then
        systemctl disable --now tyrosecd >/dev/null 2>&1 || true   # sendet ein Stopp-Ereignis an die Zentrale
        rm -f /etc/systemd/system/tyrosecd.service /etc/systemd/system/tyrosecd.service.d/actions.conf
        rmdir /etc/systemd/system/tyrosecd.service.d 2>/dev/null || true
        systemctl daemon-reload || true
    fi
    rm -f /usr/local/bin/tyrosecd
    rm -rf /opt/tyrosecd
    if [ "$PURGE" = 1 ]; then rm -rf /etc/tyrosecd /var/lib/tyrosecd /var/log/tyrosecd; info "Daten entfernt"
    else info "Daten bleiben unter /etc/tyrosecd und /var/lib/tyrosecd (entfernen mit --uninstall --purge)"; fi
    info "fertig. Den Server bitte auch in der Web-Oberfläche entfernen."
}

# Frühe Installationen: Platzhalter als Update-Quelle → Selbst-Update scheitert („nicht erlaubt“)
fix_update_source() {
    [ -f /etc/tyrosecd/agent.toml ] || return 0
    grep -q 'get\.tyrosd\.example' /etc/tyrosecd/agent.toml || return 0
    sed -i 's#https://get\.tyrosd\.example/#https://get.tyrosec.com/#g' /etc/tyrosecd/agent.toml
    info "Update-Quelle auf https://get.tyrosec.com/ korrigiert"
}

main "$@"
