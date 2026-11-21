#!/bin/sh
# Offizielle tyrosecd-Programmdatei aus diesem Quellcode nachbauen und vergleichen (siehe VERIFY.md).
# Aufruf im Wurzelordner dieses Repositorys:  sh verify.sh 0.5.7 [x86_64|aarch64]
# Braucht: docker, curl, sha256sum. Baut in der festen Umgebung aus build/Dockerfile.
set -eu
VERSION="${1:?Version angeben, z. B. sh verify.sh 0.5.7}"
ARCH="${2:-x86_64}"
case "$ARCH" in x86_64|aarch64) ;; *) echo "Architektur: x86_64 oder aarch64"; exit 2 ;; esac
TARGET="$ARCH-unknown-linux-musl"
BASE="https://get.tyrosec.com/releases/$VERSION"

echo ">> Build-Umgebung (build/Dockerfile)"
docker build -q -t tyrosecd-build build >/dev/null

echo ">> baue tyrosecd $VERSION für $ARCH"
# Quellcode unter /src/agent einbinden – derselbe Pfad wie beim offiziellen Build (geht nicht in die Datei ein)
docker run --rm -e TYROSD_VERSION="$VERSION" -v "$(pwd):/src/agent:ro" -w /src/agent \
  -v tyrosecd-verify-target:/target tyrosecd-build \
  sh -c "cargo zigbuild --locked --release -p tyrosd-cli --target $TARGET 2>&1 | tail -1 && sha256sum /target/$TARGET/release/tyrosecd" \
  | tee /dev/stderr | tail -1 | awk '{print $1}' > .verify-local.sha

echo ">> offizielle Prüfsumme ($BASE/SHA256SUMS)"
curl -fsSL "$BASE/SHA256SUMS" | awk -v f="tyrosecd-$ARCH" '$2 == f || $2 == "*" f {print $1}' > .verify-official.sha

L=$(cat .verify-local.sha); O=$(cat .verify-official.sha); rm -f .verify-local.sha .verify-official.sha
echo "lokal:     $L"
echo "offiziell: $O"
if [ -n "$O" ] && [ "$L" = "$O" ]; then
  echo ">> identisch – die offizielle Programmdatei $VERSION ($ARCH) entsteht aus genau diesem Quellcode."
else
  echo ">> ABWEICHUNG – bitte an info@tyrosec.com melden (Version, Architektur, beide Prüfsummen)."
  exit 1
fi
