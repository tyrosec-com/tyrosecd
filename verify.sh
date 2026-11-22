#!/bin/sh
# Rebuild the official tyrosecd binary from this source and compare it (see VERIFY.md).
# Run in the root folder of this repository:  sh verify.sh 0.5.8 [x86_64|aarch64]
# Requires: docker, curl, sha256sum. Builds in the fixed environment from build/Dockerfile.
set -eu
VERSION="${1:?specify a version, e.g. sh verify.sh 0.5.8}"
ARCH="${2:-x86_64}"
case "$ARCH" in x86_64|aarch64) ;; *) echo "architecture: x86_64 or aarch64"; exit 2 ;; esac
TARGET="$ARCH-unknown-linux-musl"
BASE="https://get.tyrosec.com/releases/$VERSION"

echo ">> build environment (build/Dockerfile)"
docker build -q -t tyrosecd-build build >/dev/null

echo ">> building tyrosecd $VERSION for $ARCH"
# Mount the source under /src/agent – the same path as in the official build (does not end up in the binary)
docker run --rm -e TYROSD_VERSION="$VERSION" -v "$(pwd):/src/agent:ro" -w /src/agent \
  -v tyrosecd-verify-target:/target tyrosecd-build \
  sh -c "cargo zigbuild --locked --release -p tyrosd-cli --target $TARGET 2>&1 | tail -1 && sha256sum /target/$TARGET/release/tyrosecd" \
  | tee /dev/stderr | tail -1 | awk '{print $1}' > .verify-local.sha

echo ">> official checksum ($BASE/SHA256SUMS)"
curl -fsSL "$BASE/SHA256SUMS" | awk -v f="tyrosecd-$ARCH" '$2 == f || $2 == "*" f {print $1}' > .verify-official.sha

L=$(cat .verify-local.sha); O=$(cat .verify-official.sha); rm -f .verify-local.sha .verify-official.sha
echo "local:    $L"
echo "official: $O"
if [ -n "$O" ] && [ "$L" = "$O" ]; then
  echo ">> identical – the official binary $VERSION ($ARCH) is built from exactly this source code."
else
  echo ">> MISMATCH – please report to info@tyrosec.com (version, architecture, both checksums)."
  exit 1
fi
