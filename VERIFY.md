# Verify a release

Every official tyrosecd binary can be rebuilt **bit for bit** from this source code, so you can check that exactly the
code you are reading here runs on your server.

## Quick start

```sh
git clone https://github.com/tyrosec-com/tyrosecd && cd tyrosecd
git checkout v0.5.8          # the version running on your server: tyrosecd --version
sh verify.sh 0.5.8           # or: sh verify.sh 0.5.8 aarch64
```

`verify.sh` builds in the pinned environment from [`build/Dockerfile`](build/Dockerfile) (Rust, Zig and
cargo-zigbuild with fixed versions or checksums, dependencies from `Cargo.lock`) and compares the checksum with
`https://get.tyrosec.com/releases/<version>/SHA256SUMS`. A result of “identical” means the official binary is built
from exactly this source.

## How it works

- **Same tools:** base image pinned by digest, Zig verified by checksum, cargo-zigbuild with a fixed version.
- **Same dependencies:** `cargo … --locked` uses exactly the versions and checksums from `Cargo.lock`.
- **No traces of the build environment:** build paths are remapped during compilation (`.cargo/config.toml`); the
  binary contains no timestamps.
- **Signature:** the checksums of every version are also listed in the signed manifest (`manifest.json` with signature
  `manifest.json.sig`, Ed25519) in the same folder; the agent installs updates only with a valid signature from one of
  its built-in release keys (`crates/transport/src/update.rs`). `manifest.json.sig.p256` is an additional P-256
  signature used by the installer on systems with an older openssl.

## Check on the server

```sh
tyrosecd --version
sha256sum /opt/tyrosecd/bin/tyrosecd
```

The checksum must match the line `tyrosecd-x86_64` (or `-aarch64`) in the `SHA256SUMS` of that version.
