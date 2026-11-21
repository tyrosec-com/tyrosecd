# Nachbauen und prüfen / Verify a release

Jede offizielle Programmdatei von tyrosecd lässt sich aus diesem Quellcode **bitgenau** nachbauen. So können Sie
prüfen, dass auf Ihrem Server genau der Code läuft, den Sie hier lesen.

## Schnell

```sh
git clone https://github.com/tyrosec-com/tyrosecd && cd tyrosecd
git checkout v0.5.7          # die Version, die auf Ihrem Server läuft: tyrosecd --version
sh verify.sh 0.5.7           # oder: sh verify.sh 0.5.7 aarch64
```

`verify.sh` baut in der festen Umgebung aus [`build/Dockerfile`](build/Dockerfile) (Rust, Zig und cargo-zigbuild mit
festen Versionen bzw. Prüfsummen, Abhängigkeiten aus `Cargo.lock`) und vergleicht die Prüfsumme mit
`https://get.tyrosec.com/releases/<Version>/SHA256SUMS`. Ergebnis „identisch“ = die offizielle Datei entsteht aus
genau diesem Stand.

## Was dahinter steckt

- **Gleiche Werkzeuge:** Basis-Abbild per Prüfsumme festgelegt, Zig per Prüfsumme geprüft, cargo-zigbuild mit fester
  Version.
- **Gleiche Abhängigkeiten:** `cargo … --locked` nutzt exakt die Versionen und Prüfsummen aus `Cargo.lock`.
- **Keine Umgebungsspuren:** Pfade der Build-Umgebung werden beim Übersetzen ersetzt (`.cargo/config.toml`), die
  Programmdatei enthält keine Zeitstempel.
- **Signatur:** Die Prüfsummen jeder Version stehen außerdem im signierten Manifest
  (`manifest.json`, Signaturen Ed25519 und P-256) im selben Ordner; der Agent installiert Updates nur mit gültigen
  Signaturen (`crates/transport/src/update.rs`).

## Auf dem Server nachsehen

```sh
tyrosecd --version
sha256sum /opt/tyrosecd/bin/tyrosecd
```

Die Prüfsumme muss mit der Zeile `tyrosecd-x86_64` (bzw. `-aarch64`) in `SHA256SUMS` der Version übereinstimmen.

---

**English:** every official tyrosecd binary can be rebuilt bit-for-bit from this source. Check out the tag matching
`tyrosecd --version` and run `sh verify.sh <version> [x86_64|aarch64]`; it builds in the pinned environment from
`build/Dockerfile` and compares the result with `https://get.tyrosec.com/releases/<version>/SHA256SUMS`. On the server,
`sha256sum /opt/tyrosecd/bin/tyrosecd` must match the same line.
