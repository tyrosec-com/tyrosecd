# Feste Build-Umgebung für tyrosecd – damit jeder die veröffentlichten Programmdateien aus diesem Quellcode
# nachbauen und vergleichen kann (siehe VERIFY.md). Alle Werkzeuge mit fester Version bzw. Prüfsumme.
#
# Bauen:  docker build -t tyrosecd-build agent/build
FROM rust:1.100.0-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea

RUN apt-get update \
 && apt-get install -y --no-install-recommends musl-tools xz-utils curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Zig (Linker für die statischen musl-Programmdateien), Prüfsumme laut ziglang.org/download/index.json
ARG ZIG_VERSION=0.13.0
ARG ZIG_SHA256=d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea
RUN curl -fsSLo /tmp/zig.tar.xz "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-x86_64-${ZIG_VERSION}.tar.xz" \
 && echo "${ZIG_SHA256}  /tmp/zig.tar.xz" | sha256sum -c - \
 && tar -xJf /tmp/zig.tar.xz -C /opt && rm /tmp/zig.tar.xz \
 && ln -s "/opt/zig-linux-x86_64-${ZIG_VERSION}/zig" /usr/local/bin/zig

RUN rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl \
 && cargo install cargo-zigbuild --version 0.24.1 --locked

ENV CARGO_TARGET_DIR=/target
WORKDIR /src
