# Changelog

Each version listed here corresponds exactly to the Git tag `v<version>` and to the signed binary under
`https://get.tyrosec.com/releases/<version>/` (rebuild: [VERIFY.md](VERIFY.md)).

## 0.5.9

- Compromise check: a hidden directory in a temporary folder that is empty, or that is the temporary profile of a
  headless browser (Chromium, Chrome, Firefox) owned by a regular user without any program inside, is reported as
  information only instead of a finding of medium severity. Hidden directories containing programs stay findings.

## 0.5.8

- Hardening after external security reviews:
  - Web server logs are only opened as regular files and non-blocking; in directories writable by users other than
    root, a symbolic link as the log file is not followed.
  - Malware-rule (YARA) checks never follow a symbolic link.
  - Quarantine first moves the file name atomically to a random name in the same directory and only then verifies what
    is removed.
- Source code, comments, documentation and program messages in English.
- Documentation states the update signature check precisely (agent: Ed25519 with key epochs; installer: Ed25519, or
  P-256 on systems with an older openssl).

## 0.5.7

- Source code published for the first time; pinned build environment (`build/`) and rebuild instructions.
- Binaries no longer contain paths of the build environment (reproducible build).

## 0.5.6

- Re-check of web roots after an event-queue overflow runs in stages (at most 45 s at a time); overflows right after
  start-up do not trigger a re-check.
- Short-lived, empty temporary files (e.g. from `mktemp`) are no longer reported individually.

## 0.5.5

- Domain names for targets of regular outbound connections (beaconing) from DNS responses (read-only; new systemd
  permissions `AF_PACKET`, `CAP_NET_RAW`).
- Website logins: a generic redirect (302) for every request no longer counts as a successful login.
- Compromise check: package verification is skipped while the package manager is running.
- Installer: on upgrade, downloads go to the agent's own data directory; the systemd unit is only written when changed.

## 0.5.4

- Build output (e.g. Next.js `.next/`) is summarised per build; browser and compile caches in `/tmp` are ignored.

## 0.5.3

- Fewer events per write (only completely written files), larger kernel queue, re-check of web roots after an overflow.

## 0.5.2

- Sampling of outbound connections to detect regular contacts (beaconing).
