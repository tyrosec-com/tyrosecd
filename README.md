# tyrosecd – the tyrosec agent (viewable source code)

tyrosecd is the program that runs on your Linux server when you use [tyrosec](https://tyrosec.com). It watches files,
logins, processes and connections and reports anomalies to the tyrosec central service, which analyses them and
explains them in plain language.

Because the agent runs with far-reaching privileges, its source code is **viewable** here: you can review what it does
– and verify that the official, signed binaries are built from exactly this code ([VERIFY.md](VERIFY.md)). This is
**not open-source software**: review and private, non-commercial use without redistribution are permitted; anything
else requires written consent ([LICENSE](LICENSE)).

## What the agent does

| Area | How |
|---|---|
| Files | Real-time monitoring (fanotify, otherwise inotify) plus periodic reconciliation: checksums, and for code and configuration files the change as a diff; credentials in files are redacted before anything is sent (`crates/core/src/redact.rs`) |
| Logins | SSH logins from the journal/auth log, website logins (e.g. WordPress) from web server logs |
| Processes | Program starts (kernel proc connector), suspicious patterns such as reverse shells or crypto miners |
| Network | Open ports, outbound connections, regular contacts (beaconing); domain names for them from DNS responses |
| Inventory | Packages and versions (for vulnerabilities), services, containers, websites, TLS certificates, metrics (CPU, RAM, disk) |
| Checks | Compromise check: modified system binaries, suspicious autostart entries, permissions, malware rules (YARA) |

## What it sends – and where

Only to the configured tyrosec central service (mutually authenticated TLS 1.3, server certificate pinned): the
observations listed above. Not sent, among other things: database contents, mail, session files, caches and
application log contents (these paths are not read at all, see `crates/core/src/policy.rs`).

Updates of the agent and of the malware rules are only installed if the manifest is validly signed with one of the
built-in release keys (Ed25519, with key epochs: a newer key invalidates older ones) and the file checksums match
(`crates/transport/src/update.rs`). The installer checks the same signature; on systems whose openssl cannot verify
Ed25519 it falls back to a second signature made with P-256.

## Which privileges it has

The agent runs as a systemd service with hard limits (max. 256 MB RAM, half a CPU core, lowest priority) inside a
sandbox: the system is read-only except for the agent's own directories, only the required capabilities, restricted
system calls – each with its justification in [install/install.sh](install/install.sh) (function `write_unit`).

## What it does not do

- **It does not intervene** unless you explicitly allow it: blocking, quarantine or restore only work after you enable
  them on the server itself with `sudo tyrosecd actions enable …` (`crates/cli/src/actions.rs`). Without this
  approval the service lacks the necessary write permissions.
- It opens no ports and accepts no commands from the internet; it only connects out to the central service.

## Automated rollout

For many servers, two ready-made templates are in [`deploy/`](deploy/) (the web interface shows them filled in with
your token under "Add server"):

- [cloud-init](deploy/cloud-init.md): installs and enrols the agent on the first boot of a new cloud server.
- [Ansible role `tyrosecd`](deploy/ansible/roles/tyrosecd/README.md): idempotent rollout to existing servers, token
  from ansible-vault.

Both use the official installer (signature check) and pass the enrolment token only as a root-only file that is
deleted afterwards. One token can enrol several servers if it is created with enough "uses".

## Layout

| Directory | Contents |
|---|---|
| `crates/cli` | The `tyrosecd` program: start-up, enrolment, service, local approvals |
| `crates/core` | Processing of file events, rules, redaction, state |
| `crates/source-*` | Event sources: fanotify, inotify, reconciliation scan, logins, web server logs |
| `crates/detect` | Process and network detection, beaconing, DNS |
| `crates/check` | Compromise check |
| `crates/inventory` | Inventory |
| `crates/transport` | Connection to the central service, spool, signed updates |
| `crates/yara` | Malware rules |
| `install/install.sh` | Installer including the systemd unit |
| `deploy/` | Rollout templates: cloud-init, Ansible role |
| `build/` | Pinned build environment for rebuilding |

## Reporting security issues

Please not publicly – see [SECURITY.md](SECURITY.md).
