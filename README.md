# tyrosecd – der tyrosec-Agent (einsehbarer Quellcode)

*English summary below.*

tyrosecd ist das Programm, das auf Ihrem Linux-Server läuft, wenn Sie [tyrosec](https://tyrosec.com) nutzen. Es
beobachtet Dateien, Anmeldungen, Prozesse und Verbindungen und meldet Auffälligkeiten an die tyrosec-Zentrale, die sie
auswertet und verständlich erklärt.

Weil der Agent mit weitreichenden Rechten läuft, ist sein Quellcode hier **einsehbar**: Sie können prüfen, was er tut –
und nachrechnen, dass die offiziellen, signierten Programmdateien genau aus diesem Code entstehen
([VERIFY.md](VERIFY.md)). Das ist **keine Open-Source-Software**: erlaubt sind Prüfen und private, nicht-gewerbliche
Nutzung ohne Weitergabe – alles andere nur mit Zustimmung ([LICENSE](LICENSE)).

## Was der Agent tut

| Bereich | Wie |
|---|---|
| Dateien | Echtzeit-Überwachung (fanotify, sonst inotify) und regelmäßiger Abgleich: Prüfsummen, bei Code-/Konfigurationsdateien die Änderung als Diff; Zugangsdaten in Dateien werden vor dem Senden geschwärzt (`crates/core/src/redact.rs`) |
| Anmeldungen | SSH-Anmeldungen aus Journal/Auth-Log, Website-Logins (z. B. WordPress) aus den Webserver-Logs |
| Prozesse | Programmstarts (Proc-Connector des Kernels), auffällige Muster wie Reverse Shells oder Krypto-Miner |
| Netz | Offene Ports, ausgehende Verbindungen, regelmäßige Kontakte (Beaconing); Domainnamen dazu aus DNS-Antworten |
| Bestandsaufnahme | Pakete und Versionen (für Schwachstellen), Dienste, Container, Websites, TLS-Zertifikate, Messwerte (CPU, RAM, Platte) |
| Prüfungen | Kompromittierungs-Check: veränderte Systemprogramme, verdächtige Autostarts, Rechte, Schadcode-Regeln (YARA) |

## Was er sendet – und wohin

Ausschließlich an die konfigurierte tyrosec-Zentrale (gegenseitig authentifiziertes TLS, Server-Zertifikat fest
hinterlegt): die oben genannten Beobachtungen. Nicht gesendet werden u. a. Datenbank-Inhalte, Mails, Sitzungsdateien,
Caches und Log-Inhalte von Anwendungen (diese Pfade werden gar nicht gelesen, siehe `crates/core/src/policy.rs`).
Updates des Agenten und der Schadcode-Regeln werden nur installiert, wenn ihre Signatur (Ed25519 **und** P-256) gültig
ist (`crates/transport/src/update.rs`).

## Welche Rechte er hat

Der Agent läuft als systemd-Dienst mit harten Grenzen (max. 256 MB RAM, ½ CPU-Kern, niedrigste Priorität) und in einem
Sicherheitskäfig: System schreibgeschützt bis auf eigene Ordner, nur benötigte Fähigkeiten, eingeschränkte
Systemaufrufe – jeweils mit Begründung in [install/install.sh](install/install.sh) (Abschnitt `write_unit`).

## Was er nicht tut

- **Er greift nicht ein**, solange Sie es nicht ausdrücklich erlauben: Sperren, Quarantäne oder Wiederherstellen
  funktionieren nur, wenn Sie sie auf dem Server selbst mit `sudo tyrosecd actions enable …` freischalten
  (`crates/cli/src/actions.rs`). Ohne diese Freigabe fehlen dem Dienst die nötigen Schreibrechte.
- Er öffnet keine Ports und nimmt keine Befehle aus dem Internet entgegen; er baut nur Verbindungen zur Zentrale auf.

## Aufbau

| Ordner | Inhalt |
|---|---|
| `crates/cli` | Programm `tyrosecd`: Start, Anmeldung, Dienst, lokale Freigaben |
| `crates/core` | Verarbeitung der Datei-Ereignisse, Regeln, Schwärzung, Zustand |
| `crates/source-*` | Ereignisquellen: fanotify, inotify, Abgleich-Scan, Anmeldungen, Webserver-Logs |
| `crates/detect` | Prozess- und Netzerkennung, Beaconing, DNS |
| `crates/check` | Kompromittierungs-Check |
| `crates/inventory` | Bestandsaufnahme |
| `crates/transport` | Verbindung zur Zentrale, Spool, signierte Updates |
| `crates/yara` | Schadcode-Regeln |
| `install/install.sh` | Installer inkl. systemd-Unit |
| `build/` | feste Build-Umgebung für den Nachbau |

## Sicherheitslücken melden

Bitte nicht öffentlich, sondern wie in [SECURITY.md](SECURITY.md) beschrieben.

---

## English summary

tyrosecd is the agent of [tyrosec](https://tyrosec.com), a security service for Linux servers. It watches files,
logins, processes and connections and reports to the tyrosec central service. Because it runs with far-reaching
privileges, its source code is **viewable** here so you can review it and verify that the official signed binaries are
built from exactly this code ([VERIFY.md](VERIFY.md)). This is **not open-source software**: review and private,
non-commercial use without redistribution are permitted; anything else requires written consent ([LICENSE](LICENSE)).
The agent only talks to the configured tyrosec central service (mutual TLS), installs only updates signed with both
Ed25519 and P-256, runs in a hardened systemd sandbox with hard resource limits, and never takes action on the server
(blocking, quarantine, restore) unless you enable it locally with `sudo tyrosecd actions enable …`.
Report security issues as described in [SECURITY.md](SECURITY.md).
