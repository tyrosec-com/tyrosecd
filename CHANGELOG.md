# Änderungen / Changelog

Jede Version hier entspricht genau dem Git-Tag `v<Version>` und der signierten Programmdatei unter
`https://get.tyrosec.com/releases/<Version>/` (Nachbau: [VERIFY.md](VERIFY.md)).

## 0.5.7

- Quellcode erstmals einsehbar veröffentlicht; feste Build-Umgebung (`build/`) und Anleitung zum Nachbau.
- Programmdateien enthalten keine Pfade der Build-Umgebung mehr (reproduzierbarer Build).

## 0.5.6

- Nachprüfung der Webroots nach einem Überlauf der Ereignis-Warteschlange in Etappen (höchstens 45 s am Stück),
  Überläufe direkt nach dem Start ohne Nachprüfung.
- Kurzlebige, leere Temp-Dateien (z. B. `mktemp`) werden nicht mehr einzeln gemeldet.

## 0.5.5

- Domainnamen zu Zielen regelmäßiger Verbindungen (Beaconing) aus DNS-Antworten (nur lesen; neue systemd-Rechte
  `AF_PACKET`, `CAP_NET_RAW`).
- Website-Logins: eine allgemeine Umleitung (302) auf alles gilt nicht mehr als erfolgreiche Anmeldung.
- Kompromittierungs-Check: Paketprüfung wird übersprungen, solange die Paketverwaltung läuft.
- Installer: Download beim Upgrade ins eigene Datenverzeichnis, systemd-Unit nur bei Änderung schreiben.

## 0.5.4

- Build-Ausgaben (z. B. Next.js `.next/`) werden je Build zusammengefasst; Browser- und Compile-Caches in `/tmp`
  ignoriert.

## 0.5.3

- Weniger Ereignisse je Schreibvorgang (nur fertig geschriebene Dateien), größere Kernel-Warteschlange,
  Nachprüfung der Webroots nach einem Überlauf.

## 0.5.2

- Stichprobe ausgehender Verbindungen für die Erkennung regelmäßiger Kontakte (Beaconing).
