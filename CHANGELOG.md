# Changelog

Each version listed here corresponds exactly to the Git tag `v<version>` and to the signed binary under
`https://get.tyrosec.com/releases/<version>/` (rebuild: [VERIFY.md](VERIFY.md)).

## 0.7.0
- Privilege escalation: a process that ran as a normal user (e.g. the web server user) and becomes root without a
  regular SUID program (sudo, su …) is reported – both from the kernel's user change report (setuid & co.) and when
  a non-root process starts a root program (exploit → root shell). Package management and the agent are exempt.
- Tunnel and remote-access tools (GSocket/gs-netcat, chisel, frp, ngrok, cloudflared tunnel, rathole, socat
  listeners with a program) and programs that disguise themselves as kernel threads are reported – at start and,
  for running processes with connections, in the periodic sweep.
- Programs running only from memory (memfd) are named as such.
- Web log: a POST to `wp-login.php` answered with a redirect that carries a rendered page (more than 512 bytes) is never
  counted as a successful WordPress login – sites without WordPress that redirect every unknown address were
  reported as successful logins right after an agent restart.
- Traces and hiding (checked every 30 seconds, read only):
  - security logs (auth.log, secure, syslog, messages, wtmp, btmp, lastlog, faillog, audit.log) that are deleted,
    emptied, shortened or replaced by a smaller file without a log rotation (a new or renewed rotated sibling such
    as `auth.log.1` counts as rotation);
  - processes hidden by a mount over `/proc/<pid>`, and processes the kernel reported that still exist but are
    missing from the `/proc` listing (userland rootkits) – confirmed in two rounds;
  - kernel taint flags for out-of-tree or unsigned modules newly set, and loaded kernel modules that are not part of
    the running kernel's module tree (also those loaded before the agent started; skipped if the tree is missing).
- Web log: risky backend actions are reported – new users/admin access (WordPress incl. REST API, Shopware Admin
  API, Magento admin users and integrations, Nextcloud users/groups), code uploaded or edited (plugin/theme ZIP,
  built-in file editor, Shopware extension upload), extensions/apps enabled, and saved Magento design configuration
  (HTML head/footer, a typical spot for card skimmers). Recognised from method, path and status only – no request
  bodies. Rated critical when the same IP had five or more failed logins in the hour before.
- Credential files: reading `/etc/shadow`, `/etc/gshadow` or private SSH keys (`~/.ssh/id_*` of root and the users
  in `/home`) by a program that never did so on this server is reported once. Plain open notifications (never a
  permission request – logins never wait for the agent); login, sudo, cron, SSH tools, backups and verified package
  management are exempt; the programs seen during the first 7 days are learned silently.
- Compromise check: running Docker containers that are privileged (or have SYS_ADMIN/SYS_MODULE/ALL), that have the
  Docker socket mounted, or that have a host system folder (/, /etc, /root, /boot, /usr) mounted writable – read
  from the container configuration only.
- Compromise check, hardening findings with a ready-made snippet (read only, nothing is changed): WordPress file
  editor enabled (`DISALLOW_FILE_EDIT`), PHP execution not blocked in `wp-content/uploads` (Apache `.htaccess` or
  nginx/Apache rule), Magento admin at `/admin`, Laravel `.env` inside the public folder, Nextcloud `config.php`
  readable by all users, and for the web PHP (FPM/Apache module): `display_errors`, `expose_php` and functions that
  start programs.
- Optional hardening on request (action kind `harden`, never enabled by default and **not** part of
  `tyrosecd actions enable` without a list – it must be named: `sudo tyrosecd actions enable harden`): fixed recipes
  only (`wp_disallow_file_edit` adds one line to `wp-config.php`, `wp_uploads_noexec` adds a marked block to
  `wp-content/uploads/.htaccess`), inside the web roots only. The agent builds the change itself, backs up the
  original, writes via descriptors, then checks (`php -l`, home page, an uploaded image) and restores the original
  immediately if a check fails or no check is possible. Undo restores the backup if the file was not changed since.

## 0.6.0
- Process memory: the agent now also follows process forks and exits via the proc connector and reads name, program,
  command line and user immediately when a program starts. Exited processes stay known for 120 seconds, so file
  events and detections of short-lived processes (e.g. a shell started by a web shell that exits within milliseconds)
  keep their process and parent chain. Read only – no kernel extensions, no eBPF.
- File events whose process was unknown when they were read (bursts of short-lived processes, e.g. `cp` while an
  initramfs is built) look into the process memory again when they are processed.
- Program starts of processes that have already exited are evaluated with the remembered values (marked in the
  detail); package management and the agent itself are recognised via the nearest ancestor that still runs.
- Lost kernel messages (sequence gaps, receive buffer overflow) are counted and followed by a resync of the running
  processes; larger receive buffer. The heartbeat reports whether the process memory is active, how many kernel
  messages were lost and how many exited processes were attributed from memory.

## 0.5.15
- Real-time protection trial run: program starts by verified package management (e.g. `dpkg-preconfigure`
  running `tzdata.config` from /tmp during unattended upgrades) carry the package marker and are no longer
  counted as would-be blocks.

## 0.5.14
- Compromise check: the `FilesMan` web shell signature only matches as a whole word – Next.js bundles contain
  `serverFilesManifest` and were reported as malicious code.
- Web log: known scanner paths (`.env`, `phpinfo.php`, `wp-config.php.save` …) now count as probes even when the site answers with a redirect (3xx) – sites that redirect every unknown URL hid such scans.
- Compromise check: `preg_replace` with the `/e` modifier counts as a strong web shell indicator only together with
  request input or decoding nearby (`$_GET`, `$_POST`, `base64_decode` …); legacy code with a fixed replacement
  (the modifier has no effect since PHP 7) is no longer reported on its own.
- Compromise check: card-skimmer patterns inside a Nextcloud installation (minified app bundles, no checkout) are
  reported as information only; web shell patterns there still count.

## 0.5.13

- Compromise check: a WordPress core file whose checksum differs only because of CRLF/LF line-ending conversion
  (FTP ASCII mode, git autocrlf) is reported as information only; the original is fetched read-only from
  core.svn.wordpress.org (at most 40 files per installation, 4 MB each).
- Compromise check: kernel usermode helpers (e.g. `bpfilter_umh`, program shown as `/ (deleted)`, parent kthreadd)
  are no longer reported as a process whose program file was deleted.

## 0.5.12

- Compromise check: a JavaScript/PHP file that matches a suspicious pattern but is listed with exactly its SHA-512
  in Nextcloud's signature list (`appinfo/signature.json`, `core/signature.json`) is reported as information only
  (original Nextcloud bundles).

## 0.5.11

- The daily compromise check uses the same web roots as the inventory (taken from the web server configuration),
  so applications outside the standard folders are checked too (hardening, Composer, WordPress themes).
- The official tyrosec installer (`curl https://get.tyrosec.com/install.sh | sh`) is no longer reported as a
  suspicious command – only if the command line fetches nothing but get.tyrosec.com and contains nothing else
  suspicious.

## 0.5.10

- App detection in the web roots (also the folder above a `public`/`pub`/`web`/`htdocs` docroot): WordPress,
  WooCommerce, Magento 2, Shopware 6 and 5, PrestaShop, JTL-Shop, Laravel, Symfony, TYPO3, Contao, Joomla, Drupal,
  Nextcloud, Next.js and Nuxt with version, their media/upload and cache folders and their plugins, modules and themes
  (WordPress plugins/themes, Magento `app/code`, Shopware `custom/plugins`, PrestaShop `modules`). New inventory field
  `apps`; shops are derived from the same detection. Bounded walks, symbolic links are not followed.
- Compromise check, per detected app (read only):
  - `app_debug_mode` (high): debug/developer mode in production (Laravel `APP_DEBUG`, also a cached configuration;
    Symfony/Shopware/Contao `APP_ENV=dev` from `.env`/`.env.local`/`.env.local.php`; Magento `MAGE_MODE` developer;
    WordPress `WP_DEBUG` without `WP_DEBUG_DISPLAY` false; Joomla and Nextcloud `debug`).
  - `app_install_tool` (high): TYPO3 `ENABLE_INSTALL_TOOL`, Joomla `installation/`, PrestaShop/JTL-Shop `install/`,
    leftover Shopware installers.
  - `app_config_writable` (medium): configuration file writable by all users.
  - `vendor_changed_after_install` (medium): code files under `vendor/` newer than `composer.lock` or
    `vendor/composer/installed.json` plus one hour (at most 50,000 entries walked, up to 20 paths listed).
  - `composer_autoload_foreign` (high): the Composer autoloader loads files that belong neither to an installed package
    nor to the project's autoload configuration, or contains code Composer does not generate.
- Check report: SHA-256 of all files of the installed Composer packages (field `composer`) and of the WordPress themes
  (field `wp_themes`) for the comparison with the original packages – only when the lock file, `installed.json` or the
  theme versions changed since the last report, otherwise at most every 7 days (limits: 100,000 package files, 30,000
  theme files, files over 5 MiB by size only).
- Detection `deploy_activity` (info): deploy or update command (composer install/update, bin/magento setup:upgrade …,
  artisan migrate/optimize, bin/console system:update/plugin:update/cache:clear, wp core/plugin/theme update,
  dep deploy, git pull/checkout/reset) started inside a detected app root.
- Rollout templates in `deploy/`: a cloud-init file (`deploy/cloud-init.yaml`) and an idempotent Ansible role
  (`deploy/ansible/roles/tyrosecd`, example playbook `deploy/ansible/site.yml`). Both use the official installer and
  pass the enrolment token only as a root-only file that is removed afterwards.

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
