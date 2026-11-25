# Changelog

Each version listed here corresponds exactly to the Git tag `v<version>` and to the signed binary under
`https://get.tyrosec.com/releases/<version>/` (rebuild: [VERIFY.md](VERIFY.md)).

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
