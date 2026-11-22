# cloud-init

[`cloud-init.yaml`](cloud-init.yaml) installs and enrols tyrosecd on the first boot of a new server. Most cloud
providers accept it as "user data" when creating a server.

1. Create an enrolment token in the web interface ("Add server") or via the API (`POST /api/v1/enroll-tokens`). For
   several servers, give the token enough "uses" and a validity that covers the rollout - no more.
2. Replace `ENR_REPLACE_WITH_YOUR_TOKEN` with the token. Keep the server URL unless the web interface shows a
   different one. The web interface also shows this file already filled in.
3. Pass the file as user data when creating the server.

What it does:

- `write_files` writes the token to `/root/tyrosec.token` (owner root, mode 0600).
- `runcmd` downloads the official installer to a file and runs it; the installer verifies the release signature,
  installs the agent and its systemd service and enrols the server. The token file and the installer are deleted
  afterwards, whether the installation succeeded or not.

Notes:

- The image needs `curl` (present on all common cloud images).
- User data stays readable for root on the server (`/var/lib/cloud/instance/`) and in the provider's metadata
  service. The token is only usable for its remaining uses and until it expires; revoke it in the web interface once
  the rollout is done.
- Progress and errors: `/var/log/cloud-init-output.log`, afterwards `systemctl status tyrosecd`.
