# Ansible role `tyrosecd`

Installs and enrols the tyrosec agent (tyrosecd) with the official installer, which verifies the release signature.

- **Idempotent:** a server whose `/etc/tyrosecd/agent.toml` already contains a `host_id` is not touched again (the
  agent updates itself with signed releases). Only the service state is ensured.
- **Token handling:** the token is written to a root-only file (mode 0600) with `no_log`, passed to the installer as
  a file (never on the command line) and removed afterwards - also if the installation fails.
- Requires `become: true`, systemd on the target and ansible-core 2.15 or newer.

## Variables

| Variable | Default | Meaning |
|---|---|---|
| `tyrosecd_token` | *(required)* | Enrolment token from the web interface ("Add server") or `POST /api/v1/enroll-tokens`. Keep it in ansible-vault. |
| `tyrosecd_server` | `https://ingest.tyrosec.com` | Central server shown in the web interface |
| `tyrosecd_install_url` | `https://get.tyrosec.com/install.sh` | Official installer |
| `tyrosecd_install_args` | `[]` | Extra installer options, e.g. `["--version=0.5.9"]` |
| `tyrosecd_manage_service` | `true` | Ensure `tyrosecd` is enabled and running |
| `tyrosecd_token_file` | `/root/tyrosec.token` | Temporary token file on the target |
| `tyrosecd_installer_file` | `/root/tyrosec-install.sh` | Temporary installer file on the target |

One token can enrol several servers: create it with enough "uses" (at least the number of servers) and a validity
that covers the rollout. Revoke it in the web interface afterwards.

## Example

`inventory.ini`:

```ini
[tyrosec]
web1.example.com
web2.example.com
```

Store the token encrypted:

```sh
mkdir -p group_vars/tyrosec
ansible-vault create group_vars/tyrosec/vault.yml
#   tyrosecd_token: "ENR_..."
```

or encrypt a single value and paste the output into `group_vars/tyrosec/vars.yml`:

```sh
ansible-vault encrypt_string --name tyrosecd_token 'ENR_...'
```

Playbook (see also [`../../../site.yml`](../../../site.yml)):

```yaml
- name: Roll out the tyrosec agent
  hosts: tyrosec
  become: true
  roles:
    - role: tyrosecd
```

Run it:

```sh
ansible-playbook -i inventory.ini site.yml --ask-vault-pass
```

Copy `roles/tyrosecd` into your roles path (or point `roles_path` in `ansible.cfg` at `deploy/ansible/roles`).
