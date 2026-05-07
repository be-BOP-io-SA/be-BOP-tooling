# host-bootstrap.sh

One-time host setup: provision a fresh Debian 12 VDS to be ready for
multi-tenant be-BOP. Idempotent — safe to re-run.

## Usage

In normal operation you do **not** call this directly on a fresh host —
`install.sh` (the one-shot fetcher) runs it for you in `--defer-secrets`
mode, then you re-run it manually after editing `secrets.env`:

```bash
# First-time setup (single command).
# TODO: switch to https://be-bop.io/saas/install.sh once configured.
curl -sfSL \
  https://raw.githubusercontent.com/Tirodem/be-BOP-tooling/multitenant-poc/multitenant-tooling/install.sh \
  -o install.sh \
  && sudo bash ./install.sh

# After editing secrets.env (idempotent — only finalises OVH steps):
sudo /opt/be-BOP-tooling/host-bootstrap.sh
```

Direct invocation (for re-runs, drift fixes, version bumps):

```bash
host-bootstrap.sh [options]
```

Options:
- `--secrets-file <path>` — path to secrets.env (default
  `/etc/be-BOP-tooling/secrets.env`).
- `--defer-secrets` — skip steps that need OVH credentials (used by
  `install.sh` on the very first run, before the operator has filled in
  `secrets.env`). Re-run without this flag to finalise.
- `--non-interactive` — refuse to prompt; exit if input would be needed.
- `--dry-run` — print actions without changing the system.
- `--verbose` — verbose logging.
- `--help`.

## What it does

1. Validates the host: Debian 12, ≥ 2 GiB RAM, ≥ 20 GiB free on `/var`,
   systemd present, **CPU AVX support** (required by MongoDB 5.0+ on amd64).
2. Loads `/etc/be-BOP-tooling/secrets.env`.
3. Pings the OVH API (`GET /me`) to verify credentials.
4. Installs apt packages: `nginx`, `certbot` + `python3-certbot-dns-ovh`,
   `docker.io`, `netdata`, plus `curl jq stow rclone xxd unzip openssl`.
5. Configures the NodeSource repo and installs Node.js + corepack/pnpm.
6. Configures the **MongoDB official APT repo** (signed) and installs
   `mongodb-org`, `mongodb-mongosh`, `mongodb-database-tools`. Masks the
   default `mongod.service` (we use per-tenant `mongod@<tenant>.service`
   template instances, started by `add-tenant.sh`).
7. Downloads & stows Garage (`/usr/local/garage/garage-v<VER>/`).
8. Downloads & stows phoenixd (`/usr/local/phoenixd/phoenixd-<VER>/`).
9. Creates the directory skeleton: `/var/lib/be-BOP/`, `/etc/be-BOP/`,
   `/etc/be-BOP-tooling/`, `/etc/phoenixd/`, `/var/lib/phoenixd/`,
   `/etc/be-BOP-mongodb/`, `/var/lib/be-BOP-mongodb/`.
10. Creates the `be-bop-cli` system user (parity with v1).
11. Writes `/etc/garage.toml` (no `root_domain` — see root README) and
    `/etc/systemd/system/garage.service`, starts Garage, applies layout.
12. Writes a 444 catch-all default nginx vhost; enables nginx.
13. Installs `/etc/letsencrypt/ovh.ini` (mode 0600) for certbot DNS-01.
14. Installs the systemd template units `bebop@.service`,
    `phoenixd@.service`, **`mongod@.service`**.
15. Installs the tooling libs to
    `/usr/local/share/be-BOP-tooling/lib/` and the per-tenant scripts to
    `/usr/local/bin/`.
16. Initialises `/var/lib/be-BOP/tenants.tsv` (header only).
17. Pulls and starts Uptime Kuma in Docker, bound to `127.0.0.1:8810`.
18. Enables Netdata.
19. Prints a summary.

## What it does NOT do

- Issue any TLS certificate (per-tenant SAN certs are issued by
  `add-tenant.sh`).
- Create any tenant.
- Start any mongod. The default `mongod.service` is masked; per-tenant
  `mongod@<tenant>.service` instances are started by `add-tenant.sh`.

## Configurable versions

Override at invocation time:

```bash
GARAGE_VERSION=2.2.0 PHOENIXD_VERSION=0.6.2 \
NODEJS_MAJOR_VERSION=20 UPTIME_KUMA_HOST_PORT=8810 \
host-bootstrap.sh
```

## Idempotence checks

- Garage version dir exists → skip download
- phoenixd version dir exists → skip download
- `/etc/garage.toml` exists → preserve `rpc_secret`
- Garage layout already assigned → skip layout assign
- Uptime Kuma container already exists → start if stopped
- `be-bop-cli` user exists → skip useradd

## Manual operator step (one-time)

After `host-bootstrap.sh` finishes:

1. SSH-tunnel into Uptime Kuma:
   ```bash
   ssh -L 8810:localhost:8810 your-vds
   ```
2. Open `http://localhost:8810`, create the admin account.
3. In *Settings → Notifications*, configure:
   - **Mail (SMTP)** notification using the same SMTP creds as
     `secrets.env`.
   - **Zulip** notification using the bot creds from `secrets.env`.
4. Both are host-wide and reused by every tenant's monitor.

After that, `add-tenant.sh` will print a one-line operator instruction
asking to add a monitor in the Kuma UI for each new tenant. (Programmatic
monitor creation is currently not feasible against Kuma 1.x.)

## Troubleshooting

| Symptom                                     | Likely cause / fix                      |
|---------------------------------------------|------------------------------------------|
| `secrets.env mode is XXX; should be 600`    | `chmod 600 /etc/be-BOP-tooling/secrets.env` |
| `OVH API ping failed`                       | Wrong OVH keys, or consumer key expired. Regenerate at https://api.ovh.com/createToken/ |
| `Garage did not become ready in 30s`        | First start may take longer on slow disks; re-run, or check `journalctl -u garage` |
| `MongoDB ${MONGODB_VERSION} requires CPU AVX support` | Your CPU is too old (or KVM is hiding the AVX flag). Either pick a newer host or override `MONGODB_VERSION=4.4` and accept the security tradeoffs. |
| `nginx -t` fails after re-run               | Hand-edited vhost? The default catch-all is regenerated on every run; unrelated vhosts under `sites-available` are not touched |
| Uptime Kuma container `Exited (137)`        | OOM. Bump VDS RAM or set memory limit on the container |

See also: `journalctl -t bebop-tooling-host-bootstrap`.
