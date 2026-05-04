# host-bootstrap.sh

One-time host setup: provision a fresh Debian 12 VDS to be ready for
multi-tenant be-BOP. Idempotent — safe to re-run.

## Usage

```bash
host-bootstrap.sh [options]
```

Options: `--secrets-file <path>`, `--non-interactive`, `--dry-run`,
`--verbose`, `--help`.

## What it does

1. Validates the host: Debian 12, ≥ 2 GiB RAM, ≥ 20 GiB free on `/var`,
   systemd present.
2. Loads `/etc/be-BOP-tooling/secrets.env`.
3. Pings the OVH API (`GET /me`) to verify credentials.
4. Installs apt packages: `nginx`, `certbot` + `python3-certbot-dns-ovh`,
   `docker.io`, `netdata`, plus `curl jq stow rclone xxd flock unzip openssl`.
5. Configures the NodeSource repo and installs Node.js + corepack/pnpm.
6. Downloads & stows Garage (`/usr/local/garage/garage-v<VER>/`).
7. Downloads & stows phoenixd (`/usr/local/phoenixd/phoenixd-<VER>/`).
8. Creates the directory skeleton: `/var/lib/be-BOP/`, `/etc/be-BOP/`,
   `/etc/be-BOP-tooling/`, `/etc/phoenixd/`, `/var/lib/phoenixd/`.
9. Creates the `be-bop-cli` system user (parity with v1).
10. Writes `/etc/garage.toml` (no `root_domain` — see root README) and
    `/etc/systemd/system/garage.service`, starts Garage, applies layout.
11. Writes a 444 catch-all default nginx vhost; enables nginx.
12. Installs `/etc/letsencrypt/ovh.ini` (mode 0600) for certbot DNS-01.
13. Installs the systemd template units `bebop@.service` and
    `phoenixd@.service`.
14. Installs the tooling libs to
    `/usr/local/share/be-BOP-tooling/lib/` and the per-tenant scripts to
    `/usr/local/bin/`.
15. Initialises `/var/lib/be-BOP/tenants.tsv` (header only).
16. Pulls and starts Uptime Kuma in Docker, bound to `127.0.0.1:8810`.
17. Enables Netdata.
18. Prints a summary.

## What it does NOT do

- Issue any TLS certificate (per-tenant SAN certs are issued by
  `add-tenant.sh`).
- Create any tenant.
- Install MongoDB locally — be-BOP uses OVH Managed Mongo.

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
| `nginx -t` fails after re-run               | Hand-edited vhost? The default catch-all is regenerated on every run; unrelated vhosts under `sites-available` are not touched |
| Uptime Kuma container `Exited (137)`        | OOM. Bump VDS RAM or set memory limit on the container |

See also: `journalctl -t bebop-tooling-host-bootstrap`.
