# be-BOP multi-tenant tooling

Operational tooling to host **10+ isolated be-BOP tenants** on a single
Debian 12 VDS, with one local mongod per tenant, a single mutualised
Garage S3 instance, per-tenant phoenixd Lightning daemons, and per-tenant
TLS via Let's Encrypt DNS-01 over the OVH API.

This is a fork of [be-BOP-tooling](https://github.com/be-BOP-io-SA/be-BOP-tooling)
maintained on the `multitenant-poc` branch. It lives in a sibling directory
to the original `be-bop-bootstrap/` so the v1 single-host wizard keeps
working untouched and upstream merges remain trivial.

> **Status:** PoC — embryo of the commercial be-bop.io SaaS. The directory
> structure, registry schema, and CLI flags are stable.

---

## Mental model

```
   internet ─►─► nginx :443
                   │
                   ├─►  bebop@tenant1     :3001
                   ├─►  bebop@tenant2     :3002
                   ├─►  bebop@tenantN     :30xx
                   │
                   │   phoenixd@tenant1   :9741
                   │   phoenixd@tenant2   :9742
                   │   phoenixd@tenantN   :97xx
                   │
                   │   mongod@tenant1     :27018  (1 DB, single-node rs0)
                   │   mongod@tenant2     :27019
                   │   mongod@tenantN     :270xx
                   │
                   └─►  Garage S3         :3900   (single instance, N buckets/keys)

   All bound to 127.0.0.1; nginx is the only public face.
   Single VDS Contabo, fully self-hosted (no external DBaaS).
```

Per tenant on the host:

| Resource                                                | Owner / mode           |
|---------------------------------------------------------|------------------------|
| `bebop@<tenant>.service`                                | DynamicUser (systemd)  |
| `phoenixd@<tenant>.service`                             | DynamicUser (systemd)  |
| `mongod@<tenant>.service`                               | DynamicUser (systemd)  |
| `/var/lib/be-BOP/<tenant>/releases/<tag>/`              | root:root 0755         |
| `/var/lib/be-BOP/<tenant>/state/`                       | dynamic-user 0700      |
| `/etc/be-BOP/<tenant>/config.env`                       | root:root 0640         |
| `/var/lib/phoenixd/<tenant>/.phoenix/seed.dat` ⚠       | dynamic-user 0700      |
| `/etc/phoenixd/<tenant>/port.env`                       | root:root 0640         |
| `/var/lib/be-BOP-mongodb/<tenant>/` (mongod dbPath)     | dynamic-user 0700      |
| `/etc/be-BOP-mongodb/<tenant>/port.env`                 | root:root 0640         |
| `/etc/nginx/sites-available/bebop-<tenant>.conf`        | root:root 0644         |
| `/etc/letsencrypt/live/bebop-<tenant>/`                 | root:root              |
| Garage bucket `bebop-<tenant>` + key                    | Garage internal        |

The truth source for who-is-who is the **registry**:
`/var/lib/be-BOP/tenants.tsv` (TSV with header, locked via flock for
concurrent-safe mutations).

```
tenant_id   domain                bebop_port  phoenixd_port  mongo_port  mongodb_database  garage_bucket  garage_key            bebop_version                       created_at             status
tenant1     tenant1.pvh-labs.com  3001        9741           27018       bebop_tenant1     bebop-tenant1  bebop-tenant1-key     be-BOP.release.2026-04-15.abc1234   2026-05-04T14:30:00Z   active
```

**Status values:** `active` (running, ports reserved), `soft-deleted`
(services off, data + ports preserved), `archived` (data uploaded to SFTP,
local + Mongo + Garage purged, ports released).

---

## Architectural decisions

> Each item below is a divergence from the literal spec text or a
> non-obvious choice. Future maintainers: don't change these without
> reading the *Why*.

### Per-tenant SAN certificate, not a single shared wildcard

The original spec called for a single `*.pvh-labs.com` wildcard via
DNS-01. That cert covers `tenant1.pvh-labs.com` and `s3.pvh-labs.com`,
**but not** `s3.tenant1.pvh-labs.com` — Let's Encrypt does not issue
multi-level wildcards. Since we expose Garage per-tenant under
`s3.<tenant>.<zone>`, we use one cert per tenant with two SAN entries:
`<tenant>.<zone>` and `s3.<tenant>.<zone>`. Issuance is via DNS-01 OVH
(no DNS propagation race to the public internet).

### `DynamicUser=yes` with a sub-StateDirectory

We use `DynamicUser=yes` so each tenant runs under an ephemeral UID with
no shared filesystem privileges. `StateDirectory=be-BOP/%i/state` (note
the `/state` suffix, not just `%i`) so systemd only takes ownership of
the writable subtree, leaving the parent `/var/lib/be-BOP/<tenant>/`
under root for release deployment. `Environment=HOME=/var/lib/be-BOP/%i/state`
gives pnpm a writable HOME.

### Per-tenant `s3.<tenant>` subdomain (not a shared `s3.<zone>`)

This was a tradeoff. A shared `s3.<zone>` would have fit under the single
wildcard cert, but per-tenant subdomains give:
- Zero risk of bucket-name leakage in URLs becoming an information
  channel between merchants.
- Simpler nginx config (each tenant's vhost is fully self-contained).
- Easier to migrate one tenant onto a different host later.

The cost is the per-tenant cert. Acceptable for a PoC at 10–100 tenants.

### Garage CLI: `set-quotas`, not `bucket allow --max-size`

The literal spec used `garage bucket allow --max-size 20G`, but
`bucket allow` only takes permission flags (read/write/owner). Quotas
are set via `garage bucket set-quotas --max-size 20GiB <bucket>`.
Verified against `src/garage/cli/structs.rs` on the `main-v2` branch.

### One mongod per tenant (local), not a shared cluster

We deploy one local `mongod` per tenant via the `mongod@<tenant>.service`
template — each instance bound to `127.0.0.1` on a unique port (≥ 27018),
each with its own dbPath under `/var/lib/be-BOP-mongodb/<tenant>/`, each
running as a single-node replica set named `rs0`.

We considered three alternatives and rejected them all:
- **OVH Managed MongoDB** — the entry-level "Production" tier (3 nodes,
  smallest instance, 80 GB minimum storage) is around 250 €/mois HT for
  a PoC, and OVH does not offer a Discovery tier on Mongo. Killer cost.
- **MongoDB Atlas free tier (M0)** — 512 MB total per cluster, 25 clusters
  max per org. Workable but tight for real merchant data, and the API
  surface differs significantly from a local mongod.
- **Single shared local mongod, one DB per tenant** — denser in RAM but
  forces us to enable mongod auth as the only multi-tenant boundary;
  any auth misconfig leaks data across merchants. Per-tenant instances
  give us free isolation via `DynamicUser=yes` + `StateDirectory=`.

Trade-offs of the chosen approach:
- 10 mongod instances ≈ ~1.5–3 GB RAM total (idle) on top of be-BOP +
  phoenixd. Works comfortably on an 8 GB VDS for 10–20 tenants.
- Crash blast radius is per-tenant (one tenant down ≠ all tenants down).
- Backups: `mongodump --port <tenant_port> --db <db>` per tenant; embedded
  in `remove-tenant.sh --archive`.
- Auth disabled: cross-tenant isolation comes from process + filesystem
  boundaries, not in-DB users.

### Idempotence first; rollback for fresh creation only

Every script is safe to re-run. `add-tenant.sh` on an already-active
tenant simply re-applies config. The transactional rollback (undo stack)
only fires on **fresh** creation, where the entire state can be
unwound cleanly. Reactivation and re-apply paths trust the existing
state and won't try to undo it on failure.

---

## Files in this tree

```
multitenant-tooling/
├── README.md                       this file
├── docs/
│   ├── README.host-bootstrap.md
│   ├── README.add-tenant.md
│   ├── README.remove-tenant.md
│   ├── README.upgrade-tenant.md
│   └── README.upgrade-all.md
├── lib/                            sourced bash libraries (idempotent helpers)
│   ├── log.sh                      structured logging + secret masking
│   ├── sudo.sh                     run_privileged + require_privileges
│   ├── transaction.sh              undo stack for transactional scripts
│   ├── registry.sh                 tenants.tsv read/write/lock/allocate-port
│   ├── ovh.sh                      OVH API: signing, DNS (DNS-01 + record CRUD)
│   ├── mongo.sh                    per-tenant mongod helpers (mongosh wrappers)
│   ├── garage.sh                   bucket/key/quota wrappers
│   ├── notify.sh                   SMTP + Zulip operator alerts
│   ├── uptime-kuma.sh              monitor register/unregister (Socket.IO via kuma-cli.py)
│   ├── kuma-cli.py                 Python wrapper around uptime-kuma-api
│   ├── healthcheck.sh              http_wait_ok / tcp_port_open
│   └── release.sh                  GitHub release download + pnpm install
├── templates/
│   ├── bebop@.service              systemd template unit (per tenant)
│   ├── phoenixd@.service           systemd template unit (per tenant)
│   ├── mongod@.service             systemd template unit (per tenant)
│   ├── nginx-tenant.conf.tmpl      per-tenant vhost (HTTPS + s3 vhost)
│   ├── config.env.tmpl             per-tenant be-BOP env file
│   └── secrets.env.example         shared secrets template
├── host-bootstrap.sh               run ONCE on a fresh host
├── add-tenant.sh                   onboard a tenant
├── remove-tenant.sh                soft-delete / archive / purge
├── upgrade-tenant.sh               upgrade one tenant
└── upgrade-all.sh                  upgrade many tenants
```

---

## Quick start

```bash
# 1. On a fresh Debian 12 host, one command — only curl + tar required
#    (both shipped in Debian base; no git, no manual download).
#    TODO: switch to https://be-bop.io/saas/install.sh once configured.
curl -sfSL \
  https://raw.githubusercontent.com/Tirodem/be-BOP-tooling/multitenant-poc/multitenant-tooling/install.sh \
  -o install.sh \
  && sudo bash ./install.sh

# This installer:
#   - downloads the multitenant-poc tarball from GitHub,
#   - installs the tooling to /opt/be-BOP-tooling/,
#   - seeds /etc/be-BOP-tooling/secrets.env from the template,
#   - runs host-bootstrap.sh --defer-secrets (everything that does NOT
#     require OVH credentials: apt packages, Node, Garage, phoenixd,
#     nginx catch-all, docker, Uptime Kuma, netdata, systemd units…),
#   - then opens secrets.env in nano so you can fill in OVH / SMTP /
#     Zulip / SFTP / Mongo cluster details.

# 2. After saving secrets.env, finalise the host bootstrap (this only
#    runs the deferred OVH-credential steps; safe to re-run anytime):
sudo /opt/be-BOP-tooling/host-bootstrap.sh

# 3. Manual one-time step: open Uptime Kuma in a browser via SSH tunnel,
#    create the admin account and configure mail + Zulip notification
#    channels (host-wide, used by all tenants).
ssh -L 8810:localhost:8810 your-vds
# ... open http://localhost:8810 ...

# 4. Onboard your first tenant:
sudo add-tenant.sh tenant1 --admin-email merchant1@example.com

# 5. Operate.
sudo upgrade-tenant.sh tenant1 --version latest
sudo remove-tenant.sh  tenant1                    # soft-delete (reversible)
sudo remove-tenant.sh  tenant1 --reactivate       # ← oops, restore it
                                                  # (run via add-tenant.sh)
sudo remove-tenant.sh  tenant1 --archive          # encrypted SFTP archive
sudo remove-tenant.sh  tenant1 --purge            # nuclear (with confirm)
```

> **PoC vs. production URL:** the command above curls `install.sh`
> straight from `raw.githubusercontent.com` because `be-bop.io` is not
> wired up yet. The eventual canonical entry point is
> `https://be-bop.io/saas/install.sh` — the script content does not
> change, only the host serving it.

---

## Per-script HOWTOs

- [host-bootstrap.sh](docs/README.host-bootstrap.md) — one-time host setup
- [add-tenant.sh](docs/README.add-tenant.md) — 14-phase onboarding with rollback
- [remove-tenant.sh](docs/README.remove-tenant.md) — soft-delete / archive / purge
- [upgrade-tenant.sh](docs/README.upgrade-tenant.md) — single-tenant release upgrade
- [upgrade-all.sh](docs/README.upgrade-all.md) — fleet upgrades (rolling/parallel)
- [acceptance-tests](docs/README.acceptance-tests.md) — runbook for the 10 PoC acceptance tests

---

## Common operator scenarios

### Recover from a half-failed `add-tenant.sh`

The script auto-rolls back on any phase failure (DNS, Mongo, Garage, cert,
etc.). If the rollback also failed (network glitch mid-rollback), the
notification email + Zulip post will list which steps were undone and which
weren't. Fix the underlying issue, then re-run `add-tenant.sh <id>` — it
will detect the partial state and try to reconcile, OR finish with a clear
"please run remove-tenant.sh --purge first" message.

### Restore a tenant from a remote archive

1. Pull the encrypted archive + sha256 from the SFTP destination.
2. Decrypt:
   ```bash
   openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 \
     -in bebop-archive-tenantX-YYYYMMDD.tar.gz.enc \
     -out bebop-archive-tenantX.tar.gz \
     -pass "pass:${BACKUP_ENCRYPTION_KEY}"
   tar -tf bebop-archive-tenantX.tar.gz                  # inspect
   ```
3. The archive contains `metadata.json` (tenant_id, version, ports, db/bucket
   names) plus `etc-be-BOP/`, `var-lib-phoenixd/` (seed!), `bucket/` (Garage
   objects), and `mongo-dump/` (a `mongodump` of the per-tenant DB).
4. To revive on the same or a fresh host: re-add the tenant, then restore
   files into the new layout. There is no automated `restore-tenant.sh` yet
   (see [Roadmap](#roadmap)).

### Rotate OVH credentials

1. Update `/etc/be-BOP-tooling/secrets.env` with the new
   `OVH_APPLICATION_KEY` / `OVH_APPLICATION_SECRET` / `OVH_CONSUMER_KEY`.
2. Update `/etc/letsencrypt/ovh.ini` (the certbot-dns-ovh credentials).
3. Run `host-bootstrap.sh` again — it's idempotent and will rewrite the ini
   from the env. No tenant restart needed.

### Change the DNS zone (e.g. pvh-labs.com → bop-prod.com)

Out of scope for the PoC. Requires a coordinated migration (issue new
certs, change `OVH_DNS_ZONE`, update every tenant's nginx vhost + config).
Leave this for v2.

---

## Limitations

- **No multi-VDS yet.** Cross-host failover, rebalancing, or live
  migration is out of scope. The PoC targets a single Contabo VDS.
- **`migrate-tenant.sh` not yet implemented.** Importing an existing
  single-host be-BOP into the multi-tenant layout is a v2 deliverable.
- **No periodic backups out of the box.** `remove-tenant.sh --archive`
  produces an encrypted bundle on demand (with mongodump + Garage sync
  + phoenixd state); periodic snapshots are still the operator's
  responsibility (cron + rclone + mongodump).

---

## Roadmap

| Item                                         | Phase   |
|----------------------------------------------|---------|
| `restore-tenant.sh` from SFTP archive        | v2      |
| `migrate-tenant.sh` from a single-host setup | v2      |
| Multi-VDS / failover                         | v3      |
| Rate-limit per tenant (nginx)                | v2      |
| Automated phoenixd seed off-host backup      | v2      |

---

## License

AGPL-3.0-only. Same as the upstream `be-BOP-tooling`.
