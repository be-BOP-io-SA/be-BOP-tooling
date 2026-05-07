# add-tenant.sh

Onboard a new be-BOP tenant. Transactional with automatic rollback when a
fresh creation fails.

## Usage

```bash
add-tenant.sh <tenant_id> --admin-email <email> [options]
```

Options:
- `--no-phoenixd` — don't run a phoenixd Lightning daemon for this tenant
- `--bebop-version <tag>` — pick a specific GitHub release (default: `latest`)
- `--reactivate` — restore a soft-deleted tenant (preserves data)
- `--secrets-file <path>` — non-default secrets.env
- `--non-interactive`, `--dry-run`, `--verbose`, `--help`

## Status semantics

`add-tenant.sh` reads the registry to decide what to do:

| Current status   | Default behaviour                       | With `--reactivate`              |
|------------------|------------------------------------------|----------------------------------|
| `absent`         | full creation, 14 phases with rollback   | (same — flag is ignored)         |
| `active`         | idempotent re-apply (rewrite config + vhost, restart on drift) | (same)         |
| `soft-deleted`   | **refuses**, suggests `--reactivate` or purge | restores DNS + vhost + services + Kuma; preserves data + ports |
| `archived`       | **always refuses** (data has been off-loaded) | (same)                           |

## The 14 phases (fresh creation)

```
 1. status decision         — read registry, branch
 2. derive identifiers      — domain, ports (incl. mongo), bucket+key names, mongo db
 3. DNS records             — POST 2× A records via OVH, refresh zone
 4. local mongod            — write port.env, systemctl enable --now mongod@<id>,
                              wait ready, rs.initiate() (single-node rs0)
 5. Garage                  — bucket create, key create, allow rwO, set quota
 6. directory skeleton      — /var/lib/be-BOP/<id>/, /etc/be-BOP/<id>/, …
 7. release                 — download + extract + pnpm install + symlink
 8. phoenixd                — write port.env, start phoenixd@<id>, read http-password
 9. config.env              — render template with all secrets
10. certificate             — certbot DNS-01 OVH, 2 SANs (<id> + s3.<id>)
11. nginx vhost             — render template, symlink sites-enabled, reload
12. bebop service           — systemctl enable --now bebop@<id>
13. healthcheck             — curl https://<id>.<zone>/ until 2xx (15× 2s)
14. Kuma + registry         — print Kuma manual instruction, write tenants.tsv row
```

If any phase fails, every step taken so far is undone in reverse order
(see `lib/transaction.sh`). The script then notifies the operator via SMTP
and Zulip with the failed phase, exit code, and undo report.

## Reactivation flow

When called with `--reactivate` against a `soft-deleted` tenant:

- Phases 5 (Garage), 6 (directories), 7 (release),
  8 (phoenixd port.env / seed) are **skipped** — those resources are
  already there.
- Phase 4 collapses to `systemctl enable --now mongod@<id>` (no
  rs.initiate; the replica set is already initialised on the preserved
  dbPath).
- Phases 3 (DNS), 9 (rewrite config.env from preserved values), 10 (cert
  is idempotent — skipped if already issued), 11 (vhost), 12 (services),
  13 (healthcheck), 14 (registry → status=active) **do** run.
- Garage key secret + phoenixd password: re-read from preserved
  `config.env`. MONGODB_URL is re-derived from the registry's mongo_port
  + mongodb_database (deterministic, no creds to pull).

## Idempotent re-apply

Running `add-tenant.sh tenant1 --admin-email …` against an already-active
tenant rewrites `/etc/be-BOP/<id>/config.env` and the nginx vhost from
templates, and restarts the bebop service. Mongo, Garage, phoenixd seeds:
untouched. Use this to apply a config-template change uniformly across
existing tenants.

The scissor marker (`# >8`) in `config.env` lets operators add custom env
vars below the marker — they are preserved across re-runs.

## Operator-facing output (sensitive)

On a fresh creation with phoenixd enabled, the script prints at the end:

```
==== TRANSMIT TO MERCHANT (sensitive) ====
phoenixd HTTP password:   <random-string>
phoenixd seed (hex):      <128 hex chars>
```

These control the merchant's Lightning wallet. Hand them off through your
secure channel and back the seed up off-host (encrypted) immediately —
losing the seed loses the funds.

## Rollback model

The transaction stack records an undo command after each successful step:

```
DNS A record <id>      → ovh_dns_record_delete + zone refresh
DNS A record s3.<id>   → ovh_dns_record_delete + zone refresh
mongod port.env        → rm -rf /etc/be-BOP-mongodb/<id>/
mongod@<id>.service    → systemctl disable --now + rm -rf /var/lib/be-BOP-mongodb/<id>/
Garage bucket          → garage_bucket_delete <bucket>
Garage key             → garage_key_delete <key>
tenant directory tree  → rm -rf /var/lib/... /etc/be-BOP/<id>/ ...
release <tag>          → rm -rf /var/lib/be-BOP/<id>/releases/<tag>/
phoenixd port.env      → rm /etc/phoenixd/<id>/port.env
phoenixd@<id>.service  → systemctl disable --now
config.env             → rm
Let's Encrypt cert     → certbot delete --cert-name bebop-<id>
nginx vhost            → rm sites-{available,enabled} + reload
bebop@<id>.service     → systemctl disable --now
```

Rollback walks the stack in reverse. Individual undo failures are logged
but don't abort the rollback.

## Failure recovery

| Symptom                                          | What to do                                |
|--------------------------------------------------|-------------------------------------------|
| Script exited mid-phase, rollback succeeded      | Fix the underlying cause (e.g. OVH DNS API outage) and re-run `add-tenant.sh` from scratch |
| `mongod@<id> did not become ready within 60s`    | Check `journalctl -u mongod@<id>`; usually a port collision, dbPath permissions, or AVX-missing CPU. |
| Rollback also failed (network glitch)            | Check the alert email/Zulip for the list of un-undone steps; clean them by hand or via `remove-tenant.sh --purge` then re-run |
| `cert: timeout waiting for DNS-01 propagation`   | Re-run; OVH propagation is usually < 60 s but can spike. Or increase `--dns-ovh-propagation-seconds` in phase_certificate (currently 60). |
| `pnpm install failed`                            | Network or disk issue. Check `journalctl -t bebop-tooling-add-tenant`, fix, re-run. |
| `healthcheck failed for https://<id>.<zone>/`    | Service crashed at startup. Check `journalctl -u bebop@<id>` and `journalctl -u phoenixd@<id>`. The rollback will still complete. |

## Concurrency

The registry is `flock`-locked for the whole duration of the script. Two
`add-tenant.sh` processes for two different tenants can be run
simultaneously **as long as** they are launched a few seconds apart so
each acquires the lock cleanly — they will queue otherwise (30 s
timeout). Don't try to launch 10 in parallel from a script; iterate or
use `upgrade-all.sh --parallel` as a model.
