# upgrade-all.sh

Upgrade many be-BOP tenants in one shot.

## Usage

```bash
upgrade-all.sh [options]
```

Options:
- `--version <tag>` — release tag, or `latest` (default)
- `--rolling` — one tenant at a time (default), wait for healthcheck
- `--parallel` — all selected tenants concurrently
- `--filter <regex>` — only tenants whose `tenant_id` matches
- `--continue-on-failure` — in `--rolling`, don't abort on the first
  error
- `--secrets-file`, `--non-interactive`, `--dry-run`, `--verbose`

## Selection

The script lists every tenant in `active` state from the registry, then
filters by `--filter` if provided (matched with `grep -E`). Soft-deleted
and archived tenants are silently skipped.

## Modes

### `--rolling` (default)

Sequential. Each tenant is upgraded and healthchecked before the next is
started. Stops at the first failure unless `--continue-on-failure` is
set.

Use this for production fleets: at most one tenant is being restarted at
a time, total downtime stays bounded per tenant.

### `--parallel`

Launches `upgrade-tenant.sh` for every selected tenant in the
background, then waits for them all. Wall-clock is shorter for large
fleets but downtime overlaps across tenants — every tenant is
unavailable during its restart, simultaneously.

Use this for staging/test environments or coordinated maintenance
windows.

## Final summary

Both modes print a summary line listing succeeded and failed tenants,
then send:
- one Zulip success notice if all succeeded, or
- one SMTP+Zulip failure alert listing the failed tenants if any failed
  (and the script exits 1).

Each individual `upgrade-tenant.sh` invocation also sends its own
notification — the wrap-up here is in addition.

## Examples

```bash
# Upgrade every active tenant to latest, one by one:
upgrade-all.sh

# Upgrade only "preprod*" tenants in parallel:
upgrade-all.sh --parallel --filter '^preprod'

# Pin every tenant to a specific tag, sequential, and don't stop on errors:
upgrade-all.sh --version be-BOP.release.2026-04-15.abc1234 --continue-on-failure
```
