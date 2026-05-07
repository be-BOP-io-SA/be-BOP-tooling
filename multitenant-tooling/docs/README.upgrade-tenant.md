# upgrade-tenant.sh

Upgrade a single be-BOP tenant to a new release.

## Usage

```bash
upgrade-tenant.sh <tenant_id> [options]
```

Options:
- `--version <tag>` — GitHub release tag, or `latest` (default)
- `--no-rollback-on-failure` — keep the new release even if the
  healthcheck fails (default: rollback enabled)
- `--secrets-file <path>`, `--non-interactive`, `--dry-run`, `--verbose`

The tenant must be in `active` status. Soft-deleted/archived tenants are
refused.

## Steps

1. **Resolve version.** `latest` → most recent release on
   `BEBOP_GITHUB_REPO` (default `be-BOP-io-SA/be-BOP`) whose asset
   matches `be-BOP\.release\.YYYY-MM-DD\.<sha>.*\.zip`. Any other
   string is taken as a concrete tag and validated to exist.
2. **Note the current tag** (read from
   `/var/lib/be-BOP/<id>/releases/current` symlink). If equal to the
   target, exit early — nothing to do.
3. **Download + extract + pnpm install** the new release into
   `/var/lib/be-BOP/<id>/releases/<new_tag>/`.
4. **Atomic symlink swap.** `current` → new_tag.
5. `systemctl restart bebop@<id>.service`.
6. **HTTP healthcheck** on `https://<id>.<zone>/` for 30 s (15 attempts
   × 2 s).
7. On healthcheck failure:
   - **with rollback (default):** swap symlink back to old tag, restart,
     re-run healthcheck. Either way, exit 1 and notify operators.
   - **with `--no-rollback-on-failure`:** leave the new release
     in place (operator will investigate manually), exit 1.
8. On success: write `bebop_version=<new_tag>` into the registry and
   send a one-line Zulip success notice.

## Idempotence

Running with the same `--version` as the current release is a no-op
(early exit). Running again after a failed run is safe — the release
download is content-addressed by tag, the marker file
(`.bebop_install_success`) skips already-installed deps.

## Failure modes

| Failure                                         | What happens                                               |
|-------------------------------------------------|------------------------------------------------------------|
| Tag doesn't exist on GitHub                      | Aborts before any state change                              |
| Download fails                                   | Aborts before symlink swap                                  |
| `pnpm install` fails                             | Aborts before symlink swap                                  |
| `systemctl restart` fails                        | Continues to healthcheck; may rollback                      |
| Healthcheck fails, rollback ON                   | Symlink reverts, service restarts on old tag, exit 1        |
| Healthcheck fails, rollback OFF                  | Symlink stays, service may be down, exit 1, alert sent      |
| Rollback ALSO fails healthcheck                  | Service is broken; check `journalctl -u bebop@<id>` urgently|

## Alerting

- Success: brief Zulip-only notice (no SMTP — avoid mail spam).
- Failure: SMTP **and** Zulip with rollback status and pointer to
  journald.

## Disk usage

Old releases under `/var/lib/be-BOP/<id>/releases/<tag>/` are NOT
auto-pruned — keeping them allows fast rollback and audit. Operator
should periodically `rm -rf` releases older than the retention horizon.
A future `prune-releases.sh` script will automate this; today it's
manual.
