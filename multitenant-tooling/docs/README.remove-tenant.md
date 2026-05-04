# remove-tenant.sh

Wind down a be-BOP tenant. Three modes; default is the safest.

## Usage

```bash
remove-tenant.sh <tenant_id> [options]
```

Modes (mutually exclusive):
- (default) **soft-delete** — services off, DNS + vhost removed, data
  preserved
- `--archive` — soft-delete + encrypted archive to SFTP + drop everything
  except OVH-managed Mongo backups
- `--purge` — destroy everything immediately (no archive)

Other: `--i-know-what-im-doing` (skip the interactive confirmation for
`--purge` in `--non-interactive` mode), `--secrets-file`, `--dry-run`,
`--verbose`.

## Mode 1 — soft-delete (default)

Reversible, idempotent.

1. `systemctl disable --now bebop@<id>.service phoenixd@<id>.service`
2. `rm /etc/nginx/sites-enabled/bebop-<id>.conf` (`sites-available` kept)
3. `nginx -t && systemctl reload nginx`
4. Delete A records for `<id>.<zone>` and `s3.<id>.<zone>` via OVH API
5. `kuma_unregister_tenant` (manual stub: prints operator instructions)
6. `registry_set_status <id> soft-deleted`

**Preserved:** Mongo DB, Garage bucket + key, phoenixd seed (CRITICAL),
the entire `/var/lib/be-BOP/<id>/` and `/etc/be-BOP/<id>/` trees.
**Ports stay reserved** so you can `add-tenant.sh <id> --reactivate` and
get the same ports back.

## Mode 2 — archive

Irreversible from the local machine, but the encrypted bundle on SFTP
contains everything you need to rebuild elsewhere except the Mongo data.

Steps:

1. Soft-delete (services off, DNS gone, vhost disabled).
2. Build a workspace under `/var/tmp/bebop-archive-<id>-<ts>/` with:
   - `etc-be-BOP/` — copy of `/etc/be-BOP/<id>/` (config.env, …)
   - `var-lib-phoenixd/` — copy of `/var/lib/phoenixd/<id>/` (seed!)
   - `bucket/` — Garage bucket dumped via rclone S3 → local
   - `metadata.json` — tenant id, version, ports, db/bucket/key names
3. Tar + gzip + AES-256-CBC (PBKDF2, 100k iters), key from
   `BACKUP_ENCRYPTION_KEY`. Compute SHA-256.
4. Upload archive + sha to SFTP via rclone.
5. Drop external resources: certbot delete, nginx vhost, DNS, Mongo
   DB + user, Garage bucket + key, then `rm -rf` the tenant filesystem
   trees.
6. `registry_set_status <id> archived` (registry row preserved for audit).

**Mongo data is NOT in the archive.** OVH Managed Mongo runs daily
provider-side backups — restore from there if you need point-in-time
recovery for the tenant's collections.

### Restoring from an archive

There is no `restore-tenant.sh` yet. Manual procedure:

```bash
# 1. Pull from SFTP (operator)
sftp user@sftp-host:/path/bebop-archive-tenantX-YYYY...tar.gz.enc
sftp user@sftp-host:/path/bebop-archive-tenantX-YYYY...tar.gz.enc.sha256
sha256sum -c bebop-archive-tenantX-...tar.gz.enc.sha256    # verify

# 2. Decrypt + extract
openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 \
  -in bebop-archive-tenantX-YYYY...tar.gz.enc \
  -out bebop-archive-tenantX.tar.gz \
  -pass "pass:${BACKUP_ENCRYPTION_KEY}"        # same key as the source host
tar -xzf bebop-archive-tenantX.tar.gz -C ./restore/
cat restore/metadata.json   # version, ports, db/bucket names, …

# 3. On the target host, recreate the shell of the tenant:
add-tenant.sh tenantX --admin-email <merchant>      # or with --bebop-version <tag from metadata>
remove-tenant.sh tenantX                            # immediately soft-delete

# 4. Restore data on top of the soft-deleted shell:
sudo cp -a restore/etc-be-BOP/. /etc/be-BOP/tenantX/
sudo cp -a restore/var-lib-phoenixd/. /var/lib/phoenixd/tenantX/
# Garage bucket: re-upload via rclone copy local restore/bucket/ → garage:bebop-tenantX/

# 5. Bring it back up:
add-tenant.sh tenantX --admin-email <merchant> --reactivate
```

If you need the Mongo data, restore the OVH Managed Mongo backup
*before* step 5 so the tenant comes up against the right collections.

## Mode 3 — purge

No archive, no recovery. Refuses to act unless:
- (interactive) You type the tenant_id when prompted to confirm.
- (`--non-interactive`) You also pass `--i-know-what-im-doing`.

Order of destruction matches `--archive`'s post-archive cleanup:
certbot delete, nginx vhost, DNS, Mongo, Garage, local files,
registry row. The tenant_id and ports are released for reuse.

## Operator-visible side effects

| Resource                  | soft-delete | archive | purge |
|---------------------------|:-----------:|:-------:|:-----:|
| Services stopped          | yes         | yes     | yes   |
| DNS A records             | removed     | removed | removed |
| nginx vhost (sites-enabled link) | removed | removed (file too) | removed (file too) |
| Let's Encrypt cert        | kept        | deleted | deleted |
| Mongo DB + user (OVH)     | kept        | dropped | dropped |
| Garage bucket + key       | kept        | dropped | dropped |
| `/var/lib/be-BOP/<id>/`   | kept        | dropped | dropped |
| `/etc/be-BOP/<id>/`       | kept        | dropped | dropped |
| `/var/lib/phoenixd/<id>/` (seed!) | kept | dropped (in archive) | dropped (LOST FOREVER) |
| Registry row              | status=soft-deleted | status=archived | row removed |
| Encrypted SFTP archive    | —           | uploaded | —    |

## Failure recovery

If `--archive` fails partway (e.g. SFTP unreachable after the local
workspace is built), the script aborts before deleting external
resources. Tenant is left in `soft-deleted` state. Re-run after fixing
the SFTP issue.

If purge fails partway, manual cleanup of the half-deleted resources is
needed; rerun `remove-tenant.sh <id> --purge` to retry every step
idempotently.
