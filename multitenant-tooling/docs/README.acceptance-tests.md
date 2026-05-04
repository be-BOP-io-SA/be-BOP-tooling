# Acceptance test plan

Operator-driven runbook for validating the PoC against a fresh Contabo
VDS (Debian 12, ≥ 4 GiB RAM, ≥ 40 GiB disk recommended for 10 tenants).

The 10 tests below mirror the 10 acceptance criteria from the original
PoC spec. Run them in order. Each `EXPECT:` line is the pass condition.

## Setup

```bash
# On a newly provisioned VDS
ssh root@your-contabo-vds
git clone https://github.com/Tirodem/be-BOP-tooling.git
cd be-BOP-tooling && git checkout multitenant-poc

# Prepare secrets
mkdir -p /etc/be-BOP-tooling
cp multitenant-tooling/templates/secrets.env.example /etc/be-BOP-tooling/secrets.env
chmod 600 /etc/be-BOP-tooling/secrets.env
nano /etc/be-BOP-tooling/secrets.env       # fill in OVH, SMTP, Zulip, SFTP, BACKUP_ENCRYPTION_KEY
```

---

## Test 1 — host-bootstrap.sh on a vierge VDS

```bash
multitenant-tooling/host-bootstrap.sh --verbose
```

EXPECT: exit 0; final summary printed; `garage status` works;
`systemctl is-active nginx netdata bebop-uptime-kuma` returns active for
all (the kuma container is `bebop-uptime-kuma`).

Manual operator step: `ssh -L 8810:localhost:8810 vds`, open
`http://localhost:8810`, create admin, configure mail + Zulip
notification channels.

## Test 2 — add-tenant.sh tenant1 in < 5 min

```bash
time add-tenant.sh tenant1 --admin-email test1@pvh-labs.com --verbose
```

EXPECT: total wall-clock < 5 min on a normal-bandwidth host;
`https://tenant1.pvh-labs.com/` returns 200; the script's final block
shows the phoenixd HTTP password and seed for handoff.

```bash
curl -sI https://tenant1.pvh-labs.com/ | head -1            # HTTP/2 200
systemctl is-active bebop@tenant1 phoenixd@tenant1          # active active
```

## Test 3 — sequential and parallel tenant creation up to 10

```bash
# Sequential:
for n in 2 3 4 5; do
  add-tenant.sh tenant$n --admin-email test$n@pvh-labs.com --non-interactive
done

# Parallel (registry lock will queue them — see add-tenant docs for caveats):
for n in 6 7 8 9 10; do
  add-tenant.sh tenant$n --admin-email test$n@pvh-labs.com --non-interactive &
  sleep 5     # stagger to avoid lock contention thrash
done
wait
```

EXPECT: all 10 tenants reach `active` in
`/var/lib/be-BOP/tenants.tsv`; no script exits with a non-zero status.

## Test 4 — 10 tenants running and isolated

```bash
systemctl list-units 'bebop@*.service' --no-legend --no-pager
systemctl list-units 'phoenixd@*.service' --no-legend --no-pager
ps -eo pid,user,cmd | grep -E 'pnpm run-production|phoenixd' | grep -v grep | wc -l    # ≥ 20
ss -tlnp | awk '$4 ~ /127.0.0.1:(30[0-9]+|97[0-9]+)$/ {print $4}' | sort
```

EXPECT: 10 entries each from systemd; ≥ 20 processes; 10 distinct bebop
ports + 10 distinct phoenixd ports, all bound to 127.0.0.1.

Each unit runs under a unique transient UID (DynamicUser). Verify:

```bash
for t in tenant{1..10}; do
  uid=$(systemctl show -p User bebop@$t | cut -d= -f2)
  echo "$t: User=$uid"
done | sort -u | wc -l    # 10 distinct (or all blank if systemd shows runtime UID — check journalctl instead)
```

## Test 5 — no collisions

```bash
# Distinct ports
awk -F'\t' 'NR>1 {print $3}' /var/lib/be-BOP/tenants.tsv | sort -u | wc -l    # 10
awk -F'\t' 'NR>1 {print $4}' /var/lib/be-BOP/tenants.tsv | sort -u | wc -l    # 10

# Distinct Mongo dbs / Garage buckets / cert names
awk -F'\t' 'NR>1 {print $5}' /var/lib/be-BOP/tenants.tsv | sort -u | wc -l    # 10
awk -F'\t' 'NR>1 {print $6}' /var/lib/be-BOP/tenants.tsv | sort -u | wc -l    # 10
ls /etc/letsencrypt/live | grep -c '^bebop-'                                  # 10
garage bucket list | grep -c '^bebop-'                                        # 10
```

EXPECT: `10` for every count.

## Test 6 — soft-delete, data preserved

```bash
remove-tenant.sh tenant5 --verbose
curl -sI https://tenant5.pvh-labs.com/ --max-time 5 | head -1   # 444 / connection failure / nxdomain
systemctl is-active bebop@tenant5                                # inactive
ls /var/lib/be-BOP/tenant5/releases/                              # release tree intact
ls /var/lib/phoenixd/tenant5/.phoenix/seed.dat                    # seed intact
awk -F'\t' '$1=="tenant5" {print $10}' /var/lib/be-BOP/tenants.tsv  # soft-deleted
```

EXPECT: tenant5 inactive; data on disk; status `soft-deleted` in registry.

## Test 7 — reactivate tenant5

```bash
add-tenant.sh tenant5 --admin-email test5@pvh-labs.com --reactivate --verbose
curl -sI https://tenant5.pvh-labs.com/ | head -1                 # HTTP/2 200
awk -F'\t' '$1=="tenant5" {print $10}' /var/lib/be-BOP/tenants.tsv    # active
```

EXPECT: tenant5 back online with the SAME ports, SAME bucket, SAME seed
(no rotation), same Mongo data.

## Test 8 — upgrade-tenant.sh without perceptible downtime

Pick a `--version` newer than what tenant3 currently runs (find one in
the GitHub releases). Run `curl` in a loop in a second terminal during
the upgrade.

```bash
# Terminal A
while :; do
  printf '%s ' "$(date +%H:%M:%S)"
  curl -sI -o /dev/null -w '%{http_code}' --max-time 2 https://tenant3.pvh-labs.com/
  echo
  sleep 1
done

# Terminal B
upgrade-tenant.sh tenant3 --version <NEWER_TAG> --verbose
```

EXPECT: terminal A shows ≤ 5 consecutive non-200 responses around the
restart, then back to 200. The upgrade-tenant.sh exits 0 and registry
is updated.

## Test 9 — Uptime Kuma shows 10 UP

(Manual.) In the Kuma UI, verify each tenant has a monitor; the 10
monitors are in green ✓; the configured notification channels (mail +
Zulip) appear in *Settings → Notifications*. Trigger a test alert by
stopping `bebop@tenant7.service` for 30 s; expect a mail + Zulip
within Kuma's polling interval (default 60 s).

## Test 10 — failure simulation + rollback + alert

```bash
# Pre-condition: tenant11 is absent.
add-tenant.sh tenant11 --admin-email crash@pvh-labs.com &
PID=$!
sleep 4    # let it pass phase 4 (Mongo) and start phase 5 (Garage)
kill -KILL $PID
```

EXPECT (within ~2 min):
- Mail + Zulip alert with subject `[be-BOP tooling] add-tenant tenant11 FAILED`
  (or the script may have exited cleanly via its ERR trap before SIGKILL
  could short-circuit; either way the operator gets a notification —
  if not via the trap, they will notice via the half-state).
- DNS records for `tenant11` and `s3.tenant11` are gone (or never created).
- Mongo DB `bebop_tenant11` is gone (or never created).
- Garage bucket `bebop-tenant11` is gone (or never created).
- No row for `tenant11` in `tenants.tsv` (since the row write is the LAST
  step before commit).

If `kill -KILL` (SIGKILL) is too brutal for the trap to fire, repeat with
`kill -TERM` to validate the trap path explicitly.

---

## Cleanup after testing

```bash
for n in {1..10}; do
  remove-tenant.sh tenant$n --purge --i-know-what-im-doing --non-interactive
done
# tenant11 should already be cleaned by the rollback, but if not:
remove-tenant.sh tenant11 --purge --i-know-what-im-doing --non-interactive 2>/dev/null || true
```

The host-level resources (Garage, nginx default, certbot OVH creds) are
left in place.

## What this plan does not cover

- Restoration from an SFTP archive (manual procedure, see
  `README.remove-tenant.md`).
- Cross-version migrations of be-BOP that change the config schema.
- Performance benchmarks under merchant load.
- Failure modes of OVH itself (Mongo cluster down, DNS API throttling).
