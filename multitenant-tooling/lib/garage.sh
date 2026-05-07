# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 be-bop.io contributors
#
# garage.sh — wrappers around the local `garage` CLI for bucket and key ops.
# Operates on the singleton Garage instance set up by host-bootstrap.sh
# (binds 127.0.0.1, no public socket; nginx is the only public face).
#
# Source AFTER lib/log.sh and lib/sudo.sh.

[[ -n "${_BEBOP_GARAGE_SOURCED:-}" ]] && return 0
readonly _BEBOP_GARAGE_SOURCED=1

# garage_bucket_exists <bucket>
garage_bucket_exists() {
    run_privileged garage bucket info "$1" >/dev/null 2>&1
}

# garage_bucket_create <bucket>
# Idempotent: no-op if the bucket already exists.
garage_bucket_create() {
    local bucket="$1"
    if garage_bucket_exists "$bucket"; then
        log_info "garage: bucket '${bucket}' already exists"
        return 0
    fi
    run_privileged garage bucket create "$bucket"
    log_info "garage: created bucket '${bucket}'"
}

# garage_bucket_delete <bucket>
# Idempotent: no-op if the bucket is already gone.
garage_bucket_delete() {
    local bucket="$1"
    if ! garage_bucket_exists "$bucket"; then
        log_warn "garage: bucket '${bucket}' absent, nothing to delete"
        return 0
    fi
    run_privileged garage bucket delete --yes "$bucket"
    log_info "garage: deleted bucket '${bucket}'"
}

# garage_bucket_set_quota <bucket> <max_size>   e.g. 20GiB
# Pass "none" as max_size to remove the limit.
garage_bucket_set_quota() {
    local bucket="$1" max_size="$2"
    run_privileged garage bucket set-quotas --max-size "$max_size" "$bucket"
    log_info "garage: bucket '${bucket}' quota set to ${max_size}"
}

# garage_key_exists <key_name>
garage_key_exists() {
    run_privileged garage key info "$1" >/dev/null 2>&1
}

# garage_key_create <key_name>
# On first creation, prints "<access_key_id>\t<secret_access_key>" on stdout.
# Refuses to recreate an existing key (the secret is only revealed at create
# time; if you've lost the secret you must rotate via `garage key delete`).
garage_key_create() {
    local key="$1"
    if garage_key_exists "$key"; then
        die "garage_key_create: key '${key}' already exists; refusing to recreate (would lose secret). Delete + recreate explicitly if rotation is intended."
    fi
    local out
    out=$(run_privileged garage key create "$key")
    local key_id key_secret
    key_id=$(printf '%s\n' "$out" \
        | grep -iE '^(Key ID|Access key ID)' \
        | head -1 \
        | sed -E 's/^[^:]+:[[:space:]]*//')
    key_secret=$(printf '%s\n' "$out" \
        | grep -iE '^(Secret key|Secret access key)' \
        | head -1 \
        | sed -E 's/^[^:]+:[[:space:]]*//')
    if [[ -z "$key_id" || -z "$key_secret" ]]; then
        die "garage_key_create: could not parse output of 'garage key create ${key}':"$'\n'"$out"
    fi
    log_info "garage: created key '${key}' (id=${key_id})"
    printf '%s\t%s\n' "$key_id" "$key_secret"
}

# garage_key_delete <key_name>
# Idempotent.
garage_key_delete() {
    local key="$1"
    if ! garage_key_exists "$key"; then
        log_warn "garage: key '${key}' absent, nothing to delete"
        return 0
    fi
    run_privileged garage key delete --yes "$key"
    log_info "garage: deleted key '${key}'"
}

# garage_bucket_grant <bucket> <key_name> [perm ...]
# Permissions are any subset of: read write owner. Default = read+write+owner.
garage_bucket_grant() {
    local bucket="$1" key="$2"
    shift 2
    local args=()
    if (( $# == 0 )); then
        args=(--read --write --owner)
    else
        local perm
        for perm in "$@"; do
            case "$perm" in
                read)  args+=(--read) ;;
                write) args+=(--write) ;;
                owner) args+=(--owner) ;;
                *) die "garage_bucket_grant: unknown permission '${perm}' (expected read|write|owner)" ;;
            esac
        done
    fi
    run_privileged garage bucket allow "${args[@]}" --key "$key" "$bucket"
    log_info "garage: granted ${args[*]} on '${bucket}' to key '${key}'"
}

# garage_bucket_revoke <bucket> <key_name>
# Removes ALL of read/write/owner from <key_name> on <bucket>.
garage_bucket_revoke() {
    local bucket="$1" key="$2"
    run_privileged garage bucket deny --read --write --owner --key "$key" "$bucket" || true
    log_info "garage: revoked all perms on '${bucket}' from key '${key}'"
}
