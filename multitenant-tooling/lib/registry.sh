# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 be-bop.io contributors
#
# registry.sh — manage /var/lib/be-BOP/tenants.tsv (tab-separated tenant registry).
#
# Schema (header row, 10 columns):
#   tenant_id       — slug, [a-z0-9][a-z0-9-]*, max 32 chars
#   domain          — full FQDN, e.g. tenant1.pvh-labs.com
#   bebop_port      — local port for be-BOP HTTP (≥ 3001)
#   phoenixd_port   — local port for phoenixd HTTP API (≥ 9741)
#   mongodb_database — DB name on OVH Managed Mongo, e.g. bebop_tenant1
#   garage_bucket   — bucket name, e.g. bebop-tenant1
#   garage_key      — Garage access key name, e.g. bebop-tenant1-key
#   bebop_version   — installed release tag (or empty until first install completes)
#   created_at      — RFC 3339 UTC timestamp of initial activation
#   status          — active | soft-deleted | archived
#
# Status semantics:
#   active        — tenant is running; reserves its ports
#   soft-deleted  — services off, DNS removed, but data + config + ports preserved
#   archived      — data uploaded to SFTP and locally purged; row may be removed
#                   after retention; ports are released
#
# registry_get_status returns "absent" for tenants not present in the file;
# "absent" is never written.
#
# Concurrency: registry_lock / registry_unlock wrap an flock(2) on a sibling
# lock file. All mutations (registry_add, registry_set_field, registry_remove)
# require the caller to hold the lock.
#
# Source this AFTER lib/log.sh and lib/sudo.sh.

[[ -n "${_BEBOP_REGISTRY_SOURCED:-}" ]] && return 0
readonly _BEBOP_REGISTRY_SOURCED=1

: "${REGISTRY_PATH:=/var/lib/be-BOP/tenants.tsv}"
: "${REGISTRY_LOCK_PATH:=/var/lib/be-BOP/.tenants.tsv.lock}"
: "${REGISTRY_BEBOP_PORT_MIN:=3001}"
: "${REGISTRY_PHOENIXD_PORT_MIN:=9741}"

readonly REGISTRY_HEADER=$'tenant_id\tdomain\tbebop_port\tphoenixd_port\tmongodb_database\tgarage_bucket\tgarage_key\tbebop_version\tcreated_at\tstatus'

_registry_col_index() {
    case "$1" in
        tenant_id)         echo 1 ;;
        domain)            echo 2 ;;
        bebop_port)        echo 3 ;;
        phoenixd_port)     echo 4 ;;
        mongodb_database)  echo 5 ;;
        garage_bucket)     echo 6 ;;
        garage_key)        echo 7 ;;
        bebop_version)     echo 8 ;;
        created_at)        echo 9 ;;
        status)            echo 10 ;;
        *) die "registry: unknown field '$1'" ;;
    esac
}

registry_init() {
    if [[ ! -f "$REGISTRY_PATH" ]]; then
        run_privileged install -d -m 0755 "$(dirname "$REGISTRY_PATH")"
        printf '%s\n' "$REGISTRY_HEADER" | run_privileged tee "$REGISTRY_PATH" >/dev/null
        run_privileged chmod 0644 "$REGISTRY_PATH"
        log_info "registry: created $REGISTRY_PATH"
    else
        log_debug "registry: $REGISTRY_PATH already exists"
    fi
    if [[ ! -f "$REGISTRY_LOCK_PATH" ]]; then
        run_privileged install -d -m 0755 "$(dirname "$REGISTRY_LOCK_PATH")"
        run_privileged touch "$REGISTRY_LOCK_PATH"
        run_privileged chmod 0644 "$REGISTRY_LOCK_PATH"
    fi
}

registry_lock() {
    if [[ -n "${_REGISTRY_FD:-}" ]]; then
        die "registry: lock already held in this process"
    fi
    exec {_REGISTRY_FD}>"$REGISTRY_LOCK_PATH"
    if ! flock -x -w 30 "$_REGISTRY_FD"; then
        die "registry: could not acquire lock on $REGISTRY_LOCK_PATH within 30s"
    fi
    log_debug "registry: lock acquired (fd=$_REGISTRY_FD)"
}

registry_unlock() {
    if [[ -z "${_REGISTRY_FD:-}" ]]; then
        return 0
    fi
    flock -u "$_REGISTRY_FD" 2>/dev/null || true
    eval "exec ${_REGISTRY_FD}>&-"
    unset _REGISTRY_FD
    log_debug "registry: lock released"
}

# Output the value of <field> for <tenant_id>, or empty if absent.
registry_get_field() {
    local tenant_id="$1" field="$2"
    local col
    col="$(_registry_col_index "$field")"
    awk -F'\t' -v t="$tenant_id" -v c="$col" \
        'NR>1 && $1==t { print $c; exit }' \
        "$REGISTRY_PATH"
}

# Return one of: active | soft-deleted | archived | absent.
registry_get_status() {
    local tenant_id="$1" s
    s="$(registry_get_field "$tenant_id" status)"
    if [[ -z "$s" ]]; then
        echo "absent"
    else
        echo "$s"
    fi
}

# Print all tenant_ids in the registry that match <status> (default: active).
registry_list_by_status() {
    local status="${1:-active}"
    awk -F'\t' -v s="$status" 'NR>1 && $10==s { print $1 }' "$REGISTRY_PATH"
}

# Allocate the smallest free port ≥ minimum, skipping ports reserved by tenants
# in states that hold their port (active, soft-deleted). Archived tenants
# release their ports.
# Args: kind = bebop | phoenixd
registry_allocate_port() {
    local kind="$1" col min_port
    case "$kind" in
        bebop)    col=3; min_port="$REGISTRY_BEBOP_PORT_MIN" ;;
        phoenixd) col=4; min_port="$REGISTRY_PHOENIXD_PORT_MIN" ;;
        *) die "registry_allocate_port: unknown kind '$kind' (expected bebop|phoenixd)" ;;
    esac
    local -A used=()
    local port
    while IFS= read -r port; do
        [[ -n "$port" ]] && used["$port"]=1
    done < <(awk -F'\t' -v c="$col" \
        'NR>1 && ($10=="active" || $10=="soft-deleted") { print $c }' \
        "$REGISTRY_PATH")
    local p="$min_port"
    while [[ -n "${used[$p]:-}" ]]; do
        p=$((p+1))
    done
    echo "$p"
}

# Append a new row. Caller must hold the lock.
# Args (10): tenant_id domain bebop_port phoenixd_port mongodb_database
#            garage_bucket garage_key bebop_version created_at status
registry_add() {
    if (( $# != 10 )); then
        die "registry_add: expected 10 args, got $#"
    fi
    local tenant_id="$1" status="${10}"
    local row
    row="$(IFS=$'\t'; echo "$*")"
    printf '%s\n' "$row" | run_privileged tee -a "$REGISTRY_PATH" >/dev/null
    log_info "registry: added tenant '$tenant_id' (status=$status)"
}

# Replace the value of <field> for <tenant_id>. Caller must hold the lock.
registry_set_field() {
    local tenant_id="$1" field="$2" new_value="$3"
    local col
    col="$(_registry_col_index "$field")"
    if [[ "$(registry_get_status "$tenant_id")" == "absent" ]]; then
        die "registry_set_field: tenant '$tenant_id' not in registry"
    fi
    local tmp
    tmp="$(mktemp)"
    awk -F'\t' -v OFS='\t' -v t="$tenant_id" -v c="$col" -v v="$new_value" \
        'NR==1 { print; next }
         $1==t { $c = v; print; next }
         { print }' \
        "$REGISTRY_PATH" > "$tmp"
    run_privileged install -m 0644 "$tmp" "$REGISTRY_PATH"
    rm -f "$tmp"
    log_debug "registry: set $tenant_id.$field = '$new_value'"
}

registry_set_status() {
    registry_set_field "$1" status "$2"
}

# Remove a tenant row entirely. Caller must hold the lock.
registry_remove() {
    local tenant_id="$1"
    if [[ "$(registry_get_status "$tenant_id")" == "absent" ]]; then
        die "registry_remove: tenant '$tenant_id' not in registry"
    fi
    local tmp
    tmp="$(mktemp)"
    awk -F'\t' -v t="$tenant_id" \
        'NR==1 || $1!=t' \
        "$REGISTRY_PATH" > "$tmp"
    run_privileged install -m 0644 "$tmp" "$REGISTRY_PATH"
    rm -f "$tmp"
    log_info "registry: removed tenant '$tenant_id'"
}
