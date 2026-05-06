# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 be-bop.io contributors
#
# mongo.sh — wrappers around per-tenant local mongod instances.
#
# Architecture (option B): one mongod per tenant, all bound to 127.0.0.1 on
# distinct local ports, each with its own dbPath at /var/lib/be-BOP-mongodb/<i>.
# Each instance is a single-node replica set named rs0 (Mongo requires a
# replica set for transactions and change streams).
#
# Tenant isolation is enforced at the process / filesystem level (DynamicUser
# + StateDirectory in mongod@.service), so mongod auth is NOT enabled. Each
# instance is its own bubble; no cross-tenant data path exists.
#
# Source AFTER lib/log.sh and lib/sudo.sh.
# Requires: mongosh (apt install mongodb-mongosh).

[[ -n "${_BEBOP_MONGO_SOURCED:-}" ]] && return 0
readonly _BEBOP_MONGO_SOURCED=1

: "${MONGO_RS_NAME:=rs0}"

# mongo_wait_ready <port> [retries=60] [interval_sec=1]
# Polls db.adminCommand('ping') until the mongod on <port> answers OK.
# Returns 0 on success, 1 on timeout.
mongo_wait_ready() {
    local port="$1" retries="${2:-60}" interval="${3:-1}"
    local i
    for (( i=1; i<=retries; i++ )); do
        if mongosh --quiet --port "$port" --eval "db.adminCommand('ping')" >/dev/null 2>&1; then
            log_debug "mongo_wait_ready: 127.0.0.1:${port} ready (try ${i}/${retries})"
            return 0
        fi
        log_debug "mongo_wait_ready: 127.0.0.1:${port} not ready (try ${i}/${retries})"
        (( i < retries )) && sleep "$interval"
    done
    log_error "mongo_wait_ready: 127.0.0.1:${port} did not respond within $((retries * interval))s"
    return 1
}

# mongo_init_rs <port>
# Idempotent: skips if rs.status() is already OK on the target instance.
mongo_init_rs() {
    local port="$1"
    local status
    status=$(mongosh --quiet --port "$port" --eval "rs.status().ok" 2>/dev/null \
        | tr -d '[:space:]' | tail -c 1)
    if [[ "$status" == "1" ]]; then
        log_info "mongo: replica set on 127.0.0.1:${port} already initialised ✓"
        return 0
    fi
    log_info "mongo: initialising replica set on 127.0.0.1:${port}..."
    local cfg out
    cfg=$(printf '{_id: "%s", members: [{_id: 0, host: "127.0.0.1:%s"}]}' \
        "$MONGO_RS_NAME" "$port")
    out=$(mongosh --quiet --port "$port" --eval "rs.initiate(${cfg})" 2>&1) || true
    # rs.initiate() sometimes "fails" but actually succeeds; double-check by
    # polling rs.status().ok within a short window.
    local i
    for (( i=1; i<=10; i++ )); do
        status=$(mongosh --quiet --port "$port" --eval "rs.status().ok" 2>/dev/null \
            | tr -d '[:space:]' | tail -c 1)
        [[ "$status" == "1" ]] && { log_info "mongo: rs OK on 127.0.0.1:${port}"; return 0; }
        sleep 1
    done
    die "mongo_init_rs: could not initialise replica set on 127.0.0.1:${port}: ${out}"
}

# mongo_build_url <port> <db_name>
# Outputs the mongodb:// URL be-BOP can consume.
mongo_build_url() {
    local port="$1" db="$2"
    printf 'mongodb://127.0.0.1:%s/%s?replicaSet=%s\n' "$port" "$db" "$MONGO_RS_NAME"
}

# mongo_db_drop <port> <db_name>
# Drops the named DB on the mongod listening on <port>. Idempotent (Mongo
# returns ok even if the DB doesn't exist).
mongo_db_drop() {
    local port="$1" db="$2"
    if ! mongosh --quiet --port "$port" --eval \
        "db.getSiblingDB('${db}').dropDatabase()" >/dev/null 2>&1; then
        log_warn "mongo_db_drop: dropDatabase('${db}') on 127.0.0.1:${port} returned non-zero"
        return 1
    fi
    log_info "mongo: dropped database '${db}' on 127.0.0.1:${port}"
}

# mongo_dump_db <port> <db_name> <out_dir>
# Runs mongodump for a single DB into <out_dir>. Caller is responsible for
# creating <out_dir> ahead of time. Requires mongodump (mongodb-database-tools).
mongo_dump_db() {
    local port="$1" db="$2" out="$3"
    if ! command -v mongodump >/dev/null 2>&1; then
        log_warn "mongo_dump_db: mongodump not installed (apt install mongodb-database-tools); skipping"
        return 1
    fi
    log_info "mongo: mongodump db='${db}' port=${port} → ${out}"
    mongodump --quiet --port "$port" --db "$db" --out "$out"
}
