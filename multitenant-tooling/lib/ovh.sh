# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 be-bop.io contributors
#
# ovh.sh — OVH Public API client used by the multi-tenant tooling.
#
# Exposes:
#   - low-level signed HTTP:    ovh_api_call
#   - credentials sanity check: ovh_ping
#   - DNS:                      ovh_dns_record_create / _delete / _find
#                               ovh_dns_zone_refresh
#   - Managed Mongo:            ovh_mongo_db_create / _delete / _find_id
#                               ovh_mongo_user_create / _delete / _find_id
#                               ovh_mongo_wait_for_user_ready
#                               ovh_mongo_build_url
#
# Required env (typically loaded from /etc/be-BOP-tooling/secrets.env):
#   OVH_APPLICATION_KEY
#   OVH_APPLICATION_SECRET
#   OVH_CONSUMER_KEY
# DNS calls additionally need OVH_DNS_ZONE.
# Mongo calls additionally need OVH_CLOUD_PROJECT_ID, OVH_MONGO_CLUSTER_ID,
# OVH_MONGO_ENDPOINT_HOST, OVH_MONGO_ENDPOINT_PORT.
#
# Optional:
#   OVH_API_BASE_URL  default: https://eu.api.ovh.com/1.0
#
# Source AFTER lib/log.sh. Requires `jq` and `sha1sum` (both in coreutils/jq).

[[ -n "${_BEBOP_OVH_SOURCED:-}" ]] && return 0
readonly _BEBOP_OVH_SOURCED=1

: "${OVH_API_BASE_URL:=https://eu.api.ovh.com/1.0}"

_ovh_check_credentials() {
    local missing=()
    [[ -z "${OVH_APPLICATION_KEY:-}" ]]    && missing+=("OVH_APPLICATION_KEY")
    [[ -z "${OVH_APPLICATION_SECRET:-}" ]] && missing+=("OVH_APPLICATION_SECRET")
    [[ -z "${OVH_CONSUMER_KEY:-}" ]]       && missing+=("OVH_CONSUMER_KEY")
    if (( ${#missing[@]} )); then
        die "OVH API credentials missing: ${missing[*]} (check secrets.env)"
    fi
}

# OVH signature scheme: "$1$" + sha1_hex(secret+consumer+method+url+body+timestamp)
_ovh_signature() {
    local method="$1" url="$2" body="$3" timestamp="$4"
    local payload="${OVH_APPLICATION_SECRET}+${OVH_CONSUMER_KEY}+${method}+${url}+${body}+${timestamp}"
    local digest
    digest=$(printf '%s' "$payload" | sha1sum | cut -d' ' -f1)
    printf '$1$%s' "$digest"
}

# ovh_api_call <METHOD> <PATH> [BODY]
# Outputs the response body on stdout. Curl's exit code propagates.
ovh_api_call() {
    local method="$1" path="$2" body="${3:-}"
    _ovh_check_credentials
    local url="${OVH_API_BASE_URL}${path}"
    local timestamp
    timestamp="$(date +%s)"
    local sig
    sig="$(_ovh_signature "$method" "$url" "$body" "$timestamp")"
    local curl_args=(
        --silent
        --show-error
        --request "$method"
        --header "X-Ovh-Application: ${OVH_APPLICATION_KEY}"
        --header "X-Ovh-Consumer: ${OVH_CONSUMER_KEY}"
        --header "X-Ovh-Timestamp: ${timestamp}"
        --header "X-Ovh-Signature: ${sig}"
        --header "Content-Type: application/json"
        --max-time 30
    )
    [[ -n "$body" ]] && curl_args+=(--data "$body")
    curl "${curl_args[@]}" "$url"
}

# ovh_ping — verify credentials by GET /me. Logs nichandle on success.
ovh_ping() {
    local resp
    if ! resp=$(ovh_api_call GET /me); then
        log_error "ovh_ping: curl request failed"
        return 1
    fi
    local nic
    nic=$(printf '%s' "$resp" | jq -r '.nichandle // empty' 2>/dev/null)
    if [[ -z "$nic" ]]; then
        log_error "ovh_ping: unexpected response: $(printf '%s' "$resp" | head -c 200)"
        return 1
    fi
    log_info "OVH API authenticated as nichandle '${nic}'"
}

# === DNS ===============================================================

# ovh_dns_record_find <subdomain> <type>
# Returns the first record id matching <subdomain> + <type>, or empty.
# Uses OVH_DNS_ZONE.
ovh_dns_record_find() {
    local subdomain="$1" rtype="$2"
    [[ -z "${OVH_DNS_ZONE:-}" ]] && die "ovh_dns_record_find: OVH_DNS_ZONE unset"
    local resp
    resp=$(ovh_api_call GET "/domain/zone/${OVH_DNS_ZONE}/record?subDomain=${subdomain}&fieldType=${rtype}")
    printf '%s' "$resp" | jq -r '.[0] // empty' 2>/dev/null
}

# ovh_dns_record_create <subdomain> <type> <target> [ttl=300]
# Outputs the created record id on stdout.
# Idempotent in the sense that if a matching record already exists, its id is
# returned without modification. (Use ovh_dns_record_delete + create to change.)
ovh_dns_record_create() {
    local subdomain="$1" rtype="$2" target="$3" ttl="${4:-300}"
    [[ -z "${OVH_DNS_ZONE:-}" ]] && die "ovh_dns_record_create: OVH_DNS_ZONE unset"
    local existing
    existing=$(ovh_dns_record_find "$subdomain" "$rtype")
    if [[ -n "$existing" ]]; then
        log_info "ovh_dns: ${subdomain}.${OVH_DNS_ZONE} ${rtype} record already exists (id=${existing})"
        printf '%s\n' "$existing"
        return 0
    fi
    local body
    body=$(jq -nc \
        --arg sd "$subdomain" \
        --arg rt "$rtype" \
        --arg tg "$target" \
        --argjson ttl "$ttl" \
        '{subDomain: $sd, fieldType: $rt, target: $tg, ttl: $ttl}')
    local resp
    resp=$(ovh_api_call POST "/domain/zone/${OVH_DNS_ZONE}/record" "$body")
    local record_id
    record_id=$(printf '%s' "$resp" | jq -r '.id // empty')
    if [[ -z "$record_id" ]]; then
        die "ovh_dns_record_create failed: $(printf '%s' "$resp" | head -c 300)"
    fi
    log_info "ovh_dns: created ${subdomain}.${OVH_DNS_ZONE} ${rtype} → ${target} (id=${record_id})"
    printf '%s\n' "$record_id"
}

# ovh_dns_record_delete <record_id>
ovh_dns_record_delete() {
    local record_id="$1"
    [[ -z "${OVH_DNS_ZONE:-}" ]] && die "ovh_dns_record_delete: OVH_DNS_ZONE unset"
    [[ -z "$record_id" ]] && { log_warn "ovh_dns_record_delete: empty id, nothing to do"; return 0; }
    ovh_api_call DELETE "/domain/zone/${OVH_DNS_ZONE}/record/${record_id}" >/dev/null
    log_info "ovh_dns: deleted record id ${record_id} in zone ${OVH_DNS_ZONE}"
}

# ovh_dns_zone_refresh — push pending changes to the authoritative servers.
ovh_dns_zone_refresh() {
    [[ -z "${OVH_DNS_ZONE:-}" ]] && die "ovh_dns_zone_refresh: OVH_DNS_ZONE unset"
    ovh_api_call POST "/domain/zone/${OVH_DNS_ZONE}/refresh" "" >/dev/null
    log_info "ovh_dns: zone ${OVH_DNS_ZONE} refresh requested"
}

# === Managed MongoDB ====================================================

_ovh_mongo_path() {
    [[ -z "${OVH_CLOUD_PROJECT_ID:-}" ]] && die "OVH_CLOUD_PROJECT_ID unset"
    [[ -z "${OVH_MONGO_CLUSTER_ID:-}" ]] && die "OVH_MONGO_CLUSTER_ID unset"
    printf '/cloud/project/%s/database/mongodb/%s' \
        "$OVH_CLOUD_PROJECT_ID" "$OVH_MONGO_CLUSTER_ID"
}

# ovh_mongo_db_find_id <db_name> → outputs the database id, or empty.
ovh_mongo_db_find_id() {
    local db_name="$1"
    local base; base=$(_ovh_mongo_path)
    local resp ids id name
    resp=$(ovh_api_call GET "${base}/database")
    # Response: array of database IDs (strings).
    while IFS= read -r id; do
        [[ -z "$id" ]] && continue
        name=$(ovh_api_call GET "${base}/database/${id}" | jq -r '.name // empty')
        if [[ "$name" == "$db_name" ]]; then
            printf '%s\n' "$id"
            return 0
        fi
    done < <(printf '%s' "$resp" | jq -r '.[]?')
    return 0  # not found → empty stdout
}

# ovh_mongo_db_create <db_name> → outputs database id (existing or new).
ovh_mongo_db_create() {
    local db_name="$1"
    local existing
    existing=$(ovh_mongo_db_find_id "$db_name")
    if [[ -n "$existing" ]]; then
        log_info "ovh_mongo: database '${db_name}' already exists (id=${existing})"
        printf '%s\n' "$existing"
        return 0
    fi
    local base; base=$(_ovh_mongo_path)
    local body resp db_id
    body=$(jq -nc --arg n "$db_name" '{name: $n}')
    resp=$(ovh_api_call POST "${base}/database" "$body")
    db_id=$(printf '%s' "$resp" | jq -r '.id // empty')
    if [[ -z "$db_id" ]]; then
        die "ovh_mongo_db_create failed: $(printf '%s' "$resp" | head -c 300)"
    fi
    log_info "ovh_mongo: created database '${db_name}' (id=${db_id})"
    printf '%s\n' "$db_id"
}

# ovh_mongo_db_delete <db_id>
ovh_mongo_db_delete() {
    local db_id="$1"
    [[ -z "$db_id" ]] && { log_warn "ovh_mongo_db_delete: empty id, nothing to do"; return 0; }
    local base; base=$(_ovh_mongo_path)
    ovh_api_call DELETE "${base}/database/${db_id}" >/dev/null
    log_info "ovh_mongo: deleted database id ${db_id}"
}

# ovh_mongo_user_find_id <user_name> → outputs the user id, or empty.
ovh_mongo_user_find_id() {
    local user_name="$1"
    local base; base=$(_ovh_mongo_path)
    local resp id name
    resp=$(ovh_api_call GET "${base}/user")
    while IFS= read -r id; do
        [[ -z "$id" ]] && continue
        name=$(ovh_api_call GET "${base}/user/${id}" | jq -r '.name // empty')
        if [[ "$name" == "$user_name" ]]; then
            printf '%s\n' "$id"
            return 0
        fi
    done < <(printf '%s' "$resp" | jq -r '.[]?')
    return 0  # not found → empty stdout
}

# ovh_mongo_user_create <user_name> <password> <db_id> [role=readWrite]
# Outputs the created user id on stdout. Idempotent: if user already exists,
# returns its id without changing the password (rotate via delete+create).
ovh_mongo_user_create() {
    local user_name="$1" password="$2" db_id="$3" role="${4:-readWrite}"
    local existing
    existing=$(ovh_mongo_user_find_id "$user_name")
    if [[ -n "$existing" ]]; then
        log_warn "ovh_mongo: user '${user_name}' already exists (id=${existing}); password NOT updated"
        printf '%s\n' "$existing"
        return 0
    fi
    local base; base=$(_ovh_mongo_path)
    local body resp user_id
    body=$(jq -nc \
        --arg n  "$user_name" \
        --arg p  "$password" \
        --arg id "$db_id" \
        --arg r  "$role" \
        '{name: $n, password: $p, roles: [{databaseId: $id, role: $r}]}')
    resp=$(ovh_api_call POST "${base}/user" "$body")
    user_id=$(printf '%s' "$resp" | jq -r '.id // empty')
    if [[ -z "$user_id" ]]; then
        die "ovh_mongo_user_create failed: $(printf '%s' "$resp" | head -c 300)"
    fi
    log_info "ovh_mongo: created user '${user_name}' (id=${user_id})"
    printf '%s\n' "$user_id"
}

# ovh_mongo_user_delete <user_id>
ovh_mongo_user_delete() {
    local user_id="$1"
    [[ -z "$user_id" ]] && { log_warn "ovh_mongo_user_delete: empty id, nothing to do"; return 0; }
    local base; base=$(_ovh_mongo_path)
    ovh_api_call DELETE "${base}/user/${user_id}" >/dev/null
    log_info "ovh_mongo: deleted user id ${user_id}"
}

# ovh_mongo_wait_for_user_ready <user_id> [retries=20] [interval_sec=3]
# Polls GET /user/<id> until status == "READY".
ovh_mongo_wait_for_user_ready() {
    local user_id="$1" retries="${2:-20}" interval="${3:-3}"
    local base; base=$(_ovh_mongo_path)
    local i status
    for (( i=1; i<=retries; i++ )); do
        status=$(ovh_api_call GET "${base}/user/${user_id}" | jq -r '.status // empty')
        if [[ "$status" == "READY" ]]; then
            log_debug "ovh_mongo: user ${user_id} READY (try ${i}/${retries})"
            return 0
        fi
        log_debug "ovh_mongo: user ${user_id} status=${status} (try ${i}/${retries})"
        (( i < retries )) && sleep "$interval"
    done
    log_error "ovh_mongo: user ${user_id} did not reach READY within $((retries * interval))s"
    return 1
}

# ovh_mongo_build_url <user_name> <password> <db_name>
# Outputs the mongodb:// URL be-BOP can consume. Uses TLS by default
# (OVH Managed Mongo requires TLS) and authSource=<db_name>.
ovh_mongo_build_url() {
    local user_name="$1" password="$2" db_name="$3"
    local host="${OVH_MONGO_ENDPOINT_HOST:-}"
    local port="${OVH_MONGO_ENDPOINT_PORT:-27017}"
    [[ -z "$host" ]] && die "ovh_mongo_build_url: OVH_MONGO_ENDPOINT_HOST unset"
    # URL-encode password (handles special chars like @, :, /, etc.) using jq.
    local enc_pw
    enc_pw=$(jq -rn --arg p "$password" '$p|@uri')
    printf 'mongodb://%s:%s@%s:%s/%s?authSource=%s&tls=true\n' \
        "$user_name" "$enc_pw" "$host" "$port" "$db_name" "$db_name"
}
