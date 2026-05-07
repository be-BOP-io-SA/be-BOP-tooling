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
#
# Required env (typically loaded from /etc/be-BOP-tooling/secrets.env):
#   OVH_APPLICATION_KEY
#   OVH_APPLICATION_SECRET
#   OVH_CONSUMER_KEY
# DNS calls additionally need OVH_DNS_ZONE.
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
