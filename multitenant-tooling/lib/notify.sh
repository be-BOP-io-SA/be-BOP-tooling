# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 be-bop.io contributors
#
# notify.sh — operator notifications via SMTP and Zulip.
# These are TOOLING-LEVEL alerts (script failures, rollbacks). Tenant uptime
# alerts go through Uptime Kuma — see lib/uptime-kuma.sh.
#
# Required env (typically loaded from /etc/be-BOP-tooling/secrets.env):
#   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM, SMTP_TO
#   ZULIP_SITE, ZULIP_BOT_EMAIL, ZULIP_BOT_API_KEY, ZULIP_STREAM, ZULIP_TOPIC
#
# All notify_* functions are best-effort — they log a warning if the channel
# is not configured and return 0 (so they don't fail the calling script's
# error path). Failures of an actual delivery attempt log_error and return 1.
#
# Source AFTER lib/log.sh.

[[ -n "${_BEBOP_NOTIFY_SOURCED:-}" ]] && return 0
readonly _BEBOP_NOTIFY_SOURCED=1

# notify_smtp <subject> <body>
notify_smtp() {
    local subject="$1" body="$2"
    if [[ -z "${SMTP_HOST:-}" || -z "${SMTP_TO:-}" || -z "${SMTP_FROM:-}" ]]; then
        log_warn "notify_smtp: SMTP not configured (need SMTP_HOST/SMTP_TO/SMTP_FROM); skipping"
        return 0
    fi
    local port="${SMTP_PORT:-587}"
    local scheme="smtp"
    [[ "$port" == "465" ]] && scheme="smtps"
    local url="${scheme}://${SMTP_HOST}:${port}"
    local message
    message=$(printf 'From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n' \
        "$SMTP_FROM" "$SMTP_TO" "$subject" "$(date -uR)" "$body")
    local curl_args=(
        --silent --show-error
        --url "$url"
        --mail-from "$SMTP_FROM"
        --mail-rcpt "$SMTP_TO"
        --upload-file -
        --max-time 30
    )
    [[ "$scheme" == "smtps" ]] && curl_args+=(--ssl-reqd)
    [[ "$scheme" == "smtp"  ]] && curl_args+=(--ssl)
    if [[ -n "${SMTP_USER:-}" ]]; then
        curl_args+=(--user "${SMTP_USER}:${SMTP_PASSWORD:-}")
    fi
    if printf '%s' "$message" | curl "${curl_args[@]}" >/dev/null 2>&1; then
        log_debug "notify_smtp: sent '${subject}' to ${SMTP_TO}"
        return 0
    fi
    log_error "notify_smtp: failed to send '${subject}'"
    return 1
}

# notify_zulip <subject> <body>
notify_zulip() {
    local subject="$1" body="$2"
    if [[ -z "${ZULIP_SITE:-}" || -z "${ZULIP_BOT_EMAIL:-}" || -z "${ZULIP_BOT_API_KEY:-}" ]]; then
        log_warn "notify_zulip: Zulip not configured; skipping"
        return 0
    fi
    local stream="${ZULIP_STREAM:-bebop-tooling}"
    local topic="${ZULIP_TOPIC:-$subject}"
    local content="**${subject}**

${body}"
    if curl --silent --show-error -X POST \
        --user "${ZULIP_BOT_EMAIL}:${ZULIP_BOT_API_KEY}" \
        "${ZULIP_SITE%/}/api/v1/messages" \
        --data-urlencode "type=stream" \
        --data-urlencode "to=${stream}" \
        --data-urlencode "topic=${topic}" \
        --data-urlencode "content=${content}" \
        --max-time 30 \
        > /dev/null 2>&1 ; then
        log_debug "notify_zulip: sent '${subject}' to ${stream}/${topic}"
        return 0
    fi
    log_error "notify_zulip: failed to send '${subject}'"
    return 1
}

# notify_failure <subject> <body>
# For mutation failures and rollbacks: send to BOTH SMTP and Zulip.
notify_failure() {
    local subject="$1" body="$2"
    local smtp_rc=0 zulip_rc=0
    notify_smtp  "$subject" "$body" || smtp_rc=$?
    notify_zulip "$subject" "$body" || zulip_rc=$?
    if (( smtp_rc != 0 && zulip_rc != 0 )); then
        log_error "notify_failure: ALL channels failed for '${subject}'"
        return 1
    fi
    return 0
}

# notify_success <subject> <body>
# For success notices: Zulip only — avoid mail spam.
notify_success() {
    local subject="$1" body="$2"
    notify_zulip "$subject" "$body" || true
}
