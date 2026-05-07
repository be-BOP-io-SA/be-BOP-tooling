#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 be-bop.io contributors
#
# certbot-ovh-cleanup.sh — certbot --manual-cleanup-hook companion to
# certbot-ovh-auth.sh. Deletes the _acme-challenge TXT record we
# published in the auth phase.
#
# Env vars provided by certbot:
#   CERTBOT_DOMAIN       e.g. tenant1.pvh-labs.com or s3.tenant1.pvh-labs.com
#
# Best-effort: if the record can't be found (already gone, race, etc.),
# exit 0 — we don't want to fail certbot's overall flow over a stale
# cleanup attempt.

set -eEuo pipefail

# Same as certbot-ovh-auth.sh: keep certbot from labeling our normal
# log output as "error output".
exec 2>&1

: "${SECRETS_FILE:=/etc/be-BOP-tooling/secrets.env}"
: "${BEBOP_TOOLING_LIB_DIR:=/usr/local/share/be-BOP-tooling/lib}"

# shellcheck disable=SC1090
source "$SECRETS_FILE"
# shellcheck disable=SC1090
source "${BEBOP_TOOLING_LIB_DIR}/log.sh"
# shellcheck disable=SC1090
source "${BEBOP_TOOLING_LIB_DIR}/ovh.sh"

if [[ -z "${CERTBOT_DOMAIN:-}" || -z "${OVH_DNS_ZONE:-}" ]]; then
    log_warn "certbot-ovh-cleanup: missing CERTBOT_DOMAIN or OVH_DNS_ZONE; nothing to clean"
    exit 0
fi

zone="$OVH_DNS_ZONE"
domain="$CERTBOT_DOMAIN"
if [[ "$domain" == "$zone" ]]; then
    sub="_acme-challenge"
elif [[ "$domain" == *".${zone}" ]]; then
    prefix="${domain%.${zone}}"
    sub="_acme-challenge.${prefix}"
else
    log_warn "certbot-ovh-cleanup: domain '${domain}' not within zone '${zone}'; skipping"
    exit 0
fi

record_id=$(ovh_dns_record_find "$sub" TXT 2>/dev/null || true)
if [[ -z "$record_id" ]]; then
    log_info "certbot-ovh-cleanup: no TXT ${sub}.${zone} found; nothing to delete"
    exit 0
fi
log_info "certbot-ovh-cleanup: deleting TXT ${sub}.${zone} (id=${record_id})"
ovh_dns_record_delete "$record_id"
ovh_dns_zone_refresh
