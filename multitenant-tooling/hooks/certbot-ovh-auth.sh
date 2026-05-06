#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 be-bop.io contributors
#
# certbot-ovh-auth.sh — certbot --manual-auth-hook for DNS-01 via OVH.
#
# Replaces the certbot-dns-ovh Python plugin to keep the OVH API token
# scoped narrowly to a single zone (the plugin requires a broader
# /domain/* scope so it can list zones for auto-discovery; we already
# know the zone from secrets.env).
#
# certbot calls this script once per -d domain with the env vars:
#   CERTBOT_DOMAIN       e.g. tenant1.pvh-labs.com or s3.tenant1.pvh-labs.com
#   CERTBOT_VALIDATION   the TXT record value to publish
#   CERTBOT_TOKEN        (HTTP-01 only — ignored)
#
# We compute the relative subdomain inside OVH_DNS_ZONE, create the TXT
# record _acme-challenge.<sub>, refresh the zone, and sleep to let the
# record propagate to OVH's authoritative servers.

set -eEuo pipefail

# Redirect our stderr to stdout so certbot doesn't tag our log_info /
# log_warn output as "error output" (Hook ... ran with error output).
# The hook's lib/log.sh writes to stderr by convention; certbot
# captures both streams and labels stderr as errors, even when the
# exit code is 0. Merging them keeps the log content intact (still
# visible in /var/log/letsencrypt/letsencrypt.log and in journald via
# systemd-cat) without the misleading warning.
exec 2>&1

: "${SECRETS_FILE:=/etc/be-BOP-tooling/secrets.env}"
: "${BEBOP_TOOLING_LIB_DIR:=/usr/local/share/be-BOP-tooling/lib}"
: "${ACME_PROPAGATION_SECONDS:=60}"

# shellcheck disable=SC1090
source "$SECRETS_FILE"
# shellcheck disable=SC1090
source "${BEBOP_TOOLING_LIB_DIR}/log.sh"
# shellcheck disable=SC1090
source "${BEBOP_TOOLING_LIB_DIR}/ovh.sh"

if [[ -z "${CERTBOT_DOMAIN:-}" || -z "${CERTBOT_VALIDATION:-}" ]]; then
    die "certbot-ovh-auth: CERTBOT_DOMAIN / CERTBOT_VALIDATION not set in env"
fi
if [[ -z "${OVH_DNS_ZONE:-}" ]]; then
    die "certbot-ovh-auth: OVH_DNS_ZONE not set in $SECRETS_FILE"
fi

zone="$OVH_DNS_ZONE"
domain="$CERTBOT_DOMAIN"
if [[ "$domain" == "$zone" ]]; then
    sub="_acme-challenge"
elif [[ "$domain" == *".${zone}" ]]; then
    prefix="${domain%.${zone}}"
    sub="_acme-challenge.${prefix}"
else
    die "certbot-ovh-auth: domain '${domain}' is not within zone '${zone}'"
fi

log_info "certbot-ovh-auth: publishing TXT ${sub}.${zone} for ACME challenge"
ovh_dns_record_create "$sub" TXT "$CERTBOT_VALIDATION" >/dev/null
ovh_dns_zone_refresh
log_info "certbot-ovh-auth: sleeping ${ACME_PROPAGATION_SECONDS}s for DNS propagation..."
sleep "$ACME_PROPAGATION_SECONDS"
log_info "certbot-ovh-auth: ready"
