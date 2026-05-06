#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 be-bop.io contributors
#
# add-tenant.sh — onboard a new be-BOP tenant on a host already prepared by
# host-bootstrap.sh. Transactional with automatic rollback on failure.
#
# Behaviour by tenant status (looked up in /var/lib/be-BOP/tenants.tsv):
#   absent       → fresh creation: 14 phases (DNS, Mongo, Garage, release,
#                  phoenixd, config, cert, nginx, bebop, healthcheck, …);
#                  any failure rolls back every step taken so far
#   active       → idempotent re-apply: rewrites config + vhost, no data
#                  changes, no rollback needed
#   soft-deleted → refused unless --reactivate is given
#   archived     → always refused (data has been off-loaded; pick a new id)

set -eEuo pipefail

readonly SCRIPT_VERSION="0.1.0"
readonly SCRIPT_NAME="add-tenant"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Locate libs and templates: source-tree layout when invoked from a checkout,
# system layout once installed under /usr/local/share/be-BOP-tooling.
if [[ -d "$SCRIPT_DIR/lib" ]]; then
    BEBOP_TOOLING_LIB_DIR="$SCRIPT_DIR/lib"
    BEBOP_TOOLING_TEMPLATE_DIR="$SCRIPT_DIR/templates"
elif [[ -d /usr/local/share/be-BOP-tooling/lib ]]; then
    BEBOP_TOOLING_LIB_DIR=/usr/local/share/be-BOP-tooling/lib
    BEBOP_TOOLING_TEMPLATE_DIR=/usr/local/share/be-BOP-tooling/templates
else
    echo "add-tenant: cannot locate lib/ directory" >&2
    exit 1
fi

# shellcheck source=lib/log.sh
source "$BEBOP_TOOLING_LIB_DIR/log.sh"
# shellcheck source=lib/sudo.sh
source "$BEBOP_TOOLING_LIB_DIR/sudo.sh"
# shellcheck source=lib/transaction.sh
source "$BEBOP_TOOLING_LIB_DIR/transaction.sh"
# shellcheck source=lib/registry.sh
source "$BEBOP_TOOLING_LIB_DIR/registry.sh"
# shellcheck source=lib/ovh.sh
source "$BEBOP_TOOLING_LIB_DIR/ovh.sh"
# shellcheck source=lib/mongo.sh
source "$BEBOP_TOOLING_LIB_DIR/mongo.sh"
# shellcheck source=lib/garage.sh
source "$BEBOP_TOOLING_LIB_DIR/garage.sh"
# shellcheck source=lib/notify.sh
source "$BEBOP_TOOLING_LIB_DIR/notify.sh"
# shellcheck source=lib/uptime-kuma.sh
source "$BEBOP_TOOLING_LIB_DIR/uptime-kuma.sh"
# shellcheck source=lib/healthcheck.sh
source "$BEBOP_TOOLING_LIB_DIR/healthcheck.sh"
# shellcheck source=lib/release.sh
source "$BEBOP_TOOLING_LIB_DIR/release.sh"

# === Constants ==========================================================
readonly TENANT_REGEX='^[a-z0-9][a-z0-9-]*$'
readonly TENANT_MAX_LEN=32
readonly DEFAULT_BUCKET_QUOTA="20GiB"
readonly TEMPLATE_REVISION="2026050501"
readonly HEALTHCHECK_RETRIES=15
readonly HEALTHCHECK_INTERVAL=2
readonly PHOENIXD_PASSWORD_RETRIES=20
readonly PHOENIXD_PASSWORD_INTERVAL=2

# === CLI ================================================================
SECRETS_FILE=/etc/be-BOP-tooling/secrets.env
TENANT_ID=""
ADMIN_EMAIL=""
ENABLE_PHOENIXD=true
BEBOP_VERSION="latest"
REACTIVATE=false
DRY_RUN=false
RUN_NON_INTERACTIVE=false
VERBOSE=false

usage() {
    cat <<EOF
add-tenant.sh — onboard a new be-BOP tenant.

Usage:
  add-tenant.sh <tenant_id> --admin-email <email> [options]

Required:
  <tenant_id>             slug, [a-z0-9][a-z0-9-]*, max ${TENANT_MAX_LEN} chars
  --admin-email <email>   merchant contact (used for Let's Encrypt + alerts)

Optional:
  --no-phoenixd           skip the per-tenant phoenixd daemon (default: enabled)
  --bebop-version <tag>   GitHub release tag of be-BOP, or "latest" (default)
  --reactivate            restore a soft-deleted tenant (preserves data)
  --secrets-file <path>   override default ${SECRETS_FILE}
  --non-interactive       no prompts; fail if input would be required
  --dry-run               print actions without executing
  --verbose               verbose logging
  -h, --help

Status semantics (looked up in /var/lib/be-BOP/tenants.tsv):
  absent       → fresh creation (14 phases, full rollback on failure)
  active       → idempotent: re-applies config + vhost, restarts on drift
  soft-deleted → refused unless --reactivate
  archived     → always refused (pick a different tenant_id)
EOF
}

# Parse arguments — first non-flag is tenant_id.
while (( $# )); do
    case "$1" in
        --admin-email)     ADMIN_EMAIL="$2"; shift 2 ;;
        --phoenixd)        ENABLE_PHOENIXD=true; shift ;;
        --no-phoenixd)     ENABLE_PHOENIXD=false; shift ;;
        --bebop-version)   BEBOP_VERSION="$2"; shift 2 ;;
        --reactivate)      REACTIVATE=true; shift ;;
        --secrets-file)    SECRETS_FILE="$2"; shift 2 ;;
        --non-interactive) RUN_NON_INTERACTIVE=true; shift ;;
        --dry-run)         DRY_RUN=true; shift ;;
        --verbose)         VERBOSE=true; shift ;;
        -h|--help)         usage; exit 0 ;;
        --) shift; break ;;
        -*) die "unknown option: $1 (try --help)" ;;
        *)
            if [[ -n "$TENANT_ID" ]]; then
                die "multiple tenant ids on command line: '${TENANT_ID}' and '$1'"
            fi
            TENANT_ID="$1"; shift
            ;;
    esac
done

# Required arg validation.
if [[ -z "$TENANT_ID" ]]; then
    usage; die "tenant_id is required"
fi
if [[ -z "$ADMIN_EMAIL" ]]; then
    die "--admin-email is required"
fi
if [[ ! "$TENANT_ID" =~ $TENANT_REGEX ]]; then
    die "invalid tenant_id '${TENANT_ID}' (must match ${TENANT_REGEX})"
fi
if (( ${#TENANT_ID} > TENANT_MAX_LEN )); then
    die "tenant_id too long (max ${TENANT_MAX_LEN}): '${TENANT_ID}'"
fi

# Tag log lines with the tenant id from now on.
BEBOP_TOOLING_TENANT_ID="$TENANT_ID"
BEBOP_TOOLING_SYSLOG_IDENT="bebop-tooling-${SCRIPT_NAME}"
export BEBOP_TOOLING_TENANT_ID BEBOP_TOOLING_SYSLOG_IDENT
export RUN_NON_INTERACTIVE VERBOSE DRY_RUN

# === Globals (set during phases) ========================================
DOMAIN=""              # <tenant>.<zone>
S3_DOMAIN=""           # s3.<tenant>.<zone>
ZONE=""                # <zone> from secrets.env
HOST_IP=""
BEBOP_PORT=""
PHOENIXD_PORT=""
MONGO_PORT=""
GARAGE_BUCKET=""
GARAGE_KEY_NAME=""
GARAGE_KEY_ID=""
GARAGE_KEY_SECRET=""
MONGO_DB_NAME=""
MONGO_URL=""
PHOENIXD_HTTP_PASSWORD=""
PHOENIXD_SEED_HEX=""
DNS_RECORD_BEBOP_ID=""
DNS_RECORD_S3_ID=""
RESOLVED_VERSION=""
CERT_NAME=""

# === Helpers ============================================================
detect_host_ip() {
    if [[ -n "${BEBOP_HOST_IP:-}" ]]; then
        HOST_IP="$BEBOP_HOST_IP"
    else
        HOST_IP=$(curl -sS --max-time 10 https://api.ipify.org 2>/dev/null || true)
    fi
    if [[ -z "$HOST_IP" || ! "$HOST_IP" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
        die "could not detect host public IP — set BEBOP_HOST_IP env var explicitly"
    fi
    log_info "host public IP: ${HOST_IP}"
}

# Generate a 32-char URL-safe random password.
gen_password() {
    openssl rand -base64 48 | tr -d '/+=\n' | head -c 32
}

# render_template <template_path> <key1> <val1> [<key2> <val2> ...]
# Substitutes @keyN@ tokens in the template stream and outputs to stdout.
render_template() {
    local tmpl="$1"; shift
    local sed_args=()
    while (( $# >= 2 )); do
        local key="$1" val="$2"
        # Escape sed replacement metacharacters: \ first, then | (delimiter), then &
        val="${val//\\/\\\\}"
        val="${val//|/\\|}"
        val="${val//&/\\&}"
        sed_args+=("-e" "s|@${key}@|${val}|g")
        shift 2
    done
    sed "${sed_args[@]}" "$tmpl"
}

# === Phase implementations ==============================================

# Phase 1: status decision and registry lock
phase_status_decision() {
    local status
    status=$(registry_get_status "$TENANT_ID")
    log_info "phase 1: tenant '${TENANT_ID}' status = ${status}"
    case "$status" in
        absent)
            return 0
            ;;
        active)
            log_info "tenant '${TENANT_ID}' is already active — running in idempotent re-apply mode"
            DECISION_PATH="reapply"
            ;;
        soft-deleted)
            if [[ "$REACTIVATE" != "true" ]]; then
                die "tenant '${TENANT_ID}' is soft-deleted; pass --reactivate to restore, or 'remove-tenant.sh ${TENANT_ID} --purge' first to start fresh"
            fi
            log_info "reactivating soft-deleted tenant '${TENANT_ID}' (data preserved)"
            DECISION_PATH="reactivate"
            ;;
        archived)
            die "tenant '${TENANT_ID}' is archived (data uploaded to SFTP) — pick a different tenant_id"
            ;;
        *)
            die "unexpected tenant status '${status}' in registry"
            ;;
    esac
}

# Phase 2: ports, domain names, identifier derivation
phase_derive_identifiers() {
    log_info "phase 2: deriving identifiers..."
    ZONE="${OVH_DNS_ZONE:?OVH_DNS_ZONE missing in secrets.env}"
    DOMAIN="${TENANT_ID}.${ZONE}"
    S3_DOMAIN="s3.${TENANT_ID}.${ZONE}"
    CERT_NAME="bebop-${TENANT_ID}"
    GARAGE_BUCKET="bebop-${TENANT_ID}"
    GARAGE_KEY_NAME="bebop-${TENANT_ID}-key"
    MONGO_DB_NAME="bebop_${TENANT_ID//-/_}"

    if [[ "${DECISION_PATH:-fresh}" == "fresh" ]]; then
        BEBOP_PORT=$(registry_allocate_port bebop)
        PHOENIXD_PORT=$(registry_allocate_port phoenixd)
        MONGO_PORT=$(registry_allocate_port mongo)
    else
        BEBOP_PORT=$(registry_get_field "$TENANT_ID" bebop_port)
        PHOENIXD_PORT=$(registry_get_field "$TENANT_ID" phoenixd_port)
        MONGO_PORT=$(registry_get_field "$TENANT_ID" mongo_port)
    fi
    log_info "ports: bebop=${BEBOP_PORT}, phoenixd=${PHOENIXD_PORT}, mongo=${MONGO_PORT}"
    log_info "domain: https://${DOMAIN} (S3: https://${S3_DOMAIN})"
}

# Phase 2.5: clean any orphan resources from a prior failed fresh run.
#
# The transactional rollback in run_fresh_creation walks the undo stack
# in reverse, but only undoes steps that completed AND registered their
# undo. A failure mid-step (e.g. garage_key_create succeeds then the
# script is killed before the undo registers; or a phase fails before
# its half-created resources are tracked) leaves the system with
# orphan state that breaks the next add-tenant attempt.
#
# This phase only runs in DECISION_PATH=fresh (tenant absent from
# registry) — by definition no live service references these orphans
# so destruction is safe. We don't call this from reactivate/reapply
# paths, where every resource we'd find IS the live one.
phase_clean_orphans() {
    log_info "phase 2.5: scanning for orphan resources from prior failed runs..."
    local cleaned=0
    # OVH DNS records
    local id
    id=$(ovh_dns_record_find "$TENANT_ID" A 2>/dev/null || true)
    if [[ -n "$id" ]]; then
        log_warn "orphan: DNS A ${DOMAIN} (id=${id}); deleting"
        ovh_dns_record_delete "$id" || log_warn "orphan: DNS delete failed for ${id} — continuing"
        cleaned=1
    fi
    id=$(ovh_dns_record_find "s3.${TENANT_ID}" A 2>/dev/null || true)
    if [[ -n "$id" ]]; then
        log_warn "orphan: DNS A ${S3_DOMAIN} (id=${id}); deleting"
        ovh_dns_record_delete "$id" || log_warn "orphan: DNS delete failed for ${id} — continuing"
        cleaned=1
    fi
    [[ "$cleaned" == 1 ]] && ovh_dns_zone_refresh

    # Stale systemd units (still enabled / active from a previous run).
    local unit
    for unit in "bebop@${TENANT_ID}.service" "phoenixd@${TENANT_ID}.service" "mongod@${TENANT_ID}.service"; do
        if run_privileged systemctl list-unit-files --no-legend "$unit" 2>/dev/null | grep -q .; then
            if run_privileged systemctl is-active --quiet "$unit" 2>/dev/null \
               || run_privileged systemctl is-enabled --quiet "$unit" 2>/dev/null; then
                log_warn "orphan: systemd unit ${unit}; disabling"
                run_privileged systemctl disable --now "$unit" 2>/dev/null || true
            fi
        fi
    done

    # Local state + config dirs.
    local dir
    for dir in \
        "/var/lib/be-BOP/${TENANT_ID}" \
        "/etc/be-BOP/${TENANT_ID}" \
        "/var/lib/be-BOP-mongodb/${TENANT_ID}" \
        "/etc/be-BOP-mongodb/${TENANT_ID}" \
        "/var/lib/phoenixd/${TENANT_ID}" \
        "/etc/phoenixd/${TENANT_ID}"; do
        if run_privileged test -d "$dir"; then
            log_warn "orphan: ${dir}; removing"
            run_privileged rm -rf "$dir"
        fi
    done

    # Garage bucket + key.
    if garage_key_exists "$GARAGE_KEY_NAME"; then
        log_warn "orphan: garage key '${GARAGE_KEY_NAME}'; deleting"
        garage_key_delete "$GARAGE_KEY_NAME"
    fi
    if garage_bucket_exists "$GARAGE_BUCKET"; then
        log_warn "orphan: garage bucket '${GARAGE_BUCKET}'; deleting"
        garage_bucket_delete "$GARAGE_BUCKET"
    fi

    # nginx vhost (sites-available + sites-enabled symlink).
    if run_privileged test -e "/etc/nginx/sites-available/bebop-${TENANT_ID}.conf"; then
        log_warn "orphan: nginx vhost bebop-${TENANT_ID}; removing"
        run_privileged rm -f \
            "/etc/nginx/sites-enabled/bebop-${TENANT_ID}.conf" \
            "/etc/nginx/sites-available/bebop-${TENANT_ID}.conf"
        run_privileged systemctl reload nginx 2>/dev/null || true
    fi

    # Let's Encrypt cert directory.
    if run_privileged test -d "/etc/letsencrypt/live/${CERT_NAME}"; then
        log_warn "orphan: Let's Encrypt cert ${CERT_NAME}; deleting"
        run_privileged certbot delete --non-interactive --cert-name "${CERT_NAME}" 2>/dev/null \
            || log_warn "orphan: certbot delete failed; continuing"
    fi

    # Kuma monitor (best-effort; helper warns if creds/URL missing).
    kuma_unregister_tenant "$TENANT_ID" 2>/dev/null || true

    log_info "phase 2.5: orphan cleanup complete"
}

# Phase 3: DNS A records (both <tenant>.<zone> and s3.<tenant>.<zone>)
phase_dns() {
    log_info "phase 3: DNS A records via OVH..."
    DNS_RECORD_BEBOP_ID=$(ovh_dns_record_create "$TENANT_ID" A "$HOST_IP")
    txn_register_undo "DNS A record ${DOMAIN}" \
        "ovh_dns_record_delete '${DNS_RECORD_BEBOP_ID}' && ovh_dns_zone_refresh"
    DNS_RECORD_S3_ID=$(ovh_dns_record_create "s3.${TENANT_ID}" A "$HOST_IP")
    txn_register_undo "DNS A record ${S3_DOMAIN}" \
        "ovh_dns_record_delete '${DNS_RECORD_S3_ID}' && ovh_dns_zone_refresh"
    ovh_dns_zone_refresh
    log_info "DNS records pushed; OVH propagates them to authoritative NS within ~30s"
}

# Phase 4: per-tenant local mongod (port.env + start unit + init RS)
phase_mongo() {
    log_info "phase 4: per-tenant mongod (port=${MONGO_PORT})..."
    # Write port.env BEFORE starting the unit (EnvironmentFile= reads it).
    run_privileged install -d -m 0755 "/etc/be-BOP-mongodb/${TENANT_ID}"
    local tmp
    tmp=$(mktemp)
    printf 'MONGO_PORT=%s\n' "$MONGO_PORT" > "$tmp"
    run_privileged install -m 0640 "$tmp" "/etc/be-BOP-mongodb/${TENANT_ID}/port.env"
    rm -f "$tmp"
    txn_register_undo "mongod port.env" \
        "run_privileged rm -rf '/etc/be-BOP-mongodb/${TENANT_ID}'"

    run_privileged systemctl enable --now "mongod@${TENANT_ID}.service"
    txn_register_undo "mongod@${TENANT_ID}.service" \
        "run_privileged systemctl disable --now 'mongod@${TENANT_ID}.service' 2>/dev/null || true; run_privileged rm -rf '/var/lib/be-BOP-mongodb/${TENANT_ID}'"

    if [[ "$DRY_RUN" != "true" ]]; then
        mongo_wait_ready "$MONGO_PORT" 60 1 \
            || die "mongod@${TENANT_ID} did not become ready on 127.0.0.1:${MONGO_PORT} within 60s (check 'journalctl -u mongod@${TENANT_ID}')"
        mongo_init_rs "$MONGO_PORT"
    fi
    MONGO_URL=$(mongo_build_url "$MONGO_PORT" "$MONGO_DB_NAME")
    log_info "Mongo: db=${MONGO_DB_NAME} on 127.0.0.1:${MONGO_PORT} (rs=rs0)"
}

# Phase 5: Garage bucket + key + grant + quota
phase_garage() {
    log_info "phase 5: Garage bucket + key + quota..."
    garage_bucket_create "$GARAGE_BUCKET"
    txn_register_undo "Garage bucket ${GARAGE_BUCKET}" \
        "garage_bucket_delete '${GARAGE_BUCKET}'"
    local key_out
    key_out=$(garage_key_create "$GARAGE_KEY_NAME")
    GARAGE_KEY_ID=$(printf '%s' "$key_out" | cut -f1)
    GARAGE_KEY_SECRET=$(printf '%s' "$key_out" | cut -f2)
    txn_register_undo "Garage key ${GARAGE_KEY_NAME}" \
        "garage_key_delete '${GARAGE_KEY_NAME}'"
    garage_bucket_grant "$GARAGE_BUCKET" "$GARAGE_KEY_NAME"
    garage_bucket_set_quota "$GARAGE_BUCKET" "$DEFAULT_BUCKET_QUOTA"
    log_info "Garage: bucket=${GARAGE_BUCKET}, key id=${GARAGE_KEY_ID}, quota=${DEFAULT_BUCKET_QUOTA}"
}

# Phase 6: per-tenant filesystem skeleton
#
# We deliberately do NOT pre-create the StateDirectory targets
# (/var/lib/phoenixd/<id>, /var/lib/be-BOP-mongodb/<id>, /var/lib/be-BOP/<id>/state).
# systemd's StateDirectory= sets these up with the right mode (0700) and
# owner (DynamicUser) on first service start; pre-creating them as
# root:root 0755 makes systemd fail with status=238/STATE_DIRECTORY
# ("Failed to set up special execution directory").
# We only create what bebop@.service expects to already exist (the
# release tree under /var/lib/be-BOP/<id>/releases/) and the per-tenant
# /etc/ trees that hold port.env / config.env.
phase_directories() {
    log_info "phase 6: directory skeleton for tenant..."
    run_privileged install -d -m 0755 "/var/lib/be-BOP/${TENANT_ID}"
    run_privileged install -d -m 0755 "/var/lib/be-BOP/${TENANT_ID}/releases"
    run_privileged install -d -m 0755 "/etc/be-BOP/${TENANT_ID}"
    if [[ "$ENABLE_PHOENIXD" == "true" ]]; then
        run_privileged install -d -m 0755 "/etc/phoenixd/${TENANT_ID}"
    fi
    txn_register_undo "tenant directory tree" \
        "run_privileged rm -rf '/var/lib/be-BOP/${TENANT_ID}' '/etc/be-BOP/${TENANT_ID}' '/etc/phoenixd/${TENANT_ID}' '/var/lib/phoenixd/${TENANT_ID}'"
}

# Phase 7: download + extract + pnpm install + activate symlink
phase_release() {
    log_info "phase 7: be-BOP release ${BEBOP_VERSION}..."
    RESOLVED_VERSION=$(release_resolve_version "$BEBOP_VERSION")
    log_info "resolved version: ${RESOLVED_VERSION}"
    release_download_and_extract "$TENANT_ID" "$RESOLVED_VERSION"
    txn_register_undo "release ${RESOLVED_VERSION}" \
        "run_privileged rm -rf '/var/lib/be-BOP/${TENANT_ID}/releases/${RESOLVED_VERSION}'"
    release_install_deps "$TENANT_ID" "$RESOLVED_VERSION"
    release_activate "$TENANT_ID" "$RESOLVED_VERSION"
}

# Phase 8: phoenixd port.env + start phoenixd + read http-password
phase_phoenixd() {
    if [[ "$ENABLE_PHOENIXD" != "true" ]]; then
        log_info "phase 8: phoenixd disabled (--no-phoenixd) — skipping"
        return 0
    fi
    log_info "phase 8: phoenixd ${TENANT_ID}..."
    local tmp
    tmp=$(mktemp)
    printf 'PHOENIXD_PORT=%s\n' "$PHOENIXD_PORT" > "$tmp"
    run_privileged install -m 0640 "$tmp" "/etc/phoenixd/${TENANT_ID}/port.env"
    rm -f "$tmp"
    txn_register_undo "phoenixd port.env" \
        "run_privileged rm -f '/etc/phoenixd/${TENANT_ID}/port.env'"

    run_privileged systemctl enable --now "phoenixd@${TENANT_ID}.service"
    txn_register_undo "phoenixd@${TENANT_ID}.service" \
        "run_privileged systemctl disable --now 'phoenixd@${TENANT_ID}.service' 2>/dev/null || true"

    # Wait for phoenix.conf to be readable AND contain http-password.
    local conf="/var/lib/phoenixd/${TENANT_ID}/.phoenix/phoenix.conf"
    local i pwd
    log_info "waiting for phoenix.conf at ${conf}..."
    for (( i=1; i<=PHOENIXD_PASSWORD_RETRIES; i++ )); do
        if run_privileged test -r "$conf"; then
            pwd=$(run_privileged grep -oP '^http-password=\K\S+' "$conf" 2>/dev/null || true)
            if [[ -n "$pwd" ]]; then
                PHOENIXD_HTTP_PASSWORD="$pwd"
                break
            fi
        fi
        log_debug "phoenix.conf not ready (try ${i}/${PHOENIXD_PASSWORD_RETRIES}); waiting ${PHOENIXD_PASSWORD_INTERVAL}s"
        (( i < PHOENIXD_PASSWORD_RETRIES )) && sleep "$PHOENIXD_PASSWORD_INTERVAL"
    done
    if [[ -z "$PHOENIXD_HTTP_PASSWORD" ]]; then
        die "phoenixd: could not obtain http-password from ${conf} within $((PHOENIXD_PASSWORD_RETRIES * PHOENIXD_PASSWORD_INTERVAL))s"
    fi
    # Read seed for operator output (best-effort).
    local seed_file="/var/lib/phoenixd/${TENANT_ID}/.phoenix/seed.dat"
    if run_privileged test -r "$seed_file"; then
        PHOENIXD_SEED_HEX=$(run_privileged xxd -p -c 256 "$seed_file" 2>/dev/null || true)
    fi
    log_info "phoenixd ${TENANT_ID} ready (http-password obtained)"
}

# Phase 9: per-tenant config.env
phase_config_env() {
    log_info "phase 9: writing /etc/be-BOP/${TENANT_ID}/config.env..."
    local tmp existing_custom=""
    tmp=$(mktemp)
    local target="/etc/be-BOP/${TENANT_ID}/config.env"
    # Preserve user customisations below the scissor marker.
    local marker='# ------------------------ >8 ------------------------'
    if run_privileged test -f "$target"; then
        existing_custom=$(run_privileged sed -n "/^${marker}\$/,\$p" "$target" 2>/dev/null || true)
    fi
    render_template "${BEBOP_TOOLING_TEMPLATE_DIR}/config.env.tmpl" \
        bebop_port              "$BEBOP_PORT" \
        domain                  "$DOMAIN" \
        s3_domain               "$S3_DOMAIN" \
        mongodb_url             "$MONGO_URL" \
        mongodb_database        "$MONGO_DB_NAME" \
        garage_bucket           "$GARAGE_BUCKET" \
        garage_key_id           "$GARAGE_KEY_ID" \
        garage_key_secret       "$GARAGE_KEY_SECRET" \
        phoenixd_port           "$PHOENIXD_PORT" \
        phoenixd_http_password  "$PHOENIXD_HTTP_PASSWORD" \
        template_revision       "$TEMPLATE_REVISION" \
        > "$tmp"
    if [[ -n "$existing_custom" ]]; then
        # The template already includes the marker in its tail; replace it.
        local final
        final=$(mktemp)
        sed "/^${marker}\$/,\$d" "$tmp" > "$final"
        printf '%s\n' "$existing_custom" >> "$final"
        mv "$final" "$tmp"
    fi
    run_privileged install -d -m 0755 "/etc/be-BOP/${TENANT_ID}"
    run_privileged install -m 0640 "$tmp" "$target"
    rm -f "$tmp"
    txn_register_undo "config.env ${TENANT_ID}" \
        "run_privileged rm -f '${target}'"
    log_info "config.env installed (mode 0640)"
}

# Phase 10: TLS cert (per-tenant SAN, DNS-01 via custom OVH hook)
#
# We use certbot --manual + our own auth/cleanup hooks instead of the
# certbot-dns-ovh plugin. The plugin requires an OVH token scoped to
# /domain/* (it lists all zones for auto-discovery); our hooks know
# the zone from secrets.env and only need GET/POST/DELETE under
# /domain/zone/<OVH_DNS_ZONE>/* — strictly tenant-scoped.
phase_certificate() {
    log_info "phase 10: Let's Encrypt cert (DNS-01 via custom OVH hook)..."
    if run_privileged test -d "/etc/letsencrypt/live/${CERT_NAME}"; then
        log_info "cert ${CERT_NAME} already issued — skipping certbot"
        return 0
    fi
    local hooks_dir="/usr/local/share/be-BOP-tooling/hooks"
    if [[ -d "${SCRIPT_DIR}/hooks" ]]; then
        # source-tree layout (running from a checkout)
        hooks_dir="${SCRIPT_DIR}/hooks"
    fi
    local certbot_args=(
        certonly
        --manual
        --preferred-challenges dns-01
        --manual-auth-hook "${hooks_dir}/certbot-ovh-auth.sh"
        --manual-cleanup-hook "${hooks_dir}/certbot-ovh-cleanup.sh"
        --non-interactive --agree-tos
        --email "$ADMIN_EMAIL"
        --cert-name "$CERT_NAME"
        -d "$DOMAIN"
        -d "$S3_DOMAIN"
    )
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[dry-run] would run: certbot ${certbot_args[*]}"
    else
        run_privileged certbot "${certbot_args[@]}"
    fi
    txn_register_undo "Let's Encrypt cert ${CERT_NAME}" \
        "run_privileged certbot delete --non-interactive --cert-name '${CERT_NAME}' 2>/dev/null || true"
}

# Phase 11: nginx vhost
phase_nginx() {
    log_info "phase 11: nginx vhost..."
    local available="/etc/nginx/sites-available/bebop-${TENANT_ID}.conf"
    local enabled="/etc/nginx/sites-enabled/bebop-${TENANT_ID}.conf"
    local tmp
    tmp=$(mktemp)
    render_template "${BEBOP_TOOLING_TEMPLATE_DIR}/nginx-tenant.conf.tmpl" \
        tenant_id          "$TENANT_ID" \
        domain             "$DOMAIN" \
        s3_domain          "$S3_DOMAIN" \
        bebop_port         "$BEBOP_PORT" \
        template_revision  "$TEMPLATE_REVISION" \
        > "$tmp"
    run_privileged install -m 0644 "$tmp" "$available"
    rm -f "$tmp"
    run_privileged ln -sfn "$available" "$enabled"
    txn_register_undo "nginx vhost bebop-${TENANT_ID}" \
        "run_privileged rm -f '${enabled}' '${available}' && run_privileged systemctl reload nginx"
    if [[ "$DRY_RUN" != "true" ]]; then
        if ! run_privileged nginx -t; then
            die "nginx -t failed after writing vhost — check /etc/nginx/sites-available/bebop-${TENANT_ID}.conf"
        fi
        run_privileged systemctl reload nginx
    fi
}

# Phase 12: bebop service
phase_bebop_service() {
    log_info "phase 12: bebop@${TENANT_ID}.service..."
    run_privileged systemctl enable --now "bebop@${TENANT_ID}.service"
    txn_register_undo "bebop@${TENANT_ID}.service" \
        "run_privileged systemctl disable --now 'bebop@${TENANT_ID}.service' 2>/dev/null || true"
}

# Phase 13: HTTP healthcheck
phase_healthcheck() {
    log_info "phase 13: healthcheck https://${DOMAIN}/..."
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[dry-run] skipping healthcheck"
        return 0
    fi
    if ! http_wait_ok "https://${DOMAIN}/" "$HEALTHCHECK_RETRIES" "$HEALTHCHECK_INTERVAL"; then
        die "healthcheck failed for https://${DOMAIN}/ (service may have crashed; check 'journalctl -u bebop@${TENANT_ID}')"
    fi
    log_info "healthcheck OK ✓"
}

# Phase 14: Uptime Kuma + registry update
phase_kuma_and_registry() {
    log_info "phase 14: Uptime Kuma registration + registry write..."
    kuma_register_tenant "$TENANT_ID" "https://${DOMAIN}/"
    local now
    now=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    case "${DECISION_PATH:-fresh}" in
        fresh)
            registry_add \
                "$TENANT_ID" "$DOMAIN" "$BEBOP_PORT" "$PHOENIXD_PORT" \
                "$MONGO_PORT" "$MONGO_DB_NAME" \
                "$GARAGE_BUCKET" "$GARAGE_KEY_NAME" \
                "$RESOLVED_VERSION" "$now" "active"
            ;;
        reactivate)
            registry_set_status "$TENANT_ID" active
            ;;
        reapply)
            # Already active; refresh version if it changed.
            registry_set_field "$TENANT_ID" bebop_version "$RESOLVED_VERSION"
            ;;
    esac
}

# Phase 15: success summary + operator output
phase_summary() {
    cat <<EOF

==========================================================================
  Tenant '${TENANT_ID}' is ${DECISION_PATH:-active}
==========================================================================

  Public URL:             https://${DOMAIN}/
  S3 endpoint (public):   https://${S3_DOMAIN}/
  be-BOP version:         ${RESOLVED_VERSION:-unchanged}
  bebop port (local):     ${BEBOP_PORT}
  phoenixd port (local):  ${PHOENIXD_PORT}
  mongod port (local):    ${MONGO_PORT}

  Per-tenant config:      /etc/be-BOP/${TENANT_ID}/config.env
  Per-tenant releases:    /var/lib/be-BOP/${TENANT_ID}/releases/
  Phoenixd state:         /var/lib/phoenixd/${TENANT_ID}/.phoenix/
  Mongo state:            /var/lib/be-BOP-mongodb/${TENANT_ID}/

  systemd units:          systemctl status bebop@${TENANT_ID} phoenixd@${TENANT_ID} mongod@${TENANT_ID}
  logs:                   journalctl -u bebop@${TENANT_ID} -u phoenixd@${TENANT_ID} -u mongod@${TENANT_ID}

EOF
    if [[ "${DECISION_PATH:-fresh}" == "fresh" && "$ENABLE_PHOENIXD" == "true" ]]; then
        cat <<EOF
  ==== TRANSMIT TO MERCHANT (sensitive — handle carefully) ====
  phoenixd HTTP password:   ${PHOENIXD_HTTP_PASSWORD}
  phoenixd seed (hex):      ${PHOENIXD_SEED_HEX:-(seed.dat not readable)}

  These credentials control the merchant's Lightning wallet. Store them in
  the merchant's password manager and back the seed up off-host (encrypted).

EOF
    fi
}

# === Decision path implementations ======================================

run_fresh_creation() {
    DECISION_PATH=fresh
    txn_init
    trap 'on_error_rollback' ERR
    detect_host_ip
    phase_derive_identifiers
    phase_clean_orphans
    phase_dns
    phase_mongo
    phase_garage
    phase_directories
    phase_release
    phase_phoenixd
    phase_config_env
    phase_certificate
    phase_nginx
    phase_bebop_service
    phase_healthcheck
    phase_kuma_and_registry
    txn_commit
    trap - ERR
    notify_success \
        "[be-BOP tooling] add-tenant ${TENANT_ID} OK" \
        "Tenant ${TENANT_ID} is now active at https://${DOMAIN}/ (be-BOP ${RESOLVED_VERSION})."
    phase_summary
}

run_reactivation() {
    DECISION_PATH=reactivate
    txn_init
    trap 'on_error_rollback' ERR
    detect_host_ip
    phase_derive_identifiers   # ports re-read from registry
    # Skipped on reactivation: phase_garage, phase_directories,
    # phase_release, phase_phoenixd (services, port.env, seeds intact).
    phase_dns
    # Restart the per-tenant mongod (it was stopped during soft-delete; data
    # in /var/lib/be-BOP-mongodb/<tenant> is intact).
    run_privileged systemctl enable --now "mongod@${TENANT_ID}.service"
    if [[ "$DRY_RUN" != "true" ]]; then
        mongo_wait_ready "$MONGO_PORT" 60 1 \
            || die "mongod@${TENANT_ID} did not become ready on reactivation"
    fi
    # Re-read existing phoenixd password from disk (no recreation).
    if [[ "$ENABLE_PHOENIXD" == "true" ]]; then
        local conf="/var/lib/phoenixd/${TENANT_ID}/.phoenix/phoenix.conf"
        if run_privileged test -r "$conf"; then
            PHOENIXD_HTTP_PASSWORD=$(run_privileged grep -oP '^http-password=\K\S+' "$conf" 2>/dev/null || true)
        fi
    fi
    # Rebuild the local MONGO_URL from registry-stored port + db name.
    MONGO_URL=$(mongo_build_url "$MONGO_PORT" "$MONGO_DB_NAME")
    # Pull existing Garage creds (we don't recreate the key; secret is unknown).
    if run_privileged test -f "/etc/be-BOP/${TENANT_ID}/config.env"; then
        GARAGE_KEY_ID=$(run_privileged grep -oP '^S3_KEY_ID=\K.*' "/etc/be-BOP/${TENANT_ID}/config.env" 2>/dev/null || true)
        GARAGE_KEY_SECRET=$(run_privileged grep -oP '^S3_KEY_SECRET=\K.*' "/etc/be-BOP/${TENANT_ID}/config.env" 2>/dev/null || true)
    fi
    phase_config_env       # rewrites with current vars (preserves >8 customisations)
    phase_certificate      # idempotent: skip if cert dir exists
    phase_nginx
    if [[ "$ENABLE_PHOENIXD" == "true" ]]; then
        run_privileged systemctl enable --now "phoenixd@${TENANT_ID}.service"
    fi
    phase_bebop_service
    phase_healthcheck
    phase_kuma_and_registry
    txn_commit
    trap - ERR
    notify_success \
        "[be-BOP tooling] reactivate ${TENANT_ID} OK" \
        "Tenant ${TENANT_ID} restored at https://${DOMAIN}/."
    phase_summary
}

run_reapply() {
    DECISION_PATH=reapply
    # Idempotent: no rollback needed (we only rewrite config + reload).
    detect_host_ip
    phase_derive_identifiers
    # Rebuild the local MONGO_URL deterministically from registry data.
    MONGO_URL=$(mongo_build_url "$MONGO_PORT" "$MONGO_DB_NAME")
    # Re-derive existing Garage creds + phoenixd password from current config.env.
    if run_privileged test -f "/etc/be-BOP/${TENANT_ID}/config.env"; then
        GARAGE_KEY_ID=$(run_privileged grep -oP '^S3_KEY_ID=\K.*' "/etc/be-BOP/${TENANT_ID}/config.env" 2>/dev/null || true)
        GARAGE_KEY_SECRET=$(run_privileged grep -oP '^S3_KEY_SECRET=\K.*' "/etc/be-BOP/${TENANT_ID}/config.env" 2>/dev/null || true)
        PHOENIXD_HTTP_PASSWORD=$(run_privileged grep -oP '^PHOENIXD_HTTP_PASSWORD=\K.*' "/etc/be-BOP/${TENANT_ID}/config.env" 2>/dev/null || true)
    fi
    if [[ "$BEBOP_VERSION" != "latest" || -z "$(release_get_current_tag "$TENANT_ID")" ]]; then
        phase_release
    else
        RESOLVED_VERSION=$(release_get_current_tag "$TENANT_ID")
    fi
    phase_config_env
    phase_certificate
    phase_nginx
    run_privileged systemctl restart "bebop@${TENANT_ID}.service"
    phase_healthcheck
    phase_kuma_and_registry
    notify_success \
        "[be-BOP tooling] re-apply ${TENANT_ID} OK" \
        "Tenant ${TENANT_ID} configuration refreshed (version: ${RESOLVED_VERSION})."
    phase_summary
}

# Error handler: rolls back transaction stack and notifies operators.
on_error_rollback() {
    local rc=$?
    log_error "add-tenant: failure (exit code ${rc}); initiating rollback"
    txn_rollback || true
    local body
    body=$(printf 'Tenant: %s\nDecision path: %s\nFailure exit code: %d\nUndo steps attempted: %d\n\nSee journalctl -t %s --since "1 hour ago" for the full log.\n' \
        "$TENANT_ID" "${DECISION_PATH:-fresh}" "$rc" \
        "$(txn_size)" "$BEBOP_TOOLING_SYSLOG_IDENT")
    notify_failure \
        "[be-BOP tooling] add-tenant ${TENANT_ID} FAILED" \
        "$body"
    exit "$rc"
}

# === Main ===============================================================
main() {
    require_privileges

    if [[ ! -f "$SECRETS_FILE" ]]; then
        die "secrets file not found: ${SECRETS_FILE}"
    fi
    # shellcheck disable=SC1090
    source "$SECRETS_FILE"

    registry_init
    registry_lock
    # shellcheck disable=SC2064
    trap "registry_unlock" EXIT

    phase_status_decision

    case "${DECISION_PATH:-fresh}" in
        fresh)      run_fresh_creation ;;
        reactivate) run_reactivation ;;
        reapply)    run_reapply ;;
        *) die "internal error: unknown DECISION_PATH" ;;
    esac
}

main "$@"
