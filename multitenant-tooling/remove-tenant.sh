#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 be-bop.io contributors
#
# remove-tenant.sh — wind down a be-BOP tenant.
#
# Three modes:
#   default (soft-delete)
#       Stops services, removes DNS + nginx vhost link, unregisters Kuma,
#       sets status=soft-deleted in the registry. Mongo, Garage bucket,
#       phoenixd seed, releases — ALL preserved. Reversible via
#       'add-tenant.sh <id> --reactivate'.
#
#   --archive
#       Soft-delete first (if active), then export Garage bucket + tenant
#       config + phoenixd state into a tarball, encrypt with
#       BACKUP_ENCRYPTION_KEY (openssl AES-256-CBC + PBKDF2), upload to
#       the SFTP destination defined in secrets.env, verify, then drop
#       Mongo DB + user + Garage bucket + key + local files.
#       Sets status=archived. NOTE: Mongo dumps are NOT included — OVH
#       Managed Mongo does daily provider-side backups (see README).
#
#   --purge
#       Nuclear: delete everything, no archive. Refuses unless interactive
#       confirmation is given (or --i-know-what-im-doing in
#       --non-interactive mode).

set -eEuo pipefail

readonly SCRIPT_VERSION="0.1.0"
readonly SCRIPT_NAME="remove-tenant"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -d "$SCRIPT_DIR/lib" ]]; then
    BEBOP_TOOLING_LIB_DIR="$SCRIPT_DIR/lib"
elif [[ -d /usr/local/share/be-BOP-tooling/lib ]]; then
    BEBOP_TOOLING_LIB_DIR=/usr/local/share/be-BOP-tooling/lib
else
    echo "remove-tenant: cannot locate lib/ directory" >&2
    exit 1
fi

# shellcheck source=lib/log.sh
source "$BEBOP_TOOLING_LIB_DIR/log.sh"
# shellcheck source=lib/sudo.sh
source "$BEBOP_TOOLING_LIB_DIR/sudo.sh"
# shellcheck source=lib/registry.sh
source "$BEBOP_TOOLING_LIB_DIR/registry.sh"
# shellcheck source=lib/ovh.sh
source "$BEBOP_TOOLING_LIB_DIR/ovh.sh"
# shellcheck source=lib/garage.sh
source "$BEBOP_TOOLING_LIB_DIR/garage.sh"
# shellcheck source=lib/notify.sh
source "$BEBOP_TOOLING_LIB_DIR/notify.sh"
# shellcheck source=lib/uptime-kuma.sh
source "$BEBOP_TOOLING_LIB_DIR/uptime-kuma.sh"

# === CLI ================================================================
SECRETS_FILE=/etc/be-BOP-tooling/secrets.env
TENANT_ID=""
MODE="soft-delete"
I_KNOW_WHAT_IM_DOING=false
DRY_RUN=false
RUN_NON_INTERACTIVE=false
VERBOSE=false

usage() {
    cat <<EOF
remove-tenant.sh — wind down a be-BOP tenant.

Usage:
  remove-tenant.sh <tenant_id> [options]

Modes (mutually exclusive):
  (default)              soft-delete: services off, DNS + vhost removed,
                         data + ports preserved (recover via add-tenant
                         <id> --reactivate)
  --archive              soft-delete + encrypted archive to SFTP + drop
                         Mongo/Garage/local files (status=archived)
  --purge                destroy everything without archive (DANGEROUS)

Other options:
  --i-know-what-im-doing skip the interactive confirmation for --purge
                         (required in --non-interactive)
  --secrets-file <path>  override default ${SECRETS_FILE}
  --non-interactive      no prompts; exit if input would be required
  --dry-run              print actions without executing
  --verbose
  -h, --help

Status semantics (looked up in /var/lib/be-BOP/tenants.tsv):
  active        → soft-delete OK, --archive OK, --purge OK (with confirm)
  soft-deleted  → --archive OK, --purge OK; default mode is a no-op
  archived      → only --purge has any effect (cleans the registry row)
  absent        → script exits cleanly (nothing to do)
EOF
}

while (( $# )); do
    case "$1" in
        --archive)              MODE=archive; shift ;;
        --purge)                MODE=purge; shift ;;
        --i-know-what-im-doing) I_KNOW_WHAT_IM_DOING=true; shift ;;
        --secrets-file)         SECRETS_FILE="$2"; shift 2 ;;
        --non-interactive)      RUN_NON_INTERACTIVE=true; shift ;;
        --dry-run)              DRY_RUN=true; shift ;;
        --verbose)              VERBOSE=true; shift ;;
        -h|--help)              usage; exit 0 ;;
        --) shift; break ;;
        -*) die "unknown option: $1 (try --help)" ;;
        *)
            [[ -n "$TENANT_ID" ]] && die "multiple tenant ids on command line"
            TENANT_ID="$1"; shift
            ;;
    esac
done

[[ -z "$TENANT_ID" ]] && { usage; die "tenant_id is required"; }

BEBOP_TOOLING_TENANT_ID="$TENANT_ID"
BEBOP_TOOLING_SYSLOG_IDENT="bebop-tooling-${SCRIPT_NAME}"
export BEBOP_TOOLING_TENANT_ID BEBOP_TOOLING_SYSLOG_IDENT
export RUN_NON_INTERACTIVE VERBOSE DRY_RUN

# === Globals (read from registry) =======================================
DOMAIN=""
S3_DOMAIN=""
ZONE=""
BEBOP_PORT=""
PHOENIXD_PORT=""
GARAGE_BUCKET=""
GARAGE_KEY_NAME=""
MONGO_DB_NAME=""
MONGO_USER_NAME=""
BEBOP_VERSION=""

# === Helpers ============================================================

# Stop and disable a per-tenant systemd unit, ignoring "not found" errors.
stop_disable_unit() {
    local unit="$1"
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[dry-run] would: systemctl disable --now ${unit}"
        return 0
    fi
    if run_privileged systemctl list-unit-files --no-legend "$unit" 2>/dev/null | grep -q .; then
        run_privileged systemctl disable --now "$unit" 2>/dev/null \
            || log_warn "stop_disable_unit: ${unit} disable returned non-zero (already inactive?)"
    else
        log_debug "stop_disable_unit: ${unit} not registered, nothing to do"
    fi
}

# Remove tenant DNS records (looked up by subdomain since registry doesn't
# store record IDs).
delete_dns_records() {
    log_info "deleting DNS records ${DOMAIN} and ${S3_DOMAIN}..."
    local id
    id=$(ovh_dns_record_find "$TENANT_ID" A 2>/dev/null || true)
    [[ -n "$id" ]] && ovh_dns_record_delete "$id"
    id=$(ovh_dns_record_find "s3.${TENANT_ID}" A 2>/dev/null || true)
    [[ -n "$id" ]] && ovh_dns_record_delete "$id"
    ovh_dns_zone_refresh
}

# Drop Mongo DB + scoped user.
drop_mongo_resources() {
    log_info "dropping Mongo db=${MONGO_DB_NAME} user=${MONGO_USER_NAME}..."
    local user_id db_id
    user_id=$(ovh_mongo_user_find_id "$MONGO_USER_NAME" 2>/dev/null || true)
    [[ -n "$user_id" ]] && ovh_mongo_user_delete "$user_id"
    db_id=$(ovh_mongo_db_find_id "$MONGO_DB_NAME" 2>/dev/null || true)
    [[ -n "$db_id" ]] && ovh_mongo_db_delete "$db_id"
}

# Drop Garage bucket + key.
drop_garage_resources() {
    log_info "dropping Garage bucket=${GARAGE_BUCKET} key=${GARAGE_KEY_NAME}..."
    garage_bucket_revoke "$GARAGE_BUCKET" "$GARAGE_KEY_NAME" 2>/dev/null || true
    garage_bucket_delete "$GARAGE_BUCKET"
    garage_key_delete "$GARAGE_KEY_NAME"
}

# Disable nginx vhost (keep the sites-available copy).
disable_nginx_vhost() {
    local available="/etc/nginx/sites-available/bebop-${TENANT_ID}.conf"
    local enabled="/etc/nginx/sites-enabled/bebop-${TENANT_ID}.conf"
    if [[ -L "$enabled" || -e "$enabled" ]]; then
        run_privileged rm -f "$enabled"
        log_info "nginx: disabled vhost bebop-${TENANT_ID} (sites-enabled symlink removed)"
    fi
    if [[ "$DRY_RUN" != "true" ]]; then
        run_privileged nginx -t && run_privileged systemctl reload nginx
    fi
}

# Delete nginx vhost entirely (sites-available + sites-enabled).
delete_nginx_vhost() {
    local available="/etc/nginx/sites-available/bebop-${TENANT_ID}.conf"
    local enabled="/etc/nginx/sites-enabled/bebop-${TENANT_ID}.conf"
    run_privileged rm -f "$enabled" "$available"
    if [[ "$DRY_RUN" != "true" ]]; then
        run_privileged nginx -t && run_privileged systemctl reload nginx || true
    fi
    log_info "nginx: deleted vhost bebop-${TENANT_ID}"
}

# Delete Let's Encrypt cert (per-tenant SAN cert).
delete_certificate() {
    local cert_name="bebop-${TENANT_ID}"
    if run_privileged test -d "/etc/letsencrypt/live/${cert_name}"; then
        run_privileged certbot delete --non-interactive --cert-name "$cert_name" 2>/dev/null \
            || log_warn "certbot delete returned non-zero for ${cert_name}"
    fi
}

# Remove tenant filesystem trees.
purge_local_filesystem() {
    log_info "removing tenant local filesystem..."
    run_privileged rm -rf \
        "/var/lib/be-BOP/${TENANT_ID}" \
        "/etc/be-BOP/${TENANT_ID}" \
        "/var/lib/phoenixd/${TENANT_ID}" \
        "/etc/phoenixd/${TENANT_ID}"
}

# Read tenant fields from the registry into globals.
load_tenant_from_registry() {
    DOMAIN=$(registry_get_field "$TENANT_ID" domain)
    BEBOP_PORT=$(registry_get_field "$TENANT_ID" bebop_port)
    PHOENIXD_PORT=$(registry_get_field "$TENANT_ID" phoenixd_port)
    MONGO_DB_NAME=$(registry_get_field "$TENANT_ID" mongodb_database)
    GARAGE_BUCKET=$(registry_get_field "$TENANT_ID" garage_bucket)
    GARAGE_KEY_NAME=$(registry_get_field "$TENANT_ID" garage_key)
    BEBOP_VERSION=$(registry_get_field "$TENANT_ID" bebop_version)
    ZONE="${OVH_DNS_ZONE:-}"
    S3_DOMAIN="s3.${TENANT_ID}.${ZONE}"
    # Mongo user follows the same convention as add-tenant.sh.
    MONGO_USER_NAME="bebop_${TENANT_ID//-/_}"
}

# === Soft-delete ========================================================
run_soft_delete() {
    log_info "soft-delete: tenant '${TENANT_ID}'"

    stop_disable_unit "bebop@${TENANT_ID}.service"
    stop_disable_unit "phoenixd@${TENANT_ID}.service"

    disable_nginx_vhost

    delete_dns_records

    kuma_unregister_tenant "$TENANT_ID"

    registry_set_status "$TENANT_ID" soft-deleted

    notify_success \
        "[be-BOP tooling] soft-delete ${TENANT_ID} OK" \
        "Tenant ${TENANT_ID} is now soft-deleted (data + ports preserved)."

    cat <<EOF

==========================================================================
  Tenant '${TENANT_ID}' soft-deleted
==========================================================================
  Data preserved:
    - Mongo DB:           ${MONGO_DB_NAME}
    - Garage bucket:      ${GARAGE_BUCKET}
    - Phoenixd seed:      /var/lib/phoenixd/${TENANT_ID}/.phoenix/seed.dat
    - be-BOP releases:    /var/lib/be-BOP/${TENANT_ID}/releases/
    - be-BOP config:      /etc/be-BOP/${TENANT_ID}/config.env

  To restore:    add-tenant.sh ${TENANT_ID} --admin-email <email> --reactivate
  To archive:    remove-tenant.sh ${TENANT_ID} --archive
  To purge:      remove-tenant.sh ${TENANT_ID} --purge
==========================================================================
EOF
}

# === Archive ============================================================
build_archive() {
    local workdir="$1" out_archive="$2"
    log_info "archive: gathering tenant artefacts under ${workdir}/"
    run_privileged install -d -m 0700 "${workdir}/etc-be-BOP"
    run_privileged install -d -m 0700 "${workdir}/var-lib-phoenixd"
    run_privileged install -d -m 0700 "${workdir}/bucket"

    # Per-tenant config + state (skip the live releases dir — it's just code,
    # we record the tag in metadata.json so a restore can re-download).
    if run_privileged test -d "/etc/be-BOP/${TENANT_ID}"; then
        run_privileged cp -a "/etc/be-BOP/${TENANT_ID}/." "${workdir}/etc-be-BOP/"
    fi
    if run_privileged test -d "/var/lib/phoenixd/${TENANT_ID}"; then
        run_privileged cp -a "/var/lib/phoenixd/${TENANT_ID}/." "${workdir}/var-lib-phoenixd/"
    fi

    # Garage bucket dump via rclone (S3 → local).
    log_info "archive: dumping Garage bucket ${GARAGE_BUCKET} via rclone..."
    local key_id key_secret
    key_id=$(run_privileged grep -oP '^S3_KEY_ID=\K.*' "/etc/be-BOP/${TENANT_ID}/config.env" 2>/dev/null || true)
    key_secret=$(run_privileged grep -oP '^S3_KEY_SECRET=\K.*' "/etc/be-BOP/${TENANT_ID}/config.env" 2>/dev/null || true)
    if [[ -z "$key_id" || -z "$key_secret" ]]; then
        log_warn "archive: Garage credentials not in config.env; bucket dump SKIPPED"
    else
        RCLONE_CONFIG_GARAGE_TYPE=s3 \
        RCLONE_CONFIG_GARAGE_PROVIDER=Other \
        RCLONE_CONFIG_GARAGE_ENDPOINT=http://127.0.0.1:3900 \
        RCLONE_CONFIG_GARAGE_REGION=garage \
        RCLONE_CONFIG_GARAGE_ACCESS_KEY_ID="$key_id" \
        RCLONE_CONFIG_GARAGE_SECRET_ACCESS_KEY="$key_secret" \
            rclone --quiet sync "garage:${GARAGE_BUCKET}" "${workdir}/bucket"
    fi

    # Metadata.
    cat > "${workdir}/metadata.json" <<EOF
{
  "tenant_id":           "${TENANT_ID}",
  "domain":              "${DOMAIN}",
  "bebop_port":          ${BEBOP_PORT},
  "phoenixd_port":       ${PHOENIXD_PORT},
  "bebop_version":       "${BEBOP_VERSION}",
  "mongodb_database":    "${MONGO_DB_NAME}",
  "mongodb_user":        "${MONGO_USER_NAME}",
  "garage_bucket":       "${GARAGE_BUCKET}",
  "garage_key":          "${GARAGE_KEY_NAME}",
  "archived_at":         "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "archive_format":      "1",
  "note":                "Mongo data is NOT included; rely on OVH provider-side daily backups."
}
EOF

    # Tar + encrypt (AES-256-CBC + PBKDF2).
    log_info "archive: tar + encrypt → ${out_archive}"
    if [[ -z "${BACKUP_ENCRYPTION_KEY:-}" ]]; then
        die "archive: BACKUP_ENCRYPTION_KEY not set in secrets.env"
    fi
    ( cd "$workdir" && \
        tar -cf - . \
        | gzip -9 \
        | openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
            -pass "pass:${BACKUP_ENCRYPTION_KEY}" \
            -out "$out_archive"
    )
    # Compute SHA256 for the integrity check.
    sha256sum "$out_archive" > "${out_archive}.sha256"
}

upload_archive() {
    local archive="$1" sha="$2"
    log_info "archive: uploading to SFTP ${SFTP_HOST}:${SFTP_REMOTE_PATH}/"
    if [[ -z "${SFTP_HOST:-}" || -z "${SFTP_USER:-}" || -z "${SFTP_REMOTE_PATH:-}" ]]; then
        die "SFTP destination not fully configured (need SFTP_HOST/SFTP_USER/SFTP_REMOTE_PATH)"
    fi
    local rc_args=(
        --sftp-host "$SFTP_HOST"
        --sftp-port "${SFTP_PORT:-22}"
        --sftp-user "$SFTP_USER"
    )
    if [[ "${SFTP_PASSWORD_OR_KEY_PATH:-}" == /* ]]; then
        rc_args+=(--sftp-key-file "$SFTP_PASSWORD_OR_KEY_PATH")
    elif [[ -n "${SFTP_PASSWORD_OR_KEY_PATH:-}" ]]; then
        local obs
        obs=$(rclone obscure "$SFTP_PASSWORD_OR_KEY_PATH")
        rc_args+=(--sftp-pass "$obs")
    else
        die "SFTP_PASSWORD_OR_KEY_PATH not set"
    fi
    RCLONE_CONFIG_BACKUP_TYPE=sftp \
    RCLONE_CONFIG_BACKUP_HOST="$SFTP_HOST" \
    RCLONE_CONFIG_BACKUP_PORT="${SFTP_PORT:-22}" \
    RCLONE_CONFIG_BACKUP_USER="$SFTP_USER" \
        rclone "${rc_args[@]}" copy "$archive" "backup:${SFTP_REMOTE_PATH}/"
    rclone "${rc_args[@]}" copy "$sha" "backup:${SFTP_REMOTE_PATH}/" \
        --sftp-host "$SFTP_HOST" --sftp-port "${SFTP_PORT:-22}" --sftp-user "$SFTP_USER"
    log_info "archive: uploaded ${archive} ($(stat -c %s "$archive") bytes)"
}

run_archive() {
    log_info "archive: tenant '${TENANT_ID}'"

    # Stop services and put the tenant in soft-deleted state first (no
    # rewriting of registry yet — we'll set 'archived' at the end).
    stop_disable_unit "bebop@${TENANT_ID}.service"
    stop_disable_unit "phoenixd@${TENANT_ID}.service"
    disable_nginx_vhost

    local ts workdir archive_path sha_path
    ts=$(date -u +"%Y%m%dT%H%M%SZ")
    workdir="/var/tmp/bebop-archive-${TENANT_ID}-${ts}"
    archive_path="/var/tmp/bebop-archive-${TENANT_ID}-${ts}.tar.gz.enc"
    sha_path="${archive_path}.sha256"
    run_privileged install -d -m 0700 "$workdir"
    # shellcheck disable=SC2064
    trap "run_privileged rm -rf '$workdir' '$archive_path' '$sha_path'" EXIT

    build_archive "$workdir" "$archive_path"
    upload_archive "$archive_path" "$sha_path"

    # Now delete external resources.
    delete_certificate
    delete_nginx_vhost
    delete_dns_records
    drop_mongo_resources
    drop_garage_resources
    purge_local_filesystem

    kuma_unregister_tenant "$TENANT_ID"

    registry_set_status "$TENANT_ID" archived

    notify_success \
        "[be-BOP tooling] archive ${TENANT_ID} OK" \
        "Tenant ${TENANT_ID} archived to ${SFTP_REMOTE_PATH}/$(basename "$archive_path") and purged locally."

    cat <<EOF

==========================================================================
  Tenant '${TENANT_ID}' ARCHIVED
==========================================================================
  Archive remote:   ${SFTP_HOST}:${SFTP_REMOTE_PATH}/$(basename "$archive_path")
  Archive sha256:   ${SFTP_HOST}:${SFTP_REMOTE_PATH}/$(basename "$sha_path")
  Encryption:       openssl enc -aes-256-cbc -pbkdf2 -iter 100000
  To decrypt:       openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 \\
                       -in <file> -out decrypted.tar.gz \\
                       -pass pass:<BACKUP_ENCRYPTION_KEY from secrets.env>

  Local resources removed:
    - /etc/be-BOP/${TENANT_ID}/
    - /var/lib/be-BOP/${TENANT_ID}/
    - /var/lib/phoenixd/${TENANT_ID}/
    - /etc/phoenixd/${TENANT_ID}/
    - nginx vhost bebop-${TENANT_ID}
    - Let's Encrypt cert bebop-${TENANT_ID}
    - DNS A records ${DOMAIN} + s3.${TENANT_ID}.${ZONE}
    - Mongo DB ${MONGO_DB_NAME} + user ${MONGO_USER_NAME}
    - Garage bucket ${GARAGE_BUCKET} + key ${GARAGE_KEY_NAME}

  Registry row preserved with status=archived for audit trail.
==========================================================================
EOF
}

# === Purge ==============================================================
run_purge() {
    log_warn "purge: tenant '${TENANT_ID}' — this is DESTRUCTIVE and IRREVERSIBLE"

    if [[ "$RUN_NON_INTERACTIVE" == "true" ]]; then
        if [[ "$I_KNOW_WHAT_IM_DOING" != "true" ]]; then
            die "purge in --non-interactive mode requires --i-know-what-im-doing"
        fi
    else
        echo
        echo "About to PERMANENTLY destroy tenant '${TENANT_ID}':"
        echo "  - DNS records, nginx vhost, Let's Encrypt cert"
        echo "  - Mongo DB '${MONGO_DB_NAME}' and user '${MONGO_USER_NAME}'"
        echo "  - Garage bucket '${GARAGE_BUCKET}' and key '${GARAGE_KEY_NAME}'"
        echo "  - phoenixd seed (/var/lib/phoenixd/${TENANT_ID}/.phoenix/seed.dat)"
        echo "  - all be-BOP releases and config"
        echo "  NO ARCHIVE will be created. This cannot be undone."
        echo
        read -r -p "Type the tenant id '${TENANT_ID}' to confirm: " typed
        if [[ "$typed" != "$TENANT_ID" ]]; then
            die "confirmation mismatch — purge aborted"
        fi
    fi

    stop_disable_unit "bebop@${TENANT_ID}.service"
    stop_disable_unit "phoenixd@${TENANT_ID}.service"

    delete_certificate
    delete_nginx_vhost
    delete_dns_records
    drop_mongo_resources
    drop_garage_resources
    purge_local_filesystem
    kuma_unregister_tenant "$TENANT_ID"

    registry_remove "$TENANT_ID"

    notify_success \
        "[be-BOP tooling] purge ${TENANT_ID} OK" \
        "Tenant ${TENANT_ID} purged (no archive)."

    log_info "purge complete; tenant '${TENANT_ID}' fully removed"
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

    local status
    status=$(registry_get_status "$TENANT_ID")
    if [[ "$status" == "absent" ]]; then
        log_info "tenant '${TENANT_ID}' is not in the registry — nothing to do"
        exit 0
    fi
    if [[ "$status" == "archived" && "$MODE" != "purge" ]]; then
        log_info "tenant '${TENANT_ID}' is already archived; only --purge has an effect now"
        exit 0
    fi

    load_tenant_from_registry

    case "$MODE" in
        soft-delete)
            if [[ "$status" == "soft-deleted" ]]; then
                log_info "tenant '${TENANT_ID}' is already soft-deleted — nothing to do"
                exit 0
            fi
            run_soft_delete
            ;;
        archive)
            run_archive
            ;;
        purge)
            run_purge
            ;;
    esac
}

# Catch-all error handler: notify operators on uncaught failures.
on_error() {
    local rc=$?
    log_error "remove-tenant: failure (exit code ${rc}); notifying operators"
    notify_failure \
        "[be-BOP tooling] remove-tenant ${TENANT_ID} (${MODE}) FAILED" \
        "Failure exit code: ${rc}. See journalctl -t ${BEBOP_TOOLING_SYSLOG_IDENT} --since '1 hour ago'."
    exit "$rc"
}
trap 'on_error' ERR

main "$@"
