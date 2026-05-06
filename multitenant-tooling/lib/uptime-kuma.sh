# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 be-bop.io contributors
#
# uptime-kuma.sh — programmatic Kuma monitor management via Socket.IO.
#
# Bash callers (add-tenant.sh, remove-tenant.sh) shell out to a Python
# wrapper script (lib/kuma-cli.py) that uses the `uptime-kuma-api` library
# to talk Socket.IO to the local Kuma instance. host-bootstrap.sh
# provisions:
#   - /opt/be-BOP-tooling/kuma-venv/        Python venv with uptime-kuma-api
#   - /etc/be-BOP-tooling/kuma-admin.env    (mode 0600) auto-generated
#                                            KUMA_ADMIN_USER / KUMA_ADMIN_PASSWORD
#
# Required env (loaded from secrets.env by the caller):
#   UPTIME_KUMA_URL                   e.g. http://localhost:8810
# Required env (loaded from kuma-admin.env, sourced lazily):
#   KUMA_ADMIN_USER, KUMA_ADMIN_PASSWORD
#
# All public functions are best-effort: they log a warning and return 0
# if Kuma is unreachable or creds are missing — never break the calling
# add/remove flow over a monitoring side-issue.
#
# Source AFTER lib/log.sh.

[[ -n "${_BEBOP_KUMA_SOURCED:-}" ]] && return 0
readonly _BEBOP_KUMA_SOURCED=1

: "${KUMA_ADMIN_FILE:=/etc/be-BOP-tooling/kuma-admin.env}"
: "${KUMA_VENV_PYTHON:=/opt/be-BOP-tooling/kuma-venv/bin/python}"

# Locate kuma-cli.py: source-tree layout when running from a checkout,
# system layout once installed.
_kuma_cli_path() {
    if [[ -f "${BEBOP_TOOLING_LIB_DIR:-}/kuma-cli.py" ]]; then
        printf '%s\n' "${BEBOP_TOOLING_LIB_DIR}/kuma-cli.py"
    elif [[ -f /usr/local/share/be-BOP-tooling/lib/kuma-cli.py ]]; then
        printf '%s\n' /usr/local/share/be-BOP-tooling/lib/kuma-cli.py
    else
        return 1
    fi
}

_kuma_load_admin() {
    if [[ -n "${KUMA_ADMIN_USER:-}" && -n "${KUMA_ADMIN_PASSWORD:-}" ]]; then
        return 0
    fi
    if [[ -f "$KUMA_ADMIN_FILE" ]]; then
        # shellcheck disable=SC1090
        source "$KUMA_ADMIN_FILE"
    fi
    [[ -n "${KUMA_ADMIN_USER:-}" && -n "${KUMA_ADMIN_PASSWORD:-}" ]]
}

# _kuma_run_cli <cli args...>
# Runs kuma-cli.py with --url, --user, --password injected from env.
# Skips silently (returns 0) when prerequisites are missing.
_kuma_run_cli() {
    if [[ -z "${UPTIME_KUMA_URL:-}" ]]; then
        log_warn "kuma: UPTIME_KUMA_URL unset; skipping"
        return 0
    fi
    local cli
    if ! cli=$(_kuma_cli_path); then
        log_warn "kuma: kuma-cli.py not found; skipping"
        return 0
    fi
    if [[ ! -x "$KUMA_VENV_PYTHON" ]]; then
        log_warn "kuma: venv Python missing at $KUMA_VENV_PYTHON; re-run host-bootstrap.sh"
        return 0
    fi
    if ! _kuma_load_admin; then
        log_warn "kuma: $KUMA_ADMIN_FILE missing or empty; skipping (re-run host-bootstrap.sh to provision)"
        return 0
    fi
    "$KUMA_VENV_PYTHON" "$cli" --url "$UPTIME_KUMA_URL" \
        "$@" --user "$KUMA_ADMIN_USER" --password "$KUMA_ADMIN_PASSWORD"
}

# kuma_register_tenant <tenant_id> <url>
# Creates an HTTP monitor named bebop-<tenant_id> targeting <url>.
# Idempotent on the Kuma side (kuma-cli.py no-ops if a monitor with
# that name already exists).
kuma_register_tenant() {
    local tenant_id="$1" url="$2"
    log_info "kuma: registering monitor 'bebop-${tenant_id}' → ${url}"
    if ! _kuma_run_cli add-monitor --name "bebop-${tenant_id}" --target "$url"; then
        log_warn "kuma: add-monitor failed for '${tenant_id}' (check Kuma connectivity / journalctl)"
        return 1
    fi
}

# kuma_unregister_tenant <tenant_id>
# Removes the monitor bebop-<tenant_id>. No-op if absent.
kuma_unregister_tenant() {
    local tenant_id="$1"
    log_info "kuma: unregistering monitor 'bebop-${tenant_id}'"
    if ! _kuma_run_cli delete-monitor --name "bebop-${tenant_id}"; then
        log_warn "kuma: delete-monitor failed for '${tenant_id}' (clean up manually if needed)"
        return 1
    fi
}
