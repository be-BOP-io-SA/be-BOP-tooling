# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 be-bop.io contributors
#
# uptime-kuma.sh — register/unregister tenant monitors with Uptime Kuma.
#
# *** IMPORTANT — KUMA REST API LIMITATIONS ***
#
# As of 1.x, Uptime Kuma's monitor management is exposed only over Socket.IO,
# not REST. Programmatic monitor creation from bash without a wrapper service
# is not feasible. The PoC therefore emits operator-visible instructions when
# add/remove-tenant is called, and treats the Kuma side as a manual step.
#
# The expected operator workflow at host bootstrap time:
#   1. ssh -L 8810:localhost:8810 to the host, open http://localhost:8810
#   2. create the Kuma admin account
#   3. configure mail and Zulip notification channels (host-wide, one-time)
# Then for each new tenant, the operator manually adds a monitor named
# bebop-<tenant> targeting https://<tenant>.<zone>/.
#
# When/if a stable REST API ships in Kuma 2.x, replace the manual stubs below
# with proper API calls. The function signatures are kept stable so callers
# (add-tenant.sh, remove-tenant.sh) don't need to change.
#
# Required env (best-effort, optional):
#   UPTIME_KUMA_URL         e.g. http://localhost:8810
#   UPTIME_KUMA_API_KEY     reserved for future REST integration
#
# Source AFTER lib/log.sh.

[[ -n "${_BEBOP_KUMA_SOURCED:-}" ]] && return 0
readonly _BEBOP_KUMA_SOURCED=1

# kuma_register_tenant <tenant_id> <url>
# Currently emits manual setup instructions. Future: POST to Kuma 2.x REST API.
kuma_register_tenant() {
    local tenant_id="$1" url="$2"
    if [[ -z "${UPTIME_KUMA_URL:-}" ]]; then
        log_warn "kuma: UPTIME_KUMA_URL unset; skipping monitor registration for '${tenant_id}'"
        return 0
    fi
    log_info "kuma: monitor registration for '${tenant_id}' is currently MANUAL"
    cat >&2 <<EOF

  --------------------------------------------------------------------
  ACTION REQUIRED — add an Uptime Kuma monitor for tenant '${tenant_id}'
    Open:           ${UPTIME_KUMA_URL}
    Friendly Name:  bebop-${tenant_id}
    Type:           HTTP(s)
    URL:            ${url}
    Notifications:  mail + Zulip   (host-wide channels)
  --------------------------------------------------------------------

EOF
}

# kuma_unregister_tenant <tenant_id>
kuma_unregister_tenant() {
    local tenant_id="$1"
    if [[ -z "${UPTIME_KUMA_URL:-}" ]]; then
        log_warn "kuma: UPTIME_KUMA_URL unset; nothing to unregister for '${tenant_id}'"
        return 0
    fi
    log_info "kuma: monitor de-registration for '${tenant_id}' is currently MANUAL"
    cat >&2 <<EOF

  --------------------------------------------------------------------
  ACTION REQUIRED — remove Uptime Kuma monitor for '${tenant_id}'
    Open:           ${UPTIME_KUMA_URL}
    Find the monitor named 'bebop-${tenant_id}' and delete it.
  --------------------------------------------------------------------

EOF
}
