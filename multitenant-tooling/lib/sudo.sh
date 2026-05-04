# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 be-bop.io contributors
#
# sudo.sh — privilege escalation helpers.
# Source this file AFTER lib/log.sh.
#
# Public API:
#   run_privileged <cmd...>     — exec as root (direct if RUNNING_AS_ROOT, else via sudo)
#   require_privileges          — die unless we have root or working sudo

[[ -n "${_BEBOP_SUDO_SOURCED:-}" ]] && return 0
readonly _BEBOP_SUDO_SOURCED=1

if [[ -z "${RUNNING_AS_ROOT:-}" ]]; then
    if [[ "$(id -u)" -eq 0 ]]; then
        RUNNING_AS_ROOT=true
    else
        RUNNING_AS_ROOT=false
    fi
    export RUNNING_AS_ROOT
fi

run_privileged() {
    if [[ "$RUNNING_AS_ROOT" == "true" ]]; then
        "$@"
    elif [[ "${RUN_NON_INTERACTIVE:-false}" == "true" ]]; then
        sudo -n "$@"
    else
        sudo "$@"
    fi
}

require_privileges() {
    if [[ "$RUNNING_AS_ROOT" == "true" ]]; then
        return 0
    fi
    if sudo -n true 2>/dev/null; then
        return 0
    fi
    if [[ "${RUN_NON_INTERACTIVE:-false}" == "true" ]]; then
        die "this command requires root or passwordless sudo (run as root or configure sudoers)"
    fi
    log_warn "sudo credentials may be required; you will be prompted"
    if ! sudo -v; then
        die "sudo authentication failed"
    fi
}
