#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 be-bop.io contributors
#
# upgrade-all.sh — upgrade every active tenant to a target be-BOP release.
# Delegates each individual upgrade to upgrade-tenant.sh.
#
# Modes:
#   --rolling (default)
#       Iterate tenants sequentially. Each gets upgraded + healthchecked
#       before the next is started. Stops at the first failure unless
#       --continue-on-failure is set.
#
#   --parallel
#       Launch upgrade-tenant.sh for every selected tenant in parallel,
#       wait for all, then aggregate results. Total downtime overlaps
#       across tenants but the wall-clock is shorter for large fleets.
#
# Selection:
#   --filter <regex>
#       Only operate on tenants whose tenant_id matches the regex
#       (matched with `grep -E`).

set -eEuo pipefail

readonly SCRIPT_VERSION="0.1.0"
readonly SCRIPT_NAME="upgrade-all"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -d "$SCRIPT_DIR/lib" ]]; then
    BEBOP_TOOLING_LIB_DIR="$SCRIPT_DIR/lib"
elif [[ -d /usr/local/share/be-BOP-tooling/lib ]]; then
    BEBOP_TOOLING_LIB_DIR=/usr/local/share/be-BOP-tooling/lib
else
    echo "upgrade-all: cannot locate lib/ directory" >&2
    exit 1
fi

# shellcheck source=lib/log.sh
source "$BEBOP_TOOLING_LIB_DIR/log.sh"
# shellcheck source=lib/sudo.sh
source "$BEBOP_TOOLING_LIB_DIR/sudo.sh"
# shellcheck source=lib/registry.sh
source "$BEBOP_TOOLING_LIB_DIR/registry.sh"
# shellcheck source=lib/notify.sh
source "$BEBOP_TOOLING_LIB_DIR/notify.sh"

# === CLI ================================================================
SECRETS_FILE=/etc/be-BOP-tooling/secrets.env
VERSION="latest"
MODE="rolling"
FILTER=""
CONTINUE_ON_FAILURE=false
DRY_RUN=false
RUN_NON_INTERACTIVE=false
VERBOSE=false

usage() {
    cat <<EOF
upgrade-all.sh — upgrade every active be-BOP tenant.

Usage:
  upgrade-all.sh [options]

Options:
  --version <tag>            release tag, or "latest" (default)
  --rolling                  one tenant at a time (default)
  --parallel                 all tenants in parallel
  --filter <regex>           only tenants matching this regex (grep -E)
  --continue-on-failure      in --rolling mode, do not abort on first error
  --secrets-file <path>      override default ${SECRETS_FILE}
  --non-interactive          no prompts; exit if input would be required
  --dry-run                  print actions without executing
  --verbose
  -h, --help

Notes:
  - Tenants in soft-deleted/archived states are silently skipped.
  - In --parallel mode, upgrades happen concurrently; the wall-clock is
    shorter but downtime overlaps across tenants.
  - In --rolling mode, --continue-on-failure makes the script attempt
    every tenant even if some fail (still exits non-zero overall).
EOF
}

while (( $# )); do
    case "$1" in
        --version)              VERSION="$2"; shift 2 ;;
        --rolling)              MODE=rolling; shift ;;
        --parallel)             MODE=parallel; shift ;;
        --filter)               FILTER="$2"; shift 2 ;;
        --continue-on-failure)  CONTINUE_ON_FAILURE=true; shift ;;
        --secrets-file)         SECRETS_FILE="$2"; shift 2 ;;
        --non-interactive)      RUN_NON_INTERACTIVE=true; shift ;;
        --dry-run)              DRY_RUN=true; shift ;;
        --verbose)               VERBOSE=true; shift ;;
        -h|--help)              usage; exit 0 ;;
        --) shift; break ;;
        -*) die "unknown option: $1 (try --help)" ;;
        *) die "unexpected positional arg: $1" ;;
    esac
done

BEBOP_TOOLING_SYSLOG_IDENT="bebop-tooling-${SCRIPT_NAME}"
export BEBOP_TOOLING_SYSLOG_IDENT
export RUN_NON_INTERACTIVE VERBOSE DRY_RUN

# Locate the upgrade-tenant.sh helper (sibling in source tree, /usr/local/bin
# once installed).
locate_upgrade_tenant() {
    local sibling="$SCRIPT_DIR/upgrade-tenant.sh"
    if [[ -x "$sibling" ]]; then
        echo "$sibling"; return 0
    fi
    if [[ -x /usr/local/bin/upgrade-tenant.sh ]]; then
        echo /usr/local/bin/upgrade-tenant.sh; return 0
    fi
    die "cannot locate upgrade-tenant.sh (looked in ${sibling} and /usr/local/bin)"
}

# Compose the upgrade-tenant.sh argv to forward.
upgrade_tenant_argv() {
    local tenant="$1"
    local args=("$tenant" --version "$VERSION" --secrets-file "$SECRETS_FILE")
    [[ "$DRY_RUN" == "true" ]]            && args+=(--dry-run)
    [[ "$VERBOSE" == "true" ]]            && args+=(--verbose)
    [[ "$RUN_NON_INTERACTIVE" == "true" ]] && args+=(--non-interactive)
    printf '%s\n' "${args[@]}"
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

    local upgrade_tenant_path
    upgrade_tenant_path=$(locate_upgrade_tenant)

    # Build the tenant list.
    local all_active=() filtered=()
    while IFS= read -r t; do
        [[ -z "$t" ]] && continue
        all_active+=("$t")
        if [[ -z "$FILTER" ]] || printf '%s\n' "$t" | grep -qE "$FILTER"; then
            filtered+=("$t")
        fi
    done < <(registry_list_by_status active)

    if (( ${#filtered[@]} == 0 )); then
        log_info "no active tenants to upgrade (registry has ${#all_active[@]} active in total; filter='${FILTER}')"
        exit 0
    fi
    log_info "upgrade-all: target=${VERSION}, mode=${MODE}, filter='${FILTER:-(none)}', tenants=${#filtered[@]}: ${filtered[*]}"

    local failed=() succeeded=()

    case "$MODE" in
        rolling)
            local t
            for t in "${filtered[@]}"; do
                log_info "==== upgrading ${t} (rolling) ===="
                local rc=0
                "$upgrade_tenant_path" $(upgrade_tenant_argv "$t") || rc=$?
                if (( rc == 0 )); then
                    succeeded+=("$t")
                else
                    failed+=("$t")
                    if [[ "$CONTINUE_ON_FAILURE" != "true" ]]; then
                        log_error "rolling upgrade aborted on failure of '${t}' (use --continue-on-failure to keep going)"
                        break
                    fi
                fi
            done
            ;;
        parallel)
            local t pids=() pid t_for_pid=()
            for t in "${filtered[@]}"; do
                log_info "==== launching upgrade for ${t} (parallel) ===="
                "$upgrade_tenant_path" $(upgrade_tenant_argv "$t") &
                pid=$!
                pids+=("$pid")
                t_for_pid+=("$t")
            done
            local i
            for (( i=0; i<${#pids[@]}; i++ )); do
                if wait "${pids[$i]}" 2>/dev/null; then
                    succeeded+=("${t_for_pid[$i]}")
                else
                    failed+=("${t_for_pid[$i]}")
                fi
            done
            ;;
    esac

    cat <<EOF

==========================================================================
  upgrade-all summary  (target: ${VERSION}, mode: ${MODE})
==========================================================================
  Selected:   ${#filtered[@]}  (${filtered[*]})
  Succeeded:  ${#succeeded[@]} ${succeeded[*]:-}
  Failed:     ${#failed[@]}    ${failed[*]:-}
==========================================================================
EOF

    if (( ${#failed[@]} > 0 )); then
        notify_failure \
            "[be-BOP tooling] upgrade-all (${VERSION}) had ${#failed[@]} failure(s)" \
            "Failed tenants: ${failed[*]}
Succeeded: ${succeeded[*]:-(none)}
Mode: ${MODE}"
        exit 1
    fi
    notify_success \
        "[be-BOP tooling] upgrade-all OK (${#succeeded[@]} tenants → ${VERSION})" \
        "Tenants: ${succeeded[*]}"
}

main "$@"
