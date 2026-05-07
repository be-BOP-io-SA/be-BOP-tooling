# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 be-bop.io contributors
#
# transaction.sh — undo-stack helpers for transactional scripts.
# Source this file AFTER lib/log.sh.
#
# The model: scripts that mutate external state (DNS records, Mongo databases,
# Garage buckets, systemd units, …) push a reversal command onto a stack after
# every successful step. On failure, txn_rollback walks the stack in reverse.
# On success, txn_commit clears it.
#
# Typical usage:
#
#   txn_init
#   trap 'txn_rollback; exit 1' ERR
#
#   create_dns_record "$tenant"
#   txn_register_undo "DNS A record" "delete_dns_record '$tenant'"
#
#   create_mongo_database "$tenant"
#   txn_register_undo "Mongo database" "drop_mongo_database '$tenant'"
#
#   ...
#   txn_commit
#
# Undo commands are eval'd; the caller is responsible for proper quoting of
# arguments embedded in the command string. Failures of individual undo steps
# are logged but do not abort the rollback — we always try every step.

[[ -n "${_BEBOP_TXN_SOURCED:-}" ]] && return 0
readonly _BEBOP_TXN_SOURCED=1

declare -ga TXN_UNDO_NAMES=()
declare -ga TXN_UNDO_COMMANDS=()

txn_init() {
    TXN_UNDO_NAMES=()
    TXN_UNDO_COMMANDS=()
}

txn_register_undo() {
    if (( $# != 2 )); then
        die "txn_register_undo: expected 2 args (name, command), got $#"
    fi
    TXN_UNDO_NAMES+=("$1")
    TXN_UNDO_COMMANDS+=("$2")
    log_debug "txn: registered undo for '$1'"
}

txn_rollback() {
    local n=${#TXN_UNDO_NAMES[@]}
    if (( n == 0 )); then
        log_warn "txn: rollback called with empty stack — nothing to undo"
        return 0
    fi
    log_warn "txn: rolling back $n step(s)..."
    local i
    for (( i = n - 1; i >= 0; i-- )); do
        local name="${TXN_UNDO_NAMES[$i]}"
        local cmd="${TXN_UNDO_COMMANDS[$i]}"
        log_warn "txn: undo $((i+1))/$n — $name"
        if ! eval "$cmd"; then
            log_error "txn: undo step '$name' FAILED — system may be in an inconsistent state"
        fi
    done
    log_warn "txn: rollback complete"
}

txn_commit() {
    local n=${#TXN_UNDO_NAMES[@]}
    log_debug "txn: committing transaction ($n step(s))"
    TXN_UNDO_NAMES=()
    TXN_UNDO_COMMANDS=()
}

# Returns the number of undo steps currently on the stack.
txn_size() {
    echo "${#TXN_UNDO_NAMES[@]}"
}
