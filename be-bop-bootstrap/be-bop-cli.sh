#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Roosembert Palacios <roos@be-bop.io>, 2025
#
# be-bop-cli.sh
#
# Command-line interface for be-BOP operations.

set -eEuo pipefail

readonly SCRIPT_VERSION="2.5.0"
readonly SCRIPT_NAME="be-bop-cli"
readonly EXIT_SUCCESS=0
readonly EXIT_ERROR=1

# Default command and options
COMMAND="help"

show_help() {
    cat << EOF
$SCRIPT_NAME v$SCRIPT_VERSION - be-BOP Command Line Interface

USAGE:
    $SCRIPT_NAME [OPTIONS] [COMMAND]

DESCRIPTION:
    Command-line interface for managing and operating be-BOP instances.
    Provides tools for deployment, monitoring, and administration.

COMMANDS:
    help                    Show this help message (default)

OPTIONS:
    --help, -h              Show this help message
    --version               Show version information
EOF
}

show_version() {
    echo "$SCRIPT_NAME v$SCRIPT_VERSION"
}

parse_cli_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h|help)
                COMMAND="help"
                shift
                ;;
            --version)
                COMMAND="version"
                shift
                ;;
            *)
                echo "Unknown option or command: $1. Use --help for usage information." >&2
                exit $EXIT_ERROR
                ;;
        esac
    done
}

check_if_running_as_be_bop_cli_user() {
    local current_user=$(whoami 2>/dev/null || id -un 2>/dev/null || echo "unknown")

    if [[ "$current_user" != "be-bop-cli" ]]; then
        echo "ERROR: This script must be run as the 'be-bop-cli' user." >&2
        echo "" >&2
        echo "Current user: $current_user" >&2
        echo "Required user: be-bop-cli" >&2
        echo "" >&2
        echo "If the be-bop-cli user doesn't exist, please run the be-bop-wizard to set up the system properly." >&2
        exit $EXIT_ERROR
    fi
}

check_user() {
    case "$COMMAND" in
        help|version)
            # Allow any user to run these commands
            ;;
        *)
            check_if_running_as_be_bop_cli_user
            ;;
    esac
}

execute_command() {
    case "$COMMAND" in
        help)
            show_help
            ;;
        version)
            show_version
            ;;
        *)
            echo "Unknown command: $COMMAND" >&2
            exit $EXIT_ERROR
            ;;
    esac
}

main() {
    parse_cli_arguments "$@"
    check_user
    execute_command
}

main "$@"
