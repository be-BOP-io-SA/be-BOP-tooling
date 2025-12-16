#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Roosembert Palacios <roos@be-bop.io>, 2025
#
# be-bop-cli.sh
#
# Command-line interface for be-BOP operations.

set -eEuo pipefail

readonly SCRIPT_VERSION="2.4.2"
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
    execute_command
}

main "$@"
