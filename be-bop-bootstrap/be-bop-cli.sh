#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Roosembert Palacios <roos@be-bop.io>, 2025
#
# be-bop-cli.sh
#
# Command-line interface for be-BOP operations.

set -eEuo pipefail

readonly SCRIPT_VERSION="2.5.3"
readonly SCRIPT_NAME="be-bop-cli"
readonly EXIT_SUCCESS=0
readonly EXIT_ERROR=1

# GitHub repository for be-BOP releases
readonly BEBOP_GITHUB_REPO="${BEBOP_GITHUB_REPO:-be-BOP-io-SA/be-BOP}"

# Network timeout constants
readonly CURL_CONNECT_TIMEOUT=${CURL_CONNECT_TIMEOUT:-30}
readonly CURL_DOWNLOAD_TIMEOUT=${CURL_DOWNLOAD_TIMEOUT:-600}

# Default command and options
COMMAND="release"
SUBCOMMAND="list"
FAIL_IF_LATEST_NOT_INSTALLED=false
NO_RESTART_AFTER_INSTALL=false
VERBOSE=false

# Logging functions
log_info() {
    echo "[$SCRIPT_NAME] [$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*"
}

log_warn() {
    echo "[$SCRIPT_NAME] [$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $*" >&2
}

log_error() {
    echo "[$SCRIPT_NAME] [$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >&2
}

log_debug() {
    if [[ "$VERBOSE" = true ]]; then
        echo "[$SCRIPT_NAME] [$(date '+%Y-%m-%d %H:%M:%S')] [DEBUG] $*" >&2
    fi
}

die() {
    local exit_code=$1
    local line_number=$2
    shift 2
    log_error "Line $line_number: $*"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "💡 The operation was stopped safely to prevent issues."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit $exit_code
}

die_missing_tool() {
    local tool=$1
    log_error "Required tool '$tool' is not available"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "💡 Missing required tool: $tool"
    echo ""
    echo "To continue, please install the missing tool:"
    case "$tool" in
        curl) echo "  • On Debian/Ubuntu: apt install curl" ;;
        jq) echo "  • On Debian/Ubuntu: apt install jq" ;;
        unzip) echo "  • On Debian/Ubuntu: apt install unzip" ;;
        systemctl) echo "  • systemd is required for service management" ;;
        corepack|pnpm) echo "  • Node.js ecosystem tools are required for be-BOP" ;;
        *) echo "  • Please install '$tool' using your system package manager" ;;
    esac
    echo ""
    echo "After installing the tool, run the command again."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit $EXIT_ERROR
}

die_unknown_release() {
    local release="$1"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "⚠️ The specified release could not found: $release"
    echo ""
    echo "To see all available releases, run:"
    echo "  be-bop-cli release list"
    echo ""
    echo "(The release ID is shown in the first column of the output.)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "If you need assistance, please share the full command output with us."
    echo ""
    echo "🪪 Contact options:"
    echo "    - Email: contact@be-bop.io"
    echo "    - Nostr: npub16l9pnrkhhagkucjhxvvztz2czv9ex8s5u7yg80ghw9ccjp4j25pqaku4ha"
    echo ""
    echo "📡 Follow updates and tooling improvements at:"
    echo "    → https://be-bop.io/release-note"
    echo ""
    echo "Thank you for helping us make things better — and for being a friendly human. 🤝"
    exit $EXIT_ERROR
}

list_tools_for_command() {
    case "$COMMAND" in
        "release") echo "curl jq unzip corepack pnpm systemctl" ;;
        "status") echo "curl jq" ;;
        *) echo "" ;;
    esac
}

check_required_tools() {
    local tools_needed=$(list_tools_for_command)
    for tool in $tools_needed; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            die_missing_tool "$tool"
        fi
    done
}

show_help() {
    cat << EOF
$SCRIPT_NAME v$SCRIPT_VERSION - be-BOP Command Line Interface

USAGE:
    $SCRIPT_NAME [OPTIONS] [COMMAND]

DESCRIPTION:
    Command-line interface for managing and operating be-BOP instances.
    Provides tools for deployment, monitoring, and administration.

COMMANDS:
    help                    Show this help message
    release                 Manage be-BOP releases
        list                List available releases (default)
        install [version]   Install specific version or latest
    status                  Show be-BOP status

OPTIONS:
    --help, -h              Show this help message
    --version, -v           Show version information
    --fail-if-latest-release-not-installed
                            (status only) Exit with error if latest release not installed
    --no-restart-after-install
                            (install only) Don't restart be-BOP service after installation
    --verbose               Enable detailed logging output

EXAMPLES:
    # List all available releases
    $SCRIPT_NAME release list

    # Install the latest release
    $SCRIPT_NAME release install

    # Install a specific release version
    $SCRIPT_NAME release install rel/2025-12-17/bfe5008
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
            --fail-if-latest-release-not-installed)
                FAIL_IF_LATEST_NOT_INSTALLED=true
                shift
                ;;
            --no-restart-after-install)
                NO_RESTART_AFTER_INSTALL=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            release)
                COMMAND="release"
                shift
                if [[ $# -gt 0 && ! "$1" =~ ^- ]]; then
                    case "$1" in
                        list)
                            SUBCOMMAND="list"
                            shift
                            ;;
                        install)
                            SUBCOMMAND="install"
                            shift
                            if [[ $# -gt 0 && ! "$1" =~ ^- ]]; then
                                RELEASE_VERSION="$1"
                                shift
                            fi
                            ;;
                        *)
                            echo "Unknown release subcommand: $1. Use --help for usage information." >&2
                            exit $EXIT_ERROR
                            ;;
                    esac
                fi
                ;;
            status)
                COMMAND="status"
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
    case "$COMMAND,$SUBCOMMAND" in
        help,*|version,*|release,list)
            # Allow running as any user
            ;;
        *)
            check_if_running_as_be_bop_cli_user
            ;;
    esac
}

# This function retrieves all be-BOP releases from GitHub and extracts latest release metadata
# This function exports the following variables:
#   - ALL_RELEASES_SUMMARY: An opinionated summary of some be-BOP releases suitable for display
#   - RELEASE_META: The latest be-BOP release metadata (JSON, extracted from first release)
#
# If we're unable to retrieve the release information, this function will die with an error.
fetch_all_releases() {
    log_debug "Fetching all be-BOP releases from GitHub..."

    local curl_args=(
        "--connect-timeout" "$CURL_CONNECT_TIMEOUT"
        "--fail"
        "--location"
        "--max-time" "$CURL_DOWNLOAD_TIMEOUT"
        "--show-error"
        "--silent"
    )

    local url="https://api.github.com/repos/${BEBOP_GITHUB_REPO}/releases"
    local releases_data
    if ! releases_data="$(curl "${curl_args[@]}" "$url" 2>/dev/null)"; then
        die $EXIT_ERROR $LINENO "Failed to fetch releases from GitHub. Please check your internet connection."
    fi

    if [[ -z "$releases_data" ]]; then
        die $EXIT_ERROR $LINENO "Received empty response from GitHub releases API"
    fi

    # Export latest release metadata from the releases data
    local jq_filter1='.[] | "\(.tag_name) - \(.name) (\(.published_at | split("T")[0]))"'
    export ALL_RELEASES_SUMMARY="$(echo "$releases_data" | jq -r "$jq_filter1")"
    local jq_filter2='
      .[]
      | (.assets |= map(
        select(.name | test("be-BOP\\.release\\.[0-9]{4}-[0-9]{2}-[0-9]{2}\\.[a-f0-9]+.*\\.zip"))
        | {name, browser_download_url}))
      | {
        tag_name,
        name,
        published_at: (.published_at | split("T")[0]),
        asset_name: .assets[0].name, asset_url: .assets[0].browser_download_url
      }
    '
    export RELEASE_META="$(echo "$releases_data" | jq -r "$jq_filter2" | jq -s)"
    if [[ -z "$RELEASE_META" ]]; then
        die $EXIT_ERROR $LINENO "Could not find valid be-BOP release asset in GitHub response"
    fi
    local latest_release_name="$(echo "$RELEASE_META" | jq -r '.[0].name')"
    local latest_release_tag="$(echo "$RELEASE_META" | jq -r '.[0].tag_name')"

    log_debug "Latest release: $latest_release_name ($latest_release_tag)"
}

list_releases() {
    log_info "Fetching available be-BOP releases..."
    # Always fetch the latest release info
    fetch_all_releases

    local current_installed=""
    if [[ -L /var/lib/be-BOP/releases/current ]]; then
        current_installed="$(basename "$(readlink -f /var/lib/be-BOP/releases/current)")"
    fi
    local latest_name="$(echo "$RELEASE_META" | jq -r '.[0].name')"
    local latest_asset="$(echo "$RELEASE_META" | jq -r '.[0].asset_name | sub("\\.zip$"; "")')"
    local latest_tag="$(echo "$RELEASE_META" | jq -r '.[0].tag_name')"

    echo ""
    echo "Available be-BOP releases:"
    echo "$ALL_RELEASES_SUMMARY" | head -10
    echo ""

    if [[ -n "$current_installed" ]]; then
        if [[ "$current_installed" = "$latest_asset" ]]; then
            echo "Current installation: ✓ $latest_asset ($latest_tag - $latest_name)"
        else
            echo "Current installation: $current_installed"
            echo "Latest available: ⚠ $latest_asset ($latest_tag - $latest_name)"
        fi
    else
        echo "Current installation: ✗ No be-BOP release installed"
        echo "Latest available: $latest_tag"
    fi
}

install_release() {
    local target_version="${RELEASE_VERSION:-}"

    # Fetch the latest release info if not already available
    if [[ -z "${RELEASE_META:-}" ]]; then
        fetch_all_releases
    fi

    local target_url;
    local target_name;
    case "$target_version" in
      ""|latest)
        target_url="$(echo "$RELEASE_META" | jq -r '.[0].asset_url')"
        target_name="$(echo "$RELEASE_META" | jq -r '.[0].asset_name | sub("\\.zip$"; "")')"
        ;;
      branch=*)
        branch_name="${target_version#branch=}"
        # Apply GitHub's excaping rules
        branch_name="${branch_name//\//__}"
        target_url="https://www.artifact.ci/artifact/view/be-BOP-io-SA/be-BOP/branch/$branch_name/be-BOP-release/be-BOP-release.zip"
        target_name="$branch_name"
        ;;
      *)
        local target_meta="$(echo "$RELEASE_META" | jq -r 'first(.[]|select(.tag_name == "'"$target_version"'"))')"
        target_url="$(echo "$target_meta" | jq -r '.asset_url')"
        target_name="$(echo "$target_meta" | jq -r '.asset_name | sub("\\.zip$"; "")')"
        ;;
    esac

    if [[ -z "$target_url" || "$target_url" = "null" ]]; then
        die_unknown_release "$target_version"
    fi

    local target_dir="/var/lib/be-BOP/releases/${target_name}"
    if [[ -d "$target_dir" ]] && [[ -f "$target_dir/.bebop_install_success" ]]; then
        log_info "The specified be-BOP release is already installed"
        return 0
    fi

    # Create temporary directory for download
    local TMPDIR=$(mktemp -d)
    # shellcheck disable=SC2064  # TMPDIR should be expanded here (and not on trap).
    trap "rm -rf $TMPDIR" RETURN 2>/dev/null || true
    pushd "$TMPDIR" > /dev/null

    log_info "Downloading release ${target_dir}..."
    log_debug "Download URL: ${target_url}"
    local curl_args=(
        "--connect-timeout" "$CURL_CONNECT_TIMEOUT"
        "--fail"
        "--location"
        "--max-time" "$CURL_DOWNLOAD_TIMEOUT"
        "--progress-bar"
        "--show-error"
        "--output" "be-BOP-update.zip"
    )
    if ! curl "${curl_args[@]}" "$target_url"; then
        die $EXIT_ERROR $LINENO "Failed to download be-BOP release. Please check your internet connection."
    fi

    log_debug "Extracting be-BOP release archive..."
    if ! unzip -q be-BOP-update.zip; then
        die $EXIT_ERROR $LINENO "Failed to extract be-BOP release archive"
    fi

    local extracted_dir=$(find . -maxdepth 1 -type d -name "be-BOP release *" | head -1)
    if [[ -z "$extracted_dir" ]]; then
        die $EXIT_ERROR $LINENO "Could not find extracted directory for be-BOP release"
    fi

    if [[ -d "$target_dir" ]]; then
        log_debug "Removing stalled installation directory ($target_dir)"
        rm -rf "$target_dir"
    fi
    mkdir -p "$(dirname "$target_dir")"
    mv "$extracted_dir" "$target_dir"

    # Install dependencies
    log_info "Installing be-BOP ${target_dir} dependencies..."
    pushd "$target_dir" > /dev/null
    if ! corepack enable; then
        die $EXIT_ERROR $LINENO "Failed to enable corepack"
    fi
    if ! corepack install; then
        die $EXIT_ERROR $LINENO "Failed to install package manager via corepack"
    fi
    if ! corepack prepare pnpm@latest --activate; then
        die $EXIT_ERROR $LINENO "Failed to activate pnpm"
    fi
    if ! pnpm install --prod --frozen-lockfile; then
        die $EXIT_ERROR $LINENO "Failed to install be-BOP dependencies"
    fi
    touch .bebop_install_success
    popd > /dev/null  # Inside installation

    popd > /dev/null
    rm -rf "$TMPDIR"

    log_info "Latest be-BOP release installed successfully at ${target_dir}!"

    # Create current symlink
    if [[ -L /var/lib/be-BOP/releases/current ]]; then
        rm -f /var/lib/be-BOP/releases/current
    elif [[ -e /var/lib/be-BOP/releases/current ]]; then
        die $EXIT_ERROR $LINENO "Something unknown is blocking the creation of /var/lib/be-BOP/releases/current symlink. Please check what exists at this path and remove it manually."
    fi
    ln -sf "$target_dir" /var/lib/be-BOP/releases/current

    # Restart be-BOP service after installation (unless disabled)
    if [[ "$NO_RESTART_AFTER_INSTALL" = false ]]; then
        if systemctl is-active --quiet bebop 2>/dev/null; then
            log_info "Restarting be-BOP service after installation..."
            if ! sudo systemctl restart bebop; then
                log_warn "Failed to restart be-BOP service. You may need to restart it manually."
            else
                log_info "be-BOP service restarted successfully"
            fi
        elif systemctl is-enabled --quiet bebop 2>/dev/null; then
            log_info "Starting be-BOP service after installation..."
            if ! sudo systemctl start bebop; then
                log_warn "Failed to start be-BOP service. You may need to start it manually."
            else
                log_info "be-BOP service started successfully"
            fi
        else
            log_debug "be-BOP service not configured, skipping restart"
        fi
    else
        log_info "Skipping be-BOP service restart (--no-restart-after-install specified)"
    fi
}

show_status() {
    local exit_code=0
    local current_installed=""

    echo "be-BOP Status:"
    echo ""

    # Check current installation
    if [[ -L /var/lib/be-BOP/releases/current ]]; then
        current_installed=$(basename "$(readlink -f /var/lib/be-BOP/releases/current)")
        echo "Installed release: $current_installed"

        if [[ -f "/var/lib/be-BOP/releases/$current_installed/.bebop_install_success" ]]; then
            echo "Installation status: ✓ Complete"
        else
            echo "Installation status: ⚠ Incomplete"
            exit_code=1
        fi
    else
        echo "Installation status: ✗ Not installed"
        exit_code=1
    fi

    # Always check latest release info for status display
    if fetch_all_releases 2>/dev/null; then
        local latest_name="$(echo "$RELEASE_META" | jq -r '.[0].name')"
        local latest_tag="$(echo "$RELEASE_META" | jq -r '.[0].tag_name')"
        local latest_asset="$(echo "$RELEASE_META" | jq -r '.[0].asset_name | sub("\\.zip$"; "")')"

        if [[ -n "$current_installed" ]]; then
            if [[ "$current_installed" = "$latest_asset" ]]; then
                echo "Version status: ✓ Latest version installed: $latest_asset ($latest_tag - $latest_name)"
            else
                echo "Version status: ⚠ A new version is available: $latest_asset ($latest_tag - $latest_name)"
                if [[ "$FAIL_IF_LATEST_NOT_INSTALLED" = true ]]; then
                    exit_code=2
                fi
            fi
        else
            echo "Version status: ✗ A new version is available: $latest_asset ($latest_tag - $latest_name)"
            if [[ "$FAIL_IF_LATEST_NOT_INSTALLED" = true ]]; then
                exit_code=1
            fi
        fi
    else
        if [[ "$FAIL_IF_LATEST_NOT_INSTALLED" = true ]]; then
            echo "Version status: ⚠ Could not retrieve latest release information"
            exit_code=3
        else
            echo "Version status: ? Could not retrieve latest release information"
        fi
    fi

    # Check service status
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet bebop 2>/dev/null; then
            echo "Service status: ✓ Running"
        elif systemctl is-enabled --quiet bebop 2>/dev/null; then
            echo "Service status: ⚠ Installed but not running"
        else
            echo "Service status: ✗ Not installed"
        fi
    else
        echo "Service status: ? (systemctl not available)"
    fi

    exit $exit_code
}

execute_command() {
    check_required_tools
    case "$COMMAND" in
        help)
            show_help
            ;;
        version)
            show_version
            ;;
        release)
            case "$SUBCOMMAND" in
                list)
                    list_releases
                    ;;
                install)
                    install_release
                    ;;
                *)
                    echo "Unknown release subcommand: $SUBCOMMAND" >&2
                    exit $EXIT_ERROR
                    ;;
            esac
            ;;
        status)
            show_status
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
