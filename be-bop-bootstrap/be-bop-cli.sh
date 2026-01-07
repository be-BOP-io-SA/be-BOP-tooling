#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Roosembert Palacios <roos@be-bop.io>, 2025
#
# be-bop-cli.sh
#
# Command-line interface for be-BOP operations.

set -eEuo pipefail

readonly SCRIPT_VERSION="2.5.2"
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
    case "$COMMAND" in
        version)
            # Allow running as any user
            ;;
        *)
            check_if_running_as_be_bop_cli_user
            ;;
    esac
}

# This function retrieves the latest be-BOP release metadata from GitHub
# This function exports the following variables:
#   - LATEST_RELEASE_META: The latest be-BOP release metadata (JSON)
#   - LATEST_RELEASE_ASSET_BASENAME: The basename of the latest be-BOP release asset
#   - LATEST_RELEASE_TAG: The tag name of the latest release (e.g., rel/2025-12-17/bfe5008)
#
# If we're unable to retrieve the release information, this function will die with an error.
determine_latest_release_meta() {
    log_debug "Fetching latest be-BOP release metadata from GitHub..."

    local curl_args=(
        "--connect-timeout" "$CURL_CONNECT_TIMEOUT"
        "--fail"
        "--location"
        "--max-time" "$CURL_DOWNLOAD_TIMEOUT"
        "--show-error"
        "--silent"
    )
    local url="https://api.github.com/repos/${BEBOP_GITHUB_REPO}/releases/latest"

    if ! LATEST_RELEASE_META="$(curl "${curl_args[@]}" "$url" 2>/dev/null)"; then
        die $EXIT_ERROR $LINENO "Failed to fetch release information from GitHub. Please check your internet connection."
    fi

    if [[ -z "$LATEST_RELEASE_META" ]]; then
        die $EXIT_ERROR $LINENO "Received empty response from GitHub API"
    fi

    local filter='
        .assets[]
        | select(.name | test("be-BOP\\.release\\.[0-9]{4}-[0-9]{2}-[0-9]{2}\\.[a-f0-9]+.*\\.zip"))
        | .name
        | sub("\\.zip$"; "")
    '

    LATEST_RELEASE_ASSET_BASENAME=$(echo "$LATEST_RELEASE_META" | jq -r "$filter" | head -n 1)
    LATEST_RELEASE_TAG=$(echo "$LATEST_RELEASE_META" | jq -r '.tag_name')

    if [[ -z "$LATEST_RELEASE_ASSET_BASENAME" ]]; then
        die $EXIT_ERROR $LINENO "Could not find valid be-BOP release asset in GitHub response"
    fi

    log_debug "Latest release: $LATEST_RELEASE_TAG ($LATEST_RELEASE_ASSET_BASENAME)"
}

# This function retrieves all be-BOP releases from GitHub and extracts latest release metadata
# This function exports the following variables:
#   - ALL_RELEASES_SUMMARY: An opinionated summary of some be-BOP releases suitable for display
#   - LATEST_RELEASE_META: The latest be-BOP release metadata (JSON, extracted from first release)
#   - LATEST_RELEASE_ASSET_BASENAME: The basename of the latest be-BOP release asset
#   - LATEST_RELEASE_TAG: The tag name of the latest release (e.g., rel/2025-12-17/bfe5008)
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
    export LATEST_RELEASE_META=$(echo "$releases_data" | jq '.[0]')
    local filter='
        .assets[]
        | select(.name | test("be-BOP\\.release\\.[0-9]{4}-[0-9]{2}-[0-9]{2}\\.[a-f0-9]+.*\\.zip"))
        | .name
        | sub("\\.zip$"; "")
    '
    export LATEST_RELEASE_ASSET_BASENAME=$(echo "$LATEST_RELEASE_META" | jq -r "$filter" | head -n 1)
    export LATEST_RELEASE_TAG=$(echo "$LATEST_RELEASE_META" | jq -r '.tag_name')

    if [[ -z "$LATEST_RELEASE_ASSET_BASENAME" ]]; then
        die $EXIT_ERROR $LINENO "Could not find valid be-BOP release asset in GitHub response"
    fi

    log_debug "Latest release: $LATEST_RELEASE_TAG ($LATEST_RELEASE_ASSET_BASENAME)"
}

list_releases() {
    log_info "Fetching available be-BOP releases..."
    fetch_all_releases

    local current_installed=""
    if [[ -L /var/lib/be-BOP/releases/current ]]; then
        current_installed="$(basename "$(readlink -f /var/lib/be-BOP/releases/current)")"
    fi

    echo ""
    echo "Available be-BOP releases:"
    echo "$ALL_RELEASES_SUMMARY" | head -10
    echo ""

    if [[ -n "$current_installed" ]]; then
        if [[ "$current_installed" = "$LATEST_RELEASE_ASSET_BASENAME" ]]; then
            echo "Current installation: ✓ $LATEST_RELEASE_TAG (latest)"
        else
            echo "Current installation: $current_installed"
            echo "Latest available: ⚠ $LATEST_RELEASE_TAG (update available)"
        fi
    else
        echo "Current installation: ✗ No be-BOP release installed"
        echo "Latest available: $LATEST_RELEASE_TAG"
    fi
}

install_release() {
    local target_version="${RELEASE_VERSION:-}"

    if [[ -n "$target_version" ]]; then
        log_info "Installing be-BOP release: $target_version"
        die $EXIT_ERROR $LINENO "Specific version installation not yet implemented. Use 'release install' without version to install latest."
    else
        log_info "Installing latest be-BOP release..."
    fi

    # Get latest release info if not already available
    if [[ -z "${LATEST_RELEASE_META:-}" ]]; then
        determine_latest_release_meta
    fi

    local TARGET_DIR="/var/lib/be-BOP/releases/${LATEST_RELEASE_ASSET_BASENAME}"
    if [[ -d "$TARGET_DIR" ]] && [[ -f "$TARGET_DIR/.bebop_install_success" ]]; then
        log_info "Latest be-BOP release is already installed"
        return 0
    fi

    # Create temporary directory for download
    local TMPDIR=$(mktemp -d)
    # shellcheck disable=SC2064  # TMPDIR should be expanded here (and not on trap).
    trap "rm -rf $TMPDIR" RETURN 2>/dev/null || true
    pushd "$TMPDIR" > /dev/null

    local filter='.assets[] | select(.name == "'"$LATEST_RELEASE_ASSET_BASENAME"'.zip") | .browser_download_url'
    local LATEST_RELEASE_URL=$(echo "$LATEST_RELEASE_META" | jq -r "$filter")

    if [[ -z "$LATEST_RELEASE_URL" || "$LATEST_RELEASE_URL" = "null" ]]; then
        die $EXIT_ERROR $LINENO "Could not find download URL for be-BOP release ${LATEST_RELEASE_ASSET_BASENAME}"
    fi

    log_info "Downloading ${LATEST_RELEASE_ASSET_BASENAME} from GitHub..."
    log_debug "Download URL: ${LATEST_RELEASE_URL}"
    local curl_args=(
        "--connect-timeout" "$CURL_CONNECT_TIMEOUT"
        "--fail"
        "--location"
        "--max-time" "$CURL_DOWNLOAD_TIMEOUT"
        "--progress-bar"
        "--show-error"
        "--output" "be-BOP-latest.zip"
    )
    if ! curl "${curl_args[@]}" "$LATEST_RELEASE_URL"; then
        die $EXIT_ERROR $LINENO "Failed to download be-BOP release. Please check your internet connection."
    fi

    log_debug "Extracting be-BOP release archive..."
    if ! unzip -q be-BOP-latest.zip; then
        die $EXIT_ERROR $LINENO "Failed to extract be-BOP release archive"
    fi

    local EXTRACTED_DIR=$(find . -maxdepth 1 -type d -name "be-BOP release *" | head -1)
    if [[ -z "$EXTRACTED_DIR" ]]; then
        die $EXIT_ERROR $LINENO "Could not find extracted directory for be-BOP release"
    fi

    if [[ -d "$TARGET_DIR" ]]; then
        log_debug "Removing existing installation directory"
        rm -rf "$TARGET_DIR"
    fi
    mkdir -p "$(dirname "$TARGET_DIR")"
    mv "$EXTRACTED_DIR" "$TARGET_DIR"

    # Install dependencies
    log_info "Installing be-BOP ${LATEST_RELEASE_ASSET_BASENAME} dependencies..."
    pushd "$TARGET_DIR" > /dev/null
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

    log_info "Latest be-BOP release installed successfully at ${TARGET_DIR}!"

    # Create current symlink
    if [[ -L /var/lib/be-BOP/releases/current ]]; then
        rm -f /var/lib/be-BOP/releases/current
    elif [[ -e /var/lib/be-BOP/releases/current ]]; then
        die $EXIT_ERROR $LINENO "Something unknown is blocking the creation of /var/lib/be-BOP/releases/current symlink. Please check what exists at this path and remove it manually."
    fi
    ln -sf "$LATEST_RELEASE_ASSET_BASENAME" /var/lib/be-BOP/releases/current

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
    local latest_tag=""
    local latest_basename=""

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
    if determine_latest_release_meta 2>/dev/null; then
        latest_tag="$LATEST_RELEASE_TAG"
        latest_basename="$LATEST_RELEASE_ASSET_BASENAME"

        if [[ -n "$current_installed" ]]; then
            if [[ "$current_installed" = "$latest_basename" ]]; then
                echo "Version status: ✓ Latest version installed ($latest_tag)"
            else
                echo "Version status: ⚠ Newer version available ($latest_tag)"
                if [[ "$FAIL_IF_LATEST_NOT_INSTALLED" = true ]]; then
                    exit_code=2
                fi
            fi
        else
            echo "Version status: ✗ Latest version not installed ($latest_tag)"
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
