#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Roosembert Palacios <roos@be-bop.io>, 2025
#
# be-bop-wizard.sh
#
# This script is a self-contained system setup tool.
#
# Think of this as an automated technician rather than a blind installer.
# It doesn’t just run commands — it *looks around first*, figures out what’s
# already in place, and only does what’s actually needed.
#
# Here’s the idea:
#   - The script inspects your system and writes down what it finds.
#   - Based on that, it decides what steps are required to reach a healthy,
#     working be-BOP.
#   - It gathers any tools it needs (like curl or jq) before starting work.
#   - Then it carries out those steps in a careful, predictable order.
#   - Finally, it summarizes what changed and what’s running.
#
# In other words: it’s a checklist manager for systems.
# Instead of hard-coding a one-shot installer, we describe each task
# (install Node.js, start MongoDB, configure Nginx, etc.) and let the script
# figure out when to run them.
#
# Why it’s written this way:
#   - You can rerun it safely — it only fixes what’s missing or broken.
#   - It’s readable: every action is named and described.
#   - It’s maintainable: new tasks can be added without rewriting the flow.
#
# Under the hood (for the curious):
#   The design borrows ideas from a few areas of computer science:
#     * **Expert systems** — programs that use rules and known facts to decide actions.
#     * **Effect systems** — ways of describing how operations may change the world.
#     * **Interpreters** — engines that read a list of instructions and execute them.
#   You don’t need to know any of this to use or maintain the script,
#   but it’s fun context if you like seeing how practical automation
#   and computer theory overlap. There’s a certain irony in borrowing
#   ideas from modern programming-language theory — expert systems,
#   effect tracking, interpreters — and then implementing them in
#   Bash, a language that predates the personal computer. 1970s tech,
#   2020s concepts. It works far better than it has any right to.
#
# There’s no magic here, just clear logic:
# observe the world, make a plan, and act on that plan.
# The “wizard” part is simply automation done with a bit of common sense.
set -eEuo pipefail

readonly SCRIPT_VERSION="2.5.11"
readonly SCRIPT_NAME="be-bop-wizard"
readonly SESSION_ID="wizard-$(date +%s)-$$"

# Exit codes
readonly EXIT_SUCCESS=0
readonly EXIT_ERROR=1
readonly EXIT_INCOMPATIBLE_SYSTEM_STATE=2
readonly EXIT_USER_ABORT=3

# Network and timeout constants
readonly CURL_CONNECT_TIMEOUT=${CURL_CONNECT_TIMEOUT:-30}
readonly CURL_DOWNLOAD_TIMEOUT=${CURL_DOWNLOAD_TIMEOUT:-600}
readonly SERVICE_TEST_START_RETRIES=10
readonly SERVICE_TEST_START_WAIT_SECONDS=3

# Software versions
# WARNING: Do not simply change these version numbers without careful consideration!
# Changing versions may require updating installation scripts, configuration templates,
# compatibility checks, and cleanup procedures for existing installations.
# On each version change the logic for provisioning the version be reviewed to install
# and prefer the newer version, possibly remove the previous version while keeping the
# script “safe”: For example, the previous version repositories can only be removed if
# a newer version is already installed.
readonly NODEJS_MAJOR_VERSION=22
readonly MONGODB_VERSION="8.0"
readonly PHOENIXD_VERSION="0.6.2"
readonly GARAGE_VERSION="2.2.0"

# Error trap handler
die_unexpected_error_in_function() {
    local exit_code=$?
    local line_number=$1

    log_error "A command failed at line $line_number with exit code $exit_code"
    log_error "The script paused to prevent any potential issues."
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "💡 Don’t panic — the script stopped safely after an error."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "✓ Your system has not been changed in any unsafe way"
    echo "✓ It's completely safe to re-run this script with the same arguments"
    echo "✓ The script will resume from where it left off"
    echo ""
    if ! [[ "${FULL_CMD_LINE[*]}" =~ "--verbose" ]]; then
        echo "If you’d like to investigate or get help, re-run with --verbose to get detailed output:"
        echo "  $(basename "${0:-be-bop-wizard}") ${FULL_CMD_LINE[*]} --verbose"
        echo ""
        echo "Be kind to your terminal — it’s doing its best. 🧡"
    else
        echo "If you need assistance resolving this issue, please share the full command output with us."
        echo ""
        echo "🪪 Contact options:"
        echo "    - Email: contact@be-bop.io"
        echo "    - Nostr: npub16l9pnrkhhagkucjhxvvztz2czv9ex8s5u7yg80ghw9ccjp4j25pqaku4ha"
        echo ""
        echo "📡 Follow updates and tooling improvements at:"
        echo "    → https://be-bop.io/release-note"
        echo ""
        echo "Thank you for helping us make things better — and for being a friendly human. 🤝"
    fi
    exit $exit_code
}

# Set up error trap
trap 'die_unexpected_error_in_function $LINENO' ERR

# Global configuration
ALLOW_ROOT=false
DRY_RUN=false
RUN_NON_INTERACTIVE=false
SHELL_IS_INTERACTIVE=$([ -t 0 ] && [ -t 2 ] && echo true || echo false)
VERBOSE=false

# Logging functions
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    echo "[$SESSION_ID] [$timestamp] [$level] $message" >&2

    # Also log to journald if available
    if command -v systemd-cat >/dev/null 2>&1; then
        echo "[$level] $message" | systemd-cat -t "$SCRIPT_NAME" 2>/dev/null || true
    fi
}

log_info() {
    log "INFO" "$@"
}

log_warn() {
    # Check if terminal supports colors
    if [[ -t 2 && -n "${TERM:-}" && "$TERM" != "dumb" ]]; then
        echo -ne "\033[33m" >&2  # Yellow color
        log "WARN" "$@"
        echo -ne "\033[0m" >&2   # Reset color
    else
        log "WARN" "$@"
    fi
}

log_error() {
    # Check if terminal supports colors
    if [[ -t 2 && -n "${TERM:-}" && "$TERM" != "dumb" ]]; then
        echo -ne "\033[31m" >&2  # Red color
        log "ERROR" "$@"
        echo -ne "\033[0m" >&2   # Reset color
    else
        log "ERROR" "$@"
    fi
}

log_debug() {
    if [ "$VERBOSE" = true ]; then
        log "DEBUG" "$@"
    fi
}

# Error handling
die() {
    local exit_code=${1:-$EXIT_ERROR}
    local line_number=${2:-}
    shift 2
    local message="$*"
    script_name="$(basename "${BASH_SOURCE[1]:-${0:-be-bop-wizard}}")"
    log_error "Error in ${script_name}${line_number:+ at line $line_number}: $message"
    log_error "The script paused to prevent any potential issues."
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "💡 The wizard stopped safely after an error."
    echo ""
    echo "🧩 Details:"
    echo "   • Error: $message"
    if [[ -n "$line_number" ]]; then
        echo "   • Location: ${script_name}:${line_number}"
    fi
    echo "   • Wizard version: $SCRIPT_VERSION"
    echo ""
    echo "✓ No unsafe system changes were made"
    echo "✓ It’s safe to re-run the wizard once the issue is fixed"
    echo ""
    if ! [[ "${FULL_CMD_LINE[*]}" =~ "--verbose" ]]; then
        echo "If you’d like to investigate or get help, re-run with --verbose to get detailed output:"
        echo "  $(basename "${0:-be-bop-wizard}") ${FULL_CMD_LINE[*]} --verbose"
        echo ""
        echo "Be kind to your terminal — it’s doing its best. 🧡"
    else
        echo "If you need assistance resolving this issue, please share the full command output with us."
        echo ""
        echo "🪪 Contact options:"
        echo "    - Email: contact@be-bop.io"
        echo "    - Nostr: npub16l9pnrkhhagkucjhxvvztz2czv9ex8s5u7yg80ghw9ccjp4j25pqaku4ha"
        echo ""
        echo "📡 Follow updates and tooling improvements at:"
        echo "    → https://be-bop.io/release-note"
        echo ""
        echo "Thank you for helping us make things better — and for being a friendly human. 🤝"
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit "$exit_code"
}

die_missing_option_argument() {
    local option="$1"
    log_error "Option '$option' requires an argument but none was provided."
    log_error "The script paused to prevent any potential issues."
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "💡 The option '$option' requires an argument but none was provided."
    echo ""
    echo "Example:"
    echo "   $(basename "${0:-be-bop-wizard}") $option <value>"
    echo ""
    echo "✓ No unsafe system changes were made"
    echo "✓ You can safely re-run the wizard once the command is corrected"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit "$EXIT_USER_ABORT"
}

die_user_abort() {
    local line_number="$1"
    script_name="$(basename "${BASH_SOURCE[1]:-${0:-be-bop-wizard}}")"
    if [[ -n "$line_number" ]]; then
        log_warn "Operation at ${script_name}:${line_number} aborted by user."
    else
        log_warn "Operation aborted by user."
    fi
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "💡 Operation cancelled"
    echo ""
    echo "You chose not to proceed — no changes were made to your system."
    echo ""
    echo "✓ No unsafe system changes were made"
    echo "✓ You can safely re-run the wizard at a later time"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit "$EXIT_USER_ABORT"
}

die_unexpected_architecture() {
    local arch=$1

    log_error "Unsupported architecture: $arch"
    log_error "The script paused to prevent any potential issues."
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "🤖 I've never seen this architecture before!"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "✓ Your system has not been changed in any unsafe way"
    echo ""
    echo "Your system reports architecture: $arch"
    echo ""
    echo "We'd really like to hear about your setup — it helps us support more platforms!"
    echo ""
    echo "🪪 Please reach out to us:"
    echo "    - Email: contact@be-bop.io"
    echo "    - Nostr: npub16l9pnrkhhagkucjhxvvztz2czv9ex8s5u7yg80ghw9ccjp4j25pqaku4ha"
    echo ""
    echo "📡 Follow updates and tooling improvements at:"
    echo "    → https://be-bop.io/release-note"
    echo ""
    echo "Thank you for helping us expand our horizons. 🤝"
    exit "$EXIT_INCOMPATIBLE_SYSTEM_STATE"
}

# Sudo wrapper for consistent privilege handling
run_privileged() {
    if [[ "$RUNNING_AS_ROOT" = true ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

run_bebop_cli() {
    if [[ ! -f /usr/local/bin/be-bop-cli ]]; then
        die $EXIT_ERROR $LINENO "be-bop-cli not found at /usr/local/bin/be-bop-cli"
    fi
    /usr/local/bin/be-bop-cli "$@"
}

# Wrapper for consistent file management
install_file() {
    local source="$1"
    local destination="$2"

    if [[ -z "$source" || -z "$destination" ]]; then
        die $EXIT_ERROR $LINENO "Missing source or destination file"
    elif [[ ! -f "$source" ]]; then
        die $EXIT_ERROR $LINENO "Source file '$source' does not exist"
    elif [[ "$source" = "$destination" ]]; then
        die $EXIT_ERROR $LINENO "Source and destination files are the same: $source"
    fi

    if has_tool ucf; then
        # If the file does not exist and, purge it from the ucf database in
        # case the user removed it.
        if [[ ! -f "$destination" && -f /var/lib/ucf/hashfile ]]; then
            run_privileged ucf --purge "$2" || true
        fi
        run_privileged ucf "$1" "$2"
    else
        # If ucf is not available, prefer install since it will atomically
        # replace the file.
        if has_tool install; then
            run_privileged install "$source" "$destination"
        else
            # If install is not available, we have to manually remove the file
            # and then write the new file.
            if ! rm -fr "$destination"; then
                die $EXIT_ERROR $LINENO "Failed to install $source: Failed to remove $destination"
            fi
            run_privileged cp "$source" "$destination"
        fi
    fi
}

# Show usage information
show_help() {
    cat << EOF
$SCRIPT_NAME v$SCRIPT_VERSION - be-BOP Bootstrap Utility

USAGE:
    $SCRIPT_NAME [OPTIONS]

DESCRIPTION:
    Bootstrap utility for installing and configuring be-BOP on Debian-based systems.
    Prepares the environment and installs the last be-BOP release.

COMMON OPTIONS:
    --domain <FQDN>         Domain name for be-BOP installation
    --email <address>       Contact email for Let's Encrypt registration
    --redirect-domain <FQDN>  Extra domain that redirects to main (repeatable)

MORE OPTIONS:
    --allow-root            Allow running as root (discouraged)
    --dry-run               Do not make any changes, print what would be done
    --help, -h              Show this help message
    --non-interactive       Do not prompt for confirmations (for automation)
    --verbose, -v           Enable detailed logging output
    --version               Show version information

EXAMPLES:
    # Interactive installation
    $SCRIPT_NAME --domain example.com --email admin@example.com

    # Non-interactive installation
    $SCRIPT_NAME --domain example.com --email admin@example.com --non-interactive

For more information, visit: https://github.com/be-BOP-io-SA/be-BOP
EOF
}

show_version() {
    echo "$SCRIPT_NAME v$SCRIPT_VERSION"
}

parse_cli_arguments() {
    export FULL_CMD_LINE=()
    REDIRECT_DOMAINS=()
    while [[ $# -gt 0 ]]; do
        FULL_CMD_LINE+=("$1")
        case $1 in
            --allow-root)
                ALLOW_ROOT=true
                shift
                ;;
            --domain)
                if [[ $# -lt 2 ]]; then
                    die_missing_option_argument "--domain"
                fi
                export DOMAIN="$2"
                FULL_CMD_LINE+=("$DOMAIN")
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --email)
                if [[ $# -lt 2 ]]; then
                    die_missing_option_argument "--email"
                fi
                export EMAIL="$2"
                FULL_CMD_LINE+=("$EMAIL")
                shift 2
                ;;
            --help|-h)
                show_help
                exit $EXIT_SUCCESS
                ;;
            --non-interactive)
                RUN_NON_INTERACTIVE=true
                shift
                ;;
            --redirect-domain)
                [[ $# -lt 2 ]] && die_missing_option_argument "--redirect-domain"
                REDIRECT_DOMAINS+=("$2"); FULL_CMD_LINE+=("$2"); shift 2
                ;;
            --verbose|-v)
                VERBOSE=true
                shift
                ;;
            --version)
                show_version
                exit $EXIT_SUCCESS
                ;;
            *)
                die $EXIT_ERROR $LINENO "Unknown option: $1. Use --help for usage information."
                ;;
        esac
    done

    # Validate required arguments
    if [[ -n "${DOMAIN:-}" ]]; then
        if ! echo "$DOMAIN" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$'; then
            if [[ "$DOMAIN" != "localhost" ]]; then
                die $EXIT_ERROR $LINENO "Invalid domain format: $DOMAIN"
            fi
        fi
        if [[ ${#DOMAIN} -gt 253 ]]; then
            die $EXIT_ERROR $LINENO "Domain too long (max 253 chars): $DOMAIN"
        fi
        IFS='.' read -ra LABELS <<< "$DOMAIN"
        for label in "${LABELS[@]}"; do
            if [[ ${#label} -gt 63 ]]; then
                die $EXIT_ERROR $LINENO "Domain label too long (max 63 chars): $label"
            fi
        done
    fi

    # Basic email validation
    if [[ -n "${EMAIL:-}" ]]; then
        if ! echo "$EMAIL" | grep -qE '^[^@]+@[^@]+\.[^@]+$'; then
            die $EXIT_ERROR $LINENO "Invalid email format: $EMAIL"
        fi
    fi
}

display_run_as_root_warning() {
    log_warn "
  ┌─────────────────────────────────────────────────────────────┐
  │ WARNING: Running as root is strongly discouraged            │
  └─────────────────────────────────────────────────────────────┘

  Running as root bypasses critical security controls:

  • NO AUDIT TRAIL: All system modifications happen silently
    without logging what privileged operations occurred

  • UNNECESSARY PRIVILEGE: Network downloads, file processing,
    and JSON parsing all run with full system access

  • HIGH-VALUE ATTACK TARGET: Root processes are prime targets
    for local privilege escalation exploits

  If this script is compromised or contains bugs, running as root
  provides immediate, unlogged access to your entire system.
"
}

# Check privilege requirements
check_privileges() {
    if [[ $EUID -eq 0 ]]; then
        if [[ "$ALLOW_ROOT" = false ]]; then
            if [[ $SHELL_IS_INTERACTIVE = true ]] && [[ $RUN_NON_INTERACTIVE = false ]]; then
                display_run_as_root_warning
                log_warn "Are you sure you want to continue?"
                read -rp "Type 'proceed' to continue: " response
                if [[ "$response" != "proceed" ]]; then
                    die_user_abort $LINENO
                fi
                export RUNNING_AS_ROOT=true
            else
                log_warn "Running as root is discouraged."
                log_warn "If you must run as root, use the --allow-root option."
                die $EXIT_ERROR $LINENO "Running as root is discouraged. Use --allow-root if you really need to run as root, or run as a regular user."
            fi
        else
            log_warn "Running as root. sudo commands will be skipped."
            export RUNNING_AS_ROOT=true
        fi
    else
        log_debug "Running as regular user. Will use sudo for privileged operations."
        export RUNNING_AS_ROOT=false

        # Check if user has sudo access
        if ! sudo -n true 2>/dev/null; then
            log_info "This script requires sudo access for system modifications."
            log_info "You may be prompted for your password."

            # Test sudo access
            if ! command -v sudo &>/dev/null; then
                die $EXIT_ERROR $LINENO "sudo access is required. Please ensure your user has sudo privileges."
            fi
        fi
    fi
}

detect_os_information() {
    local id name release pretty

    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        id="${ID:-unknown}"
        name="${NAME:-${ID:-Unknown}}"
        release="${VERSION_CODENAME:-${VERSION_ID:-unknown}}"
        pretty="${PRETTY_NAME:-${NAME} ${VERSION_ID}}"

    elif command -v lsb_release >/dev/null 2>&1; then
        id=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
        name=$(lsb_release -si)
        release=$(lsb_release -sc)
        pretty=$(lsb_release -sd | tr -d '"')

    elif [ "$(uname -s)" = "FreeBSD" ]; then
        id="freebsd"
        name="FreeBSD"
        release=$(freebsd-version | cut -d- -f1)
        pretty="FreeBSD $(freebsd-version)"

    else
        id=$(uname -s | tr '[:upper:]' '[:lower:]')
        name=$(uname -s)
        release=$(uname -r)
        pretty="$name $release"
    fi

    export DETECTED_MACHINE_OS_NAME="$id"
    export DETECTED_MACHINE_OS_RELEASE="$release"
    export DETECTED_HUMAN_OS_DISTRIBUTION="$pretty"
}

is_systemd_operational() {
    if ! command -v systemctl >/dev/null 2>&1; then
        return 1
    fi
    if [ "$(ps -p 1 -o comm=)" != "systemd" ]; then
        return 1
    fi

    local state
    state=$(systemctl is-system-running 2>/dev/null || true)

    case "$state" in
        initializing|starting|running|degraded|maintenance) return 0 ;;  # good enough
        *) return 1 ;;
    esac
}

wizard_file_fingerprint() {
    # Unique identifier of the configuration template revision.
    # The wizard uses this value to compute the configuration fingerprint.
    # Increment it whenever the template’s structure of the be-BOP configuration
    # file change, so that different template generations can be distinguished
    # programmatically.
    # The value is currently internal, but may be exposed in the future.
    local template_rev
    case "${1:-bebop_config}" in
        bebop_config) template_rev="2026022302" ;;
        nginx_config) template_rev="2026022301" ;;
        bebop_cli_wrapper) template_rev="2026010601" ;;
        bebop_cli_sudoers) template_rev="2026010601" ;;
    esac
    if command -v sha256sum >/dev/null 2>&1; then
        printf 'sha256:%s\n' "$(printf '%s' "$template_rev" | sha256sum | awk '{print $1}')"
    elif command -v sha256 >/dev/null 2>&1; then
        printf 'sha256:%s\n' "$(printf '%s' "$template_rev" | sha256 | awk '{print $NF}')"
    else
        # sha256sum or sha256 are "always" present in Linux and BSD distributions.
        die $EXIT_ERROR $LINENO "The wizard cannot function without either sha256sum or sha256"
    fi
}

# ---[ 1. Inspect the system ]---
# Collect information about the current system configuration.
# Each check adds "facts" that describe what’s already installed or running.
# For example: whether Node.js is available, MongoDB is active,
# Nginx is installed, or SSL certificates are present.
# These facts form the base truth used to decide what actions are needed.
inspect_system_state() {
    log_info "Inspecting system state..."

    # Initialize system facts array
    export SYSTEM_STATE=()

    # Track if domain was explicitly provided via CLI (before auto-detection)
    if [[ -n "${DOMAIN:-}" ]]; then
        SYSTEM_STATE+=("domain_explicitly_provided")
    fi

    # Auto-detect domain from existing config if not provided via CLI
    if [[ -z "${DOMAIN:-}" ]] && [[ -f /etc/be-BOP/config.env ]]; then
        local detected_domain
        detected_domain=$(grep '^ORIGIN=' /etc/be-BOP/config.env | sed 's|ORIGIN=https\?://||')
        if [[ -n "$detected_domain" ]]; then
            DOMAIN="$detected_domain"
            log_info "Detected domain from existing configuration: $DOMAIN"
        fi
    fi

    if [[ -n "${DOMAIN:-}" ]]; then
        SYSTEM_STATE+=("specified_domain=${DOMAIN}")
    fi

    # Auto-detect email from certbot account if not provided via CLI
    if [[ -z "${EMAIL:-}" ]] && run_privileged test -d /etc/letsencrypt/accounts 2>/dev/null; then
        local detected_email
        detected_email=$(run_privileged grep -roh '"mailto:[^"]*"' /etc/letsencrypt/accounts/ 2>/dev/null \
            | head -1 | sed 's/"mailto:\(.*\)"/\1/' || true)
        if [[ -n "$detected_email" ]]; then
            EMAIL="$detected_email"
            log_info "Detected email from existing Let's Encrypt account: $EMAIL"
        fi
    fi

    if [[ -n "${EMAIL:-}" ]]; then
        SYSTEM_STATE+=("specified_email=${EMAIL}")
    fi

    # Compute derived domain facts
    if [[ -n "${DOMAIN:-}" ]]; then
        local base="${DOMAIN#www.}" redir=("${REDIRECT_DOMAINS[@]:-}")
        SYSTEM_STATE+=("bebop_domain=${DOMAIN}" "s3_domain=s3.${base}")
        [[ "$DOMAIN" != "$base" ]] && redir+=("$base")
        [[ ${#redir[@]} -gt 0 ]] && SYSTEM_STATE+=("redirect_domains=${redir[*]}")
    fi

    # We piggy-back on Debian's architecture naming convention, but our use is
    # unrelated to Debian. We use their naming convention because it's thought
    # with the objective of maintaining package-sets. This is in contrast to
    # kernel conventions where the objective is to describe the CPU architecture
    # but the same binary may run on multiple architectures.
    # See https://www.debian.org/ports
    case "$(uname -m)" in
        x86_64)
            SYSTEM_STATE+=("debian_arch=amd64")
            ;;
        aarch64)
            SYSTEM_STATE+=("debian_arch=arm64")
            ;;
        *)
            die_unexpected_architecture "$(uname -m)"
            ;;
    esac

    detect_os_information
    SYSTEM_STATE+=("os_name=${DETECTED_MACHINE_OS_NAME}")
    SYSTEM_STATE+=("os_release=${DETECTED_MACHINE_OS_RELEASE}")

    if command -v systemd-detect-virt >/dev/null 2>&1; then
        local container_type="none"
        container_type=$(systemd-detect-virt --container 2>/dev/null || true)
        if [[ "$container_type" != "none" ]]; then
            SYSTEM_STATE+=("running_in_container")
        fi
    fi

    # Check what tools are available
    local potential_commands=(
        "apt"
        "be-bop-cli"
        "corepack"
        "curl"
        "gcc"
        "gpg"
        "install"
        "jq"
        "mongosh"
        "openssl"
        "pnpm"
        "sha256sum"
        "stow"
        "sudo"
        "tcc"
        "ucf"
        "unzip"
    )
    export AVAILABLE_TOOLS=()
    for cmd in "${potential_commands[@]}"; do
        if command -v "$cmd" >/dev/null 2>&1; then
            AVAILABLE_TOOLS+=("$cmd")
        fi
    done
    local potential_packages=(
        "certbot"
        "libc6-dev"
        "mongodb-org"
        "nginx"
        "python3-certbot-nginx"
        "ssl-cert"
    )
    if command -v dpkg >/dev/null 2>&1; then
        for pkg in "${potential_packages[@]}"; do
            if dpkg -s "$pkg" >/dev/null 2>&1; then
                AVAILABLE_TOOLS+=("$pkg")
            fi
        done
    fi

    # Check if systemd is operational
    if is_systemd_operational; then
        SYSTEM_STATE+=("systemd_operational")
    fi
    if has_fact systemd_operational && command -v systemctl >/dev/null 2>&1; then
        AVAILABLE_TOOLS+=("systemctl")
    fi

    log_debug "Available tools: ${AVAILABLE_TOOLS[*]}"

    # Check repositories
    if [[ -f /etc/apt/sources.list.d/nodesource.list ]]; then
        SYSTEM_STATE+=("nodejs_repo_configured")
    fi

    # Check installed packages
    if command -v node >/dev/null 2>&1; then
        local node_version=$(node --version | sed 's/v//')
        log_debug "Found Node.js version: $node_version"
        SYSTEM_STATE+=("nodejs_available")
    fi

    if [[ -f /etc/apt/sources.list.d/mongodb-org-${MONGODB_VERSION}.list ]]; then
        SYSTEM_STATE+=("mongodb_repo_configured")
    fi

    if has_tool mongodb-org >/dev/null 2>&1; then
        SYSTEM_STATE+=("mongodb_installed")
    fi

    if has_tool systemctl && systemctl is-active --quiet mongod 2>/dev/null || \
        has_tool mongosh && mongosh --quiet --eval "db.adminCommand('ping')" >/dev/null 2>&1; then
        SYSTEM_STATE+=("mongodb_running")
    fi

    if has_tool mongosh && mongosh --quiet --eval "rs.status().ok" 2>/dev/null | grep -q "1"; then
        SYSTEM_STATE+=("mongodb_rs_initialized")
    fi

    if has_tool systemctl && systemctl is-active --quiet nginx 2>/dev/null; then
        SYSTEM_STATE+=("nginx_running")
    fi

    # Check SSL certificate availability (check package instead of private key due to permissions)
    if has_tool ssl-cert >/dev/null 2>&1 && [[ -f /etc/ssl/certs/ssl-cert-snakeoil.pem ]]; then
        SYSTEM_STATE+=("snakeoil_cert_available")
    fi

    if [[ -L /etc/nginx/sites-enabled/be-BOP.conf ]] || [[ -f /etc/nginx/sites-enabled/be-BOP.conf ]]; then
        SYSTEM_STATE+=("bebop_site_enabled")
        local nginx_fp="$(awk '/^# wizard-fingerprint:/{print $NF}' /etc/nginx/sites-available/be-BOP.conf 2>/dev/null)"
        [[ -n "$nginx_fp" ]] && SYSTEM_STATE+=("nginx_config_fingerprint=${nginx_fp}")

        # Check if nginx site is correctly configured for this domain
        if ! validate_bebop_nginx_config_domains; then
            SYSTEM_STATE+=("bebop_nginx_site_domain_mismatch")
        fi

        # Check if be-BOP site is actually responding via HTTP/HTTPS
        if ! has_fact "specified_domain"; then
            log_debug "I cannot check the be-BOP site is available without a domain."
        elif has_fact "nginx_running" && has_fact "bebop_site_enabled"; then
            local test_url
            local curl_args=(
                "--connect-timeout" "$CURL_CONNECT_TIMEOUT"
                "--fail"
                "--max-time" "$CURL_DOWNLOAD_TIMEOUT"
                "--output" "/dev/null"
                "--silent"
                "--write-out" "%{http_code}"
            )

            local domain="$(get_fact "specified_domain")"
            if [[ "$domain" = "localhost" ]]; then
                test_url="http://localhost/"
            else
                test_url="https://localhost/"
                curl_args+=("-H" "Host: $domain" "-k")  # -k to ignore self-signed cert issues
            fi

            # Test if the site responds (allow up to 5 seconds)
            if has_tool curl; then
                local response_code=$(curl "${curl_args[@]}" "$test_url" 2>/dev/null || echo "000")
                # Accept any 2xx, 3xx, 4xx response (shows nginx is routing correctly)
                if [[ "$response_code" =~ ^[234][0-9][0-9]$ ]]; then
                    SYSTEM_STATE+=("bebop_site_running")
                fi
            fi
        fi
    fi

    if has_tool certbot; then
        SYSTEM_STATE+=("certbot_installed")
    fi

    if has_tool systemctl && systemctl is-active --quiet garage 2>/dev/null; then
        SYSTEM_STATE+=("garage_running")
    fi

    # Detect existing MinIO (for migration)
    if [[ -f /usr/local/bin/minio ]]; then
        SYSTEM_STATE+=("legacy_minio_installed")
    fi
    if has_tool systemctl && systemctl is-active --quiet minio 2>/dev/null; then
        SYSTEM_STATE+=("legacy_minio_running")
    fi
    if [[ -f /etc/garage/migration-from-minio.done ]]; then
        SYSTEM_STATE+=("minio_migration_verified")
    fi

    if has_tool systemctl && systemctl is-active --quiet bebop 2>/dev/null; then
        SYSTEM_STATE+=("bebop_running")
    fi

    if has_tool be-bop-cli && run_bebop_cli status --fail-if-latest-release-not-installed >/dev/null 2>&1; then
        SYSTEM_STATE+=("bebop_latest_release_installed")
    fi

    if [[ -f /usr/local/bin/phoenixd ]]; then
        SYSTEM_STATE+=("phoenixd_installed")
    fi

    if [[ -f /usr/local/bin/garage ]]; then
        SYSTEM_STATE+=("garage_installed")
    fi

    if has_tool systemctl && systemctl is-active --quiet phoenixd 2>/dev/null; then
        SYSTEM_STATE+=("phoenixd_running")
    fi

    if [[ -f /usr/local/bin/be-bop-cli ]]; then
        # Extract wrapper fingerprint from binary
        local wrapper_fingerprint
        if wrapper_fingerprint=$(grep -ao "be-bop-cli-wrapper-fingerprint:[^[:space:]]*" /usr/local/bin/be-bop-cli 2>/dev/null | head -1 | cut -d: -f2- || true); then
            if [[ -n "$wrapper_fingerprint" ]]; then
                SYSTEM_STATE+=("bebop_cli_wrapper_fingerprint=${wrapper_fingerprint}")
            fi
        fi

        # Extract CLI version
        local cli_version_output
        if cli_version_output=$(/usr/local/bin/be-bop-cli --version 2>/dev/null || true); then
            local cli_version=$(echo "$cli_version_output" | awk '{print $2}' | sed 's/v//')
            if [[ -n "$cli_version" ]]; then
                SYSTEM_STATE+=("bebop_cli_version=${cli_version}")
            fi
        fi
    fi

    if [[ -f /etc/garage.toml ]]; then
        SYSTEM_STATE+=("garage_config_exists")
        if ! validate_garage_config_domain; then
            SYSTEM_STATE+=("garage_config_domain_mismatch")
        fi
    fi

    if has_tool garage && garage key list 2>/dev/null | grep -q "bebop-key"; then
        SYSTEM_STATE+=("garage_provisioned")
    fi

    if [[ -f /etc/be-BOP/config.env ]]; then
        if ! command -v awk &>/dev/null; then
            # POSIX.1-2017 explicitly lists awk as a required utility.
            die $EXIT_ERROR $LINENO "The wizard cannot function without awk"
        fi
        local awk_command='/^# wizard-fingerprint:/ {print $NF}'
        local fingerprint="$(awk "$awk_command" /etc/be-BOP/config.env)"
        SYSTEM_STATE+=("bebop_config_exists=${fingerprint}")
        if ! validate_bebop_config_domain; then
            SYSTEM_STATE+=("bebop_config_domain_mismatch")
        fi
    fi

    if [[ -f /etc/systemd/system/bebop.service ]]; then
        SYSTEM_STATE+=("bebop_service_exists")
        if grep -q "minio" /etc/systemd/system/bebop.service 2>/dev/null; then
            SYSTEM_STATE+=("bebop_service_depends_on_minio")
        fi
    fi

    if [[ -f /etc/systemd/system/phoenixd.service.d/overrides.conf ]]; then
        SYSTEM_STATE+=("phoenixd_overrides_exist")
    fi

    if [[ -f /etc/systemd/system/garage.service.d/overrides.conf ]]; then
        SYSTEM_STATE+=("garage_overrides_exist")
    fi

    if [[ -f /etc/systemd/system/bebop.service.d/overrides.conf ]]; then
        SYSTEM_STATE+=("bebop_overrides_exist")
    fi

    # Check be-bop-cli user configuration
    if getent passwd be-bop-cli >/dev/null 2>&1; then
        SYSTEM_STATE+=("bebop_cli_user_exists")

        # Check if home directory is correct
        local user_home=$(getent passwd be-bop-cli | cut -d: -f6)
        if [[ "$user_home" = "/var/lib/be-BOP" ]]; then
            SYSTEM_STATE+=("bebop_cli_user_home_correct")
        fi
    fi

    # Check be-BOP directory permissions
    if has_fact "bebop_cli_user_exists" && [[ -d /var/lib/be-BOP ]]; then
        if [[ -z "$(find /var/lib/be-BOP -not -user be-bop-cli -o -not -group be-bop-cli)" ]]; then
            SYSTEM_STATE+=("bebop_directory_permissions_correct")
        fi
    fi

    # Check be-BOP CLI sudoers rule fingerprint
    if [[ -f /etc/sudoers.d/be-bop-cli-bebop ]]; then
        local sudoers_fingerprint
        if sudoers_fingerprint=$(grep -oP '^# wizard-fingerprint:\K.*' \
            /etc/sudoers.d/be-bop-cli-bebop 2>/dev/null | head -1); then
            if [[ -n "$sudoers_fingerprint" ]]; then
                SYSTEM_STATE+=("bebop_cli_sudoers_fingerprint=${sudoers_fingerprint}")
            fi
        fi
    fi
    log_debug "Available tools: ${AVAILABLE_TOOLS[*]}"
    log_debug "System state: ${SYSTEM_STATE[*]}"
    log_debug "System state check complete"
}

validate_bebop_nginx_config_domains() {
    if [[ ! -f /etc/nginx/sites-available/be-BOP.conf ]]; then
        return 1
    fi

    local domain
    if ! domain="$(get_fact "specified_domain")"; then
        log_debug "Cannot validate nginx config, as the domain was not specified"
        return 0
    fi

    local expected_domains
    if [[ "$domain" = "localhost" ]]; then
        expected_domains="localhost s3.localhost"
    else
        expected_domains="$(domains_for_nginx)"
    fi

    for expected_domain in $expected_domains; do
        if ! grep -qE "server_name[[:space:]]+[^;]*\b$expected_domain\b" /etc/nginx/sites-available/be-BOP.conf 2>/dev/null; then
            log_debug "nginx config missing domain: $expected_domain"
            return 1
        fi
    done

    # Check no extra domains exist
    local actual
    actual=$(grep -oE 'server_name[[:space:]]+[^;]+' /etc/nginx/sites-available/be-BOP.conf 2>/dev/null | sed 's/server_name[[:space:]]*//' | tr ' ' '\n' | sort -u)
    for d in $actual; do
        [[ " $expected_domains " == *" $d "* ]] || { log_debug "nginx config has extra domain: $d"; return 1; }
    done

    return 0
}

validate_garage_config_domain() {
    if [[ ! -f /etc/garage.toml ]]; then
        return 1
    fi

    local domain
    if ! domain="$(get_fact "specified_domain")"; then
        log_debug "Cannot validate Garage config, as the domain was not specified"
        return 0
    fi

    # For localhost, Garage config doesn't set root_domain so nothing to validate
    if [[ "$domain" = "localhost" ]]; then
        return 0
    fi

    local expected_root_domain="s3.$domain"
    if ! grep -q "root_domain.*=.*\"$expected_root_domain\"" /etc/garage.toml 2>/dev/null; then
        log_debug "Garage config has incorrect root_domain (expected: $expected_root_domain)"
        return 1
    fi

    return 0
}

validate_bebop_config_domain() {
    if [[ ! -f /etc/be-BOP/config.env ]]; then
        return 1
    fi

    local domain
    if ! domain="$(get_fact "specified_domain")"; then
        log_debug "Cannot validate be-BOP config, as the domain was not specified"
        return 0
    fi

    local expected_origin expected_s3_url
    if [[ "$domain" = "localhost" ]]; then
        expected_origin="http://localhost"
        expected_s3_url="http://s3.localhost"
    else
        expected_origin="https://$domain"
        expected_s3_url="https://$(get_fact s3_domain)"
    fi

    if ! grep -q "^ORIGIN=$expected_origin$" /etc/be-BOP/config.env 2>/dev/null; then
        log_debug "be-BOP config has incorrect ORIGIN (expected: $expected_origin)"
        return 1
    fi

    if ! grep -q "^PUBLIC_S3_ENDPOINT_URL=$expected_s3_url$" /etc/be-BOP/config.env 2>/dev/null; then
        log_debug "be-BOP config has incorrect PUBLIC_S3_ENDPOINT_URL (expected: $expected_s3_url)"
        return 1
    fi

    return 0
}

domains_for_nginx() {
    echo "$(get_fact bebop_domain) $(get_fact s3_domain) $(get_fact redirect_domains 2>/dev/null || true)"
}

# Helper function to check if a tool is available
has_tool() {
    local tool="$1"
    for available_tool in "${AVAILABLE_TOOLS[@]}"; do
        if [[ "$available_tool" = "$tool" ]]; then
            return 0
        fi
    done
    return 1
}

# Helper function to check if a system fact exists
has_fact() {
    local fact="$1"
    for existing_fact in "${SYSTEM_STATE[@]}"; do
        if [[ "$existing_fact" = "$fact" ]] || [[ "${existing_fact%%=*}" = "$fact" ]]; then
            return 0
        fi
    done
    return 1
}

# Helper function to check if a system fact exists and return its value
get_fact() {
    local fact="$1"
    for existing_fact in "${SYSTEM_STATE[@]}"; do
        if [[ "${existing_fact%%=*}" = "$fact" ]]; then
            echo "${existing_fact#*=}"
            return 0
        elif [[ "$existing_fact" = "$fact" ]]; then
            echo ""
            return 0
        fi
    done
    return 1
}

die_unsupported_os_distribution_for_tasks() {
    local tasks=("$@")
    local distro_name="${DETECTED_HUMAN_OS_DISTRIBUTION:-}"
    local comment=""
    if ! has_fact systemd_operational; then
        comment="(without systemd)"
    fi

    local task_descriptions=()
    for task in "${tasks[@]}"; do
        local description
        if description="$(describe_task "$task")"; then
            task_descriptions+=("$description")
        fi
    done

    if [[ -n "$distro_name" ]]; then
        log_error "Unsupported OS distribution: $distro_name $comment"
    else
        log_error "Unsupported unknown OS distribution $comment"
    fi
    log_error "The script paused to prevent any potential issues."
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "💡 The script stopped safely — your Linux or BSD distribution is not supported yet."
    echo ""
    if [[ -n "$distro_name" ]]; then
        echo "Your operating system distribution appears to be:"
        echo "   • ${distro_name} $comment"
        echo ""
    fi
    if [[ "${tasks[*]}" =~ install_missing_tools ]]; then
        echo "We couldn’t verify that all the necessary tools are installed, and this script"
        echo "does not yet know how to install them automatically on your distribution."
        echo ""
        echo "The following tools are necessary but could not be found:"
        for tool in "${INSTALL_TOOLS[@]}"; do
            echo "   • ${tool}"
        done
        echo ""
        echo "You have two safe options to continue:"
        echo "   1. Install the missing tools manually using your distribution’s package system."
        echo "   2. Reach out and tell us your distribution name — we're always looking to make"
        echo "      the wizard smarter and compatible with more systems 🧙."
    elif [[ "${tasks[*]}" =~ configure_mongodb_repo ]]; then
        echo "We couldn’t verify that MongoDB is installed, and this script doesn’t yet know"
        echo "how to install MongoDB automatically on your distribution."
        echo ""
        echo "You have two safe options to continue:"
        echo "   1. Install MongoDB manually using your distribution’s package system"
        echo "      and ensure command mongosh is available."
        echo "   2. Reach out and tell us your distribution name — we're always looking to make"
        echo "      the wizard smarter and compatible with more systems 🧙."
    else
        if [[ ${#task_descriptions[@]} -ne 0 ]]; then
            echo "This script doesn’t yet know how to perform the following task in your"
            echo "distribution’s environment:"
            for description in "${task_descriptions[@]}"; do
                echo "   • ${description}"
            done
            echo ""
            echo "Please reach out and tell us your distribution name — we're always looking to"
            echo "make the wizard smarter and compatible with more systems 🧙."
        else
            echo "This script doesn’t yet know how to work with your distribution’s environment"
            echo "or package system. Please reach out and tell us your distribution name — we're"
            echo "always looking to make the wizard smarter and compatible with more systems 🧙."
        fi
    fi
    echo ""
    echo "🪪 Contact options:"
    echo "   - Email: contact@be-bop.io"
    echo "   - Nostr: npub16l9pnrkhhagkucjhxvvztz2czv9ex8s5u7yg80ghw9ccjp4j25pqaku4ha"
    echo ""
    echo "📡 Stay tuned for new distribution support and updates:"
    echo "   → https://be-bop.io/release-note"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit "$EXIT_INCOMPATIBLE_SYSTEM_STATE"
}

die_systemd_unavailable_for_task() {
    local task="$1"
    local systemd_state="$2"
    local description
    if description="$(describe_task "$task")"; then
        log_error "systemd is required for task '$task' ($description)."
    else
        log_error "systemd is required for task '$task'."
    fi
    log_error "The wizard tried to wait for systemd to be ready but couldn't confirm it's ready."
    log_error "systemd reported state '$systemd_state'."
    log_error "The script paused to prevent any potential issues."
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "💡 The wizard stopped safely — your system may not be ready for service management."
    echo ""
    echo "This typically happens when your system is:"
    echo "   • Shutting down or restarting"
    echo "   • Preparing to sleep or hibernate"
    echo "   • In an emergency or recovery state"
    echo ""
    echo "You can try these options:"
    echo "   1. Wait a few minutes and try running the wizard again"
    echo "   2. Restart your system and try again once it's fully booted"
    echo ""
    echo "If your system seems normal and this keeps happening, please reach out — we'd"
    echo "like to help figure out what's going on."
    echo ""
    echo "🪪 Contact options:"
    echo "   - Email: contact@be-bop.io"
    echo "   - Nostr: npub16l9pnrkhhagkucjhxvvztz2czv9ex8s5u7yg80ghw9ccjp4j25pqaku4ha"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit "$EXIT_INCOMPATIBLE_SYSTEM_STATE"
}

check_os_supported_by_wizard() {
    local unsupported_tasks=()

    local os_name="$(get_fact os_name)"
    local os_release="$(get_fact os_release)"
    case "$os_name-$os_release" in
        debian-bookworm) ;;
        debian-bullseye) ;;
        debian-buster) ;;
        debian-jessie) ;;
        debian-stretch) ;;
        debian-wheezy) ;;
        ubuntu-bionic) ;;
        ubuntu-focal) ;;
        ubuntu-jammy) ;;
        ubuntu-noble) ;;
        ubuntu-precise) ;;
        ubuntu-trusty) ;;
        ubuntu-xenial) ;;
        *)
            if [[ "${TASK_PLAN[*]}" =~ "configure_mongodb_repo" ]]; then
                unsupported_tasks+=("configure_mongodb_repo")
            fi
            ;;
    esac
    if [[ ${#INSTALL_TOOLS[@]} -ne 0 ]] && ! has_tool apt; then
        unsupported_tasks+=("install_missing_tools")
    fi
    local tasks_requiring_apt=(
        "configure_mongodb_repo"
        "configure_nodejs_repo"
        "install_mongodb"
        "install_nodejs"
    )
    for task in "${tasks_requiring_apt[@]}"; do
        if [[ "${TASK_PLAN[*]}" =~ "$task" ]] && ! has_tool apt; then
            unsupported_tasks+=("$task")
        fi
    done
    for task in "${TASK_PLAN[@]}"; do
        if task_requires_systemd_operational "$task" && ! has_fact systemd_operational; then
            unsupported_tasks+=("$task")
        fi
    done
    if [[ ${#unsupported_tasks[@]} -ne 0 ]]; then
        die_unsupported_os_distribution_for_tasks "${unsupported_tasks[@]}"
    fi
}

# ---[ 2. Plan what needs to be done ]---
# Use the collected system facts to build a to-do list of setup tasks.
# If something is missing or misconfigured, we queue the matching task.
# Example: if MongoDB isn’t running, add "install_mongodb" and "start_mongodb" to the plan.
# This produces an ordered list of actions that will bring the system
# to a complete and working be-BOP installation.
plan_setup_tasks() {
    log_debug "Planning what needs to be done..."
    export TASK_PLAN=()

    # Configure be-bop-cli user (must come early in the plan)
    if ! has_fact "bebop_cli_user_exists" || ! has_fact "bebop_cli_user_home_correct"; then
        TASK_PLAN+=("configure_bebop_cli_user")
    fi

    # Set up be-BOP directory permissions (after user is configured)
    if ! has_fact "bebop_directory_permissions_correct"; then
        TASK_PLAN+=("setup_bebop_directory_permissions")
    fi

    # Smart cascading logic for Node.js
    if ! has_fact "nodejs_available"; then
        # Only configure repo if Node.js is not already installed
        if ! has_fact "nodejs_repo_configured"; then
            TASK_PLAN+=("configure_nodejs_repo")
        fi
        TASK_PLAN+=("install_nodejs")
    fi

    # Install pnpm (requires Node.js to be available)
    if ! has_tool pnpm; then
        TASK_PLAN+=("enable_corepack")
    fi

    if ! has_fact "garage_installed"; then
        TASK_PLAN+=("install_garage")
    fi

    # Configure Garage (needed for be-BOP config)
    if ! has_fact "garage_config_exists" || has_fact "garage_config_domain_mismatch"; then
        TASK_PLAN+=("write_garage_configuration")
    fi

    if ! has_fact "garage_running"; then
        TASK_PLAN+=("install_garage_service")
        if ! has_fact "running_in_container" && ! has_fact "garage_overrides_exist"; then
            TASK_PLAN+=("configure_garage_hardening_overrides")
        fi
        TASK_PLAN+=("start_and_enable_garage")
    fi

    if ! has_fact "garage_provisioned"; then
        TASK_PLAN+=("provision_garage")
    fi

    # Migrate data from legacy MinIO and remove it
    if has_fact "legacy_minio_running" && ! has_fact "minio_migration_verified"; then
        TASK_PLAN+=("migrate_minio_to_garage")
    fi
    if has_fact "legacy_minio_running" || \
       (has_fact "legacy_minio_installed" && has_fact "minio_migration_verified"); then
        TASK_PLAN+=("remove_legacy_minio")
    fi

    # Smart cascading logic for MongoDB
    if ! has_fact "mongodb_rs_initialized"; then
        # If RS is not initialized, we need to work backwards through the chain
        if ! has_fact "mongodb_running"; then
            # If not running, we need to ensure it's installed
            if ! has_fact "mongodb_installed"; then
                # If not installed, we need to ensure repo is configured
                if ! has_fact "mongodb_repo_configured"; then
                    TASK_PLAN+=("configure_mongodb_repo")
                fi
                TASK_PLAN+=("install_mongodb")
            fi
            TASK_PLAN+=("start_and_enable_mongodb")
        fi
        TASK_PLAN+=("initialize_mongodb_rs")
    fi

    # Smart cascading logic for nginx and be-BOP site
    if ! has_fact "bebop_site_running" || has_fact "bebop_nginx_site_domain_mismatch"; then
        if has_fact "bebop_nginx_site_domain_mismatch"; then
            TASK_PLAN+=("configure_bebop_site")
        elif ! has_fact "specified_domain" && has_fact "bebop_site_enabled" && has_fact "nginx_running"; then
            log_debug "nginx is running with be-BOP site enabled: Assuming no-need to reconfigure nginx."
        else
            TASK_PLAN+=("configure_bebop_site")
        fi

        if [[ "${TASK_PLAN[*]}" =~ "configure_bebop_site" ]]; then
            if ! has_fact "nginx_running"; then
                TASK_PLAN+=("start_and_enable_nginx")
            else
                TASK_PLAN+=("reload_nginx")
            fi
        fi

        local domain
        if domain="$(get_fact "specified_domain")" && [[ "$domain" != "localhost" ]]; then
            TASK_PLAN+=("provision_ssl_cert")
        fi
    fi

    # Check if nginx config fingerprint changed
    if has_fact nginx_config_fingerprint && \
       [[ "$(get_fact nginx_config_fingerprint)" != "$(wizard_file_fingerprint nginx_config)" ]]; then
        [[ ! "${TASK_PLAN[*]}" =~ configure_bebop_site ]] && TASK_PLAN+=("configure_bebop_site")
        has_fact nginx_running && TASK_PLAN+=("reload_nginx")
        local domain
        if domain="$(get_fact "specified_domain")" && [[ "$domain" != "localhost" ]]; then
            [[ ! "${TASK_PLAN[*]}" =~ provision_ssl_cert ]] && TASK_PLAN+=("provision_ssl_cert")
        fi
    fi

    if ! has_fact "phoenixd_running"; then
        if ! has_fact "phoenixd_installed"; then
            TASK_PLAN+=("install_phoenixd")
        fi
        TASK_PLAN+=("install_phoenixd_service")
        if ! has_fact "running_in_container" && ! has_fact "phoenixd_overrides_exist"; then
            TASK_PLAN+=("configure_phoenixd_hardening_overrides")
        fi
        TASK_PLAN+=("start_and_enable_phoenixd")
    fi

    # Update CLI if wrapper fingerprint doesn't match OR version is wrong/missing
    # Since wrapper has script hash baked in, both components must be updated together
    local current_cli_version="$(get_fact "bebop_cli_version" || true)"
    if [[ "$(get_fact "bebop_cli_wrapper_fingerprint" || true)" != \
          "$(wizard_file_fingerprint "bebop_cli_wrapper")" ]] || \
       [[ -z "$current_cli_version" ]] || \
       [[ "$current_cli_version" != "${SCRIPT_VERSION}" ]]; then
        TASK_PLAN+=("install_bebop_cli")
    fi

    # Check if CLI sudoers rule needs updating
    if [[ "$(get_fact "bebop_cli_sudoers_fingerprint" || true)" != \
          "$(wizard_file_fingerprint "bebop_cli_sudoers")" ]]; then
        TASK_PLAN+=("install_bebop_cli_sudoers")
    fi

    if ! has_fact "bebop_service_exists" || has_fact "bebop_service_depends_on_minio"; then
        TASK_PLAN+=("install_bebop_service")
        if ! has_fact "running_in_container" && ! has_fact "bebop_overrides_exist"; then
            TASK_PLAN+=("configure_bebop_hardening_overrides")
        fi
    fi

    if ! has_fact "bebop_latest_release_installed"; then
        TASK_PLAN+=("install_bebop_latest_release")
        if has_fact "bebop_running"; then
            TASK_PLAN+=("restart_bebop")
        fi
    fi

    # Generate be-BOP configuration
    if has_fact "bebop_config_domain_mismatch"; then
        # Domain should be reconfigured
        TASK_PLAN+=("write_bebop_configuration")
    elif ! has_fact "bebop_config_exists"; then
        # File does not exist
        TASK_PLAN+=("write_bebop_configuration")
    elif [[ "$(get_fact bebop_config_exists)" != "$(wizard_file_fingerprint bebop_config)" ]]; then
        # Config file was generated by a different schema
        TASK_PLAN+=("write_bebop_configuration")
    fi

    if ! has_fact "bebop_running"; then
        TASK_PLAN+=("start_and_enable_bebop")
    elif [[ "${TASK_PLAN[*]}" =~ "write_bebop_configuration" ]]; then
        TASK_PLAN+=("restart_bebop")
    fi

    if [[ "${TASK_PLAN[*]}" =~ "start_and_enable_bebop" ]] || [[ "${TASK_PLAN[*]}" =~ "restart_bebop" ]]; then
        if has_fact "specified_domain"; then
            TASK_PLAN+=("await_bebop_ready")
        fi
    fi

    # When domain is explicitly provided, always re-provision SSL cert
    if has_fact "domain_explicitly_provided"; then
        local domain="$(get_fact "specified_domain")"
        if [[ "$domain" != "localhost" ]]; then
            [[ ! "${TASK_PLAN[*]}" =~ provision_ssl_cert ]] && TASK_PLAN+=("provision_ssl_cert")
        fi
    fi

    log_debug "Planned actions: ${TASK_PLAN[*]}"
}

check_options_required_by_planned_tasks_but_missing() {
    export REQUIRED_OPTIONS=()
    export TASKS_REQUIRING_OPTIONS=()
    for task in "${TASK_PLAN[@]}"; do
        case "$task" in
            "configure_bebop_site"|"write_bebop_configuration"|"write_garage_configuration")
                if ! has_fact "specified_domain"; then
                    REQUIRED_OPTIONS+=("domain")
                    TASKS_REQUIRING_OPTIONS+=("$task")
                fi
                ;;
            "provision_ssl_cert")
                if ! has_fact "specified_domain"; then
                    REQUIRED_OPTIONS+=("domain")
                    TASKS_REQUIRING_OPTIONS+=("$task")
                fi
                if ! has_fact "specified_email"; then
                    REQUIRED_OPTIONS+=("email")
                    TASKS_REQUIRING_OPTIONS+=("$task")
                fi
                ;;
            *)
                ;;
        esac
    done
    local deduplicated=($(printf '%s\n' "${REQUIRED_OPTIONS[@]}" | sort -u))
    REQUIRED_OPTIONS=("${deduplicated[@]}")

    if [ ${#REQUIRED_OPTIONS[@]} -gt 0 ]; then
        die_missing_options
    fi
}

check_cpu_features_required_by_planned_tasks() {
    local machine="$(uname -m)"
    # Check if MongoDB will be started on amd64 and verify AVX support
    if [[ "$(get_fact "debian_arch")" = "amd64" ]] && [[ "${TASK_PLAN[*]}" =~ "start_and_enable_mongodb" ]]; then
        log_debug "MongoDB service start is planned, checking CPU AVX instruction set support..."

        if ! grep -q ' avx ' /proc/cpuinfo 2>/dev/null; then
            echo ""
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo "💡 MongoDB requires a newer CPU with AVX instruction set support"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo ""
            echo "Your server's CPU doesn't have AVX support, which MongoDB has required"
            echo "since version 5 (released in 2021). This can happen for two reasons:"
            echo ""
            echo "   1. Your server has an older CPU that was built before AVX became standard"
            echo "   2. Your hosting provider has disabled AVX in their virtualization settings"
            echo ""
            echo "This is a common issue with some low-cost hosting providers."
            echo ""
            echo "✨ What you can do:"
            echo "   • Contact your hosting provider and ask if they can enable AVX support"
            echo "   • Consider upgrading to a newer server or different hosting plan"
            echo "   • Switch to a hosting provider that supports modern CPU features"
            echo ""
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            exit $EXIT_INCOMPATIBLE_SYSTEM_STATE
        fi

        log_debug "CPU has AVX instruction set support - MongoDB requirements satisfied"
    fi
}

die_missing_options() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "💡 The script paused safely — we need a bit more information to start."
    echo ""
    echo "To move forward, please include the following options(s):"
    for option in "${REQUIRED_OPTIONS[@]}"; do
        echo "   • --${option}"
    done
    echo ""
    echo "The following steps are waiting for that info:"
    for task in "${TASKS_REQUIRING_OPTIONS[@]}"; do
        echo "   • $(describe_task "$task")"
    done
    echo ""
    echo "👉 Example:"
    echo "   $(basename "${0:-be-bop-wizard}") --${REQUIRED_OPTIONS[0]} <value>"
    echo ""
    echo "🪪 Need a hand or want to share feedback?"
    echo "   - Email: contact@be-bop.io"
    echo "   - Nostr: npub16l9pnrkhhagkucjhxvvztz2czv9ex8s5u7yg80ghw9ccjp4j25pqaku4ha"
    echo ""
    echo "Once you add the missing option(s), just re-run the script — it’ll pick up right it left off."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit "$EXIT_ERROR"
}

list_tools_for_task() {
    case "$1" in
        "configure_bebop_site") echo "curl nginx ssl-cert" ;;
        "configure_mongodb_repo") echo "curl gpg" ;;
        "configure_nodejs_repo") echo "curl gpg" ;;
        "install_bebop_cli") echo "curl jq unzip sha256sum tcc" ;;
        "install_bebop_cli_sudoers") echo "sudo" ;;
        "install_garage") echo "curl stow" ;;
        "install_phoenixd") echo "curl unzip stow" ;;
        "migrate_minio_to_garage") echo "rclone" ;;
        "provision_ssl_cert") echo "certbot python3-certbot-nginx" ;;
        "write_garage_configuration") echo "openssl" ;;
        *) echo "" ;;
    esac
}

# ---[ 3. Figure out required tools ]---
# Before running tasks, we check which external programs or packages (tools)
# each task depends on — things like curl, jq, nginx or python3-certbot-nginx.
# The goal is to install these tools first so later steps don’t fail mid-run.
# This phase acts as a "check your toolbox" moment before doing the real work.
collect_all_required_tools() {
    log_debug "Collecting required tools..."
    local needed_tools=()

    # Collect tools needed for all planned actions
    for action in "${TASK_PLAN[@]}"; do
        local action_tools=$(list_tools_for_task "$action")
        if [[ -n "$action_tools" ]]; then
            needed_tools+=($action_tools)
        fi
    done

    # Calculate what tools need to be installed (needed but not available)
    export INSTALL_TOOLS=()
    for tool in "${needed_tools[@]}"; do
        if ! has_tool "$tool"; then
            # Map some tools to their package names
            case "$tool" in
                "gpg")
                    INSTALL_TOOLS+=("gnupg")
                    ;;
                "mongosh")
                    INSTALL_TOOLS+=("mongodb-mongosh")
                    ;;
                "tcc"|"gcc"|"cc")
                    if ! has_tool gcc && ! has_tool tcc; then
                        INSTALL_TOOLS+=("tcc" "libc6-dev")
                    fi
                    ;;
                "sha256sum")
                    INSTALL_TOOLS+=("coreutils")
                    ;;
                *)
                    INSTALL_TOOLS+=("$tool")
                    ;;
            esac
        fi
    done

    # Remove duplicates from INSTALL_TOOLS
    if [[ ${#INSTALL_TOOLS[@]} -gt 0 ]]; then
        local unique_tools=($(printf '%s\n' "${INSTALL_TOOLS[@]}" | sort -u))
        INSTALL_TOOLS=("${unique_tools[@]}")
    fi

    log_debug "Tools to install: ${INSTALL_TOOLS[*]}"
}

summarize_state_and_plan() {
    # State display functions
    mongodb_state() {
        if has_fact "mongodb_running" && has_fact "mongodb_rs_initialized"; then
            echo "✓ running with replica set initialized"
        elif has_fact "mongodb_running"; then
            echo "⚠ running but replica set not initialized"
        elif has_fact "mongodb_installed"; then
            echo "⚠ installed but not running"
        elif has_fact "mongodb_repo_configured"; then
            echo "⚠ repository configured but not installed"
        else
            echo "✗ missing"
        fi
    }

    nginx_state() {
        if has_fact "bebop_nginx_site_domain_mismatch"; then
            echo "⚠ be-BOP site configured for different domain (needs reconfiguration)"
        elif has_fact "nginx_running" && has_fact "bebop_site_running"; then
            echo "✓ be-BOP site running"
        elif has_fact "nginx_running" && has_fact "bebop_site_enabled"; then
            echo "✓ be-BOP site enabled"
        elif has_fact "nginx_running"; then
            echo "⚠ installed but not running"
        elif has_tool nginx; then
            echo "⚠ installed but not running"
        else
            echo "✗ missing"
        fi
    }

    phoenixd_state() {
        if has_fact "phoenixd_running"; then
            echo "✓ running"
        elif has_fact "phoenixd_installed"; then
            echo "⚠ installed but not running"
        else
            echo "✗ missing"
        fi
    }

    cli_state() {
        local cli_version="$(get_fact "bebop_cli_version" || true)"
        local wrapper_fingerprint="$(get_fact "bebop_cli_wrapper_fingerprint" || true)"
        local expected_wrapper_fingerprint="$(wizard_file_fingerprint "bebop_cli_wrapper")"

        if [[ -z "$cli_version" ]]; then
            echo "✗ missing"
        elif [[ -z "$wrapper_fingerprint" ]]; then
            echo "⚠ installed but wrapper fingerprint missing"
        elif [[ "$wrapper_fingerprint" != "$expected_wrapper_fingerprint" ]]; then
            echo "⚠ installed but wrapper fingerprint mismatch"
        elif [[ "$cli_version" != "$SCRIPT_VERSION" ]]; then
            echo "⚠ installed but version mismatch (v${cli_version} ≠ v${SCRIPT_VERSION})"
        else
            echo "✓ installed (v${cli_version})"
        fi
    }

    garage_state() {
        if has_fact "garage_config_domain_mismatch"; then
            echo "⚠ configured for different domain (needs reconfiguration)"
        elif has_fact "garage_running" && has_fact "garage_config_exists" && has_fact "garage_provisioned"; then
            echo "✓ running"
        elif has_fact "garage_running" && has_fact "garage_config_exists"; then
            echo "⚠ running but not provisioned"
        elif has_fact "garage_running"; then
            echo "⚠ running but not configured"
        elif has_fact "garage_installed"; then
            echo "⚠ installed but not running"
        else
            echo "✗ missing"
        fi
    }

    bebop_state() {
        if has_fact "bebop_config_domain_mismatch"; then
            echo "⚠ configured for different domain (needs reconfiguration)"
        elif has_fact "bebop_config_exists" && \
            [[ "$(get_fact "bebop_config_exists")" != "$(wizard_file_fingerprint bebop_config)" ]]; then
            echo "⚠ configuration file is outdated"
        elif has_fact "bebop_running"; then
            if has_fact "bebop_latest_release_installed"; then
                echo "✓ up-to-date and running"
            elif ! has_tool be-bop-cli; then
                echo "⚠ a newer release may be available (be-bop-cli required)"
            else
                echo "⚠ a new release is available"
            fi
        elif has_fact "bebop_config_exists" && has_fact "bebop_service_exists"; then
            echo "⚠ service configured but not running"
        else
            echo "✗ missing"
        fi
    }

    nodejs_state() {
        if has_fact "nodejs_available" && has_tool "pnpm"; then
            echo "✓ available with pnpm"
        elif has_fact "nodejs_available"; then
            echo "⚠ installed but pnpm missing"
        elif has_fact "nodejs_repo_configured"; then
            echo "⚠ repository configured but not installed"
        else
            echo "✗ missing"
        fi
    }

    ssl_state() {
        local domain
        if ! domain="$(get_fact "specified_domain")"; then
            echo "⚪ unknown (run with --domain <domain> to check)"
        elif [[ "$domain" = "localhost" ]]; then
            echo "⚪ not needed (localhost)"
        elif has_fact "certbot_installed"; then
            echo "✓ Let's Encrypt available"
        elif has_fact "snakeoil_cert_available"; then
            echo "⚠ self-signed certificate only"
        else
            echo "✗ missing"
        fi
    }

    hardening_state() {
        if has_fact "running_in_container"; then
            echo "⚪ disabled (running in container)"
        else
            echo "✓ available"
        fi
    }

    echo ""
    echo "=========================================="
    echo "be-BOP Installation Plan"
    echo "=========================================="
    local domain email
    if domain="$(get_fact "specified_domain")"; then
        echo "Domain: $domain"
        [[ "$domain" != "localhost" ]] && echo "  nginx: $(domains_for_nginx)"
    fi
    if email="$(get_fact "specified_email")"; then
        echo "Email: $email"
    fi
    if [[ -n "${DETECTED_HUMAN_OS_DISTRIBUTION:-}" ]]; then
        echo "Environment: $DETECTED_HUMAN_OS_DISTRIBUTION"
        echo ""
    fi

    echo "Current system status:"
    echo "  • Node.js: $(nodejs_state)"
    echo "  • MongoDB: $(mongodb_state)"
    echo "  • nginx: $(nginx_state)"
    echo "  • SSL certificate: $(ssl_state)"
    echo "  • phoenixd: $(phoenixd_state)"
    echo "  • Garage: $(garage_state)"
    echo "  • be-BOP CLI: $(cli_state)"
    echo "  • be-BOP: $(bebop_state)"
    echo "  • Security hardening: $(hardening_state)"
    echo ""

    if [[ ${#TASK_PLAN[@]} -eq 0 ]] && [[ ${#INSTALL_TOOLS[@]} -eq 0 ]]; then
        log_info "🎉 Nothing to do! Your be-BOP installation is already up-to-date and correctly configured."
        echo ""
        exit 0
    else
        echo "Planned actions:"
        if [[ ${#INSTALL_TOOLS[@]} -gt 0 ]]; then
            echo "  • Install required tools: ${INSTALL_TOOLS[*]}"
        fi
        for action in "${TASK_PLAN[@]}"; do
            echo "  • $(describe_task "$action")"
        done

        echo ""
    fi
}

# Ask for user confirmation
prompt_user_confirmation() {
    if [[ "$RUN_NON_INTERACTIVE" = true ]]; then
        log_info "Skipping confirmation (--non-interactive specified)"
        return 0
    fi

    read -rp "Do you want to proceed? [Y/n] " response
    case "$response" in
        [yY][eE][sS]|[yY]|"")
            return 0
            ;;
        *)
            log_info "Installation cancelled by user"
            exit $EXIT_SUCCESS
            ;;
    esac
}

# Returns 1 when the task does not require systemd operational
task_requires_systemd_operational() {
    case "$1" in
        configure_bebop_hardening_overrides) ;;
        configure_garage_hardening_overrides) ;;
        configure_phoenixd_hardening_overrides) ;;
        initialize_mongodb_rs) ;;
        install_bebop_service) ;;
        install_garage_service) ;;
        install_phoenixd_service) ;;
        provision_garage) ;;
        reload_nginx) ;;
        restart_bebop) ;;
        restart_garage) ;;
        start_and_enable_bebop) ;;
        start_and_enable_garage) ;;
        start_and_enable_nginx) ;;
        start_and_enable_phoenixd) ;;
        remove_legacy_minio) ;;
        *)
            return 1
            ;;
    esac
}

wait_systemd_operational() {
    local state
    state=$(systemctl is-system-running --wait 2>/dev/null || true)
    case "$state" in
        running|degraded)  # good enough
            ;;
        *)
            die_systemd_unavailable_for_task "$task" "$state"
            ;;
    esac
}

execute_task_plan() {
    log_info "Executing planned tasks..."
    local systemd_operational=false
    for task in "${TASK_PLAN[@]}"; do
        if [[ "$systemd_operational" != true ]] && task_requires_systemd_operational "$task"; then
            wait_systemd_operational
            systemd_operational=true
        fi
        log_info "Running task: $task"
        run_task "$task"
    done
}

update_package_lists() {
    log_info "Updating package list..."
    run_privileged apt update
}

# ---[ 4. Prepare the toolbox ]---
# Install any command-line tools that the planned tasks require
# but aren’t currently available on the system.
# This makes sure every action has the programs it needs to run properly.
prepare_toolbox() {
    if [[ ${#INSTALL_TOOLS[@]} -eq 0 ]]; then
        log_debug "No additional tools needed"
        return 0
    fi
    log_info "Installing required tools: ${INSTALL_TOOLS[*]}"
    update_package_lists
    run_privileged apt install -y "${INSTALL_TOOLS[@]}"
}

# ---[ 5. Human-readable task descriptions ]---
# Provide a short explanation for each task name.
# Used for logging and summaries, so users can read the plan in plain English
# instead of just seeing raw function names.
describe_task() {
    case "$1" in
        "await_bebop_ready") echo "Wait for be-BOP service to be ready" ;;
        "configure_bebop_cli_user") echo "Configure be-BOP CLI system user" ;;
        "configure_bebop_hardening_overrides") echo "Apply security hardening to be-BOP service" ;;
        "configure_bebop_site") echo "Configure be-BOP nginx site" ;;
        "configure_garage_hardening_overrides") echo "Apply security hardening to Garage service" ;;
        "configure_mongodb_repo") echo "Configure MongoDB 8.0 repository" ;;
        "configure_nodejs_repo") echo "Configure Node.js 22 repository" ;;
        "configure_phoenixd_hardening_overrides") echo "Apply security hardening to phoenixd service" ;;
        "enable_corepack") echo "Enable corepack and install pnpm" ;;
        "initialize_mongodb_rs") echo "Initialize MongoDB replica set" ;;
        "install_bebop_cli") echo "Install be-BOP maintenance tool (be-bop-cli)" ;;
        "install_bebop_cli_sudoers") echo "Install be-BOP CLI sudoers rule" ;;
        "install_bebop_latest_release") echo "Install latest be-BOP release" ;;
        "install_bebop_service") echo "Install be-BOP systemd service" ;;
        "install_garage") echo "Install Garage S3-compatible storage server" ;;
        "install_garage_service") echo "Install Garage systemd service" ;;
        "install_mongodb") echo "Install MongoDB" ;;
        "install_nodejs") echo "Install Node.js" ;;
        "install_phoenixd") echo "Install phoenixd Lightning Network daemon" ;;
        "install_phoenixd_service") echo "Install phoenixd systemd service" ;;
        "migrate_minio_to_garage") echo "Migrate data from MinIO to Garage" ;;
        "provision_garage") echo "Provision Garage storage (layout, key, bucket)" ;;
        "provision_ssl_cert") echo "Provision SSL certificate with Let's Encrypt" ;;
        "reload_nginx") echo "Reload nginx configuration" ;;
        "restart_bebop") echo "Restart be-BOP service" ;;
        "restart_garage") echo "Restart Garage service" ;;
        "setup_bebop_directory_permissions") echo "Set up be-BOP directory permissions" ;;
        "start_and_enable_bebop") echo "Start and enable be-BOP service" ;;
        "start_and_enable_garage") echo "Start and enable Garage service" ;;
        "start_and_enable_mongodb") echo "Start and enable MongoDB service" ;;
        "start_and_enable_nginx") echo "Start and enable nginx service" ;;
        "start_and_enable_phoenixd") echo "Start and enable phoenixd service" ;;
        "remove_legacy_minio") echo "Remove legacy MinIO (service, binary, data)" ;;
        "write_bebop_configuration") echo "Write be-BOP configuration" ;;
        "write_garage_configuration") echo "Write Garage configuration" ;;
        *)
            return 1
            ;;
    esac
    return 0
}

# ---[ 6. Run the tasks ]---
# Go through the planned tasks one by one and execute them.
# Each task is handled by a specific function that knows how to do that job
# (like installing MongoDB or configuring Nginx).
# This is where the script actually changes the system to match the plan.
run_task() {
    case "$1" in
        "await_bebop_ready") task_await_bebop_ready ;;
        "configure_bebop_cli_user") configure_bebop_cli_user ;;
        "configure_bebop_hardening_overrides") configure_bebop_hardening_overrides ;;
        "configure_bebop_site") configure_bebop_site ;;
        "configure_garage_hardening_overrides") configure_garage_hardening_overrides ;;
        "configure_mongodb_repo") configure_mongodb_repo ;;
        "configure_nodejs_repo") configure_nodejs_repo ;;
        "configure_phoenixd_hardening_overrides") configure_phoenixd_hardening_overrides ;;
        "enable_corepack") enable_corepack ;;
        "initialize_mongodb_rs") initialize_mongodb_rs ;;
        "install_bebop_cli") install_bebop_cli ;;
        "install_bebop_cli_sudoers") install_bebop_cli_sudoers ;;
        "install_bebop_latest_release") install_bebop_latest_release ;;
        "install_bebop_service") install_bebop_service ;;
        "install_garage") install_garage ;;
        "install_garage_service") install_garage_service ;;
        "install_mongodb") install_mongodb ;;
        "install_nodejs") install_nodejs ;;
        "install_phoenixd") install_phoenixd ;;
        "install_phoenixd_service") install_phoenixd_service ;;
        "migrate_minio_to_garage") migrate_minio_to_garage ;;
        "provision_garage") provision_garage ;;
        "provision_ssl_cert") provision_ssl_cert ;;
        "reload_nginx") reload_nginx ;;
        "restart_bebop") restart_bebop ;;
        "restart_garage") restart_garage ;;
        "setup_bebop_directory_permissions") setup_bebop_directory_permissions ;;
        "start_and_enable_bebop") start_and_enable_bebop ;;
        "start_and_enable_garage") start_and_enable_garage ;;
        "start_and_enable_mongodb") start_and_enable_mongodb ;;
        "start_and_enable_nginx") start_and_enable_nginx ;;
        "start_and_enable_phoenixd") start_and_enable_phoenixd ;;
        "remove_legacy_minio") remove_legacy_minio ;;
        "write_bebop_configuration") write_bebop_configuration ;;
        "write_garage_configuration") write_garage_configuration ;;
        *) die $EXIT_ERROR $LINENO "Unable to execute task: $1" ;;
    esac
}

configure_nodejs_repo() {
    log_info "Configuring Node.js repository..."

    local node_major="$NODEJS_MAJOR_VERSION"
    local TMPDIR=$(mktemp -d)
    # shellcheck disable=SC2064  # TMPDIR should be expanded here (and not on trap).
    trap "rm -rf $TMPDIR" RETURN 2>/dev/null || true

    # Download and add NodeSource GPG key
    local curl_args=(
        "--connect-timeout" "$CURL_CONNECT_TIMEOUT"
        "--fail"
        "--location"
        "--max-time" "$CURL_DOWNLOAD_TIMEOUT"
        "--show-error"
        "--silent"
    )
    curl "${curl_args[@]}" https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | \
        gpg --batch --yes --output "$TMPDIR/nodesource.gpg" --dearmor

    # Create repository configuration
    cat > "$TMPDIR/nodesource.list" << EOF
# This file is managed by be-bop-wizard
deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${node_major}.x nodistro main
EOF

    # Create package preferences
    cat > "$TMPDIR/nodejs" << EOF
Package: nodejs
Pin: origin deb.nodesource.com
Pin-Priority: 600
EOF

    install_file "$TMPDIR/nodesource.gpg" /usr/share/keyrings/nodesource.gpg
    install_file "$TMPDIR/nodesource.list" /etc/apt/sources.list.d/nodesource.list
    install_file "$TMPDIR/nodejs" /etc/apt/preferences.d/nodejs

    # Cleanup
    rm -rf "$TMPDIR"
    update_package_lists
}

configure_mongodb_repo() {
    log_info "Configuring MongoDB repository..."

    local os_name="$(get_fact "os_name")"
    local os_release="$(get_fact "os_release")"
    log_debug "Installing mongodb repository for ${os_name} ${os_release}"

    case "$os_name-$os_release" in
        debian-bookworm|debian-bullseye|debian-buster|debian-jessie|debian-stretch|debian-wheezy)
            local archive="main"
            ;;
        ubuntu-bionic|ubuntu-focal|ubuntu-jammy|ubuntu-noble|ubuntu-precise|ubuntu-trusty|ubuntu-xenial)
            local archive="multiverse"
            ;;
        *)
            # We should not reach this case: check_os_supported_by_wizard should
            # have explained the user the distribution is unsupported.
            die $EXIT_ERROR $LINENO "Unsupported distribution: ${os_name} ${os_release}"
            ;;
    esac

    local TMPDIR=$(mktemp -d)
    # shellcheck disable=SC2064  # TMPDIR should be expanded here (and not on trap).
    trap "rm -rf $TMPDIR" RETURN 2>/dev/null || true

    # Download and add MongoDB GPG key
    local curl_args=(
        "--connect-timeout" "$CURL_CONNECT_TIMEOUT"
        "--fail"
        "--location"
        "--max-time" "$CURL_DOWNLOAD_TIMEOUT"
        "--show-error"
        "--silent"
    )
    curl "${curl_args[@]}" https://www.mongodb.org/static/pgp/server-8.0.asc | \
        gpg --batch --yes --output "$TMPDIR/mongodb-server-8.0.gpg" --dearmor

    # Create repository configuration
    cat > "$TMPDIR/mongodb-org-8.0.list" << EOF
# This file is managed by be-bop-wizard
deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg] https://repo.mongodb.org/apt/${os_name} ${os_release}/mongodb-org/${MONGODB_VERSION} ${archive}
EOF

    install_file "$TMPDIR/mongodb-server-8.0.gpg" /usr/share/keyrings/mongodb-server-8.0.gpg
    install_file "$TMPDIR/mongodb-org-8.0.list" /etc/apt/sources.list.d/mongodb-org-${MONGODB_VERSION}.list

    # Cleanup
    rm -rf "$TMPDIR"
    update_package_lists
}

install_nodejs() {
    log_info "Installing Node.js..."
    run_privileged apt install -y nodejs
}

install_mongodb() {
    log_info "Installing MongoDB..."
    run_privileged apt install -y mongodb-org mongodb-mongosh
}

start_and_enable_mongodb() {
    log_info "Starting and enabling MongoDB service..."
    run_privileged systemctl enable mongod
    run_privileged systemctl start mongod
}

wait_mongodb_ready() {
    local retries="$SERVICE_TEST_START_RETRIES"
    while ! mongosh --quiet --eval "db.adminCommand('ping')" >/dev/null 2>&1; do
        if [[ $retries -le 0 ]]; then
            die $EXIT_ERROR $LINENO "MongoDB failed to start after 30 seconds"
        fi
        log_debug "Waiting for MongoDB to be ready... ($retries retries left)"
        sleep "$SERVICE_TEST_START_WAIT_SECONDS"
        ((retries--))
    done
}

initialize_mongodb_rs() {
    log_info "Initializing MongoDB replica set..."

    # Configure MongoDB replica set
    run_privileged sed -i '/^#\?replication:/,/^[^ ]/c replication:\n  replSetName: "rs0"' /etc/mongod.conf
    run_privileged systemctl restart mongod
    wait_mongodb_ready

    local out
    if ! out="$(mongosh --eval 'rs.initiate()' 2>&1)"; then
        # rs.initiate() is fragile and may sometimes “succeed” even when the command
        # fails. If mongo reports the rs as initialized, disregard the error.
        if ! mongosh --quiet --eval "rs.status().ok" 2>/dev/null | grep -q "1"; then
            die $EXIT_ERROR $LINENO "Unable to initialize MongoDB replica set: $out"
        fi
    fi

    # Restart to ensure replica set configuration is fully applied
    run_privileged systemctl restart mongod
    wait_mongodb_ready
}

configure_bebop_site() {
    log_info "Configuring be-BOP nginx site..."
    local domain="$(get_fact "specified_domain")"

    # Remove nginx default site
    run_privileged rm -f /etc/nginx/sites-enabled/default

    local TMPDIR=$(mktemp -d)
    # shellcheck disable=SC2064  # TMPDIR should be expanded here (and not on trap).
    trap "rm -rf $TMPDIR" RETURN 2>/dev/null || true

    if [[ "$domain" = "localhost" ]]; then
        # Localhost configuration (HTTP only)
        awk -v fp="$(wizard_file_fingerprint nginx_config)" '{gsub(/@file_fingerprint@/, fp); print}' > "$TMPDIR/be-BOP.conf" << 'EOF'
# The sites in this file are managed by be-bop-wizard
# wizard-fingerprint: @file_fingerprint@
server {
    listen 80;
    listen [::]:80;
    server_name localhost;

    proxy_set_header "Connection" "";

    # SSE endpoints - long-lived connections for real-time sync
    location ~ /sse$ {
        proxy_pass http://127.0.0.1:3000;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
        proxy_buffering off;
        proxy_cache off;
        proxy_set_header Connection '';
        proxy_http_version 1.1;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Host $http_host;
    }

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $server_name;
        proxy_redirect off;
    }
}

server {
    listen 80;
    listen [::]:80;
    server_name s3.localhost;

    proxy_set_header "Connection" "";
    client_max_body_size 1000M;

    location / {
        proxy_pass http://localhost:3900;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $server_name;
        proxy_redirect off;
        proxy_connect_timeout 300;
        proxy_http_version 1.1;
        chunked_transfer_encoding off;
    }
}
EOF
    else
        # Production configuration with HTTPS
        local all_domains="$(domains_for_nginx)"

        awk -v all_doms="$all_domains" \
            -v main_dom="$domain" \
            -v s3_dom="$(get_fact s3_domain)" \
            -v fp="$(wizard_file_fingerprint nginx_config)" \
            '{
                gsub(/@http_to_https_domains@/, all_doms)
                gsub(/@main_domain@/, main_dom)
                gsub(/@s3_domain@/, s3_dom)
                gsub(/@file_fingerprint@/, fp)
                print
            }' > "$TMPDIR/be-BOP.conf" << 'EOF'
# The sites in this file are managed by be-bop-wizard
# wizard-fingerprint: @file_fingerprint@

server {
    listen 80;
    listen [::]:80;
    server_name @http_to_https_domains@;

    location / {
        return 307 https://$host$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name @main_domain@;

    ssl_certificate     /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;

    # Mozilla's "Intermediate" SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ecdh_curve X25519:prime256v1:secp384r1;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    ssl_prefer_server_ciphers off;
    ssl_stapling on;
    ssl_stapling_verify on;
    proxy_set_header "Connection" "";

    # SSE endpoints - long-lived connections for real-time sync
    location ~ /sse$ {
        proxy_pass http://127.0.0.1:3000;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
        proxy_buffering off;
        proxy_cache off;
        proxy_set_header Connection '';
        proxy_http_version 1.1;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Host $http_host;
    }

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $server_name;
        proxy_redirect off;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name @s3_domain@;

    ssl_certificate     /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;

    # Mozilla's "Intermediate" SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ecdh_curve X25519:prime256v1:secp384r1;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    ssl_prefer_server_ciphers off;
    ssl_stapling on;
    ssl_stapling_verify on;
    proxy_set_header "Connection" "";

    client_max_body_size 1000M;

    location / {
        proxy_pass http://localhost:3900;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $server_name;
        proxy_redirect off;
        proxy_connect_timeout 300;
        proxy_http_version 1.1;
        chunked_transfer_encoding off;
    }
}
EOF

        # Add HTTPS redirect block for redirect domains
        local redir="$(get_fact redirect_domains 2>/dev/null)"
        if [[ -n "$redir" ]]; then
            cat >> "$TMPDIR/be-BOP.conf" << EOF

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${redir};
    ssl_certificate     /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
    return 307 https://${domain}\$request_uri;
}
EOF
        fi
    fi

    install_file "$TMPDIR/be-BOP.conf" /etc/nginx/sites-available/be-BOP.conf
    run_privileged ln -sf /etc/nginx/sites-available/be-BOP.conf /etc/nginx/sites-enabled/

    # Test nginx configuration
    if ! run_privileged nginx -t; then
        die $EXIT_ERROR $LINENO "nginx configuration test failed"
    fi

    # Cleanup
    rm -rf "$TMPDIR"
}

start_and_enable_nginx() {
    log_info "Starting and enabling nginx service..."
    run_privileged systemctl enable nginx
    run_privileged systemctl start nginx
}

reload_nginx() {
    log_info "Reloading nginx configuration..."
    run_privileged nginx -t
    run_privileged systemctl reload nginx
}

provision_ssl_cert() {
    log_info "Provisioning SSL certificate with Let's Encrypt..."
    local email="$(get_fact "specified_email")"
    local main_domain="$(get_fact bebop_domain)"
    local domains="$(domains_for_nginx)"

    local certbot_args=(
        "--agree-tos"
        "--cert-name" "${main_domain}"
        "--email" "${email}"
        "--nginx"
        "--non-interactive"
        "--reinstall"
    )
    for d in $domains; do
        certbot_args+=(-d "$d")
    done
    run_privileged certbot "${certbot_args[@]}"

    if has_tool ucf; then
        # Certbot updates the nginx configuration, let ucf know about it.
        run_privileged ucf /etc/nginx/sites-available/be-BOP.conf /etc/nginx/sites-available/be-BOP.conf
    fi
}

install_phoenixd() {
    log_info "Installing phoenixd Lightning Network daemon..."

    local STOW_DIR="/usr/local/phoenixd"
    local PACKAGE_DIR="$STOW_DIR/phoenixd-${PHOENIXD_VERSION}"

    # Check if the version directory already exists
    if [[ -d "$PACKAGE_DIR" ]]; then
        log_info "phoenixd ${PHOENIXD_VERSION} already installed in stow directory"
    else
        # Create temporary directory for download
        local TEMP_DIR=$(mktemp -d)
        # shellcheck disable=SC2064  # TEMP_DIR should be expanded here (and not on trap).
        trap "rm -rf $TEMP_DIR" RETURN 2>/dev/null || true
        pushd "$TEMP_DIR" > /dev/null

        # Download and extract phoenixd
        local arch_string
        case "$(get_fact "debian_arch")" in
            amd64)
                arch_string="x64"
                ;;
            arm64)
                arch_string="arm64"
                ;;
            *)
                die_unexpected_architecture "$(get_fact "debian_arch")"
                ;;
        esac
        local phoenixd_url="https://github.com/ACINQ/phoenixd/releases/download/v${PHOENIXD_VERSION}/phoenixd-${PHOENIXD_VERSION}-linux-${arch_string}.zip"
        log_info "Downloading phoenixd ${PHOENIXD_VERSION} from ${phoenixd_url}"
        local curl_args=(
            "--connect-timeout" "$CURL_CONNECT_TIMEOUT"
            "--fail"
            "--location"
            "--max-time" "$CURL_DOWNLOAD_TIMEOUT"
            "--progress-bar"
            "--show-error"
            "--output" phoenixd.zip
        )
        curl "${curl_args[@]}" "$phoenixd_url"
        unzip -q phoenixd.zip

        # Create stow directory structure
        run_privileged mkdir -p "$PACKAGE_DIR/bin"

        # Install phoenixd binary to stow package directory
        run_privileged cp phoenixd-*/* "$PACKAGE_DIR/bin/"
        run_privileged chmod +x "$PACKAGE_DIR/bin/phoenixd"

        popd > /dev/null
        rm -rf "$TEMP_DIR"
    fi

    # Use stow to symlink the binary
    pushd "$STOW_DIR" > /dev/null
    run_privileged stow "phoenixd-${PHOENIXD_VERSION}"
    popd > /dev/null
    log_info "phoenixd ${PHOENIXD_VERSION} installed using stow"
}

install_bebop_cli() {
    log_info "Installing be-BOP CLI with SUID wrapper..."

    # Determine which compiler to use
    local CC=""
    if command -v tcc &>/dev/null; then
        CC="tcc"
    elif command -v gcc &>/dev/null; then
        CC="gcc"
    elif command -v cc &>/dev/null; then
        CC="cc"
    else
        die $EXIT_ERROR $LINENO "No C compiler available (tried tcc, gcc, cc)."
    fi
    log_info "Using C compiler: $CC"

    # Get the directory where this wizard script is located
    local SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local CLI_SCRIPT="$SCRIPT_DIR/be-bop-cli.sh"
    local WRAPPER_TEMPLATE="$SCRIPT_DIR/be-bop-cli-wrapper.c"

    if [[ ! -f "$CLI_SCRIPT" ]]; then
        die $EXIT_ERROR $LINENO "Could not find be-bop-cli.sh in the same directory as this wizard"
    fi

    if [[ ! -f "$WRAPPER_TEMPLATE" ]]; then
        die $EXIT_ERROR $LINENO "Could not find be-bop-cli-wrapper.c in the same directory as this wizard"
    fi

    # Create directories
    run_privileged mkdir -p /usr/local/libexec
    run_privileged mkdir -p /usr/local/bin

    # Install the real script
    run_privileged cp "$CLI_SCRIPT" /usr/local/libexec/be-bop-cli.real
    run_privileged chmod 755 /usr/local/libexec/be-bop-cli.real
    run_privileged chown be-bop-cli:be-bop-cli /usr/local/libexec/be-bop-cli.real

    # Calculate script size and hash
    local SCRIPT_SIZE=$(stat -c %s /usr/local/libexec/be-bop-cli.real)
    local SCRIPT_HASH=""
    if command -v sha256sum &>/dev/null; then
        SCRIPT_HASH=$(sha256sum /usr/local/libexec/be-bop-cli.real | cut -d' ' -f1)
    else
        die $EXIT_ERROR $LINENO "sha256sum tool is required but not available"
    fi
    local WRAPPER_FINGERPRINT=$(wizard_file_fingerprint "bebop_cli_wrapper")

    # Create temporary directory for compilation
    local TMPDIR=$(mktemp -d)
    # shellcheck disable=SC2064  # TMPDIR should be expanded here (and not on trap).
    trap "rm -rf $TMPDIR" RETURN 2>/dev/null || true

    # Compile the wrapper with embedded values via -D flags
    log_info "Compiling SUID wrapper with hash: $SCRIPT_HASH"
    if ! $CC \
        -DSCRIPT_EXPECTED_SHA256_HEX="\"$SCRIPT_HASH\"" \
        -DSCRIPT_SIZE_BYTES="$SCRIPT_SIZE" \
        -DWRAPPER_FINGERPRINT="\"$WRAPPER_FINGERPRINT\"" \
        -o "$TMPDIR/be-bop-cli" \
        "$WRAPPER_TEMPLATE"; then
        die $EXIT_ERROR $LINENO "Failed to compile be-bop-cli wrapper"
    fi

    # Install the compiled wrapper
    run_privileged cp "$TMPDIR/be-bop-cli" /usr/local/bin/be-bop-cli
    run_privileged chown be-bop-cli:be-bop-cli /usr/local/bin/be-bop-cli
    run_privileged chmod 6755 /usr/local/bin/be-bop-cli

    log_info "be-BOP CLI v${SCRIPT_VERSION} installed with SUID wrapper"
}

install_bebop_cli_sudoers() {
    log_info "Installing be-BOP CLI sudoers rule..."

    local TMPDIR=$(mktemp -d)
    # shellcheck disable=SC2064  # TMPDIR should be expanded here (and not on trap).
    trap "rm -rf $TMPDIR" RETURN 2>/dev/null || true

    # Generate sudoers rule with fingerprint
    local fingerprint="$(wizard_file_fingerprint "bebop_cli_sudoers")"
    local systemctl="$(which systemctl)"
    cat > "$TMPDIR/be-bop-cli-bebop" << EOF
# wizard-fingerprint:${fingerprint}
Defaults:be-bop-cli !authenticate
Defaults:be-bop-cli env_reset
Defaults:be-bop-cli secure_path="/usr/sbin:/usr/bin:/sbin:/bin"

be-bop-cli ALL=(root) NOPASSWD: ${systemctl} restart bebop.service, ${systemctl} start bebop.service
EOF

    # Install the sudoers file
    install_file "$TMPDIR/be-bop-cli-bebop" /etc/sudoers.d/be-bop-cli-bebop
    run_privileged chmod 440 /etc/sudoers.d/be-bop-cli-bebop
    run_privileged chown root:root /etc/sudoers.d/be-bop-cli-bebop

    log_info "be-BOP CLI sudoers rule installed"
}

install_garage() {
    log_info "Installing Garage S3-compatible storage server..."

    local STOW_DIR="/usr/local/garage"
    local PACKAGE_DIR="$STOW_DIR/garage-v${GARAGE_VERSION}"

    # Check if the version directory already exists
    if [[ -d "$PACKAGE_DIR" ]]; then
        log_info "Garage v${GARAGE_VERSION} already installed in stow directory"
    else
        # Create temporary directory for download
        local TEMP_DIR=$(mktemp -d)
        # shellcheck disable=SC2064  # TEMP_DIR should be expanded here (and not on trap).
        trap "rm -rf $TEMP_DIR" RETURN 2>/dev/null || true
        pushd "$TEMP_DIR" > /dev/null

        local arch_string
        case "$(get_fact "debian_arch")" in
            amd64)
                arch_string="x86_64-unknown-linux-musl"
                ;;
            arm64)
                arch_string="aarch64-unknown-linux-musl"
                ;;
            *)
                die_unexpected_architecture "$(get_fact "debian_arch")"
                ;;
        esac
        local GARAGE_URL="https://garagehq.deuxfleurs.fr/_releases/v${GARAGE_VERSION}/${arch_string}/garage"
        log_info "Downloading Garage v${GARAGE_VERSION} from ${GARAGE_URL}"
        local curl_args=(
            "--connect-timeout" "$CURL_CONNECT_TIMEOUT"
            "--fail"
            "--location"
            "--max-time" "$CURL_DOWNLOAD_TIMEOUT"
            "--progress-bar"
            "--show-error"
            "--output" garage
        )
        curl "${curl_args[@]}" "$GARAGE_URL"

        # Create stow directory structure
        run_privileged mkdir -p "$PACKAGE_DIR/bin"

        # Install Garage binary to stow package directory
        run_privileged cp garage "$PACKAGE_DIR/bin/"
        run_privileged chmod +x "$PACKAGE_DIR/bin/garage"

        popd > /dev/null
        rm -rf "$TEMP_DIR"
    fi

    # Use stow to symlink the binary
    pushd "$STOW_DIR" > /dev/null
    run_privileged stow "garage-v${GARAGE_VERSION}"
    popd > /dev/null
    log_info "Garage v${GARAGE_VERSION} installed using stow"
}

write_garage_configuration() {
    log_info "Writing Garage configuration..."
    local domain="$(get_fact "specified_domain")"

    local TMPDIR=$(mktemp -d)
    # shellcheck disable=SC2064  # TMPDIR should be expanded here (and not on trap).
    trap "rm -rf $TMPDIR" RETURN 2>/dev/null || true

    # Generate Garage configuration
    if [[ -f /etc/garage.toml ]]; then
        log_debug "Patching domain in existing Garage configuration"
        cp /etc/garage.toml "$TMPDIR/garage.toml"
        if [[ "$domain" != "localhost" ]]; then
            sed -i "s|^root_domain.*=.*|root_domain = \"s3.${domain}\"|" "$TMPDIR/garage.toml"
        fi
    else
        # Create new configuration with generated RPC secret
        local rpc_secret
        rpc_secret=$(openssl rand -hex 32)

        if [[ "$domain" = "localhost" ]]; then
            cat > "$TMPDIR/garage.toml" << EOF
metadata_dir = "/var/lib/garage/meta"
data_dir = "/var/lib/garage/data"
db_engine = "lmdb"
replication_factor = 1

rpc_secret = "${rpc_secret}"
rpc_bind_addr = "127.0.0.1:3901"

[s3_api]
s3_region = "garage"
api_bind_addr = "127.0.0.1:3900"

[admin]
api_bind_addr = "127.0.0.1:3903"
EOF
        else
            cat > "$TMPDIR/garage.toml" << EOF
metadata_dir = "/var/lib/garage/meta"
data_dir = "/var/lib/garage/data"
db_engine = "lmdb"
replication_factor = 1

rpc_secret = "${rpc_secret}"
rpc_bind_addr = "127.0.0.1:3901"

[s3_api]
s3_region = "garage"
api_bind_addr = "127.0.0.1:3900"
root_domain = "s3.${domain}"

[admin]
api_bind_addr = "127.0.0.1:3903"
EOF
        fi
    fi

    install_file "$TMPDIR/garage.toml" /etc/garage.toml
    run_privileged chmod 640 /etc/garage.toml
}

wait_garage_ready() {
    local retries="$SERVICE_TEST_START_RETRIES"
    while ! garage status >/dev/null 2>&1; do
        if [[ $retries -le 0 ]]; then
            die $EXIT_ERROR $LINENO "Garage did not become ready in time"
        fi
        log_debug "Waiting for Garage to become ready... ($retries retries left)"
        sleep "$SERVICE_TEST_START_WAIT_SECONDS"
        ((retries--))
    done
}

provision_garage() {
    log_info "Provisioning Garage storage (layout, key, bucket)..."

    wait_garage_ready

    # Get node ID
    local node_id
    node_id=$(garage node id 2>/dev/null | cut -d@ -f1)
    if [[ -z "$node_id" ]]; then
        die $EXIT_ERROR $LINENO "Could not determine Garage node ID"
    fi
    log_debug "Garage node ID: $node_id"

    # Assign layout (only if node has no layout yet)
    local node_needs_layout=false
    if garage status 2>/dev/null | grep "${node_id:0:16}" | grep -q "NO ROLE ASSIGNED"; then
        node_needs_layout=true
    fi
    if [[ "$node_needs_layout" == true ]]; then
        garage layout assign -z dc1 -c 1G "$node_id"

        # Read current layout version and increment
        local layout_version
        layout_version=$(garage layout show 2>/dev/null | awk '/Current cluster layout version:/{print $NF}')
        layout_version=$(( ${layout_version:-0} + 1 ))
        garage layout apply --version "$layout_version"
    else
        log_debug "Node already has layout assigned, skipping"
    fi

    # Create access key and save credentials (only if key does not already exist)
    if ! garage key list 2>/dev/null | grep -q "bebop-key"; then
        local key_output
        key_output=$(garage key create bebop-key 2>&1)

        local key_id key_secret
        key_id=$(echo "$key_output" | grep -oP 'Key ID:\s+\K\S+' || echo "")
        key_secret=$(echo "$key_output" | grep -oP 'Secret key:\s+\K\S+' || echo "")

        if [[ -z "$key_id" ]] || [[ -z "$key_secret" ]]; then
            die $EXIT_ERROR $LINENO "Could not create Garage access key"
        fi

        local TMPDIR=$(mktemp -d)
        # shellcheck disable=SC2064  # TMPDIR should be expanded here (and not on trap).
        trap "rm -rf $TMPDIR" RETURN 2>/dev/null || true

        cat > "$TMPDIR/credentials.env" << EOF
GARAGE_KEY_ID=${key_id}
GARAGE_KEY_SECRET=${key_secret}
EOF

        run_privileged mkdir -p /etc/garage
        install_file "$TMPDIR/credentials.env" /etc/garage/credentials.env
        run_privileged chmod 600 /etc/garage/credentials.env
    else
        log_debug "Garage key 'bebop-key' already exists, skipping key creation"
    fi

    # Create bucket (only if it does not exist)
    if ! garage bucket list 2>/dev/null | grep -q "bebop"; then
        garage bucket create bebop
        garage bucket allow --read --write --owner bebop --key bebop-key
    else
        log_debug "Bucket 'bebop' already exists, skipping"
    fi

    log_info "Garage provisioned: key 'bebop-key' created, bucket 'bebop' ready"
}

migrate_minio_to_garage() {
    log_info "Migrating data from MinIO to Garage..."

    # Read MinIO credentials
    local minio_user minio_password
    minio_user="$(run_privileged grep '^MINIO_ROOT_USER=' /etc/minio/config.env 2>/dev/null | cut -d'=' -f2- || echo "")"
    minio_password="$(run_privileged grep '^MINIO_ROOT_PASSWORD=' /etc/minio/config.env 2>/dev/null | cut -d'=' -f2- || echo "")"

    if [[ -z "$minio_user" ]] || [[ -z "$minio_password" ]]; then
        log_warn "Could not read MinIO credentials, skipping data migration"
        return 0
    fi

    # Read Garage credentials
    local garage_key_id garage_key_secret
    garage_key_id="$(run_privileged grep '^GARAGE_KEY_ID=' /etc/garage/credentials.env 2>/dev/null | cut -d'=' -f2- || echo "")"
    garage_key_secret="$(run_privileged grep '^GARAGE_KEY_SECRET=' /etc/garage/credentials.env 2>/dev/null | cut -d'=' -f2- || echo "")"

    if [[ -z "$garage_key_id" ]] || [[ -z "$garage_key_secret" ]]; then
        log_warn "Could not read Garage credentials — skipping migration (re-run wizard to retry)"
        return 0
    fi

    # Create temporary rclone config
    local TMPDIR=$(mktemp -d)
    # shellcheck disable=SC2064  # TMPDIR should be expanded here (and not on trap).
    trap "rm -rf $TMPDIR" RETURN 2>/dev/null || true

    cat > "$TMPDIR/rclone.conf" << EOF
[minio]
type = s3
provider = Minio
endpoint = http://localhost:9000
access_key_id = ${minio_user}
secret_access_key = ${minio_password}

[garage]
type = s3
provider = Other
endpoint = http://localhost:3900
access_key_id = ${garage_key_id}
secret_access_key = ${garage_key_secret}
region = garage
EOF

    log_info "Copying data from MinIO to Garage (this may take a while)..."
    if ! rclone sync minio:bebop garage:bebop --config "$TMPDIR/rclone.conf" --progress 2>&1; then
        log_warn "rclone sync reported errors — please verify data integrity manually"
        return 0
    fi

    log_info "Verifying data integrity..."
    if rclone check minio:bebop garage:bebop --config "$TMPDIR/rclone.conf" 2>&1; then
        log_info "Data migration verified — all objects match"
        run_privileged mkdir -p /etc/garage
        echo "verified" | run_privileged tee /etc/garage/migration-from-minio.done > /dev/null
    else
        log_warn "Data verification found mismatches — migration will retry on next run"
    fi

}

remove_legacy_minio() {
    log_info "Removing legacy MinIO..."
    run_privileged systemctl stop minio 2>/dev/null || true
    run_privileged systemctl disable minio 2>/dev/null || true

    # Update nginx to proxy S3 traffic to Garage instead of MinIO
    if [[ -f /etc/nginx/sites-available/be-BOP.conf ]] && \
       grep -q "proxy_pass http://localhost:9000" /etc/nginx/sites-available/be-BOP.conf 2>/dev/null; then
        log_info "Updating nginx S3 proxy: MinIO (9000) → Garage (3900)"
        run_privileged sed -i 's|proxy_pass http://localhost:9000|proxy_pass http://localhost:3900|' /etc/nginx/sites-available/be-BOP.conf
        run_privileged systemctl reload nginx
    fi

    # Full removal only after verified migration
    if ! has_fact "minio_migration_verified"; then
        log_warn "MinIO data preserved — migration not yet verified"
        return 0
    fi

    run_privileged rm -f /etc/systemd/system/minio.service
    run_privileged rm -rf /etc/systemd/system/minio.service.d
    run_privileged systemctl daemon-reload
    run_privileged rm -f /usr/local/bin/minio
    run_privileged rm -rf /usr/local/minio
    run_privileged rm -rf /etc/minio
    run_privileged rm -rf /var/lib/minio
    run_privileged rm -rf /var/lib/private/minio
    run_privileged rm -f /etc/garage/migration-from-minio.done

    log_info "MinIO fully removed from system"
}

write_bebop_configuration() {
    log_info "Generating be-BOP environment configuration..."
    local domain="$(get_fact "specified_domain")"

    # Read various secrets to embed into the configuration file.
    local s3_root_user="$(run_privileged grep '^GARAGE_KEY_ID=' /etc/garage/credentials.env 2>/dev/null | cut -d'=' -f2- || echo "")"
    local s3_root_password="$(run_privileged grep '^GARAGE_KEY_SECRET=' /etc/garage/credentials.env 2>/dev/null | cut -d'=' -f2- || echo "")"
    local phoenixd_http_password="$(run_privileged grep -oP 'http-password=\K[^ ]+' /var/lib/phoenixd/.phoenix/phoenix.conf)"

    if [[ -z "$s3_root_user" ]] || [[ -z "$s3_root_password" ]]; then
        die $EXIT_ERROR $LINENO "Could not find Garage credentials in /etc/garage/credentials.env"
    fi

    local TMPDIR=$(mktemp -d)
    # shellcheck disable=SC2064  # TMPDIR should be expanded here (and not on trap).
    trap "rm -rf $TMPDIR" RETURN 2>/dev/null || true

    # Make sure to update the template_rev in wizard_file_fingerprint bebop_config
    cat > "$TMPDIR/config.env" << EOF
# This configuration is managed by be-bop-wizard
# wizard-fingerprint: $(wizard_file_fingerprint bebop_config)
ADDRESS_HEADER=X-Forwarded-For
MONGODB_DB=bebop
MONGODB_URL=mongodb://127.0.0.1:27017
ORIGIN=https://${domain}
PUBLIC_S3_ENDPOINT_URL=https://$(get_fact s3_domain)
PHOENIXD_ENDPOINT_URL=http://127.0.0.1:9740
PHOENIXD_HTTP_PASSWORD=${phoenixd_http_password}
S3_BUCKET=bebop
S3_ENDPOINT_URL=http://127.0.0.1:3900
S3_KEY_ID=${s3_root_user}
S3_KEY_SECRET=${s3_root_password}
S3_REGION=garage
XFF_DEPTH=1
EOF

    if [[ "$domain" = "localhost" ]]; then
        # Don't use https for localhost
        sed -i 's|ORIGIN=https://|ORIGIN=http://|' "$TMPDIR/config.env"
        sed -i 's|PUBLIC_S3_ENDPOINT_URL=https://|PUBLIC_S3_ENDPOINT_URL=http://|' "$TMPDIR/config.env"
    fi

    local marker='# ------------------------ >8 ------------------------'
    if [[ -f /etc/be-BOP/config.env ]]; then
        # If the file already exists, copy everything from the marker (including
        # the marker) into the new config file.
        sed -n "/^${marker}"'$/,$p' /etc/be-BOP/config.env >> "$TMPDIR/config.env"
    else
        echo "$marker" >> "$TMPDIR/config.env"
        echo '# Put your custom configuration (even new environment variables) after this line' >> "$TMPDIR/config.env"
    fi

    run_privileged mkdir -p /etc/be-BOP
    install_file "$TMPDIR/config.env" /etc/be-BOP/config.env
    # Ensure it's world-readable (so the configured domain can be checked)
    run_privileged chmod 644 /etc/be-BOP/config.env

    # Cleanup
    rm -rf "$TMPDIR"
}

install_phoenixd_service() {
    log_info "Configuring phoenixd systemd service..."

    local TMPDIR=$(mktemp -d)
    # shellcheck disable=SC2064  # TMPDIR should be expanded here (and not on trap).
    trap "rm -rf $TMPDIR" RETURN 2>/dev/null || true

    # Create phoenixd systemd service file (container-compatible)
    cat > "$TMPDIR/phoenixd.service" << 'EOF'
[Unit]
Description=phoenixd Lightning Network Daemon
Documentation=https://github.com/ACINQ/phoenixd
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/phoenixd --http-bind-ip=127.0.0.1
Restart=always
RestartSec=5
TimeoutStartSec=60
TimeoutStopSec=30

# State directory for persistent data
StateDirectory=phoenixd
StateDirectoryMode=0755

# Working directory and environment
WorkingDirectory=/var/lib/phoenixd
Environment=HOME=/var/lib/phoenixd

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=phoenixd

# Resource limits
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    install_file "$TMPDIR/phoenixd.service" /etc/systemd/system/phoenixd.service
    run_privileged systemctl daemon-reload

    # Cleanup
    rm -rf "$TMPDIR"
}

install_garage_service() {
    log_info "Configuring Garage systemd service..."

    local TMPDIR=$(mktemp -d)
    # shellcheck disable=SC2064  # TMPDIR should be expanded here (and not on trap).
    trap "rm -rf $TMPDIR" RETURN 2>/dev/null || true

    # Create Garage systemd service file (container-compatible)
    cat > "$TMPDIR/garage.service" << 'EOF'
[Unit]
Description=Garage S3-compatible Storage Server
Documentation=https://garagehq.deuxfleurs.fr
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/garage server
Restart=always
RestartSec=5
TimeoutStartSec=60
TimeoutStopSec=30

# State directory for persistent data
StateDirectory=garage
StateDirectoryMode=0755

# Working directory and environment
WorkingDirectory=/var/lib/garage
Environment=HOME=/var/lib/garage
Environment=GARAGE_CONFIG_FILE=/etc/garage.toml

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=garage

# Resource limits
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    install_file "$TMPDIR/garage.service" /etc/systemd/system/garage.service
    run_privileged systemctl daemon-reload

    # Cleanup
    rm -rf "$TMPDIR"
}

install_bebop_service() {
    log_info "Configuring be-BOP systemd service..."

    local TMPDIR=$(mktemp -d)
    # shellcheck disable=SC2064  # TMPDIR should be expanded here (and not on trap).
    trap "rm -rf $TMPDIR" RETURN 2>/dev/null || true

    # Create be-BOP systemd service file (container-compatible)
    cat > "$TMPDIR/bebop.service" << 'EOF'
[Unit]
Description=be-BOP Application Server
Documentation=https://github.com/be-BOP/be-BOP
After=network.target garage.service mongod.service
Wants=network.target garage.service mongod.service

[Service]
Type=simple
ExecStart=/usr/bin/pnpm run-production
Restart=always
RestartSec=5
TimeoutStartSec=60
TimeoutStopSec=30

# State directory for persistent data
StateDirectory=be-BOP/state
StateDirectoryMode=0755

# Working directory and environment
WorkingDirectory=/var/lib/be-BOP/releases/current
Environment=HOME=/var/lib/be-BOP/state
Environment=NODE_ENV=production
EnvironmentFile=/etc/be-BOP/config.env

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=be-BOP

# Resource limits
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    install_file "$TMPDIR/bebop.service" /etc/systemd/system/bebop.service
    run_privileged systemctl daemon-reload

    # Cleanup
    rm -rf "$TMPDIR"
}

configure_phoenixd_hardening_overrides() {
    log_info "Applying security hardening to phoenixd service..."

    local TMPDIR=$(mktemp -d)
    # shellcheck disable=SC2064  # TMPDIR should be expanded here (and not on trap).
    trap "rm -rf $TMPDIR" RETURN 2>/dev/null || true

    # Create security hardening override
    cat > "$TMPDIR/overrides.conf" << 'EOF'
[Service]
# Security hardening (VM/bare metal only)
DynamicUser=yes
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
EOF

    # Create override directory and install configuration
    run_privileged mkdir -p /etc/systemd/system/phoenixd.service.d
    install_file "$TMPDIR/overrides.conf" /etc/systemd/system/phoenixd.service.d/overrides.conf
    run_privileged systemctl daemon-reload

    # Cleanup
    rm -rf "$TMPDIR"
}

configure_garage_hardening_overrides() {
    log_info "Applying security hardening to Garage service..."

    local TMPDIR=$(mktemp -d)
    # shellcheck disable=SC2064  # TMPDIR should be expanded here (and not on trap).
    trap "rm -rf $TMPDIR" RETURN 2>/dev/null || true

    # Create security hardening override
    cat > "$TMPDIR/overrides.conf" << 'EOF'
[Service]
# Security hardening (VM/bare metal only)
# Note: DynamicUser is NOT used here because Garage reads /etc/garage.toml
# which must be root-owned with restricted permissions (640) to protect rpc_secret.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
EOF

    # Create override directory and install configuration
    run_privileged mkdir -p /etc/systemd/system/garage.service.d
    install_file "$TMPDIR/overrides.conf" /etc/systemd/system/garage.service.d/overrides.conf
    run_privileged systemctl daemon-reload

    # Cleanup
    rm -rf "$TMPDIR"
}

configure_bebop_hardening_overrides() {
    log_info "Applying security hardening to be-BOP service..."

    local TMPDIR=$(mktemp -d)
    # shellcheck disable=SC2064  # TMPDIR should be expanded here (and not on trap).
    trap "rm -rf $TMPDIR" RETURN 2>/dev/null || true

    # Create security hardening override
    cat > "$TMPDIR/overrides.conf" << 'EOF'
[Service]
# Security hardening (VM/bare metal only)
DynamicUser=yes
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictNamespaces=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
EOF

    # Create override directory and install configuration
    run_privileged mkdir -p /etc/systemd/system/bebop.service.d
    install_file "$TMPDIR/overrides.conf" /etc/systemd/system/bebop.service.d/overrides.conf
    run_privileged systemctl daemon-reload

    # Cleanup
    rm -rf "$TMPDIR"
}

enable_corepack() {
    log_info "Enabling corepack (and configure pnpm)..."
    run_privileged corepack enable
    run_privileged corepack prepare pnpm@latest --activate
}

start_and_enable_phoenixd() {
    log_info "Starting and enabling phoenixd service..."
    run_privileged systemctl daemon-reload
    run_privileged systemctl enable phoenixd
    run_privileged systemctl start phoenixd
}

start_and_enable_garage() {
    log_info "Starting and enabling Garage service..."
    run_privileged systemctl daemon-reload
    run_privileged systemctl enable garage
    run_privileged systemctl start garage
}

restart_garage() {
    log_info "Restarting Garage service..."
    run_privileged systemctl restart garage
}

start_and_enable_bebop() {
    log_info "Starting and enabling be-BOP service..."
    run_privileged systemctl enable bebop
    run_privileged systemctl start bebop
}

restart_bebop() {
    log_info "Restarting be-BOP service..."
    run_privileged systemctl restart bebop
}

task_await_bebop_ready() {
    log_info "Waiting for be-BOP service to be ready..."
    local domain="$(get_fact "specified_domain")"
    local retries="$SERVICE_TEST_START_RETRIES"
    local test_url curl_args=()

    # Configure URL and curl arguments based on domain
    if [[ "$domain" = "localhost" ]]; then
        test_url="http://localhost/.well-known/version.txt"
    else
        test_url="https://localhost/.well-known/version.txt"
        curl_args+=("-H" "Host: $domain" "-k")  # -k to ignore self-signed cert issues
    fi

    # Add common curl arguments
    curl_args+=(
        "--connect-timeout" "$CURL_CONNECT_TIMEOUT"
        "--max-time" "$CURL_DOWNLOAD_TIMEOUT"
        "--silent"
        "--show-error"
        "--location"  # Follow redirections
        "--write-out" "%{http_code}"
        "--output" "/dev/null"
    )

    while true; do
        local http_code
        if http_code="$(curl "${curl_args[@]}" "$test_url" 2>/dev/null)" && [[ "$http_code" = "200" ]]; then
            log_info "be-BOP service is ready and responding"
            return 0
        fi

        if [[ $retries -le 0 ]]; then
            die $EXIT_ERROR $LINENO "be-BOP service failed to become ready after $((SERVICE_TEST_START_RETRIES * SERVICE_TEST_START_WAIT_SECONDS)) seconds"
        fi

        log_debug "Waiting for be-BOP to be ready... ($retries retries left, HTTP code: ${http_code:-'connection failed'})"
        sleep "$SERVICE_TEST_START_WAIT_SECONDS"
        ((retries--))
    done
}

install_bebop_latest_release() {
    log_info "Installing latest be-BOP release..."
    run_bebop_cli release install --no-restart-after-install
}

show_phoenixd_information() {
    echo "=============================================="
    echo "IMPORTANT: phoenixd Lightning Network credentials"
    echo "=============================================="

    # Check if terminal supports colors
    if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && tput setaf 1 >/dev/null 2>&1; then
        echo -ne "\033[33m"  # Yellow color
        echo -e "⚠️  WARNING: Keep these credentials safe and do not share them with anyone!"
        echo -e "   Anyone with access to these credentials can control your Lightning funds."
        echo -ne "\033[0m"   # Reset color
    else
        echo "WARNING: Keep these credentials safe and do not share them with anyone!"
        echo "Anyone with access to these credentials can control your Lightning funds."
    fi

    echo ""

    local PHOENIXD_DATA_DIR="/var/lib/phoenixd/.phoenix"

    echo -n "phoenixd seed phrase: "
    run_privileged cat "$PHOENIXD_DATA_DIR/seed.dat" 2>/dev/null \
      || echo "(seed not found)"
    echo ""
    echo -n "phoenixd HTTP API password: "
    run_privileged grep -oP 'http-password=\K[^ ]+' "$PHOENIXD_DATA_DIR/phoenix.conf" 2>/dev/null \
      || echo "(http-password not found in $PHOENIXD_DATA_DIR/phoenix.conf)"
    echo ""
}

configure_bebop_cli_user() {
    log_info "Configuring be-BOP CLI system user..."

    if ! getent passwd be-bop-cli >/dev/null 2>&1; then
        log_info "Creating be-bop-cli system user..."
        run_privileged useradd --system --home-dir /var/lib/be-BOP \
            --create-home --shell /bin/false \
            --comment "be-BOP CLI system user" be-bop-cli
    else
        log_info "be-bop-cli user exists, checking configuration..."

        # Check and fix home directory if needed
        local current_home=$(getent passwd be-bop-cli | cut -d: -f6)
        if [[ "$current_home" != "/var/lib/be-BOP" ]]; then
            log_info "Fixing be-bop-cli user home directory (was: $current_home)..."
            run_privileged usermod --home /var/lib/be-BOP be-bop-cli

            # Create the home directory if it doesn't exist
            if [[ ! -d /var/lib/be-BOP ]]; then
                run_privileged mkdir -p /var/lib/be-BOP
            fi
        fi
    fi
}

setup_bebop_directory_permissions() {
    log_info "Setting up be-BOP directory permissions..."

    # Ensure /var/lib/be-BOP exists
    if [[ ! -d /var/lib/be-BOP ]]; then
        run_privileged mkdir -p /var/lib/be-BOP
    fi

    # Set ownership to be-bop-cli user and group
    run_privileged chown be-bop-cli:be-bop-cli /var/lib/be-BOP

    # Set permissions: owner can read/write/execute, group and others can read/execute
    run_privileged chmod 755 /var/lib/be-BOP

    # Ensure subdirectories have correct ownership (recursively)
    # This handles any existing subdirectories that might have wrong ownership
    if [[ -n "$(find /var/lib/be-BOP -not -user be-bop-cli -o -not -group be-bop-cli)" ]]; then
        log_info "Fixing ownership of existing subdirectories in /var/lib/be-BOP..."
        run_privileged chown -R be-bop-cli:be-bop-cli /var/lib/be-BOP
    fi
}

# ---[ 7. Summarize the outcome ]---
# After all tasks finish, report which parts of the setup succeeded,
# which are running, and where to look if something went wrong.
# Think of it as the "mission debrief" — a clear final status for operators.
summarize_results() {
    local domain
    log_info "Installation completed successfully!"
    echo ""
    echo "=========================================="
    echo "be-BOP Installation Complete!"
    echo "=========================================="
    if domain="$(get_fact "specified_domain")"; then
        echo "Your be-BOP instance should be accessible at: https://$domain"
    fi
    echo ""

    if [[ "${TASK_PLAN[*]}" =~ "install_phoenixd" ]] || [[ "${TASK_PLAN[*]}" =~ "install_phoenixd_service" ]]; then
        show_phoenixd_information
    fi
}

# ---[ Entry point ]---
# Orchestrates the full process in the same order described at the top:
#   1. Inspect the system and collect facts.
#   2. Plan which setup tasks are required.
#   3. Identify all tools needed for those tasks.
#   4. Prepare the toolbox by installing any missing tools.
#   5. Use human-readable descriptions for progress reporting.
#   6. Execute the plan safely and in order.
#   7. Summarize the overall results once complete.
#
# This top-level flow ties everything together into a readable, maintainable
# automation pipeline that anyone can follow step by step.
main() {
    parse_cli_arguments "$@"
    log_info "Starting $SCRIPT_NAME v$SCRIPT_VERSION (session: $SESSION_ID)"
    check_privileges

    # Detect environment and inspect system state
    inspect_system_state
    plan_setup_tasks
    collect_all_required_tools
    check_os_supported_by_wizard

    summarize_state_and_plan

    if [[ ${#TASK_PLAN[@]} -eq 0 ]]; then
        log_info "Nothing to do. Exiting."
        exit $EXIT_SUCCESS
    fi

    check_options_required_by_planned_tasks_but_missing
    check_cpu_features_required_by_planned_tasks

    if [ "$DRY_RUN" = true ]; then
        log_info "Exit before making any changes (--dry-run specified)."
        exit $EXIT_SUCCESS
    fi

    prompt_user_confirmation

    log_info "Beginning installation..."
    prepare_toolbox
    execute_task_plan

    summarize_results
}

# Execute main function with all arguments
main "$@"
