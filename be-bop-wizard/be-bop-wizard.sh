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

readonly SCRIPT_VERSION="2.0.0"
readonly SCRIPT_NAME="be-bop-wizard"
readonly SESSION_ID="wizard-$(date +%s)-$$"

# GitHub repository for be-BOP releases (can be overridden for development)
readonly BEBOP_GITHUB_REPO="${BEBOP_GITHUB_REPO:-be-BOP-io-SA/be-BOP}"

# Exit codes
readonly EXIT_SUCCESS=0
readonly EXIT_ERROR=1
readonly EXIT_FATAL=2

# Error trap handler
handle_error() {
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
    echo "If you’d like to investigate or get help:"
    echo "  1. Re-run with --verbose to get detailed output:"
    if [[ -n "${DOMAIN:-}" && -n "${EMAIL:-}" ]]; then
        local rerun_cmd="$(basename "${0:-be-bop-wizard}") --domain $DOMAIN --email $EMAIL"
        [[ "$ALLOW_ROOT" = true ]] && rerun_cmd="$rerun_cmd --allow-root"
        [[ "$RUN_NON_INTERACTIVE" = true ]] && rerun_cmd="$rerun_cmd --non-interactive"
        [[ "$DRY_RUN" = true ]] && rerun_cmd="$rerun_cmd --dry-run"
        echo "     $rerun_cmd --verbose"
    else
        echo "     $(basename "${0:-be-bop-wizard}") --domain <your-domain> --email <your-email> --verbose"
    fi
    echo ""
    echo "  2. Share the verbose output when requesting support"
    echo ""

    exit $exit_code
}

# Set up error trap
trap 'handle_error $LINENO' ERR

# Global configuration
ALLOW_ROOT=false
DOMAIN=""
DRY_RUN=false
EMAIL=""
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
    shift
    log_error "$@"
    exit "$exit_code"
}

# Sudo wrapper for consistent privilege handling
run_privileged() {
    if [[ "$RUNNING_AS_ROOT" = true ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

# ucf wrapper for consistent file management
ucf_install() {
    # If the file does not exist and, purge it from the ucf database in case
    # the user removed it.
    if [[ ! -f "$2" && -f /var/lib/ucf/hashfile ]]; then
        run_privileged ucf --purge "$2" || true
    fi
    run_privileged ucf "$1" "$2"
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

REQUIRED OPTIONS:
    --domain <FQDN>         Domain name for be-BOP installation
    --email <address>       Contact email for Let's Encrypt registration

OPTIONS:
    --allow-root            Allow running as root (not recommended)
    --dry-run               Do not make any changes, print what would be done
    --help, -h              Show this help message
    --non-interactive       Do not prompt for confirmations (for automation)
    --verbose, -v           Enable detailed logging output

EXAMPLES:
    # Interactive installation
    $SCRIPT_NAME --domain example.com --email admin@example.com

    # Non-interactive installation
    $SCRIPT_NAME --domain example.com --email admin@example.com --non-interactive

For more information, visit: https://github.com/be-BOP-io-SA/be-BOP
EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --allow-root)
                ALLOW_ROOT=true
                shift
                ;;
            --domain)
                DOMAIN="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --email)
                EMAIL="$2"
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
            --verbose|-v)
                VERBOSE=true
                shift
                ;;
            *)
                die $EXIT_ERROR "Unknown option: $1. Use --help for usage information."
                ;;
        esac
    done

    # Validate required arguments
    if [[ -z "$DOMAIN" ]]; then
        die $EXIT_ERROR "Domain is required. Use --domain <FQDN>"
    fi

    if [[ -z "$EMAIL" ]]; then
        die $EXIT_ERROR "Email is required. Use --email <address>"
    fi

    # Basic domain validation
    {
        if ! echo "$DOMAIN" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$'; then
            if [[ "$DOMAIN" != "localhost" ]]; then
                die $EXIT_ERROR "Invalid domain format: $DOMAIN"
            fi
        fi
        if [[ ${#DOMAIN} -gt 253 ]]; then
            die $EXIT_ERROR "Domain too long (max 253 chars): $DOMAIN"
        fi
        IFS='.' read -ra LABELS <<< "$DOMAIN"
        for label in "${LABELS[@]}"; do
            if [[ ${#label} -gt 63 ]]; then
                die $EXIT_ERROR "Domain label too long (max 63 chars): $label"
            fi
        done
    }

    # Basic email validation
    if ! echo "$EMAIL" | grep -qE '^[^@]+@[^@]+\.[^@]+$'; then
        die $EXIT_ERROR "Invalid email format: $EMAIL"
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
                    die $EXIT_ERROR "Operation aborted."
                fi
                export RUNNING_AS_ROOT=true
            else
                log_warn "Running as root is not recommended."
                log_warn "If you must run as root, use --allow-root flag."
                die $EXIT_ERROR "Use --allow-root if you really need to run as root, or run as a regular user."
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
                die $EXIT_ERROR "sudo access is required. Please ensure your user has sudo privileges."
            fi
        fi
    fi
}

# Environment detection
detect_environment() {
    log_info "Detecting system environment..."

    # Check OS
    if [[ ! -f /etc/os-release ]]; then
        die $EXIT_FATAL "/etc/os-release not found. Unsupported system."
    fi

    source /etc/os-release
    log_debug "Detected OS: $PRETTY_NAME"

    # Check if Debian-based
    if [[ "$ID" != "debian" && "$ID" != "ubuntu" ]]; then
        die $EXIT_FATAL "Unsupported OS: $ID. This script requires Debian or Ubuntu."
    fi

    # Check package manager
    if ! command -v apt >/dev/null 2>&1; then
        die $EXIT_FATAL "apt package manager not found. This script requires Debian/Ubuntu with apt."
    fi

    # Check systemd available
    if ! command -v systemctl &>/dev/null; then
        die $EXIT_FATAL "systemd not found. This script requires systemd."
    fi

    # Detect container environment
    local container_type="none"
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        container_type=$(systemd-detect-virt --container 2>/dev/null || true)
    fi

    log_info "Environment: $PRETTY_NAME"
    log_info "Container: $container_type"

    # Store environment info in global variables for later use
    export DETECTED_OS="$ID"
    export DETECTED_VERSION="$VERSION_CODENAME"
    export DETECTED_CONTAINER="$container_type"
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

    # Check if running in container
    if [[ "$DETECTED_CONTAINER" != "none" ]]; then
        SYSTEM_STATE+=("running_in_container")
    fi

    # Check what tools are available
    export AVAILABLE_TOOLS=()
    local potential_commands=("curl" "gpg" "jq" "openssl" "stow" "unzip")
    for cmd in "${potential_commands[@]}"; do
        if command -v "$cmd" >/dev/null 2>&1; then
            AVAILABLE_TOOLS+=("$cmd")
        fi
    done
    local potential_packages=("certbot" "nginx" "python3-certbot-nginx" "ssl-cert")
    for pkg in "${potential_packages[@]}"; do
        if dpkg -s "$pkg" >/dev/null 2>&1; then
            AVAILABLE_TOOLS+=("$pkg")
        fi
    done

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

    if command -v pnpm >/dev/null 2>&1; then
        SYSTEM_STATE+=("pnpm_available")
    fi

    if [[ -f /etc/apt/sources.list.d/mongodb-org-8.0.list ]]; then
        SYSTEM_STATE+=("mongodb_repo_configured")
    fi

    if dpkg -s mongodb-org >/dev/null 2>&1; then
        SYSTEM_STATE+=("mongodb_installed")
    fi

    if systemctl is-active --quiet mongod 2>/dev/null; then
        SYSTEM_STATE+=("mongodb_running")
    fi

    if command -v mongosh >/dev/null && mongosh --quiet --eval "rs.status().ok" 2>/dev/null | grep -q "1"; then
        SYSTEM_STATE+=("mongodb_rs_initialized")
    fi

    if command -v nginx >/dev/null 2>&1; then
        SYSTEM_STATE+=("nginx_installed")
    fi

    if systemctl is-active --quiet nginx 2>/dev/null; then
        SYSTEM_STATE+=("nginx_running")
    fi

    # Check SSL certificate availability (check package instead of private key due to permissions)
    if dpkg -s ssl-cert >/dev/null 2>&1 && [[ -f /etc/ssl/certs/ssl-cert-snakeoil.pem ]]; then
        SYSTEM_STATE+=("snakeoil_cert_available")
    fi

    if [[ -L /etc/nginx/sites-enabled/be-BOP.conf ]] || [[ -f /etc/nginx/sites-enabled/be-BOP.conf ]]; then
        SYSTEM_STATE+=("bebop_site_enabled")

        # Check if nginx site is correctly configured for this domain
        if validate_bebop_nginx_config_domains; then
            SYSTEM_STATE+=("bebop_site_correctly_configured")
        fi

        # Check if be-BOP site is actually responding via HTTP/HTTPS
        if has_fact "nginx_running" && has_fact "bebop_site_enabled"; then
            local test_url
            local curl_args=("--silent" "--output" "/dev/null" "--write-out" "%{http_code}")

            if [[ "$DOMAIN" = "localhost" ]]; then
                test_url="http://localhost/"
            else
                test_url="https://localhost/"
                curl_args+=("-H" "Host: $DOMAIN" "-k")  # -k to ignore self-signed cert issues
            fi

            # Test if the site responds (allow up to 5 seconds)
            if command -v curl >/dev/null 2>&1; then
                local response_code=$(curl "${curl_args[@]}" --connect-timeout 5 "$test_url" 2>/dev/null || echo "000")
                # Accept any 2xx, 3xx, 4xx response (shows nginx is routing correctly)
                if [[ "$response_code" =~ ^[234][0-9][0-9]$ ]]; then
                    SYSTEM_STATE+=("bebop_site_running")
                fi
            fi
        fi
    fi

    if command -v certbot >/dev/null 2>&1; then
        SYSTEM_STATE+=("certbot_installed")
    fi

    if systemctl is-active --quiet minio 2>/dev/null; then
        SYSTEM_STATE+=("minio_running")
    fi

    # Check if MinIO is available but service not running (try HTTP check as fallback)
    if ! has_fact "minio_running" && command -v curl >/dev/null 2>&1; then
        # Check if MinIO is responding via HTTP (even if systemctl doesn't show it as active)
        local minio_response=$(curl --silent --fail --output /dev/null --write-out "%{http_code}" --connect-timeout 5 "http://localhost:9000/minio/health/live" 2>/dev/null || echo "000")
        if [[ "$minio_response" =~ ^[234][0-9][0-9]$ ]]; then
            SYSTEM_STATE+=("minio_running")
        fi
    fi

    if systemctl is-active --quiet bebop 2>/dev/null; then
        SYSTEM_STATE+=("bebop_running")
    fi

    if [[ -L /var/lib/be-BOP/releases/current ]]; then
        installed_release="$(basename "$(readlink -f /var/lib/be-BOP/releases/current)")"
        if [[ "$installed_release" = "${LATEST_RELEASE_ASSET_BASENAME:-}" ]]; then
            if [[ -f "/var/lib/be-BOP/releases/$installed_release/.bebop_install_success" ]]; then
                SYSTEM_STATE+=("bebop_latest_release_installed")
            fi
        fi
    fi

    if [[ -f /usr/local/bin/phoenixd ]]; then
        SYSTEM_STATE+=("phoenixd_installed")
    fi

    if [[ -f /usr/local/bin/minio ]]; then
        SYSTEM_STATE+=("minio_installed")
    fi

    if systemctl is-active --quiet phoenixd 2>/dev/null; then
        SYSTEM_STATE+=("phoenixd_running")
    fi

    if [[ -f /etc/minio/config.env ]]; then
        SYSTEM_STATE+=("minio_config_exists")
        if validate_minio_config_domain; then
            SYSTEM_STATE+=("minio_correctly_configured")
        fi
    fi

    if [[ -f /etc/be-BOP/config.env ]]; then
        SYSTEM_STATE+=("bebop_config_exists")
        if validate_bebop_config_domain; then
            SYSTEM_STATE+=("bebop_correctly_configured")
        fi
    fi

    if [[ -f /etc/systemd/system/bebop.service ]]; then
        SYSTEM_STATE+=("bebop_service_exists")
    fi

    if [[ -f /etc/systemd/system/phoenixd.service.d/overrides.conf ]]; then
        SYSTEM_STATE+=("phoenixd_overrides_exist")
    fi

    if [[ -f /etc/systemd/system/minio.service.d/overrides.conf ]]; then
        SYSTEM_STATE+=("minio_overrides_exist")
    fi

    if [[ -f /etc/systemd/system/bebop.service.d/overrides.conf ]]; then
        SYSTEM_STATE+=("bebop_overrides_exist")
    fi

    log_debug "Available tools: ${AVAILABLE_TOOLS[*]}"
    log_debug "System state: ${SYSTEM_STATE[*]}"
    log_debug "System state check complete"
}

validate_bebop_nginx_config_domains() {
    if [[ ! -f /etc/nginx/sites-available/be-BOP.conf ]]; then
        return 1
    fi

    local expected_domains
    if [[ "$DOMAIN" = "localhost" ]]; then
        expected_domains="localhost s3.localhost"
    else
        expected_domains="$DOMAIN s3.$DOMAIN"
    fi

    for expected_domain in $expected_domains; do
        if ! grep -qE "server_name[[:space:]]+[^;]*\b$expected_domain\b" /etc/nginx/sites-available/be-BOP.conf 2>/dev/null; then
            log_debug "nginx config missing domain: $expected_domain"
            return 1
        fi
    done

    return 0
}

validate_minio_config_domain() {
    if [[ ! -f /etc/minio/config.env ]]; then
        return 1
    fi

    local expected_url
    if [[ "$DOMAIN" = "localhost" ]]; then
        expected_url="http://s3.localhost"
    else
        expected_url="https://s3.$DOMAIN"
    fi

    if ! grep -q "^MINIO_SERVER_URL=$expected_url$" /etc/minio/config.env 2>/dev/null; then
        log_debug "MinIO config has incorrect server URL (expected: $expected_url)"
        return 1
    fi

    return 0
}

validate_bebop_config_domain() {
    if [[ ! -f /etc/be-BOP/config.env ]]; then
        return 1
    fi

    local expected_origin expected_s3_url
    if [[ "$DOMAIN" = "localhost" ]]; then
        expected_origin="http://localhost"
        expected_s3_url="http://s3.localhost"
    else
        expected_origin="https://$DOMAIN"
        expected_s3_url="https://s3.$DOMAIN"
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
        if [[ "$existing_fact" = "$fact" ]]; then
            return 0
        fi
    done
    return 1
}

# This function retrieves the latest be-BOP release metadata
# This function should export the following variables:
#   - LATEST_RELEASE_META: The latest be-BOP release metadata
#   - LATEST_RELEASE_ASSET_BASENAME: The basename of the latest be-BOP release asset
#
# If we're unable to retrieve the release information, LATEST_RELEASE_META
# will be empty and LATEST_RELEASE_ASSET_BASENAME unset. This can happen if
# `jq` is not installed or we're unable to obtain the data from GitHub.
determine_latest_release_meta() {
    if ! command -v jq > /dev/null; then
        log_debug "Could not fetch latest be-BOP release metadata since jq is not installed"
        export LATEST_RELEASE_META=""
        return 0
    fi
    log_info "📡 Fetching latest be-BOP release metadata..."
    local url="https://api.github.com/repos/${BEBOP_GITHUB_REPO}/releases/latest"
    export LATEST_RELEASE_META="$(curl --connect-timeout 5 --silent --fail "$url" 2>/dev/null || true)"
    log_debug "Latest release metadata: $(echo "$LATEST_RELEASE_META" | jq -c .)"
    local filter='
        .assets[]
        | select(.name | test("be-BOP\\.release\\.[0-9]{4}-[0-9]{2}-[0-9]{2}\\.[a-f0-9]+.*\\.zip"))
        | .name
        | sub("\\.zip$"; "")
    '
    if [[ -n "$LATEST_RELEASE_META" ]]; then
        export LATEST_RELEASE_ASSET_BASENAME=$(echo "$LATEST_RELEASE_META" | jq -r "$filter" | head -n 1)
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

    # Smart cascading logic for Node.js
    if ! has_fact "nodejs_available"; then
        # Only configure repo if Node.js is not already installed
        if ! has_fact "nodejs_repo_configured"; then
            TASK_PLAN+=("configure_nodejs_repo")
        fi
        TASK_PLAN+=("install_nodejs")
    fi

    # Install pnpm (requires Node.js to be available)
    if ! has_fact "pnpm_available"; then
        TASK_PLAN+=("install_pnpm")
    fi

    if ! has_fact "minio_installed"; then
        TASK_PLAN+=("install_minio")
    fi

    # Configure MinIO (needed for be-BOP config)
    if ! has_fact "minio_config_exists" || ! has_fact "minio_correctly_configured"; then
        TASK_PLAN+=("write_minio_configuration")
        if has_fact "minio_running"; then
            TASK_PLAN+=("restart_minio")
        fi
    fi

    if ! has_fact "minio_running"; then
        TASK_PLAN+=("install_minio_service")
        if ! has_fact "running_in_container" && ! has_fact "minio_overrides_exist"; then
            TASK_PLAN+=("configure_minio_hardening_overrides")
        fi
        TASK_PLAN+=("start_and_enable_minio")
    fi

    # Generate be-BOP configuration (needs MinIO credentials)
    if ! has_fact "bebop_config_exists" || ! has_fact "bebop_correctly_configured"; then
        TASK_PLAN+=("write_bebop_configuration")
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
    if ! has_fact "bebop_site_running" || ! has_fact "bebop_site_correctly_configured"; then
        TASK_PLAN+=("configure_bebop_site")

        if ! has_fact "nginx_running"; then
            TASK_PLAN+=("start_and_enable_nginx")
        else
            TASK_PLAN+=("reload_nginx")
        fi

        if [[ "$DOMAIN" != "localhost" ]]; then
            TASK_PLAN+=("provision_ssl_cert")
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

    if ! has_fact "bebop_service_exists"; then
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

    if ! has_fact "bebop_running"; then
        TASK_PLAN+=("start_and_enable_bebop")
    fi

    log_debug "Planned actions: ${TASK_PLAN[*]}"
}

list_tools_for_task() {
    case "$1" in
        "configure_bebop_site") echo "curl nginx ssl-cert" ;;
        "configure_mongodb_repo") echo "curl gpg" ;;
        "configure_nodejs_repo") echo "curl gpg" ;;
        "install_bebop_latest_release") echo "curl jq unzip" ;;
        "install_minio") echo "curl stow" ;;
        "install_phoenixd") echo "curl unzip stow" ;;
        "provision_ssl_cert") echo "certbot python3-certbot-nginx" ;;
        "write_minio_configuration") echo "openssl" ;;
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
        if has_fact "nginx_running" && has_fact "bebop_site_running" && has_fact "bebop_site_correctly_configured"; then
            echo "✓ running with be-BOP site correctly configured for $DOMAIN"
        elif has_fact "nginx_running" && has_fact "bebop_site_running" && has_fact "bebop_site_enabled"; then
            echo "⚠ running but site configured for different domain (needs reconfiguration)"
        elif has_fact "nginx_running" && has_fact "bebop_site_enabled"; then
            echo "⚠ running but be-BOP site not responding"
        elif has_fact "nginx_running"; then
            echo "⚠ running but be-BOP site not configured"
        elif has_fact "nginx_installed"; then
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

    minio_state() {
        if has_fact "minio_running" && has_fact "minio_correctly_configured"; then
            echo "✓ running and correctly configured for s3.$DOMAIN"
        elif has_fact "minio_running" && has_fact "minio_config_exists"; then
            echo "⚠ running but configured for different domain (needs reconfiguration)"
        elif has_fact "minio_running"; then
            echo "⚠ running but not configured"
        elif has_fact "minio_installed"; then
            echo "⚠ installed but not running"
        else
            echo "✗ missing"
        fi
    }

    bebop_state() {
        if has_fact "bebop_running" && has_fact "bebop_correctly_configured"; then
            if has_fact "bebop_latest_release_installed"; then
                echo "✓ running, up-to-date and correctly configured for $DOMAIN"
            elif [[ -z $LATEST_RELEASE_META ]]; then
                echo "⚠ failed to fetch latest release information"
            else
                echo "⚠ running and configured for $DOMAIN but a new release is available"
            fi
        elif has_fact "bebop_running" && has_fact "bebop_config_exists"; then
            echo "⚠ running but configured for different domain (needs reconfiguration)"
        elif has_fact "bebop_running"; then
            echo "⚠ running but not configured"
        elif has_fact "bebop_config_exists" && has_fact "bebop_service_exists"; then
            echo "⚠ service configured but not running"
        else
            echo "✗ missing"
        fi
    }

    nodejs_state() {
        if has_fact "nodejs_available" && has_fact "pnpm_available"; then
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
        if [[ "$DOMAIN" = "localhost" ]]; then
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
    echo "Domain: $DOMAIN"
    echo "Email: $EMAIL"
    echo "Environment: $DETECTED_OS $DETECTED_VERSION"
    echo ""

    echo "Current system status:"
    echo "  • Node.js: $(nodejs_state)"
    echo "  • MongoDB: $(mongodb_state)"
    echo "  • nginx: $(nginx_state)"
    echo "  • SSL certificate: $(ssl_state)"
    echo "  • phoenixd: $(phoenixd_state)"
    echo "  • MinIO: $(minio_state)"
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
        "configure_bebop_hardening_overrides") echo "Apply security hardening to be-BOP service" ;;
        "configure_bebop_site") echo "Configure be-BOP nginx site for $DOMAIN" ;;
        "configure_minio_hardening_overrides") echo "Apply security hardening to MinIO service" ;;
        "configure_mongodb_repo") echo "Configure MongoDB 8.0 repository" ;;
        "configure_nodejs_repo") echo "Configure Node.js 22 repository" ;;
        "configure_phoenixd_hardening_overrides") echo "Apply security hardening to phoenixd service" ;;
        "initialize_mongodb_rs") echo "Initialize MongoDB replica set" ;;
        "install_bebop_latest_release") echo "Install latest be-BOP release" ;;
        "install_bebop_service") echo "Install be-BOP systemd service" ;;
        "install_minio") echo "Install MinIO object storage server" ;;
        "install_minio_service") echo "Install MinIO systemd service" ;;
        "install_mongodb") echo "Install MongoDB" ;;
        "install_nodejs") echo "Install Node.js" ;;
        "install_phoenixd") echo "Install phoenixd Lightning Network daemon" ;;
        "install_phoenixd_service") echo "Install phoenixd systemd service" ;;
        "install_pnpm") echo "Install pnpm package manager" ;;
        "provision_ssl_cert") echo "Provision SSL certificate with Let's Encrypt" ;;
        "reload_nginx") echo "Reload nginx configuration" ;;
        "restart_bebop") echo "Restart be-BOP service" ;;
        "restart_minio") echo "Restart MinIO service" ;;
        "start_and_enable_bebop") echo "Start and enable be-BOP service" ;;
        "start_and_enable_minio") echo "Start and enable MinIO service" ;;
        "start_and_enable_mongodb") echo "Start and enable MongoDB service" ;;
        "start_and_enable_nginx") echo "Start and enable nginx service" ;;
        "start_and_enable_phoenixd") echo "Start and enable phoenixd service" ;;
        "write_bebop_configuration") echo "Generate be-BOP environment configuration for $DOMAIN" ;;
        "write_minio_configuration") echo "Configure MinIO with generated credentials for $DOMAIN" ;;
        *) echo "Unknown action: $1" ;;
    esac
}

# ---[ 6. Run the tasks ]---
# Go through the planned tasks one by one and execute them.
# Each task is handled by a specific function that knows how to do that job
# (like installing MongoDB or configuring Nginx).
# This is where the script actually changes the system to match the plan.
run_task() {
    case "$1" in
        "configure_bebop_hardening_overrides") configure_bebop_hardening_overrides ;;
        "configure_bebop_site") configure_bebop_site ;;
        "configure_minio_hardening_overrides") configure_minio_hardening_overrides ;;
        "configure_mongodb_repo") configure_mongodb_repo ;;
        "configure_nodejs_repo") configure_nodejs_repo ;;
        "configure_phoenixd_hardening_overrides") configure_phoenixd_hardening_overrides ;;
        "initialize_mongodb_rs") initialize_mongodb_rs ;;
        "install_bebop_latest_release") install_bebop_latest_release ;;
        "install_bebop_service") install_bebop_service ;;
        "install_minio") install_minio ;;
        "install_minio_service") install_minio_service ;;
        "install_mongodb") install_mongodb ;;
        "install_nodejs") install_nodejs ;;
        "install_phoenixd") install_phoenixd ;;
        "install_phoenixd_service") install_phoenixd_service ;;
        "install_pnpm") install_pnpm ;;
        "provision_ssl_cert") provision_ssl_cert ;;
        "reload_nginx") reload_nginx ;;
        "restart_bebop") restart_bebop ;;
        "restart_minio") restart_minio ;;
        "start_and_enable_bebop") start_and_enable_bebop ;;
        "start_and_enable_minio") start_and_enable_minio ;;
        "start_and_enable_mongodb") start_and_enable_mongodb ;;
        "start_and_enable_nginx") start_and_enable_nginx ;;
        "start_and_enable_phoenixd") start_and_enable_phoenixd ;;
        "write_bebop_configuration") write_bebop_configuration ;;
        "write_minio_configuration") write_minio_configuration ;;
        *) die $EXIT_ERROR "Unknown action: $1" ;;
    esac
}

configure_nodejs_repo() {
    log_info "Configuring Node.js repository..."

    local NODE_MAJOR=22
    local TMPDIR=$(mktemp -d)
    # shellcheck disable=SC2064  # TMPDIR should be expanded here (and not on trap).
    trap "rm -rf $TMPDIR" RETURN 2>/dev/null || true

    # Download and add NodeSource GPG key
    curl --connect-timeout 5 -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | \
        gpg --batch --yes --output "$TMPDIR/nodesource.gpg" --dearmor

    # Create repository configuration
    cat > "$TMPDIR/nodesource.list" << EOF
# This file is managed by be-bop-wizard
deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main
EOF

    # Create package preferences
    cat > "$TMPDIR/nodejs" << EOF
Package: nodejs
Pin: origin deb.nodesource.com
Pin-Priority: 600
EOF

    # Install configuration files using ucf
    ucf_install "$TMPDIR/nodesource.gpg" /usr/share/keyrings/nodesource.gpg
    ucf_install "$TMPDIR/nodesource.list" /etc/apt/sources.list.d/nodesource.list
    ucf_install "$TMPDIR/nodejs" /etc/apt/preferences.d/nodejs

    # Cleanup
    rm -rf "$TMPDIR"
    update_package_lists
}

configure_mongodb_repo() {
    log_info "Configuring MongoDB repository..."

    if [[ ! -f /etc/os-release ]]; then
        die $EXIT_FATAL "Cannot determine OS version"
    fi

    source /etc/os-release
    local RELEASE="$VERSION_CODENAME"
    local DISTRIBUTION="$ID"

    # Determine archive component
    case "$DISTRIBUTION" in
        ubuntu)
            local ARCHIVE="multiverse"
            ;;
        debian)
            local ARCHIVE="main"
            ;;
        *)
            die $EXIT_FATAL "Unsupported distribution: ${DISTRIBUTION}"
            ;;
    esac

    # Validate supported releases
    case "$DISTRIBUTION-$RELEASE" in
        ubuntu-noble|ubuntu-jammy|ubuntu-focal|debian-bookworm)
            ;;
        *)
            die $EXIT_FATAL "Unsupported release: ${DISTRIBUTION} ${RELEASE}"
            ;;
    esac

    local TMPDIR=$(mktemp -d)
    # shellcheck disable=SC2064  # TMPDIR should be expanded here (and not on trap).
    trap "rm -rf $TMPDIR" RETURN 2>/dev/null || true

    # Download and add MongoDB GPG key
    curl --connect-timeout 5 -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | \
        gpg --batch --yes --output "$TMPDIR/mongodb-server-8.0.gpg" --dearmor

    # Create repository configuration
    cat > "$TMPDIR/mongodb-org-8.0.list" << EOF
# This file is managed by be-bop-wizard
deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg] https://repo.mongodb.org/apt/${DISTRIBUTION} ${RELEASE}/mongodb-org/8.0 ${ARCHIVE}
EOF

    # Install configuration files using ucf
    ucf_install "$TMPDIR/mongodb-server-8.0.gpg" /usr/share/keyrings/mongodb-server-8.0.gpg
    ucf_install "$TMPDIR/mongodb-org-8.0.list" /etc/apt/sources.list.d/mongodb-org-8.0.list

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
    # Configure replica set in mongod.conf
    run_privileged sed -i '/^#\?replication:/,/^[^ ]/c replication:\n  replSetName: "rs0"' /etc/mongod.conf
    run_privileged systemctl enable mongod
    run_privileged systemctl start mongod
}

initialize_mongodb_rs() {
    log_info "Initializing MongoDB replica set..."
    # Wait for MongoDB to be ready
    local retries=10
    while ! mongosh --quiet --eval "db.adminCommand('ping')" >/dev/null 2>&1; do
        if [[ $retries -le 0 ]]; then
            die $EXIT_ERROR "MongoDB failed to start after 30 seconds"
        fi
        log_debug "Waiting for MongoDB to be ready... ($retries retries left)"
        sleep 3
        ((retries--))
    done

    # Initialize replica set (ignore error if already initialized)
    mongosh --eval 'rs.initiate()' >/dev/null 2>&1 || true

    # Restart to ensure replica set configuration is fully applied
    run_privileged systemctl restart mongod

    # Wait again after restart
    retries=10
    while ! mongosh --quiet --eval "db.adminCommand('ping')" >/dev/null 2>&1; do
        if [[ $retries -le 0 ]]; then
            die $EXIT_ERROR "MongoDB failed to restart after replica set initialization"
        fi
        log_debug "Waiting for MongoDB to be ready after restart... ($retries retries left)"
        sleep 3
        ((retries--))
    done
}

configure_bebop_site() {
    log_info "Configuring be-BOP nginx site..."

    # Remove nginx default site
    run_privileged rm -f /etc/nginx/sites-enabled/default

    local TMPDIR=$(mktemp -d)
    # shellcheck disable=SC2064  # TMPDIR should be expanded here (and not on trap).
    trap "rm -rf $TMPDIR" RETURN 2>/dev/null || true

    if [[ "$DOMAIN" = "localhost" ]]; then
        # Localhost configuration (HTTP only)
        cat > "$TMPDIR/be-BOP.conf" << 'EOF'
# The sites in this file are managed by be-bop-wizard
server {
    listen 80;
    listen [::]:80;
    server_name localhost;

    proxy_set_header "Connection" "";

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
        proxy_pass http://localhost:9000;
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
        sed "s/example.com/${DOMAIN}/g" > "$TMPDIR/be-BOP.conf" << 'EOF'
# The sites in this file are managed by be-bop-wizard

server {
    listen 80;
    listen [::]:80;
    server_name example.com s3.example.com;

    location / {
        return 307 https://$host$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name example.com;

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
    server_name s3.example.com;

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
        proxy_pass http://localhost:9000;
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
    fi

    # Install configuration using ucf
    ucf_install "$TMPDIR/be-BOP.conf" /etc/nginx/sites-available/be-BOP.conf
    run_privileged ln -sf /etc/nginx/sites-available/be-BOP.conf /etc/nginx/sites-enabled/

    # Test nginx configuration
    if ! run_privileged nginx -t; then
        die $EXIT_ERROR "nginx configuration test failed"
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
    run_privileged certbot --nginx -d "${DOMAIN}" -d "s3.${DOMAIN}" --non-interactive --agree-tos --email "${EMAIL}"
}

install_phoenixd() {
    log_info "Installing phoenixd Lightning Network daemon..."

    local PHOENIXD_VERSION="0.6.2"
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
        local PHOENIXD_URL="https://github.com/ACINQ/phoenixd/releases/download/v${PHOENIXD_VERSION}/phoenixd-${PHOENIXD_VERSION}-linux-x64.zip"
        log_info "Downloading phoenixd ${PHOENIXD_VERSION} from ${PHOENIXD_URL}"
        curl --connect-timeout 5 -fSL# "$PHOENIXD_URL" -o phoenixd.zip -m 300
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

install_minio() {
    log_info "Installing MinIO object storage server..."

    local MINIO_VERSION="RELEASE.2025-09-07T16-13-09Z"
    local STOW_DIR="/usr/local/minio"
    local PACKAGE_DIR="$STOW_DIR/minio-${MINIO_VERSION}"

    # Check if the version directory already exists
    if [[ -d "$PACKAGE_DIR" ]]; then
        log_info "MinIO ${MINIO_VERSION} already installed in stow directory"
    else
        # Create temporary directory for download
        local TEMP_DIR=$(mktemp -d)
        # shellcheck disable=SC2064  # TEMP_DIR should be expanded here (and not on trap).
        trap "rm -rf $TEMP_DIR" RETURN 2>/dev/null || true
        pushd "$TEMP_DIR" > /dev/null

        # Download MinIO binary
        local MINIO_URL="https://dl.min.io/server/minio/release/linux-amd64/archive/minio.${MINIO_VERSION}"
        log_info "Downloading MinIO ${MINIO_VERSION} from ${MINIO_URL}"
        curl --connect-timeout 5 -fSL# "$MINIO_URL" -o minio -m 300

        # Create stow directory structure
        run_privileged mkdir -p "$PACKAGE_DIR/bin"

        # Install MinIO binary to stow package directory
        run_privileged cp minio "$PACKAGE_DIR/bin/"
        run_privileged chmod +x "$PACKAGE_DIR/bin/minio"

        popd > /dev/null
        rm -rf "$TEMP_DIR"
    fi

    # Use stow to symlink the binary
    pushd "$STOW_DIR" > /dev/null
    run_privileged stow "minio-${MINIO_VERSION}"
    popd > /dev/null
    log_info "MinIO ${MINIO_VERSION} installed using stow"
}

write_minio_configuration() {
    log_info "Configuring MinIO with generated credentials..."

    local TMPDIR=$(mktemp -d)
    # shellcheck disable=SC2064  # TMPDIR should be expanded here (and not on trap).
    trap "rm -rf $TMPDIR" RETURN 2>/dev/null || true

    # Generate MinIO configuration
    if [[ -f /etc/minio/config.env ]]; then
        log_debug "Patching domain in existing MinIO configuration"
        cp /etc/minio/config.env "$TMPDIR/config.env"
        sed -i "s|^MINIO_SERVER_URL=.*|MINIO_SERVER_URL=https://s3.${DOMAIN}|" "$TMPDIR/config.env"
    else
        # Create new configuration with generated credentials
        cat > "$TMPDIR/config.env" << EOF
MINIO_ROOT_USER=$(openssl rand -base64 63 | tr -d '\n')
MINIO_ROOT_PASSWORD=$(openssl rand -base64 63 | tr -d '\n')
MINIO_SERVER_URL=https://s3.${DOMAIN}
EOF
    fi

    if [[ "$DOMAIN" = "localhost" ]]; then
        # Don't use https for localhost
        sed -i 's|MINIO_SERVER_URL=https://|MINIO_SERVER_URL=http://|' "$TMPDIR/config.env"
    fi

    # Install configuration using ucf
    run_privileged mkdir -p /etc/minio
    ucf_install "$TMPDIR/config.env" /etc/minio/config.env
    # Ensure it's world-readable (so the configured domain can be checked)
    run_privileged chmod 644 /etc/minio/config.env

    # Cleanup
    rm -rf "$TMPDIR"
}

write_bebop_configuration() {
    log_info "Generating be-BOP environment configuration..."

    # Read MinIO credentials from config file
    local S3_ROOT_USER=$(run_privileged grep '^MINIO_ROOT_USER=' /etc/minio/config.env 2>/dev/null | cut -d'=' -f2- || echo "")
    local S3_ROOT_PASSWORD=$(run_privileged grep '^MINIO_ROOT_PASSWORD=' /etc/minio/config.env 2>/dev/null | cut -d'=' -f2- || echo "")

    if [[ -z "$S3_ROOT_USER" ]] || [[ -z "$S3_ROOT_PASSWORD" ]]; then
        die $EXIT_ERROR "Could not find MinIO credentials in /etc/minio/config.env"
    fi

    local TMPDIR=$(mktemp -d)
    # shellcheck disable=SC2064  # TMPDIR should be expanded here (and not on trap).
    trap "rm -rf $TMPDIR" RETURN 2>/dev/null || true

    # Generate be-BOP configuration
    cat > "$TMPDIR/config.env" << EOF
# This configuration is managed by be-bop-wizard
ADDRESS_HEADER=X-Forwarded-For
MONGODB_DB=bebop
MONGODB_URL=mongodb://127.0.0.1:27017
ORIGIN=https://${DOMAIN}
PUBLIC_S3_ENDPOINT_URL=https://s3.${DOMAIN}
S3_BUCKET=bebop
S3_ENDPOINT_URL=http://127.0.0.1:9000
S3_KEY_ID=${S3_ROOT_USER}
S3_KEY_SECRET=${S3_ROOT_PASSWORD}
S3_REGION=localhost
XFF_DEPTH=1
# ------------------------ >8 ------------------------
# Put your custom configuration (with new environment variables) after this line
EOF

    if [[ "$DOMAIN" = "localhost" ]]; then
        # Don't use https for localhost
        sed -i 's|ORIGIN=https://|ORIGIN=http://|' "$TMPDIR/config.env"
        sed -i 's|PUBLIC_S3_ENDPOINT_URL=https://|PUBLIC_S3_ENDPOINT_URL=http://|' "$TMPDIR/config.env"
    fi

    # Install configuration using ucf
    run_privileged mkdir -p /etc/be-BOP
    ucf_install "$TMPDIR/config.env" /etc/be-BOP/config.env
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

    # Install service file using ucf
    ucf_install "$TMPDIR/phoenixd.service" /etc/systemd/system/phoenixd.service
    run_privileged systemctl daemon-reload

    # Cleanup
    rm -rf "$TMPDIR"
}

install_minio_service() {
    log_info "Configuring MinIO systemd service..."

    local TMPDIR=$(mktemp -d)
    # shellcheck disable=SC2064  # TMPDIR should be expanded here (and not on trap).
    trap "rm -rf $TMPDIR" RETURN 2>/dev/null || true

    # Create MinIO systemd service file (container-compatible)
    cat > "$TMPDIR/minio.service" << 'EOF'
[Unit]
Description=MinIO Object Storage Server
Documentation=https://min.io/docs/minio/linux/index.html
After=network.target
Wants=network.target

[Service]
Type=notify
ExecStartPre=/usr/bin/mkdir -p /var/lib/minio/be-BOP
ExecStart=/usr/local/bin/minio server /var/lib/minio/be-BOP --console-address :9001
Restart=always
RestartSec=5
TimeoutStartSec=60
TimeoutStopSec=30

# State directory for persistent data
StateDirectory=minio
StateDirectoryMode=0755

# Working directory and environment
WorkingDirectory=/var/lib/minio
Environment=HOME=/var/lib/minio
EnvironmentFile=/etc/minio/config.env

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=minio

# Resource limits
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    # Install service file using ucf
    ucf_install "$TMPDIR/minio.service" /etc/systemd/system/minio.service
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
After=network.target minio.service mongod.service
Wants=network.target minio.service mongod.service

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

    # Install service file using ucf
    ucf_install "$TMPDIR/bebop.service" /etc/systemd/system/bebop.service
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
    ucf_install "$TMPDIR/overrides.conf" /etc/systemd/system/phoenixd.service.d/overrides.conf
    run_privileged systemctl daemon-reload

    # Cleanup
    rm -rf "$TMPDIR"
}

configure_minio_hardening_overrides() {
    log_info "Applying security hardening to MinIO service..."

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
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
EOF

    # Create override directory and install configuration
    run_privileged mkdir -p /etc/systemd/system/minio.service.d
    ucf_install "$TMPDIR/overrides.conf" /etc/systemd/system/minio.service.d/overrides.conf
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
    ucf_install "$TMPDIR/overrides.conf" /etc/systemd/system/bebop.service.d/overrides.conf
    run_privileged systemctl daemon-reload

    # Cleanup
    rm -rf "$TMPDIR"
}

start_and_enable_phoenixd() {
    log_info "Starting and enabling phoenixd service..."
    run_privileged systemctl daemon-reload
    run_privileged systemctl enable phoenixd
    run_privileged systemctl start phoenixd
}

start_and_enable_minio() {
    log_info "Starting and enabling MinIO service..."
    run_privileged systemctl enable minio
    run_privileged systemctl start minio
}

install_pnpm() {
    log_info "Installing pnpm package manager..."
    run_privileged corepack enable
    run_privileged corepack prepare pnpm@latest --activate
}

restart_minio() {
    log_info "Restarting MinIO service..."
    run_privileged systemctl restart minio
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

install_bebop_latest_release() {
    log_info "Installing latest be-BOP release..."

    if [[ ! -n "$LATEST_RELEASE_META" ]] || [[ ! -n "${LATEST_RELEASE_ASSET_BASENAME:-}" ]]; then
        # It is possible that jq was not available when we first tried to
        # retrieve the release information. By the time we get here, it
        # should be available, so we try one last time.
        determine_latest_release_meta
    fi

    if [[ ! -n "$LATEST_RELEASE_META" ]] || [[ ! -n "${LATEST_RELEASE_ASSET_BASENAME:-}" ]]; then
        local current=/var/lib/be-BOP/releases/current
        if [[ -f "$current/.bebop_install_success" ]]; then
            installed_date=$(date -r "$current/.bebop_install_success")
            log_warn "
┌──────────────────────────────────────────────────────────────────────────┐
│ WARNING: I was unable to retrieve the latest be-BOP release information. │
└──────────────────────────────────────────────────────────────────────────┘
I found an existing installation of be-BOP installed on $installed_date.
I will skip the current step, leave the existing installation intact, and continue.
Please check your internet connection and try again at a later time."
            return 0
        else
            die $EXIT_ERROR "Unable to retrieve latest be-BOP release information"
        fi
    fi

    local TARGET_DIR="/var/lib/be-BOP/releases/${LATEST_RELEASE_ASSET_BASENAME}"
    if [[ -d "$TARGET_DIR" ]] && [[ -f "$TARGET_DIR/.bebop_install_success" ]]; then
        log_info "Latest be-BOP release is already installed"
    else
        # Create temporary directory for download
        local TMPDIR=$(mktemp -d)
        # shellcheck disable=SC2064  # TMPDIR should be expanded here (and not on trap).
        trap "rm -rf $TMPDIR" RETURN 2>/dev/null || true
        pushd "$TMPDIR" > /dev/null

        local filter='.assets[] | select(.name == "'"$LATEST_RELEASE_ASSET_BASENAME"'.zip") | .browser_download_url'
        local LATEST_RELEASE_URL=$(echo "$LATEST_RELEASE_META" | jq -r "$filter")

        if [[ -z "$LATEST_RELEASE_URL" || "$LATEST_RELEASE_URL" = "null" ]]; then
            die $EXIT_ERROR "Could not find latest be-BOP release URL"
        fi

        log_info "Downloading ${LATEST_RELEASE_ASSET_BASENAME} from ${LATEST_RELEASE_URL}"
        curl --connect-timeout 5 -fSL# "$LATEST_RELEASE_URL" -o be-BOP-latest.zip -m 300
        unzip -q be-BOP-latest.zip

        local EXTRACTED_DIR=$(find . -maxdepth 1 -type d -name "be-BOP release *" | head -1)
        if [[ -z "$EXTRACTED_DIR" ]]; then
            die $EXIT_ERROR "Could not find extracted directory for be-BOP release"
        fi

        if [[ -d "$TARGET_DIR" ]]; then
            run_privileged rm -rf "$TARGET_DIR"
        fi
        run_privileged mkdir -p "$(dirname "$TARGET_DIR")"
        run_privileged mv "$EXTRACTED_DIR" "$TARGET_DIR"

        # Install dependencies
        log_info "Installing be-BOP ${LATEST_RELEASE_ASSET_BASENAME} dependencies..."
        pushd "$TARGET_DIR" > /dev/null
        run_privileged corepack enable
        run_privileged corepack install
        run_privileged pnpm install --prod --frozen-lockfile
        run_privileged touch .bebop_install_success
        popd > /dev/null

        popd > /dev/null
        rm -rf "$TMPDIR"

        log_info "Latest be-BOP release installed successfully at ${TARGET_DIR}!"
    fi

    # Create current symlink
    if [[ -L /var/lib/be-BOP/releases/current ]]; then
        run_privileged rm -f /var/lib/be-BOP/releases/current
    elif [[ -e /var/lib/be-BOP/releases/current ]]; then
        die $EXIT_ERROR "Something unknown is blocking the creation of /var/lib/be-BOP/releases/current symlink. Please check what exists at this path and remove it manually."
    fi
    run_privileged ln -sf "$TARGET_DIR" /var/lib/be-BOP/releases/current
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

# ---[ 7. Summarize the outcome ]---
# After all tasks finish, report which parts of the setup succeeded,
# which are running, and where to look if something went wrong.
# Think of it as the "mission debrief" — a clear final status for operators.
summarize_results() {
    log_info "Installation completed successfully!"
    echo ""
    echo "=========================================="
    echo "be-BOP Installation Complete!"
    echo "=========================================="
    echo "Your be-BOP instance should be accessible at: https://$DOMAIN"
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
    log_info "Starting $SCRIPT_NAME v$SCRIPT_VERSION (session: $SESSION_ID)"

    # Parse arguments and validate
    parse_args "$@"

    # Check prerequisites
    check_privileges

    # Detect environment and inspect system state
    detect_environment
    determine_latest_release_meta
    inspect_system_state
    plan_setup_tasks
    collect_all_required_tools

    summarize_state_and_plan

    if [[ ${#TASK_PLAN[@]} -eq 0 ]]; then
        log_info "Nothing to do. Exiting."
        exit $EXIT_SUCCESS
    fi

    if [ "$DRY_RUN" = true ]; then
        log_info "Exit before making any changes (--dry-run specified)."
        exit $EXIT_SUCCESS
    fi

    prompt_user_confirmation

    log_info "Beginning installation..."
    prepare_toolbox
    for action in "${TASK_PLAN[@]}"; do
        log_info "Executing: $(describe_task "$action")"
        run_task "$action"
    done

    summarize_results
}

# Execute main function with all arguments
main "$@"
