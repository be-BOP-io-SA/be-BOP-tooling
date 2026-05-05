#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 be-bop.io contributors
#
# host-bootstrap.sh — provision a Debian 12 VDS to host multiple isolated
# be-BOP tenants.
#
# Run ONCE on a fresh host as root (or with passwordless sudo). The script is
# idempotent: re-running is safe and only fixes what is missing or has drifted.
#
# What this script DOES NOT do:
#   - Create any tenant. (See add-tenant.sh.)
#   - Issue any TLS certificate. (Per-tenant SAN certs are issued by add-tenant.sh
#     via DNS-01 OVH; the only cert-related thing here is installing the
#     certbot OVH plugin and the credentials file.)
#   - Install MongoDB locally. (Tenants use OVH Managed Mongo — see secrets.env.)
#
# What this script DOES, in order:
#   1.  Validates the host (Debian 12, RAM, disk).
#   2.  Loads /etc/be-BOP-tooling/secrets.env.
#   3.  Verifies OVH API credentials work (calls /me).
#   4.  Installs apt packages: nodejs, pnpm, certbot+dns-ovh, nginx, docker,
#       netdata, plus the build/runtime deps (curl, jq, stow, openssl, unzip).
#   5.  Downloads & stows Garage and phoenixd binaries.
#   6.  Creates the /var/lib/be-BOP/, /etc/be-BOP/, /etc/be-BOP-tooling/,
#       /etc/phoenixd/ directory skeleton.
#   7.  Creates the be-bop-cli system user (parity with v1 wizard, used by
#       upgrade-tenant.sh for systemctl restart privileges).
#   8.  Writes /etc/garage.toml + garage.service, starts Garage, applies layout.
#   9.  Writes a 444 catch-all default vhost for nginx, then enables nginx.
#  10.  Installs /etc/letsencrypt/ovh.ini (mode 0600) for certbot DNS-01.
#  11.  Installs the systemd template units bebop@.service and phoenixd@.service.
#  12.  Installs tooling libs (/usr/local/share/be-BOP-tooling/lib/) and the
#       per-tenant scripts ({add,remove,upgrade}-tenant.sh, upgrade-all.sh).
#  13.  Initialises the empty /var/lib/be-BOP/tenants.tsv registry.
#  14.  Installs Uptime Kuma (Docker, bound to 127.0.0.1:8810) and Netdata.
#  15.  Prints a summary including the next operator step (Uptime Kuma admin
#       account creation, see README).

set -eEuo pipefail

readonly SCRIPT_VERSION="0.1.0"
readonly SCRIPT_NAME="host-bootstrap"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Locate libs and templates: source-tree layout when invoked from a checkout,
# system layout once installed under /usr/local/share/be-BOP-tooling.
if [[ -d "$SCRIPT_DIR/lib" ]]; then
    BEBOP_TOOLING_LIB_DIR="$SCRIPT_DIR/lib"
    BEBOP_TOOLING_TEMPLATE_DIR="$SCRIPT_DIR/templates"
elif [[ -d /usr/local/share/be-BOP-tooling/lib ]]; then
    BEBOP_TOOLING_LIB_DIR=/usr/local/share/be-BOP-tooling/lib
    BEBOP_TOOLING_TEMPLATE_DIR=/usr/local/share/be-BOP-tooling/templates
else
    echo "host-bootstrap: cannot locate lib/ directory" >&2
    exit 1
fi
readonly BEBOP_TOOLING_LIB_DIR BEBOP_TOOLING_TEMPLATE_DIR

# shellcheck source=lib/log.sh
source "$BEBOP_TOOLING_LIB_DIR/log.sh"
# shellcheck source=lib/sudo.sh
source "$BEBOP_TOOLING_LIB_DIR/sudo.sh"
# shellcheck source=lib/registry.sh
source "$BEBOP_TOOLING_LIB_DIR/registry.sh"
# shellcheck source=lib/ovh.sh
source "$BEBOP_TOOLING_LIB_DIR/ovh.sh"

BEBOP_TOOLING_SYSLOG_IDENT="bebop-tooling-${SCRIPT_NAME}"
export BEBOP_TOOLING_SYSLOG_IDENT

# === Constants (overridable via environment) ===========================
: "${NODEJS_MAJOR_VERSION:=20}"
: "${GARAGE_VERSION:=2.2.0}"
: "${PHOENIXD_VERSION:=0.6.2}"
: "${UPTIME_KUMA_IMAGE:=louislam/uptime-kuma:1}"
: "${UPTIME_KUMA_HOST_PORT:=8810}"
: "${BEBOP_TOOLING_INSTALL_PREFIX:=/usr/local/share/be-BOP-tooling}"

# === CLI flags =========================================================
SECRETS_FILE=/etc/be-BOP-tooling/secrets.env
DRY_RUN=false
RUN_NON_INTERACTIVE=false
VERBOSE=false
DEFER_SECRETS=false

usage() {
    cat <<EOF
host-bootstrap.sh — set up shared infra for be-BOP multi-tenant tooling.
Run once on a fresh Debian 12 host. Idempotent.

Usage:
  host-bootstrap.sh [options]

Options:
  --secrets-file <path>  Path to secrets.env. Default: ${SECRETS_FILE}
  --defer-secrets        Run only the steps that do not need secrets.env
                         (apt packages, binaries, dirs, garage, nginx,
                         systemd units, registry, docker, kuma, netdata).
                         Skips OVH connectivity check and certbot OVH
                         credentials. Re-run host-bootstrap.sh after
                         editing secrets.env to finalise — it is idempotent.
  --non-interactive      Refuse to prompt; exit if input would be required.
  --dry-run              Print what would happen without changing the system.
  --verbose              Verbose logging (also enables --debug at journald).
  -h, --help             Show this help.

Required environment in secrets.env:
  OVH_APPLICATION_KEY, OVH_APPLICATION_SECRET, OVH_CONSUMER_KEY,
  OVH_DNS_ZONE, OVH_CLOUD_PROJECT_ID, OVH_MONGO_CLUSTER_ID,
  OVH_MONGO_ENDPOINT_HOST, OVH_MONGO_ENDPOINT_PORT, plus SFTP/SMTP/Zulip/Kuma.
See templates/secrets.env.example.
EOF
}

while (( $# )); do
    case "$1" in
        --secrets-file)    SECRETS_FILE="$2"; shift 2 ;;
        --defer-secrets)   DEFER_SECRETS=true; shift ;;
        --non-interactive) RUN_NON_INTERACTIVE=true; shift ;;
        --dry-run)         DRY_RUN=true; shift ;;
        --verbose)         VERBOSE=true; shift ;;
        -h|--help)         usage; exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
done

export RUN_NON_INTERACTIVE VERBOSE DRY_RUN DEFER_SECRETS

# Wrapper: do nothing in --dry-run mode but still log.
maybe_run() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[dry-run] would run: $*"
    else
        "$@"
    fi
}

# === Prerequisites check ===============================================
step_check_prerequisites() {
    log_info "Checking host prerequisites..."

    # OS detection
    local os_id="" os_codename=""
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        os_id="${ID:-}"
        os_codename="${VERSION_CODENAME:-}"
    fi
    if [[ "$os_id" != "debian" || "$os_codename" != "bookworm" ]]; then
        die "this script targets Debian 12 (bookworm); detected ID=${os_id} CODENAME=${os_codename}"
    fi
    log_info "OS: Debian 12 (bookworm) ✓"

    # RAM
    local ram_kb
    ram_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
    if (( ram_kb < 2000000 )); then
        log_warn "low RAM: ${ram_kb} kB (recommended: ≥ 2 GiB)"
    fi

    # Disk: free space on /var
    local var_free_gb
    var_free_gb=$(df --output=avail -BG /var | tail -1 | tr -d 'G ')
    if (( var_free_gb < 20 )); then
        log_warn "low free disk on /var: ${var_free_gb}G (recommended: ≥ 20G for releases + Garage)"
    fi

    # systemd
    if ! command -v systemctl >/dev/null 2>&1; then
        die "systemctl not found — host must run systemd"
    fi
    log_info "systemd: present ✓"
}

# === Secrets ============================================================
step_load_secrets() {
    log_info "Loading secrets from ${SECRETS_FILE}..."
    if [[ ! -f "$SECRETS_FILE" ]]; then
        if [[ "$DEFER_SECRETS" == "true" ]]; then
            log_warn "secrets file not found: ${SECRETS_FILE} — continuing in --defer-secrets mode"
            return 0
        fi
        die "secrets file not found: ${SECRETS_FILE} (copy templates/secrets.env.example, fill it, chmod 600, and rerun)"
    fi
    local mode
    mode=$(stat -c '%a' "$SECRETS_FILE")
    if [[ "$mode" != "600" ]]; then
        log_warn "${SECRETS_FILE} mode is ${mode}; should be 600 (chmod 600 ${SECRETS_FILE})"
    fi
    # shellcheck disable=SC1090
    source "$SECRETS_FILE"

    local missing=()
    for v in OVH_APPLICATION_KEY OVH_APPLICATION_SECRET OVH_CONSUMER_KEY OVH_DNS_ZONE; do
        [[ -z "${!v:-}" ]] && missing+=("$v")
    done
    if (( ${#missing[@]} )); then
        if [[ "$DEFER_SECRETS" == "true" ]]; then
            log_warn "secrets.env has empty values: ${missing[*]} — continuing in --defer-secrets mode"
            return 0
        fi
        die "secrets.env is missing required values: ${missing[*]}"
    fi
    log_info "secrets loaded ✓"
}

# === OVH connectivity ====================================================
step_verify_ovh_connectivity() {
    if [[ "$DEFER_SECRETS" == "true" && -z "${OVH_APPLICATION_KEY:-}" ]]; then
        log_info "Skipping OVH connectivity check (--defer-secrets)"
        return 0
    fi
    log_info "Verifying OVH API connectivity..."
    if ! ovh_ping; then
        die "OVH API ping failed; check OVH_APPLICATION_KEY / OVH_APPLICATION_SECRET / OVH_CONSUMER_KEY in ${SECRETS_FILE}"
    fi
}

# === apt packages =======================================================
step_install_apt_packages() {
    log_info "Updating apt cache and installing core packages..."
    maybe_run run_privileged env DEBIAN_FRONTEND=noninteractive apt-get update -qq
    local pkgs=(
        ca-certificates curl gpg jq openssl unzip stow xxd
        flock util-linux
        rclone
        nginx
        certbot python3-certbot-dns-ovh
        docker.io
        netdata
    )
    maybe_run run_privileged env DEBIAN_FRONTEND=noninteractive \
        apt-get install -y --no-install-recommends "${pkgs[@]}"
}

# === Node.js + pnpm =====================================================
step_install_nodejs_pnpm() {
    if command -v node >/dev/null 2>&1; then
        local actual
        actual=$(node --version 2>/dev/null | sed 's/^v//' | cut -d. -f1)
        if [[ "$actual" == "$NODEJS_MAJOR_VERSION" ]]; then
            log_info "Node.js v${actual} already installed ✓"
        else
            log_warn "Node.js v${actual} installed; expected v${NODEJS_MAJOR_VERSION}"
        fi
    else
        log_info "Configuring NodeSource repository for Node.js ${NODEJS_MAJOR_VERSION}.x..."
        local keyring=/usr/share/keyrings/nodesource.gpg
        maybe_run run_privileged bash -c "
            curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key |
            gpg --dearmor -o '${keyring}' &&
            echo 'deb [signed-by=${keyring}] https://deb.nodesource.com/node_${NODEJS_MAJOR_VERSION}.x nodistro main' \
                > /etc/apt/sources.list.d/nodesource.list
        "
        maybe_run run_privileged env DEBIAN_FRONTEND=noninteractive apt-get update -qq
        maybe_run run_privileged env DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs
    fi
    if ! command -v corepack >/dev/null 2>&1; then
        die "corepack not available — Node.js install seems broken"
    fi
    log_info "Enabling corepack and pnpm..."
    maybe_run run_privileged corepack enable
    maybe_run run_privileged corepack prepare pnpm@latest --activate
}

# === Garage binary ======================================================
step_install_garage_binary() {
    local stow_dir="/usr/local/garage"
    local pkg_dir="${stow_dir}/garage-v${GARAGE_VERSION}"
    if [[ -x "${pkg_dir}/bin/garage" ]]; then
        log_info "Garage v${GARAGE_VERSION} already installed (${pkg_dir}) ✓"
    else
        log_info "Downloading Garage v${GARAGE_VERSION}..."
        local arch
        case "$(uname -m)" in
            x86_64)  arch="x86_64-unknown-linux-musl" ;;
            aarch64) arch="aarch64-unknown-linux-musl" ;;
            *) die "unsupported CPU architecture: $(uname -m)" ;;
        esac
        local url="https://garagehq.deuxfleurs.fr/_releases/v${GARAGE_VERSION}/${arch}/garage"
        local tmp
        tmp=$(mktemp -d)
        # shellcheck disable=SC2064
        trap "rm -rf '${tmp}'" RETURN
        maybe_run curl -fsSL --connect-timeout 10 --max-time 300 -o "${tmp}/garage" "${url}"
        maybe_run run_privileged install -d -m 0755 "${pkg_dir}/bin"
        maybe_run run_privileged install -m 0755 "${tmp}/garage" "${pkg_dir}/bin/garage"
        rm -rf "${tmp}"
        trap - RETURN
    fi
    log_info "Stowing Garage..."
    ( cd "${stow_dir}" && maybe_run run_privileged stow --restow "garage-v${GARAGE_VERSION}" )
}

# === phoenixd binary ====================================================
step_install_phoenixd_binary() {
    local stow_dir="/usr/local/phoenixd"
    local pkg_dir="${stow_dir}/phoenixd-${PHOENIXD_VERSION}"
    if [[ -x "${pkg_dir}/bin/phoenixd" ]]; then
        log_info "phoenixd ${PHOENIXD_VERSION} already installed (${pkg_dir}) ✓"
    else
        log_info "Downloading phoenixd ${PHOENIXD_VERSION}..."
        local arch
        case "$(uname -m)" in
            x86_64)  arch="x64" ;;
            aarch64) arch="arm64" ;;
            *) die "unsupported CPU architecture: $(uname -m)" ;;
        esac
        local url="https://github.com/ACINQ/phoenixd/releases/download/v${PHOENIXD_VERSION}/phoenixd-${PHOENIXD_VERSION}-linux-${arch}.zip"
        local tmp
        tmp=$(mktemp -d)
        # shellcheck disable=SC2064
        trap "rm -rf '${tmp}'" RETURN
        maybe_run curl -fsSL --connect-timeout 10 --max-time 300 -o "${tmp}/phoenixd.zip" "${url}"
        ( cd "${tmp}" && maybe_run unzip -q phoenixd.zip )
        maybe_run run_privileged install -d -m 0755 "${pkg_dir}/bin"
        maybe_run run_privileged bash -c "install -m 0755 ${tmp}/phoenixd-*/phoenixd ${pkg_dir}/bin/"
        maybe_run run_privileged bash -c "install -m 0755 ${tmp}/phoenixd-*/phoenix-cli ${pkg_dir}/bin/"
        rm -rf "${tmp}"
        trap - RETURN
    fi
    log_info "Stowing phoenixd..."
    ( cd "${stow_dir}" && maybe_run run_privileged stow --restow "phoenixd-${PHOENIXD_VERSION}" )
}

# === Filesystem skeleton ================================================
step_setup_directories() {
    log_info "Creating directory skeleton..."
    maybe_run run_privileged install -d -m 0755 /var/lib/be-BOP
    maybe_run run_privileged install -d -m 0755 /etc/be-BOP
    maybe_run run_privileged install -d -m 0700 /etc/be-BOP-tooling
    maybe_run run_privileged install -d -m 0755 /etc/phoenixd
    maybe_run run_privileged install -d -m 0755 /var/lib/phoenixd
    # Garage state & config dirs (Garage service handles its own state via
    # StateDirectory, but we create the meta/data parents explicitly).
    maybe_run run_privileged install -d -m 0755 /var/lib/garage
    # Let's Encrypt
    maybe_run run_privileged install -d -m 0755 /etc/letsencrypt
}

# === be-bop-cli system user (parity with v1 wizard) =====================
step_setup_user_be_bop_cli() {
    if id be-bop-cli >/dev/null 2>&1; then
        log_info "system user 'be-bop-cli' already exists ✓"
    else
        log_info "Creating system user 'be-bop-cli'..."
        maybe_run run_privileged useradd \
            --system --shell /usr/sbin/nologin \
            --home-dir /var/lib/be-BOP --no-create-home \
            be-bop-cli
    fi
}

# === Garage configuration ===============================================
step_write_garage_config() {
    log_info "Writing /etc/garage.toml..."
    if [[ -f /etc/garage.toml ]]; then
        log_info "/etc/garage.toml already exists; leaving rpc_secret intact"
        return 0
    fi
    local rpc_secret
    rpc_secret=$(openssl rand -hex 32)
    local tmp
    tmp=$(mktemp)
    cat > "$tmp" <<EOF
# /etc/garage.toml — managed by be-BOP multi-tenant tooling
metadata_dir = "/var/lib/garage/meta"
data_dir = "/var/lib/garage/data"
db_engine = "lmdb"
replication_factor = 1

rpc_secret = "${rpc_secret}"
rpc_bind_addr = "127.0.0.1:3901"

[s3_api]
s3_region = "garage"
api_bind_addr = "127.0.0.1:3900"
# No root_domain: per-tenant subdomains use path-style (forcePathStyle in
# be-BOP's S3 client). Garage doesn't need to parse the bucket from the host.

[admin]
api_bind_addr = "127.0.0.1:3903"
EOF
    maybe_run run_privileged install -m 0640 "$tmp" /etc/garage.toml
    rm -f "$tmp"
}

step_write_garage_service() {
    log_info "Writing /etc/systemd/system/garage.service..."
    local tmp
    tmp=$(mktemp)
    cat > "$tmp" <<'EOF'
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
StateDirectory=garage
StateDirectoryMode=0755
WorkingDirectory=/var/lib/garage
Environment=HOME=/var/lib/garage
Environment=GARAGE_CONFIG_FILE=/etc/garage.toml
StandardOutput=journal
StandardError=journal
SyslogIdentifier=garage
LimitNOFILE=65536

# Hardening (DynamicUser is NOT used — Garage reads /etc/garage.toml which is
# root:root 0640 to protect rpc_secret).
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

[Install]
WantedBy=multi-user.target
EOF
    maybe_run run_privileged install -m 0644 "$tmp" /etc/systemd/system/garage.service
    rm -f "$tmp"
    maybe_run run_privileged systemctl daemon-reload
}

step_start_garage() {
    log_info "Enabling and starting garage.service..."
    maybe_run run_privileged systemctl enable --now garage
    log_info "Waiting for Garage to become ready..."
    local retries=10
    while ! run_privileged garage status >/dev/null 2>&1; do
        if (( retries-- <= 0 )); then
            die "Garage did not become ready in 30s"
        fi
        sleep 3
    done
    log_info "Garage ready ✓"
}

step_provision_garage_layout() {
    local node_id
    node_id=$(run_privileged garage node id 2>/dev/null | cut -d'@' -f1)
    if [[ -z "$node_id" ]]; then
        die "could not determine Garage node id"
    fi
    if run_privileged garage status 2>/dev/null | grep "${node_id:0:16}" | grep -q "NO ROLE ASSIGNED"; then
        log_info "Assigning layout to Garage node ${node_id:0:16}..."
        maybe_run run_privileged garage layout assign -z dc1 -c 1G "$node_id"
        local layout_version
        layout_version=$(run_privileged garage layout show 2>/dev/null \
            | awk '/Current cluster layout version:/{print $NF}')
        layout_version=$(( ${layout_version:-0} + 1 ))
        maybe_run run_privileged garage layout apply --version "$layout_version"
    else
        log_info "Garage layout already assigned ✓"
    fi
}

# === nginx default catch-all ============================================
step_write_nginx_default_vhost() {
    log_info "Writing nginx catch-all vhost..."
    local tmp
    tmp=$(mktemp)
    cat > "$tmp" <<'EOF'
# Catch-all default — drops connections to unknown hosts. Per-tenant vhosts
# are added under sites-enabled by add-tenant.sh.
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 444;
}
EOF
    maybe_run run_privileged install -m 0644 "$tmp" /etc/nginx/sites-available/default
    maybe_run run_privileged ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
    rm -f "$tmp"
    if [[ "$DRY_RUN" != "true" ]]; then
        run_privileged nginx -t
    fi
}

step_start_nginx() {
    log_info "Enabling and starting nginx..."
    maybe_run run_privileged systemctl enable --now nginx
}

# === certbot OVH credentials ============================================
step_install_ovh_credentials_for_certbot() {
    if [[ "$DEFER_SECRETS" == "true" && -z "${OVH_APPLICATION_KEY:-}" ]]; then
        log_info "Skipping certbot OVH credentials (--defer-secrets) — re-run after editing secrets.env"
        return 0
    fi
    log_info "Installing /etc/letsencrypt/ovh.ini..."
    local tmp
    tmp=$(mktemp)
    cat > "$tmp" <<EOF
# OVH API credentials for certbot-dns-ovh — managed by host-bootstrap.sh
dns_ovh_endpoint = ovh-eu
dns_ovh_application_key = ${OVH_APPLICATION_KEY}
dns_ovh_application_secret = ${OVH_APPLICATION_SECRET}
dns_ovh_consumer_key = ${OVH_CONSUMER_KEY}
EOF
    maybe_run run_privileged install -m 0600 "$tmp" /etc/letsencrypt/ovh.ini
    rm -f "$tmp"
}

# === systemd template units =============================================
step_install_template_units() {
    log_info "Installing systemd template units..."
    maybe_run run_privileged install -m 0644 \
        "${BEBOP_TOOLING_TEMPLATE_DIR}/bebop@.service" \
        /etc/systemd/system/bebop@.service
    maybe_run run_privileged install -m 0644 \
        "${BEBOP_TOOLING_TEMPLATE_DIR}/phoenixd@.service" \
        /etc/systemd/system/phoenixd@.service
    maybe_run run_privileged systemctl daemon-reload
}

# === Tooling libs + per-tenant scripts ==================================
step_install_tooling_libs_and_scripts() {
    log_info "Installing tooling libs to ${BEBOP_TOOLING_INSTALL_PREFIX}..."
    maybe_run run_privileged install -d -m 0755 "${BEBOP_TOOLING_INSTALL_PREFIX}/lib"
    maybe_run run_privileged install -d -m 0755 "${BEBOP_TOOLING_INSTALL_PREFIX}/templates"
    local f
    for f in "${BEBOP_TOOLING_LIB_DIR}"/*.sh; do
        maybe_run run_privileged install -m 0644 "$f" "${BEBOP_TOOLING_INSTALL_PREFIX}/lib/"
    done
    for f in "${BEBOP_TOOLING_TEMPLATE_DIR}"/*; do
        maybe_run run_privileged install -m 0644 "$f" "${BEBOP_TOOLING_INSTALL_PREFIX}/templates/"
    done
    log_info "Installing per-tenant scripts to /usr/local/bin/..."
    local script
    for script in add-tenant.sh remove-tenant.sh upgrade-tenant.sh upgrade-all.sh; do
        if [[ -f "${SCRIPT_DIR}/${script}" ]]; then
            maybe_run run_privileged install -m 0755 "${SCRIPT_DIR}/${script}" "/usr/local/bin/${script}"
        else
            log_warn "skipping /usr/local/bin/${script} — source not present yet (expected during early dev)"
        fi
    done
}

# === Registry ==========================================================
step_init_registry() {
    log_info "Initialising tenant registry..."
    registry_init
}

# === Uptime Kuma + Netdata =============================================
step_setup_docker() {
    if ! systemctl is-active --quiet docker; then
        log_info "Enabling and starting docker..."
        maybe_run run_privileged systemctl enable --now docker
    else
        log_info "docker already running ✓"
    fi
}

step_install_uptime_kuma() {
    if run_privileged docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx 'bebop-uptime-kuma'; then
        log_info "Uptime Kuma container already exists ✓"
        if ! run_privileged docker ps --format '{{.Names}}' 2>/dev/null | grep -qx 'bebop-uptime-kuma'; then
            maybe_run run_privileged docker start bebop-uptime-kuma
        fi
        return 0
    fi
    log_info "Pulling ${UPTIME_KUMA_IMAGE}..."
    maybe_run run_privileged docker pull "${UPTIME_KUMA_IMAGE}"
    maybe_run run_privileged install -d -m 0755 /var/lib/uptime-kuma
    log_info "Starting Uptime Kuma container on 127.0.0.1:${UPTIME_KUMA_HOST_PORT}..."
    maybe_run run_privileged docker run -d \
        --name bebop-uptime-kuma \
        --restart=always \
        -v /var/lib/uptime-kuma:/app/data \
        -p "127.0.0.1:${UPTIME_KUMA_HOST_PORT}:3001" \
        "${UPTIME_KUMA_IMAGE}"
}

step_install_netdata() {
    if systemctl is-active --quiet netdata; then
        log_info "netdata already running ✓"
        return 0
    fi
    log_info "Enabling and starting netdata..."
    maybe_run run_privileged systemctl enable --now netdata
}

# === Summary ===========================================================
step_print_summary() {
    local title="be-BOP multi-tenant host bootstrap COMPLETE"
    if [[ "$DEFER_SECRETS" == "true" && -z "${OVH_APPLICATION_KEY:-}" ]]; then
        title="be-BOP multi-tenant host bootstrap PARTIAL (deferred-secrets mode)"
    fi
    cat <<EOF

==========================================================================
  ${title}
==========================================================================

Versions installed:
  Node.js:    $(node --version 2>/dev/null || echo '?')
  pnpm:       $(pnpm --version 2>/dev/null || echo '?')
  Garage:     v${GARAGE_VERSION}
  phoenixd:   ${PHOENIXD_VERSION}
  certbot:    $(certbot --version 2>/dev/null || echo '?')
  docker:     $(docker --version 2>/dev/null || echo '?')

Key paths:
  Tenant registry        /var/lib/be-BOP/tenants.tsv
  Per-tenant config      /etc/be-BOP/<tenant>/config.env
  Per-tenant releases    /var/lib/be-BOP/<tenant>/releases/
  Phoenixd data          /var/lib/phoenixd/<tenant>/.phoenix/
  Garage state           /var/lib/garage/{meta,data}/
  Secrets                ${SECRETS_FILE}    (mode 0600)
  Cert OVH credentials   /etc/letsencrypt/ovh.ini       (mode 0600)
  Template units         /etc/systemd/system/{bebop,phoenixd}@.service
  Tooling libs           ${BEBOP_TOOLING_INSTALL_PREFIX}/lib/

Services running:
  garage.service (single-instance, mutualised)
  nginx.service (catch-all 444; per-tenant vhosts added by add-tenant.sh)
  netdata.service
  bebop-uptime-kuma (Docker, bound to 127.0.0.1:${UPTIME_KUMA_HOST_PORT})

NEXT STEPS (manual, one-time):
EOF
    if [[ "$DEFER_SECRETS" == "true" && -z "${OVH_APPLICATION_KEY:-}" ]]; then
        cat <<EOF
  0. Edit ${SECRETS_FILE} (mode 0600), then re-run:
       sudo ${BEBOP_TOOLING_INSTALL_PREFIX}/host-bootstrap.sh
     This will install OVH cert credentials and verify connectivity.
EOF
    fi
    cat <<EOF
  1. Set up the Uptime Kuma admin account:
       ssh -L ${UPTIME_KUMA_HOST_PORT}:localhost:${UPTIME_KUMA_HOST_PORT} this-host
       open http://localhost:${UPTIME_KUMA_HOST_PORT} in your browser
       create the admin user (the API token is then set in secrets.env)
  2. Configure mail + Zulip notification channels in Uptime Kuma
     (Settings > Notifications). Take note of their IDs for secrets.env
     (see the README for the exact var names).
  3. Add your first tenant:
       add-tenant.sh tenant1 --admin-email merchant1@example.com

==========================================================================
EOF
}

# === Orchestration =====================================================
main() {
    require_privileges

    step_check_prerequisites
    step_load_secrets
    step_verify_ovh_connectivity

    step_install_apt_packages
    step_install_nodejs_pnpm
    step_install_garage_binary
    step_install_phoenixd_binary

    step_setup_directories
    step_setup_user_be_bop_cli

    step_write_garage_config
    step_write_garage_service
    step_start_garage
    step_provision_garage_layout

    step_write_nginx_default_vhost
    step_start_nginx

    step_install_ovh_credentials_for_certbot
    step_install_template_units
    step_install_tooling_libs_and_scripts
    step_init_registry

    step_setup_docker
    step_install_uptime_kuma
    step_install_netdata

    step_print_summary
}

main "$@"
