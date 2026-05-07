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
#   - Start any mongod. The default mongod.service shipped by mongodb-org is
#     masked; per-tenant mongod@<tenant>.service instances are started by
#     add-tenant.sh.
#
# What this script DOES, in order:
#   1.  Validates the host (Debian 12, RAM, disk, AVX support).
#   2.  Loads /etc/be-BOP-tooling/secrets.env.
#   3.  Verifies OVH API credentials work (calls /me).
#   4.  Installs apt packages: nodejs, pnpm, mongodb-org + mongodb-mongosh +
#       mongodb-database-tools, certbot, nginx, docker, netdata, plus
#       the build/runtime deps (curl, jq, stow, openssl, unzip, python3-venv).
#       certbot's DNS-01 OVH challenge is handled by hooks/ scripts using
#       our own zone-scoped OVH token, so no certbot-dns-ovh plugin needed.
#   5.  Downloads & stows Garage and phoenixd binaries.
#   6.  Creates the /var/lib/be-BOP/, /etc/be-BOP/, /etc/be-BOP-tooling/,
#       /etc/phoenixd/, /etc/be-BOP-mongodb/, /var/lib/be-BOP-mongodb/ skeleton.
#   7.  Creates the be-bop-cli system user (parity with v1 wizard, used by
#       upgrade-tenant.sh for systemctl restart privileges).
#   8.  Masks the default mongod.service (we use per-tenant template instances).
#   9.  Writes /etc/garage.toml + garage.service, starts Garage, applies layout.
#  10.  Writes a 444 catch-all default vhost for nginx, then enables nginx.
#  11.  (No-op now — kept for backwards compat: removes the legacy
#       /etc/letsencrypt/ovh.ini if present, certbot --manual hooks read
#       OVH creds directly from secrets.env.)
#  12.  Installs systemd template units bebop@, phoenixd@, mongod@.
#  13.  Installs tooling libs (/usr/local/share/be-BOP-tooling/lib/) and the
#       per-tenant scripts ({add,remove,upgrade}-tenant.sh, upgrade-all.sh).
#  14.  Initialises the empty /var/lib/be-BOP/tenants.tsv registry.
#  15.  Installs Uptime Kuma (Docker, bound to 127.0.0.1:8810) and Netdata.
#  16.  Prints a summary including the next operator step (Uptime Kuma admin
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
: "${MONGODB_VERSION:=8.0}"
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
  OVH_DNS_ZONE, plus SFTP/SMTP/Zulip/Kuma (all optional except OVH_*).
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

    # MongoDB 5.0+ requires AVX on amd64. ARM64 is fine without.
    local arch
    arch=$(dpkg --print-architecture 2>/dev/null || uname -m)
    if [[ "$arch" == "amd64" || "$arch" == "x86_64" ]]; then
        if ! grep -qE '^flags[[:space:]]*:.* avx( |$)' /proc/cpuinfo; then
            die "MongoDB ${MONGODB_VERSION} requires CPU AVX support; this host's CPU does not advertise it (check /proc/cpuinfo)"
        fi
        log_info "CPU AVX: supported ✓"
    fi
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
        util-linux
        rclone
        nginx apache2-utils
        certbot
        python3-venv python3-pip
        docker.io
        netdata
    )
    maybe_run run_privileged env DEBIAN_FRONTEND=noninteractive \
        apt-get install -y --no-install-recommends "${pkgs[@]}"
}

# === MongoDB APT repo + install =========================================
step_install_mongodb() {
    local list_file="/etc/apt/sources.list.d/mongodb-org-${MONGODB_VERSION}.list"
    local keyring="/usr/share/keyrings/mongodb-server-${MONGODB_VERSION}.gpg"
    if [[ -f "$list_file" && -f "$keyring" ]]; then
        log_info "MongoDB ${MONGODB_VERSION} apt repo already configured ✓"
    else
        log_info "Configuring MongoDB ${MONGODB_VERSION} apt repository..."
        local arch
        arch=$(dpkg --print-architecture)
        local os_codename=""
        if [[ -f /etc/os-release ]]; then
            # shellcheck source=/dev/null
            . /etc/os-release
            os_codename="${VERSION_CODENAME:-bookworm}"
        fi
        # MongoDB publishes per-arch repos (amd64, arm64). Debian 12 (bookworm)
        # uses the corresponding component path under repo.mongodb.org.
        maybe_run run_privileged bash -c "
            curl -fsSL https://www.mongodb.org/static/pgp/server-${MONGODB_VERSION}.asc \
                | gpg --batch --yes --dearmor -o '${keyring}' &&
            echo 'deb [arch=${arch} signed-by=${keyring}] https://repo.mongodb.org/apt/debian ${os_codename}/mongodb-org/${MONGODB_VERSION} main' \
                > '${list_file}'
        "
        maybe_run run_privileged env DEBIAN_FRONTEND=noninteractive apt-get update -qq
    fi
    log_info "Installing mongodb-org + mongodb-mongosh + mongodb-database-tools..."
    maybe_run run_privileged env DEBIAN_FRONTEND=noninteractive apt-get install -y \
        mongodb-org mongodb-mongosh mongodb-database-tools

    # Mask the default mongod.service that ships with mongodb-org. We use
    # per-tenant mongod@<tenant>.service instances instead. Masking is
    # idempotent and survives package upgrades.
    if systemctl list-unit-files mongod.service --no-legend 2>/dev/null | grep -q .; then
        if ! systemctl is-enabled mongod.service 2>/dev/null | grep -qx 'masked'; then
            log_info "Masking default mongod.service (per-tenant template instances are used instead)..."
            maybe_run run_privileged systemctl disable --now mongod.service 2>/dev/null || true
            maybe_run run_privileged systemctl mask mongod.service
        else
            log_info "default mongod.service already masked ✓"
        fi
    fi
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
    # Per-tenant mongod parents (StateDirectory in mongod@.service creates the
    # per-instance subdirs; we just ensure the parents exist for consistency).
    maybe_run run_privileged install -d -m 0755 /etc/be-BOP-mongodb
    maybe_run run_privileged install -d -m 0755 /var/lib/be-BOP-mongodb
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

# === certbot OVH credentials (no longer needed) =========================
# certbot-dns-ovh has been replaced by certbot --manual + our hooks/
# scripts (see add-tenant.sh::phase_certificate). The hooks read OVH
# creds from /etc/be-BOP-tooling/secrets.env directly, so /etc/letsencrypt/ovh.ini
# is no longer used. We remove a stale one if it exists from a prior install.
step_remove_legacy_ovh_ini() {
    if [[ -f /etc/letsencrypt/ovh.ini ]]; then
        log_info "Removing legacy /etc/letsencrypt/ovh.ini (now obsolete)..."
        maybe_run run_privileged rm -f /etc/letsencrypt/ovh.ini
    fi
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
    maybe_run run_privileged install -m 0644 \
        "${BEBOP_TOOLING_TEMPLATE_DIR}/mongod@.service" \
        /etc/systemd/system/mongod@.service
    maybe_run run_privileged systemctl daemon-reload
}

# === Tooling libs + per-tenant scripts ==================================
step_install_tooling_libs_and_scripts() {
    log_info "Installing tooling libs to ${BEBOP_TOOLING_INSTALL_PREFIX}..."
    maybe_run run_privileged install -d -m 0755 "${BEBOP_TOOLING_INSTALL_PREFIX}/lib"
    maybe_run run_privileged install -d -m 0755 "${BEBOP_TOOLING_INSTALL_PREFIX}/templates"
    maybe_run run_privileged install -d -m 0755 "${BEBOP_TOOLING_INSTALL_PREFIX}/hooks"
    local f
    for f in "${BEBOP_TOOLING_LIB_DIR}"/*.sh "${BEBOP_TOOLING_LIB_DIR}"/*.py; do
        [[ -f "$f" ]] || continue
        maybe_run run_privileged install -m 0644 "$f" "${BEBOP_TOOLING_INSTALL_PREFIX}/lib/"
    done
    for f in "${BEBOP_TOOLING_TEMPLATE_DIR}"/*; do
        maybe_run run_privileged install -m 0644 "$f" "${BEBOP_TOOLING_INSTALL_PREFIX}/templates/"
    done
    # certbot --manual hooks: must be executable.
    local hooks_src="${SCRIPT_DIR}/hooks"
    if [[ -d "$hooks_src" ]]; then
        for f in "$hooks_src"/*.sh; do
            [[ -f "$f" ]] || continue
            maybe_run run_privileged install -m 0755 "$f" "${BEBOP_TOOLING_INSTALL_PREFIX}/hooks/"
        done
    fi
    log_info "Installing per-tenant scripts to /usr/local/bin/..."
    local script
    for script in add-tenant.sh remove-tenant.sh upgrade-tenant.sh upgrade-all.sh list-tenants.sh; do
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

# === Kuma Python venv (uptime-kuma-api) ================================
step_install_kuma_python_env() {
    local venv=/opt/be-BOP-tooling/kuma-venv
    if [[ -x "$venv/bin/python" ]] \
        && run_privileged "$venv/bin/python" -c 'import uptime_kuma_api' 2>/dev/null; then
        log_info "Kuma Python venv already provisioned at ${venv} ✓"
        return 0
    fi
    log_info "Creating Python venv at ${venv} with uptime-kuma-api..."
    maybe_run run_privileged python3 -m venv "$venv"
    maybe_run run_privileged "$venv/bin/pip" install --quiet --upgrade pip
    maybe_run run_privileged "$venv/bin/pip" install --quiet 'uptime-kuma-api>=1.2'
}

# === Kuma admin auto-provisioning ======================================
step_setup_kuma_admin() {
    local admin_file=/etc/be-BOP-tooling/kuma-admin.env
    if [[ -f "$admin_file" ]]; then
        log_info "Kuma admin credentials file already exists at ${admin_file} ✓"
        return 0
    fi
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[dry-run] would auto-provision Kuma admin and write ${admin_file}"
        return 0
    fi
    # Wait for Kuma to be reachable (it just started; needs a few seconds).
    local kuma_url="http://127.0.0.1:${UPTIME_KUMA_HOST_PORT}"
    log_info "Waiting for Kuma to become reachable at ${kuma_url}..."
    local i ready=false
    for (( i=1; i<=60; i++ )); do
        if curl -sf --max-time 2 "${kuma_url}/" >/dev/null 2>&1; then
            ready=true
            break
        fi
        sleep 2
    done
    if [[ "$ready" != "true" ]]; then
        die "Kuma did not become reachable at ${kuma_url} within 120s"
    fi
    log_info "Kuma reachable; provisioning admin via uptime-kuma-api..."
    local user="bebop-admin"
    local pass
    pass=$(openssl rand -base64 33 | tr -d '+/=\n' | head -c 32)

    local cli="${BEBOP_TOOLING_LIB_DIR}/kuma-cli.py"
    local venv_python=/opt/be-BOP-tooling/kuma-venv/bin/python
    if ! run_privileged "$venv_python" "$cli" \
            --url "$kuma_url" setup-admin \
            --user "$user" --password "$pass"; then
        die "kuma: setup-admin failed (see kuma-cli output above)"
    fi
    local tmp
    tmp=$(mktemp)
    cat > "$tmp" <<EOF
# Auto-generated by host-bootstrap.sh — DO NOT edit by hand.
# Used by lib/uptime-kuma.sh via add-tenant.sh / remove-tenant.sh.
KUMA_ADMIN_USER="${user}"
KUMA_ADMIN_PASSWORD="${pass}"
EOF
    run_privileged install -m 0600 "$tmp" "$admin_file"
    rm -f "$tmp"
    log_info "Kuma admin credentials saved to ${admin_file} (mode 0600)"
}

# === Kuma notification channels (SMTP + Zulip) =========================
step_setup_kuma_notifications() {
    if [[ "$DEFER_SECRETS" == "true" && -z "${SMTP_HOST:-}${ZULIP_SITE:-}" ]]; then
        log_info "Skipping Kuma notifications setup (--defer-secrets)"
        return 0
    fi
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[dry-run] would configure Kuma SMTP + Zulip notification channels"
        return 0
    fi
    local admin_file=/etc/be-BOP-tooling/kuma-admin.env
    if [[ ! -f "$admin_file" ]]; then
        log_warn "Kuma admin file ${admin_file} not found; skipping notifications setup"
        return 0
    fi
    # shellcheck disable=SC1090
    source "$admin_file"
    local kuma_url="http://127.0.0.1:${UPTIME_KUMA_HOST_PORT}"
    local cli="${BEBOP_TOOLING_LIB_DIR}/kuma-cli.py"
    local venv_python=/opt/be-BOP-tooling/kuma-venv/bin/python
    log_info "Configuring Kuma notification channels (SMTP + Zulip)..."
    # Pass the env explicitly through `env` so the Python child sees them,
    # whether host-bootstrap runs as root (most common — env passes naturally)
    # or via sudo (where env_reset would otherwise strip these).
    run_privileged env \
        SMTP_HOST="${SMTP_HOST:-}" \
        SMTP_PORT="${SMTP_PORT:-587}" \
        SMTP_USER="${SMTP_USER:-}" \
        SMTP_PASSWORD="${SMTP_PASSWORD:-}" \
        SMTP_FROM="${SMTP_FROM:-}" \
        SMTP_TO="${SMTP_TO:-}" \
        ZULIP_SITE="${ZULIP_SITE:-}" \
        ZULIP_BOT_EMAIL="${ZULIP_BOT_EMAIL:-}" \
        ZULIP_BOT_API_KEY="${ZULIP_BOT_API_KEY:-}" \
        ZULIP_STREAM="${ZULIP_STREAM:-bebop-tooling}" \
        ZULIP_TOPIC="${ZULIP_TOPIC:-kuma alerts}" \
        "$venv_python" "$cli" --url "$kuma_url" setup-notifications \
            --user "$KUMA_ADMIN_USER" --password "$KUMA_ADMIN_PASSWORD" \
        || log_warn "kuma: setup-notifications had issues (see output above)"
}

step_install_netdata() {
    if systemctl is-active --quiet netdata; then
        log_info "netdata already running ✓"
        return 0
    fi
    log_info "Enabling and starting netdata..."
    maybe_run run_privileged systemctl enable --now netdata
}

# === Netdata public reverse-proxy (optional, opt-in via secrets.env) ====
# When NETDATA_PUBLIC_HOSTNAME is set, expose the Netdata UI publicly
# behind nginx + Let's Encrypt + HTTP basic auth. The hostname must
# resolve under OVH_DNS_ZONE; we create the A record + cert via the
# OVH API, generate a random admin password, and configure the vhost.
step_setup_netdata_public_access() {
    if [[ -z "${NETDATA_PUBLIC_HOSTNAME:-}" ]]; then
        log_info "NETDATA_PUBLIC_HOSTNAME unset — Netdata stays local-only (SSH tunnel for access)"
        return 0
    fi
    if [[ "$DEFER_SECRETS" == "true" && -z "${OVH_APPLICATION_KEY:-}" ]]; then
        log_info "Skipping Netdata public access (--defer-secrets)"
        return 0
    fi
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[dry-run] would expose Netdata at https://${NETDATA_PUBLIC_HOSTNAME}/"
        return 0
    fi
    local zone="${OVH_DNS_ZONE:-}"
    local hostname="$NETDATA_PUBLIC_HOSTNAME"
    if [[ -z "$zone" ]]; then
        die "NETDATA_PUBLIC_HOSTNAME set but OVH_DNS_ZONE is empty"
    fi
    if [[ "$hostname" != *".${zone}" ]]; then
        die "NETDATA_PUBLIC_HOSTNAME=${hostname} must be within OVH_DNS_ZONE=${zone}"
    fi
    local sub="${hostname%.${zone}}"

    # 1. DNS A record (idempotent — ovh_dns_record_create returns the
    #    existing id if a matching record already exists).
    local host_ip
    host_ip="${BEBOP_HOST_IP:-}"
    if [[ -z "$host_ip" ]]; then
        host_ip=$(curl -sS --max-time 10 https://api.ipify.org 2>/dev/null || true)
    fi
    if [[ -z "$host_ip" || ! "$host_ip" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
        die "could not detect host public IP (set BEBOP_HOST_IP in env to override)"
    fi
    log_info "Ensuring DNS A record ${hostname} -> ${host_ip}..."
    ovh_dns_record_create "$sub" A "$host_ip" >/dev/null
    ovh_dns_zone_refresh

    # 2. TLS cert (single-domain, via our certbot --manual hooks).
    if run_privileged test -d /etc/letsencrypt/live/netdata-host; then
        log_info "Cert netdata-host already issued ✓"
    else
        local acme_email="${LE_OPERATOR_EMAIL:-${ADMIN_EMAIL:-}}"
        if [[ -z "$acme_email" ]]; then
            log_warn "No LE_OPERATOR_EMAIL (or ADMIN_EMAIL) — Netdata cert NOT issued"
            log_warn "Set LE_OPERATOR_EMAIL in secrets.env and re-run this script to finish"
            return 0
        fi
        local hooks_dir="${SCRIPT_DIR}/hooks"
        if [[ ! -d "$hooks_dir" ]]; then
            hooks_dir="${BEBOP_TOOLING_INSTALL_PREFIX}/hooks"
        fi
        log_info "Issuing Let's Encrypt cert for ${hostname} (DNS-01 via OVH hooks)..."
        run_privileged certbot certonly \
            --manual \
            --preferred-challenges dns-01 \
            --manual-auth-hook "${hooks_dir}/certbot-ovh-auth.sh" \
            --manual-cleanup-hook "${hooks_dir}/certbot-ovh-cleanup.sh" \
            --non-interactive --agree-tos \
            --email "$acme_email" \
            --cert-name netdata-host \
            -d "$hostname"
    fi

    # 3. Basic-auth credentials. Persist them so re-runs reuse the same.
    local admin_file=/etc/be-BOP-tooling/netdata-admin.env
    local user="netdata-admin" pass=""
    if [[ -f "$admin_file" ]]; then
        # shellcheck disable=SC1090
        source "$admin_file"
        user="${NETDATA_ADMIN_USER:-netdata-admin}"
        pass="${NETDATA_ADMIN_PASSWORD:-}"
    fi
    if [[ -z "$pass" ]]; then
        pass=$(openssl rand -base64 33 | tr -d '+/=\n' | head -c 32)
        local tmp
        tmp=$(mktemp)
        cat > "$tmp" <<EOF
# Auto-generated by host-bootstrap.sh — DO NOT edit by hand.
NETDATA_ADMIN_USER="${user}"
NETDATA_ADMIN_PASSWORD="${pass}"
EOF
        run_privileged install -m 0600 "$tmp" "$admin_file"
        rm -f "$tmp"
        log_info "Generated Netdata admin credentials → ${admin_file} (mode 0600)"
    else
        log_info "Reusing existing Netdata admin credentials from ${admin_file}"
    fi

    # 4. nginx htpasswd file.
    if ! command -v htpasswd >/dev/null 2>&1; then
        die "htpasswd not installed (apache2-utils) — cannot configure Netdata basic auth"
    fi
    log_info "Writing /etc/nginx/.netdata-htpasswd..."
    run_privileged htpasswd -B -b -c /etc/nginx/.netdata-htpasswd "$user" "$pass" >/dev/null
    run_privileged chmod 0640 /etc/nginx/.netdata-htpasswd
    run_privileged chown root:www-data /etc/nginx/.netdata-htpasswd 2>/dev/null || true

    # 5. nginx vhost.
    log_info "Installing nginx vhost for ${hostname}..."
    local tmpl="${BEBOP_TOOLING_TEMPLATE_DIR}/nginx-netdata.conf.tmpl"
    local rev="2026050601"
    local tmp
    tmp=$(mktemp)
    sed -e "s|@netdata_hostname@|${hostname}|g" \
        -e "s|@template_revision@|${rev}|g" \
        "$tmpl" > "$tmp"
    run_privileged install -m 0644 "$tmp" /etc/nginx/sites-available/netdata.conf
    run_privileged ln -sfn /etc/nginx/sites-available/netdata.conf /etc/nginx/sites-enabled/netdata.conf
    rm -f "$tmp"

    if ! run_privileged nginx -t 2>/dev/null; then
        die "nginx -t failed after installing the netdata vhost"
    fi
    run_privileged systemctl reload nginx
    log_info "Netdata public access ready at https://${hostname}/ (creds in ${admin_file})"
}

# === Kuma public reverse-proxy (optional, opt-in via secrets.env) =======
# When KUMA_PUBLIC_HOSTNAME is set, expose the Uptime Kuma UI publicly
# behind nginx + Let's Encrypt. No extra basic-auth — Kuma has its own
# admin login (auto-provisioned at /etc/be-BOP-tooling/kuma-admin.env).
step_setup_kuma_public_access() {
    if [[ -z "${KUMA_PUBLIC_HOSTNAME:-}" ]]; then
        log_info "KUMA_PUBLIC_HOSTNAME unset — Kuma stays local-only (SSH tunnel for access)"
        return 0
    fi
    if [[ "$DEFER_SECRETS" == "true" && -z "${OVH_APPLICATION_KEY:-}" ]]; then
        log_info "Skipping Kuma public access (--defer-secrets)"
        return 0
    fi
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[dry-run] would expose Kuma at https://${KUMA_PUBLIC_HOSTNAME}/"
        return 0
    fi
    local zone="${OVH_DNS_ZONE:-}"
    local hostname="$KUMA_PUBLIC_HOSTNAME"
    if [[ -z "$zone" ]]; then
        die "KUMA_PUBLIC_HOSTNAME set but OVH_DNS_ZONE is empty"
    fi
    if [[ "$hostname" != *".${zone}" ]]; then
        die "KUMA_PUBLIC_HOSTNAME=${hostname} must be within OVH_DNS_ZONE=${zone}"
    fi
    local sub="${hostname%.${zone}}"

    # 1. DNS A record (idempotent).
    local host_ip="${BEBOP_HOST_IP:-}"
    if [[ -z "$host_ip" ]]; then
        host_ip=$(curl -sS --max-time 10 https://api.ipify.org 2>/dev/null || true)
    fi
    if [[ -z "$host_ip" || ! "$host_ip" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
        die "could not detect host public IP (set BEBOP_HOST_IP in env to override)"
    fi
    log_info "Ensuring DNS A record ${hostname} -> ${host_ip}..."
    ovh_dns_record_create "$sub" A "$host_ip" >/dev/null
    ovh_dns_zone_refresh

    # 2. TLS cert (single-domain, via certbot --manual + our hooks).
    if run_privileged test -d /etc/letsencrypt/live/kuma-host; then
        log_info "Cert kuma-host already issued ✓"
    else
        local acme_email="${LE_OPERATOR_EMAIL:-${ADMIN_EMAIL:-}}"
        if [[ -z "$acme_email" ]]; then
            log_warn "No LE_OPERATOR_EMAIL (or ADMIN_EMAIL) — Kuma cert NOT issued"
            log_warn "Set LE_OPERATOR_EMAIL in secrets.env and re-run this script to finish"
            return 0
        fi
        local hooks_dir="${SCRIPT_DIR}/hooks"
        if [[ ! -d "$hooks_dir" ]]; then
            hooks_dir="${BEBOP_TOOLING_INSTALL_PREFIX}/hooks"
        fi
        log_info "Issuing Let's Encrypt cert for ${hostname} (DNS-01 via OVH hooks)..."
        run_privileged certbot certonly \
            --manual \
            --preferred-challenges dns-01 \
            --manual-auth-hook "${hooks_dir}/certbot-ovh-auth.sh" \
            --manual-cleanup-hook "${hooks_dir}/certbot-ovh-cleanup.sh" \
            --non-interactive --agree-tos \
            --email "$acme_email" \
            --cert-name kuma-host \
            -d "$hostname"
    fi

    # 3. nginx vhost.
    log_info "Installing nginx vhost for ${hostname}..."
    local tmpl="${BEBOP_TOOLING_TEMPLATE_DIR}/nginx-kuma.conf.tmpl"
    local rev="2026050601"
    local tmp
    tmp=$(mktemp)
    sed -e "s|@kuma_hostname@|${hostname}|g" \
        -e "s|@kuma_host_port@|${UPTIME_KUMA_HOST_PORT}|g" \
        -e "s|@template_revision@|${rev}|g" \
        "$tmpl" > "$tmp"
    run_privileged install -m 0644 "$tmp" /etc/nginx/sites-available/kuma.conf
    run_privileged ln -sfn /etc/nginx/sites-available/kuma.conf /etc/nginx/sites-enabled/kuma.conf
    rm -f "$tmp"

    if ! run_privileged nginx -t 2>/dev/null; then
        die "nginx -t failed after installing the kuma vhost"
    fi
    run_privileged systemctl reload nginx
    log_info "Kuma public access ready at https://${hostname}/ (login with creds in /etc/be-BOP-tooling/kuma-admin.env)"
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
  MongoDB:    $(mongod --version 2>/dev/null | head -1 || echo '?')
  mongosh:    $(mongosh --version 2>/dev/null || echo '?')
  Garage:     v${GARAGE_VERSION}
  phoenixd:   ${PHOENIXD_VERSION}
  certbot:    $(certbot --version 2>/dev/null || echo '?')
  docker:     $(docker --version 2>/dev/null || echo '?')

Key paths:
  Tenant registry        /var/lib/be-BOP/tenants.tsv
  Per-tenant config      /etc/be-BOP/<tenant>/config.env
  Per-tenant releases    /var/lib/be-BOP/<tenant>/releases/
  Per-tenant mongod      /var/lib/be-BOP-mongodb/<tenant>/   (state)
                         /etc/be-BOP-mongodb/<tenant>/port.env
  Phoenixd data          /var/lib/phoenixd/<tenant>/.phoenix/
  Garage state           /var/lib/garage/{meta,data}/
  Secrets                ${SECRETS_FILE}    (mode 0600)
  Certbot OVH hooks      ${BEBOP_TOOLING_INSTALL_PREFIX}/hooks/   (read OVH creds from secrets.env)
  Template units         /etc/systemd/system/{bebop,phoenixd,mongod}@.service
  Tooling libs           ${BEBOP_TOOLING_INSTALL_PREFIX}/lib/

Services running:
  garage.service (single-instance, mutualised)
  nginx.service (catch-all 444; per-tenant vhosts added by add-tenant.sh)
  netdata.service
  bebop-uptime-kuma (Docker, bound to 127.0.0.1:${UPTIME_KUMA_HOST_PORT})

NEXT STEPS:
EOF
    if [[ "$DEFER_SECRETS" == "true" && -z "${OVH_APPLICATION_KEY:-}" ]]; then
        cat <<EOF
  0. Edit ${SECRETS_FILE} (mode 0600), then re-run:
       sudo ${BEBOP_TOOLING_INSTALL_PREFIX}/host-bootstrap.sh
     This will install OVH cert credentials, verify connectivity, and
     auto-provision the Kuma admin + notification channels.
EOF
    fi
    cat <<EOF
  1. Add your first tenant:
       add-tenant.sh tenant1 --admin-email merchant1@example.com

  Optional — if you want to log in to the Kuma UI to view dashboards,
  the auto-generated admin credentials are at /etc/be-BOP-tooling/kuma-admin.env
  (mode 0600). Reach the UI via:
       ssh -L ${UPTIME_KUMA_HOST_PORT}:localhost:${UPTIME_KUMA_HOST_PORT} this-host
       open http://localhost:${UPTIME_KUMA_HOST_PORT}

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
    step_install_mongodb
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

    step_remove_legacy_ovh_ini
    step_install_template_units
    step_install_tooling_libs_and_scripts
    step_init_registry

    step_setup_docker
    step_install_uptime_kuma
    step_install_kuma_python_env
    step_setup_kuma_admin
    step_setup_kuma_notifications
    step_install_netdata
    step_setup_netdata_public_access
    step_setup_kuma_public_access

    step_print_summary
}

main "$@"
