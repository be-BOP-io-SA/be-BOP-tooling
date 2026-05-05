#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 be-bop.io contributors
#
# install.sh — one-shot bootstrap for the be-BOP multi-tenant tooling.
#
# Mirrors the v1 wizard distribution model (single command, blank VPS to
# ready-to-configure host). Only requires curl and tar (both shipped in
# Debian 12 base) — no pre-installation of git or anything else needed.
#
# Usage (PoC — TODO: switch to https://be-bop.io/saas/install.sh once configured):
#   curl -sfSL \
#     https://raw.githubusercontent.com/Tirodem/be-BOP-tooling/multitenant-poc/multitenant-tooling/install.sh \
#     -o install.sh \
#     && sudo bash ./install.sh
#
# What it does, in order:
#   1. Verifies curl and tar are available; refuses to run as non-root.
#   2. Downloads the multitenant-poc branch tarball from GitHub.
#   3. Installs the multitenant-tooling/ subtree to /opt/be-BOP-tooling/.
#   4. Seeds /etc/be-BOP-tooling/secrets.env from the template (if missing).
#   5. Runs host-bootstrap.sh --defer-secrets — provisions everything that
#      does not need OVH credentials (apt packages, Node, Garage, phoenixd,
#      nginx catch-all, docker, Uptime Kuma, netdata, systemd units, …).
#   6. Opens secrets.env in $EDITOR / nano (if a TTY is attached).
#   7. Prints the next-step command: re-run host-bootstrap.sh to finalise.
#
# Re-run safe: every step is idempotent.
#
# Extra args are forwarded to host-bootstrap.sh (e.g. --dry-run, --verbose).

set -eEuo pipefail

readonly REPO="${BEBOP_TOOLING_REPO:-Tirodem/be-BOP-tooling}"
readonly REF="${BEBOP_TOOLING_REF:-multitenant-poc}"
readonly INSTALL_DIR="${BEBOP_TOOLING_INSTALL_DIR:-/opt/be-BOP-tooling}"
readonly SECRETS_DIR="/etc/be-BOP-tooling"
readonly SECRETS_FILE="${SECRETS_DIR}/secrets.env"

log()  { printf '[install] %s\n' "$*"; }
warn() { printf '[install] WARN: %s\n' "$*" >&2; }
die()  { printf '[install] FATAL: %s\n' "$*" >&2; exit 1; }

# 1. Prerequisites — curl and tar should be in Debian base; bail with a
# clear message if they aren't.
for tool in curl tar; do
    command -v "$tool" >/dev/null 2>&1 \
        || die "'$tool' is required but not installed (apt-get install -y $tool)"
done

if (( EUID != 0 )); then
    die "this installer must run as root (use sudo)"
fi

# 2. Download + extract tarball.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

log "Downloading be-BOP multi-tenant tooling (${REPO}@${REF})..."
url="https://github.com/${REPO}/archive/refs/heads/${REF}.tar.gz"
if ! curl -sfSL --connect-timeout 10 --max-time 300 -o "${tmp}/tooling.tar.gz" "$url"; then
    die "could not download ${url}"
fi
tar -xz -C "$tmp" -f "${tmp}/tooling.tar.gz"

# The archive top-level dir is repo-${ref-with-slashes-replaced}; locate it
# defensively rather than assuming the exact name.
extracted_root=$(find "$tmp" -mindepth 1 -maxdepth 1 -type d ! -name '.*' \
    -name "be-BOP-tooling-*" | head -n1)
if [[ -z "$extracted_root" || ! -d "${extracted_root}/multitenant-tooling" ]]; then
    die "tarball did not contain a multitenant-tooling/ directory"
fi

# 3. Install to /opt/be-BOP-tooling/.
log "Installing tooling to ${INSTALL_DIR}..."
install -d -m 0755 "$INSTALL_DIR"
cp -a "${extracted_root}/multitenant-tooling/." "${INSTALL_DIR}/"
chmod 0755 \
    "${INSTALL_DIR}/host-bootstrap.sh" \
    "${INSTALL_DIR}/add-tenant.sh" \
    "${INSTALL_DIR}/remove-tenant.sh" \
    "${INSTALL_DIR}/upgrade-tenant.sh" \
    "${INSTALL_DIR}/upgrade-all.sh" \
    "${INSTALL_DIR}/install.sh" 2>/dev/null || true

# 4. Seed secrets.env from template if absent.
install -d -m 0700 "$SECRETS_DIR"
if [[ -f "$SECRETS_FILE" ]]; then
    log "${SECRETS_FILE} already exists — leaving it alone"
else
    install -m 0600 \
        "${INSTALL_DIR}/templates/secrets.env.example" \
        "$SECRETS_FILE"
    log "Created ${SECRETS_FILE} (mode 0600)"
fi

# 5. Run host-bootstrap.sh in deferred-secrets mode. Forward any extra args
# the operator passed (e.g. --dry-run, --verbose).
log "Running host-bootstrap.sh --defer-secrets..."
"${INSTALL_DIR}/host-bootstrap.sh" --defer-secrets "$@"

# 6. Open secrets.env in the operator's editor if interactive.
editor="${EDITOR:-nano}"
if [[ -t 0 && -t 1 ]] && command -v "$editor" >/dev/null 2>&1; then
    log "Opening ${SECRETS_FILE} in ${editor}..."
    "$editor" "$SECRETS_FILE"
else
    warn "non-interactive shell — edit ${SECRETS_FILE} manually before continuing"
fi

# 7. Final instructions.
cat <<EOF

==========================================================================
  be-BOP multi-tenant tooling installed
==========================================================================

  Tooling:    ${INSTALL_DIR}/
  Secrets:    ${SECRETS_FILE}

NEXT STEPS:

  1. (If you skipped editing secrets above) edit secrets:
       sudo \$EDITOR ${SECRETS_FILE}

  2. Finalise the host bootstrap (idempotent — only runs the
     OVH-credential steps that were deferred):
       sudo ${INSTALL_DIR}/host-bootstrap.sh

  3. Add your first tenant:
       sudo add-tenant.sh tenant1 --admin-email merchant@example.com

Documentation: ${INSTALL_DIR}/README.md
==========================================================================
EOF
