# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 be-bop.io contributors
#
# release.sh — download and install be-BOP releases per tenant.
#
# A "release" is a GitHub release on $BEBOP_GITHUB_REPO whose asset matches
# the pattern  be-BOP\.release\.YYYY-MM-DD\.<sha>(.*)?\.zip . The release tag
# itself is the same string without the .zip extension (e.g.
# "be-BOP.release.2026-04-15.abc1234"). The string "latest" resolves to the
# most recent published release.
#
# Per-tenant filesystem layout (created by add-tenant.sh):
#   /var/lib/be-BOP/<tenant>/releases/<tag>/        unpacked release tree
#   /var/lib/be-BOP/<tenant>/releases/current       → symlink to active tag
#
# Source AFTER lib/log.sh and lib/sudo.sh.
# Requires: curl, jq, unzip, pnpm.

[[ -n "${_BEBOP_RELEASE_SOURCED:-}" ]] && return 0
readonly _BEBOP_RELEASE_SOURCED=1

: "${BEBOP_GITHUB_REPO:=be-BOP-io-SA/be-BOP}"
readonly _BEBOP_RELEASE_ASSET_RE='^be-BOP\.release\.[0-9]{4}-[0-9]{2}-[0-9]{2}\.[a-f0-9]+.*\.zip$'

# release_resolve_version <version_arg>
# - "latest" → most recent release tag
# - any other string is taken as a concrete tag and validated to exist
# Outputs the resolved tag on stdout.
release_resolve_version() {
    local arg="$1"
    if [[ "$arg" != "latest" && -n "$arg" ]]; then
        # Validate that the tag exists.
        if ! curl -sS --fail --max-time 30 \
            "https://api.github.com/repos/${BEBOP_GITHUB_REPO}/releases/tags/${arg}" \
            >/dev/null ; then
            die "release_resolve_version: tag '${arg}' not found in ${BEBOP_GITHUB_REPO}"
        fi
        printf '%s\n' "$arg"
        return 0
    fi
    # "latest" — pull the first release with a matching asset.
    local resp
    resp=$(curl -sS --fail --max-time 30 \
        "https://api.github.com/repos/${BEBOP_GITHUB_REPO}/releases?per_page=20") \
        || die "release_resolve_version: GitHub API request failed"
    local tag
    tag=$(printf '%s' "$resp" \
        | jq -r --arg re "$_BEBOP_RELEASE_ASSET_RE" \
            '[.[] | select(.assets[]?.name | test($re))] | .[0].tag_name // empty')
    if [[ -z "$tag" ]]; then
        die "release_resolve_version: no release with a matching be-BOP asset found"
    fi
    printf '%s\n' "$tag"
}

# release_get_asset_url <tag>
# Outputs the browser_download_url for the be-BOP zip asset of <tag>.
release_get_asset_url() {
    local tag="$1"
    local resp
    resp=$(curl -sS --fail --max-time 30 \
        "https://api.github.com/repos/${BEBOP_GITHUB_REPO}/releases/tags/${tag}") \
        || die "release_get_asset_url: failed to fetch release ${tag}"
    local url
    url=$(printf '%s' "$resp" \
        | jq -r --arg re "$_BEBOP_RELEASE_ASSET_RE" \
            '.assets[] | select(.name | test($re)) | .browser_download_url' \
        | head -1)
    if [[ -z "$url" ]]; then
        die "release_get_asset_url: no matching asset on release ${tag}"
    fi
    printf '%s\n' "$url"
}

# release_dir <tenant_id> <tag>
release_dir() {
    printf '/var/lib/be-BOP/%s/releases/%s' "$1" "$2"
}

# release_download_and_extract <tenant_id> <tag>
# Idempotent: if the release dir already exists with a marker, no-op.
release_download_and_extract() {
    local tenant="$1" tag="$2"
    local target_dir
    target_dir=$(release_dir "$tenant" "$tag")
    if [[ -f "${target_dir}/.bebop_install_success" ]]; then
        log_info "release: ${tag} already extracted at ${target_dir}"
        return 0
    fi
    local url
    url=$(release_get_asset_url "$tag")
    log_info "release: downloading ${tag} from ${url}"
    local tmp
    tmp=$(mktemp -d)
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" RETURN
    if ! curl -fsSL --connect-timeout 10 --max-time 600 -o "${tmp}/release.zip" "$url"; then
        die "release: download failed for ${tag}"
    fi
    ( cd "$tmp" && unzip -q release.zip ) \
        || die "release: unzip failed for ${tag}"
    # Released archive contains a single top-level directory matching the tag.
    local extracted
    extracted=$(find "$tmp" -mindepth 1 -maxdepth 1 -type d ! -name 'release.zip' | head -1)
    if [[ -z "$extracted" ]]; then
        die "release: archive ${tag} has no top-level directory"
    fi
    run_privileged install -d -m 0755 "$(dirname "$target_dir")"
    # Move the extracted tree into place.
    run_privileged rm -rf "$target_dir"
    run_privileged mv "$extracted" "$target_dir"
    run_privileged chown -R root:root "$target_dir"
    run_privileged find "$target_dir" -type d -exec chmod 0755 {} +
    run_privileged find "$target_dir" -type f -exec chmod 0644 {} +
    rm -rf "$tmp"
    trap - RETURN
    log_info "release: extracted ${tag} into ${target_dir}"
}

# release_install_deps <tenant_id> <tag>
# Runs pnpm install --prod --frozen-lockfile inside the release dir.
release_install_deps() {
    local tenant="$1" tag="$2"
    local target_dir
    target_dir=$(release_dir "$tenant" "$tag")
    if [[ -f "${target_dir}/.bebop_install_success" ]]; then
        log_info "release: deps already installed for ${tag}"
        return 0
    fi
    log_info "release: pnpm install --prod --frozen-lockfile in ${target_dir}"
    # COREPACK_ENABLE_DOWNLOAD_PROMPT=0 silences corepack's interactive
    # confirmation when it auto-downloads the pnpm version pinned by
    # the be-BOP release's package.json (otherwise add-tenant.sh hangs
    # at phase 7 with "? Do you want to continue? [Y/n]").
    ( cd "$target_dir" && run_privileged env \
        HOME=/tmp COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
        pnpm install --prod --frozen-lockfile ) \
        || die "release: pnpm install failed for ${tag}"
    run_privileged touch "${target_dir}/.bebop_install_success"
    log_info "release: deps installed for ${tag}"
}

# release_activate <tenant_id> <tag>
# Atomically swaps the 'current' symlink. The caller is responsible for
# restarting the tenant's bebop@<tenant>.service afterwards.
release_activate() {
    local tenant="$1" tag="$2"
    local releases_dir="/var/lib/be-BOP/${tenant}/releases"
    local link="${releases_dir}/current"
    local target_dir
    target_dir=$(release_dir "$tenant" "$tag")
    [[ -d "$target_dir" ]] || die "release_activate: ${target_dir} does not exist"
    # Atomic swap via mv on a sibling temp link.
    local tmp_link="${releases_dir}/.current.$$"
    run_privileged ln -sfn "$tag" "$tmp_link"
    run_privileged mv -T "$tmp_link" "$link"
    log_info "release: ${tenant}/current → ${tag}"
}

# release_get_current_tag <tenant_id> → outputs the tag the symlink points to,
# or empty if no current release.
release_get_current_tag() {
    local tenant="$1"
    local link="/var/lib/be-BOP/${tenant}/releases/current"
    if [[ -L "$link" ]]; then
        readlink "$link"
    fi
}

# release_remove <tenant_id> <tag>
# Removes a release directory. Skips if it's the current one.
release_remove() {
    local tenant="$1" tag="$2"
    local target_dir
    target_dir=$(release_dir "$tenant" "$tag")
    [[ -d "$target_dir" ]] || return 0
    local current
    current=$(release_get_current_tag "$tenant")
    if [[ "$current" == "$tag" ]]; then
        die "release_remove: refusing to delete currently-active release '${tag}'"
    fi
    run_privileged rm -rf "$target_dir"
    log_info "release: removed ${target_dir}"
}
