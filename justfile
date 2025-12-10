# Directory where release artifacts are written
DIST_DIR := "dist"

# Release metadata
GIT_COMMIT_HASH := `git rev-parse --short HEAD`
COMMIT_DATE := `git log -1 --date=format:%F --pretty=format:%cd`
ARTIFACT_NAME := "be-BOP Bootstrap " + COMMIT_DATE + "-" + GIT_COMMIT_HASH

default: clean release

target_directory:
    @echo "==> Creating release directory"
    mkdir -p "{{DIST_DIR}}"

wizard: target_directory
    @echo "==> Building be-bop-wizard.sh (be-BOP bootstrap)"
    makeself \
        --keep-umask \
        --nox11 \
        "be-bop-bootstrap" \
        "{{DIST_DIR}}/be-bop-wizard.sh" \
        "{{ARTIFACT_NAME}}" \
        ./be-bop-wizard.sh

release: wizard
    @echo "==> Release build complete"
    @echo "Artifacts available in: {{DIST_DIR}}"

clean:
    @echo "==> Cleaning release artifacts"
    rm -rf "{{DIST_DIR}}"
