# Directory where release artifacts are written
DIST_DIR := "dist"

default: clean release

target_directory:
    @echo "==> Creating release directory"
    mkdir -p "{{DIST_DIR}}"

wizard: target_directory
    @echo "==> Copying be-bop-wizard.sh"
    cp be-bop-wizard/be-bop-wizard.sh "{{DIST_DIR}}/be-bop-wizard.sh"

release: wizard
    @echo "==> Release build complete"
    @echo "Artifacts available in: {{DIST_DIR}}"

clean:
    @echo "==> Cleaning release artifacts"
    rm -rf "{{DIST_DIR}}"
