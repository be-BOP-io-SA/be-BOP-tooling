# be-BOP-tooling

A great set of official tools for be-BOP.

This repository contains several utilities used to install, configure, and
operate a be-BOP instance.

## be-bop-bootstrap

This is a single-file installer that users run with `curl` to set up be-BOP on a
new server. It is built as part of the release process from the contents of the
`be-bop-bootstrap/` directory. When a user runs the script, it unpacks the
bundle into a temporary location and starts **be-bop-wizard**. The resulting
script is a drop-in replacement for the `be-bop-wizard`.

## Release process

A `justfile` is provided at the root of this repository.
Running `just build` creates the release artifacts in the `dist/` directory.
