#!/usr/bin/env bash
# Keep host-specific path remaps out of Cargo's crate-identity calculation.
# Cargo sees only the fixed RUSTFLAGS in check-components.sh; this wrapper
# adds the dynamic prefixes after Cargo has selected dependency hashes.
set -euo pipefail

rustc="$1"
shift
repo_root="${KYYN_REPRO_REPO_ROOT:?missing reproducible-build repository root}"
cargo_home="${CARGO_HOME:-${HOME}/.cargo}"
rust_sysroot="$("$rustc" --print sysroot)"

exec "$rustc" "$@" \
  "--remap-path-prefix=${repo_root}=/workspace" \
  "--remap-path-prefix=${cargo_home}=/cargo" \
  "--remap-path-prefix=${rust_sysroot}=/rust"
