#!/usr/bin/env bash
# Reproducibly build the committed kyyn:tap@1 guest components. Component
# construction is a trusted release activity; Kyyn consumers execute only
# the committed, digest-pinned artifacts.
set -euo pipefail

update=false
case "${1:-}" in
  "") ;;
  --update) update=true ;;
  *) echo "usage: $0 [--update]" >&2; exit 2 ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repro="$(mktemp -d -p /tmp kyyn-plugins-repro.XXXXXX)"
trap 'case "$repro" in /tmp/kyyn-plugins-repro.*) rm -rf -- "$repro" ;; esac' EXIT

cargo_home="${CARGO_HOME:-${HOME}/.cargo}"
rust_sysroot="$(rustc --print sysroot)"
remap="--remap-path-prefix=${repo_root}=/workspace \
--remap-path-prefix=${cargo_home}=/cargo \
--remap-path-prefix=${rust_sysroot}=/rust \
-C metadata=kyyn-first-party-tap-v1"

guests="sweep git-repo kb pack salesforce"
packages=""
for guest in $guests; do
  packages="$packages -p kyyn-component-$guest"
done

CARGO_TARGET_DIR="$repro" RUSTFLAGS="$remap" \
  cargo build --locked --quiet --release --target wasm32-unknown-unknown $packages
CARGO_TARGET_DIR="$repro" RUSTFLAGS="$remap" \
  cargo clippy --locked --quiet --release --target wasm32-unknown-unknown \
    $packages -- -D warnings

mkdir -p "$repo_root/components"
failed=false
for guest in $guests; do
  crate_name="${guest//-/_}"
  core="$repro/wasm32-unknown-unknown/release/kyyn_component_${crate_name}.wasm"
  built="$repro/${guest}.wasm"
  cargo run --locked --quiet -p kyyn-plugin-componentize -- "$core" "$built"

  leaked="$(LC_ALL=C strings "$built" | grep -E '(/home/|/Users/|\.cargo[/\\]|\.rustup[/\\])' || true)"
  test -z "$leaked" || {
    echo "$guest: component embeds host paths:" >&2
    echo "$leaked" >&2
    exit 1
  }

  committed="$repo_root/components/${guest}.wasm"
  digest="$(sha256sum "$built" | cut -d' ' -f1)"
  if $update; then
    cp "$built" "$committed"
    echo "updated components/${guest}.wasm ($digest)"
  elif ! cmp -s "$built" "$committed"; then
    echo "$guest: committed component is stale (rebuilt $digest)" >&2
    echo "  run scripts/check-components.sh --update and re-pin kyyn-tap.ron" >&2
    failed=true
  fi
done
$failed && exit 1

if $update; then
  echo "components updated — re-pin component_sha256 in kyyn-tap.ron:"
  for guest in $guests; do
    printf '  %-10s %s\n' \
      "$guest" \
      "$(sha256sum "$repo_root/components/${guest}.wasm" | cut -d' ' -f1)"
  done
fi
echo "components: kyyn:tap@1 guests compile and componentize reproducibly"
