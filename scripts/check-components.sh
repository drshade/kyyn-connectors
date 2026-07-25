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

# rustc's final wasm layout is sensitive to the lexical sysroot path even
# when every embedded path is remapped. Give all builders the same relative
# sysroot spelling while keeping the installed toolchain itself read-only.
rust_sysroot="$(rustc --print sysroot)"
rust_release="$(rustc -vV | sed -n 's/^release: //p')"
rust_host="$(rustc -vV | sed -n 's/^host: //p')"
case "${rust_release}-${rust_host}" in
  *[!A-Za-z0-9._-]*) echo "unsafe Rust toolchain identity" >&2; exit 1 ;;
esac
stable_sysroot="/tmp/kyyn-component-sysroot-${rust_release}-${rust_host}"
if test -e "$stable_sysroot" || test -L "$stable_sysroot"; then
  stable_release="$("$stable_sysroot/bin/rustc" -vV 2>/dev/null | sed -n 's/^release: //p')"
  stable_host="$("$stable_sysroot/bin/rustc" -vV 2>/dev/null | sed -n 's/^host: //p')"
  if test "$stable_release" != "$rust_release" || test "$stable_host" != "$rust_host"; then
    echo "$stable_sysroot is not the expected Rust toolchain; remove it and retry" >&2
    exit 1
  fi
else
  ln -s "$rust_sysroot" "$stable_sysroot"
fi

guests="sweep git-repo kb pack salesforce graph-calendar graph-mail graph-chats graph-meetings sharepoint-file"
packages=""
for guest in $guests; do
  packages="$packages -p kyyn-component-$guest"
done

(
  cd "$repo_root"
  export CARGO_TARGET_DIR="$repro"
  export KYYN_REPRO_REPO_ROOT="$repo_root"
  export RUSTC_WRAPPER="./scripts/repro-rustc.sh"
  export RUSTFLAGS="--sysroot=${stable_sysroot} \
--remap-path-prefix=${stable_sysroot}=/rust \
-C metadata=kyyn-first-party-tap-v1"
  cargo build --locked --quiet --release --target wasm32-unknown-unknown $packages
  cargo clippy --locked --quiet --release --target wasm32-unknown-unknown \
      $packages -- -D warnings
)

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
