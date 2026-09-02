#!/usr/bin/env bash
# Reproducibly build the committed direction-distinct guest components. Component
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
scratch_parent="${KYYN_COMPONENT_SCRATCH:-${CARGO_TARGET_DIR:-$repo_root/target}/component-repro}"
mkdir -p "$scratch_parent/sysroots"
repro="$(mktemp -d -p "$scratch_parent" kyyn-connectors-repro.XXXXXX)"
trap 'case "$repro" in "$scratch_parent"/kyyn-connectors-repro.*) rm -rf -- "$repro" ;; esac' EXIT

# rustc's final wasm layout is sensitive to the canonical target-sysroot path
# even when every embedded path is remapped. Copy the immutable wasm target
# libraries to a fixed path; a symlink is insufficient because rustc resolves
# it. Host-side build scripts and proc macros keep using the installed sysroot.
rust_sysroot="$(rustc --print sysroot)"
rust_release="$(rustc -vV | sed -n 's/^release: //p')"
rust_host="$(rustc -vV | sed -n 's/^host: //p')"
case "${rust_release}-${rust_host}" in
  *[!A-Za-z0-9._-]*) echo "unsafe Rust toolchain identity" >&2; exit 1 ;;
esac
stable_sysroot="$scratch_parent/sysroots/${rust_release}-${rust_host}"
stable_target="$stable_sysroot/lib/rustlib/wasm32-unknown-unknown"
installed_target="$rust_sysroot/lib/rustlib/wasm32-unknown-unknown"
exec 9>"$scratch_parent/sysroots.lock"
flock 9
if test -L "$stable_sysroot"; then
  echo "$stable_sysroot is a stale symlink; remove it and retry" >&2
  exit 1
fi
if test -e "$stable_sysroot"; then
  if ! test -d "$stable_target" || ! test -O "$stable_sysroot"; then
    echo "$stable_sysroot is not a build sysroot owned by this user" >&2
    exit 1
  fi
else
  staged_sysroot="$(mktemp -d -p "$scratch_parent" kyyn-component-sysroot-stage.XXXXXX)"
  mkdir -p "$staged_sysroot/lib/rustlib"
  cp -a "$installed_target" "$staged_sysroot/lib/rustlib/"
  mv "$staged_sysroot" "$stable_sysroot"
fi
flock -u 9

source_guests="sweep git-repo pack salesforce graph-calendar graph-mail graph-chats graph-meetings graph-org-meetings microsoft-files"
sink_guests="file-replace git-ref microsoft-file-replace"
connection_guests="microsoft-connection salesforce-connection"
configurator_guests="microsoft-files graph-population"
evidence_tool_guests="graph-message-as-text graph-member-observations graph-meeting-attendance graph-meeting-detail graph-meeting-occurrences graph-meeting-transcript"
source_packages=""
sink_packages=""
connection_packages=""
configurator_packages=""
evidence_tool_packages=""
for guest in $source_guests; do
  source_packages="$source_packages -p kyyn-component-$guest"
done
for guest in $evidence_tool_guests; do
  evidence_tool_packages="$evidence_tool_packages -p kyyn-evidence-tool-$guest"
done
for guest in $sink_guests; do
  sink_packages="$sink_packages -p kyyn-component-$guest"
done
for guest in $connection_guests; do
  connection_packages="$connection_packages -p kyyn-component-$guest"
done
for guest in $configurator_guests; do
  configurator_packages="$configurator_packages -p kyyn-configurator-$guest"
done

(
  cd "$repo_root"
  export CARGO_TARGET_DIR="$repro"
  export KYYN_REPRO_REPO_ROOT="$repo_root"
  export RUSTC_WRAPPER="./scripts/repro-rustc.sh"
  export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS="--sysroot=${stable_sysroot} \
--remap-path-prefix=${stable_sysroot}=/rust \
-C metadata=kyyn-first-party-source-v1"
  cargo build --locked --quiet --release --target wasm32-unknown-unknown $source_packages
  cargo clippy --locked --quiet --release --target wasm32-unknown-unknown \
      $source_packages -- -D warnings

  export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS="--sysroot=${stable_sysroot} \
--remap-path-prefix=${stable_sysroot}=/rust \
-C metadata=kyyn-first-party-sink-v1"
  cargo build --locked --quiet --release --target wasm32-unknown-unknown $sink_packages
  cargo clippy --locked --quiet --release --target wasm32-unknown-unknown \
      $sink_packages -- -D warnings

  export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS="--sysroot=${stable_sysroot} \
--remap-path-prefix=${stable_sysroot}=/rust \
-C metadata=kyyn-first-party-connection-v1"
  cargo build --locked --quiet --release --target wasm32-unknown-unknown $connection_packages
  cargo clippy --locked --quiet --release --target wasm32-unknown-unknown \
      $connection_packages -- -D warnings

  export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS="--sysroot=${stable_sysroot} \
--remap-path-prefix=${stable_sysroot}=/rust \
-C metadata=kyyn-first-party-configurator-v1"
  cargo build --locked --quiet --release --target wasm32-unknown-unknown $configurator_packages
  cargo clippy --locked --quiet --release --target wasm32-unknown-unknown \
      $configurator_packages -- -D warnings

  export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS="--sysroot=${stable_sysroot} \
--remap-path-prefix=${stable_sysroot}=/rust \
-C metadata=kyyn-first-party-evidence-tool-v1"
  cargo build --locked --quiet --release --target wasm32-unknown-unknown $evidence_tool_packages
  cargo clippy --locked --quiet --release --target wasm32-unknown-unknown \
      $evidence_tool_packages -- -D warnings
)

mkdir -p "$repo_root/components/sources"
mkdir -p "$repo_root/components/sinks"
mkdir -p "$repo_root/components/connections"
mkdir -p "$repo_root/components/configurators"
mkdir -p "$repo_root/components/evidence-tools"
failed=false
for guest in $source_guests $sink_guests $connection_guests; do
  crate_name="${guest//-/_}"
  core="$repro/wasm32-unknown-unknown/release/kyyn_component_${crate_name}.wasm"
  built="$repro/${guest}.wasm"
  cargo run --locked --quiet -p kyyn-connector-componentize -- "$core" "$built"

  leaked="$(LC_ALL=C strings "$built" | grep -E '(/home/|/Users/|\.cargo[/\\]|\.rustup[/\\])' || true)"
  test -z "$leaked" || {
    echo "$guest: component embeds host paths:" >&2
    echo "$leaked" >&2
    exit 1
  }

  case " $sink_guests " in
    *" $guest "*) direction=sinks ;;
    *) case " $connection_guests " in
         *" $guest "*) direction=connections ;;
         *) direction=sources ;;
       esac ;;
  esac
  committed="$repo_root/components/${direction}/${guest}.wasm"
  digest="$(sha256sum "$built" | cut -d' ' -f1)"
  if $update; then
    cp "$built" "$committed"
    echo "updated components/${direction}/${guest}.wasm ($digest)"
  elif ! cmp -s "$built" "$committed"; then
    echo "$guest: committed component is stale (rebuilt $digest)" >&2
    echo "  run scripts/check-components.sh --update and re-pin kyyn-connectors.ron" >&2
    failed=true
  fi
done
for guest in $configurator_guests; do
  crate_name="${guest//-/_}"
  core="$repro/wasm32-unknown-unknown/release/kyyn_configurator_${crate_name}.wasm"
  built="$repro/configurator-${guest}.wasm"
  cargo run --locked --quiet -p kyyn-connector-componentize -- "$core" "$built"

  leaked="$(LC_ALL=C strings "$built" | grep -E '(/home/|/Users/|\.cargo[/\\]|\.rustup[/\\])' || true)"
  test -z "$leaked" || {
    echo "configurator/$guest: component embeds host paths:" >&2
    echo "$leaked" >&2
    exit 1
  }

  committed="$repo_root/components/configurators/${guest}.wasm"
  digest="$(sha256sum "$built" | cut -d' ' -f1)"
  if $update; then
    cp "$built" "$committed"
    echo "updated components/configurators/${guest}.wasm ($digest)"
  elif ! cmp -s "$built" "$committed"; then
    echo "configurator/$guest: committed component is stale (rebuilt $digest)" >&2
    echo "  run scripts/check-components.sh --update and re-pin kyyn-connectors.ron" >&2
    failed=true
  fi
done
for guest in $evidence_tool_guests; do
  crate_name="${guest//-/_}"
  core="$repro/wasm32-unknown-unknown/release/kyyn_evidence_tool_${crate_name}.wasm"
  built="$repro/evidence-tool-${guest}.wasm"
  cargo run --locked --quiet -p kyyn-connector-componentize -- "$core" "$built"
  leaked="$(LC_ALL=C strings "$built" | grep -E '(/home/|/Users/|\.cargo[/\\]|\.rustup[/\\])' || true)"
  test -z "$leaked" || { echo "evidence-tool/$guest: component embeds host paths:" >&2; echo "$leaked" >&2; exit 1; }
  committed="$repo_root/components/evidence-tools/${guest}.wasm"
  digest="$(sha256sum "$built" | cut -d' ' -f1)"
  if $update; then
    cp "$built" "$committed"
    echo "updated components/evidence-tools/${guest}.wasm ($digest)"
  elif ! cmp -s "$built" "$committed"; then
    echo "evidence-tool/$guest: committed component is stale (rebuilt $digest)" >&2
    echo "  run scripts/check-components.sh --update and re-pin kyyn-connectors.ron" >&2
    failed=true
  fi
done
$failed && exit 1

if $update; then
  echo "components updated — re-pin component_sha256 in kyyn-connectors.ron:"
  for guest in $source_guests $sink_guests $connection_guests; do
    case " $sink_guests " in
      *" $guest "*) direction=sinks ;;
      *) case " $connection_guests " in
           *" $guest "*) direction=connections ;;
           *) direction=sources ;;
         esac ;;
    esac
    printf '  %-16s %s\n' \
      "$direction/$guest" \
      "$(sha256sum "$repo_root/components/${direction}/${guest}.wasm" | cut -d' ' -f1)"
  done
  for guest in $configurator_guests; do
    printf '  %-16s %s\n' \
      "configurators/$guest" \
      "$(sha256sum "$repo_root/components/configurators/${guest}.wasm" | cut -d' ' -f1)"
  done
  for guest in $evidence_tool_guests; do
    printf '  %-16s %s\n' \
      "evidence-tools/$guest" \
      "$(sha256sum "$repo_root/components/evidence-tools/${guest}.wasm" | cut -d' ' -f1)"
  done
fi
echo "components: source, sink, connection, configurator and evidence-tool guests compile and componentize reproducibly"
