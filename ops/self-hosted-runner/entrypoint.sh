#!/usr/bin/env bash
set -euo pipefail

: "${RUNNER_REPOSITORY:?RUNNER_REPOSITORY is required}"
: "${RUNNER_NAME:?RUNNER_NAME is required}"

runner_labels=${RUNNER_LABELS:-kyyn-connectors-ci}
runner_url="https://github.com/${RUNNER_REPOSITORY}"

mkdir -p "$HOME" "$CARGO_HOME" "$CARGO_TARGET_DIR" "$RUSTUP_HOME"

if [[ ! -x /runner/run.sh ]]; then
  cp -a /opt/actions-runner/. /runner/
fi

if [[ ! -x "$CARGO_HOME/bin/rustup" ]]; then
  rustup-init -y --no-modify-path --default-toolchain none
fi

if [[ ! -f /runner/.runner ]]; then
  : "${RUNNER_TOKEN:?RUNNER_TOKEN is required for first registration}"
  /runner/config.sh \
    --unattended \
    --replace \
    --url "$runner_url" \
    --token "$RUNNER_TOKEN" \
    --name "$RUNNER_NAME" \
    --labels "$runner_labels" \
    --work /runner/_work
fi

unset RUNNER_TOKEN
exec /runner/run.sh
