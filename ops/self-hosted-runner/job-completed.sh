#!/usr/bin/env bash
set -euo pipefail

# The runner distribution and its registration live beside _work. Remove only
# completed-job material; Cargo/rustup/target caches are separate named volumes.
if [[ -d /runner/_work ]]; then
  find /runner/_work -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
fi
