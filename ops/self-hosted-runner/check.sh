#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

workflow=.github/workflows/check.yml
runner=ops/self-hosted-runner

grep -q '^  workflow_dispatch:' "$workflow"
grep -Fq '["self-hosted","linux","x64","kyyn-connectors-ci"]' "$workflow"
grep -q 'inputs.hosted == true' "$workflow"
grep -q '^USER runner$' "$runner/Containerfile"
grep -q '^ReadOnly=true$' "$runner/kyyn-connectors-ci-runner.container"
grep -q -- '--cap-drop=all' "$runner/kyyn-connectors-ci-runner.container"
grep -q -- '--security-opt=no-new-privileges' "$runner/kyyn-connectors-ci-runner.container"
grep -q '^Environment=RUNNER_REPOSITORY=drshade/kyyn-connectors$' "$runner/kyyn-connectors-ci-runner.container"
grep -q 'ACTIONS_RUNNER_HOOK_JOB_COMPLETED=' "$runner/Containerfile"

for script in entrypoint.sh job-completed.sh manage.sh; do
  bash -n "$runner/$script"
done

if rg -n '/var/run/docker\.sock|podman\.sock|Volume=.*(/home|/run/user)' \
  "$runner/Containerfile" \
  "$runner/entrypoint.sh" \
  "$runner/job-completed.sh" \
  "$runner/manage.sh" \
  "$runner/kyyn-connectors-ci-runner.container"; then
  echo "self-hosted-runner: forbidden host authority is mounted" >&2
  exit 1
fi

echo "self-hosted-runner: rootless repository-scoped contract verified"
