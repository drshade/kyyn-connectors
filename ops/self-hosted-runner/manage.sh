#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
runner_dir="$repo_root/ops/self-hosted-runner"
image=localhost/kyyn-actions-runner:2.336.0
repository=drshade/kyyn-connectors
runner_name=endor-kyyn-connectors-ci
service=kyyn-connectors-ci-runner.service

build() {
  podman build --pull=never --tag "$image" --file "$runner_dir/Containerfile" "$runner_dir"
}

install_quadlets() {
  podman quadlet install --replace \
    "$runner_dir/kyyn-connectors-ci-cache.volume" \
    "$runner_dir/kyyn-connectors-ci-state.volume" \
    "$runner_dir/kyyn-connectors-ci-runner.container"
}

register() {
  token=$(gh api --method POST "repos/$repository/actions/runners/registration-token" --jq .token)
  test -n "$token"
  printf '%s' "$token" | podman secret create --replace kyyn-connectors-ci-registration-token - >/dev/null
  unset token
  systemctl --user restart "$service"

  for _ in $(seq 1 60); do
    status=$(gh api "repos/$repository/actions/runners" \
      --jq ".runners[] | select(.name == \"$runner_name\") | .status" | head -n1)
    if [[ "$status" == online ]]; then
      echo "self-hosted-runner: $runner_name is online"
      return 0
    fi
    sleep 2
  done

  echo "self-hosted-runner: $runner_name did not become online" >&2
  systemctl --user status "$service" --no-pager >&2 || true
  return 1
}

status() {
  systemctl --user status "$service" --no-pager
  gh api "repos/$repository/actions/runners" \
    --jq ".runners[] | select(.name == \"$runner_name\") | {name, status, busy, labels: [.labels[].name]}"
}

case "${1:-}" in
  build)
    build
    ;;
  install)
    install_quadlets
    ;;
  register)
    register
    ;;
  bootstrap)
    build
    install_quadlets
    register
    ;;
  status)
    status
    ;;
  *)
    echo "usage: $0 {build|install|register|bootstrap|status}" >&2
    exit 2
    ;;
esac
