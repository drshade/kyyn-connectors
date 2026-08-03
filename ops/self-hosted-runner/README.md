# Kyyn connectors self-hosted check runner

This rootless Podman runner supplies this repository's `make check` job while
hosted Actions minutes are unavailable. It is registered only to
`drshade/kyyn-connectors` and carries the custom `kyyn-connectors-ci` label.

The container runs as a non-root user with a read-only root filesystem, no Linux
capabilities, no privilege escalation, no host-directory mounts and no container
socket. Two Podman volumes retain only runner registration/diagnostics and Rust
caches. A completed-job hook removes the checkout and downloaded actions after
every job.

## Bootstrap on `endor`

Prerequisites: rootless Podman, `gh` authenticated as a repository administrator,
and a running user systemd manager.

```bash
./ops/self-hosted-runner/manage.sh bootstrap
./ops/self-hosted-runner/manage.sh status
```

Enable lingering once so the user service survives logout and starts after a
reboot without an interactive login:

```bash
sudo loginctl enable-linger "$USER"
```

The first registration token expires quickly and is retained only as a Podman
secret consumed during initial configuration. The runner's repository-scoped
credential is held in the state volume. Re-running `register` replaces the
short-lived registration secret and restarts the existing registration.

The `cache` volume contains `CARGO_HOME`, `RUSTUP_HOME` and `CARGO_TARGET_DIR`.
Remove that volume manually only when a fully cold rebuild is intended. The
runner distribution auto-updates in its state volume; GitHub stops assigning
jobs to runners that fall outside its supported update window.
