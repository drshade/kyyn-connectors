.PHONY: check

check:
	cargo fmt --all --check
	cargo clippy --workspace --all-targets -- -D warnings
	cargo test --workspace
	./scripts/check-components.sh
	./ops/self-hosted-runner/check.sh
