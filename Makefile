# Local entry points for the CI gates (AGENTS.md, Gates). Agents and humans run
# `make fix` after writing code and `make gates` before opening a pull request.
.PHONY: help fmt fix gates fmt-check clippy test deny audit unsafe-policy fuzz hooks verify-gate next backlog backlog-check

FUZZ_SECONDS ?= 60

help:
	@echo "make next         the next issue in each lane (docs/project/backlog.md)"
	@echo "make backlog      every open issue, by lane, in pick-up order"
	@echo "make backlog-check open issues missing a status: or priority: label"
	@echo
	@echo "make fix          format and apply clippy's machine-applicable fixes"
	@echo "make gates        run every CI gate locally (fuzz: FUZZ_SECONDS=$(FUZZ_SECONDS) per target)"
	@echo "make hooks        install the pre-commit hook (cargo fmt --check)"
	@echo "make verify-gate SHA=<commit>   verify CI's quality-gate attestation for a commit on main"

fmt:
	cargo fmt --all

fix: fmt
	cargo clippy --workspace --all-targets --fix --allow-dirty --allow-staged -- -D warnings
	cargo fmt --all

gates: fmt-check clippy test deny audit unsafe-policy fuzz
	@echo "All gates passed."

fmt-check:
	cargo fmt --all --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace

deny:
	@cargo deny --version >/dev/null 2>&1 || { echo "cargo install cargo-deny --locked"; exit 1; }
	cargo deny check

audit:
	@cargo audit --version >/dev/null 2>&1 || { echo "cargo install cargo-audit --version 0.22.2 --locked"; exit 1; }
	cargo audit

unsafe-policy:
	bash scripts/ci/unsafe-policy.sh

fuzz:
	scripts/ci/fuzz.sh $(FUZZ_SECONDS)

hooks:
	git config core.hooksPath scripts/hooks
	@echo "pre-commit hook installed (scripts/hooks/pre-commit)."

verify-gate:
	@test -n "$(SHA)" || { echo "usage: make verify-gate SHA=<commit>"; exit 1; }
	scripts/ci/verify-quality-gate.sh "$(SHA)"

next:
	@scripts/backlog/backlog.sh next

backlog:
	@scripts/backlog/backlog.sh list

backlog-check:
	@scripts/backlog/backlog.sh check
