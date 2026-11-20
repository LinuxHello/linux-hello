#!/usr/bin/env bash
# The Agent links no TPM library.
#
# The Agent is a static, pure-Rust binary: the confinement VM builds it for musl, which cannot link
# the TSS2 C libraries, and a smaller binary in a confined daemon is worth having anyway. It reaches
# the TPM through the provider, over a socket (linuxhello-tpm-provider, feature "tpm" off).
#
# Fails when tss-esapi (or its -sys crate) is in the dependency tree that building the Agent uses.
#
#   scripts/ci/agent-links-no-tpm.sh
set -euo pipefail

tree="$(cargo tree -p linuxhello-agent --edges normal,build --prefix none --locked)"
if grep -Eq '^(tss-esapi|tss-esapi-sys) ' <<<"$tree"; then
  echo "the Agent's dependencies include a TPM library:" >&2
  grep -E '^(tss-esapi|tss-esapi-sys) ' <<<"$tree" >&2
  echo "build the provider crate with default-features = false in the Agent's manifest" >&2
  exit 1
fi
echo "The Agent links no TPM library."
