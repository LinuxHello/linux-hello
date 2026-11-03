#!/usr/bin/env bash
# Verify that CI attested a passed quality gate for a commit (ADR-0006).
#
#   scripts/ci/verify-quality-gate.sh <commit-sha>                 a commit on main
#   scripts/ci/verify-quality-gate.sh <commit-sha> refs/pull/N/merge   a pull request head
#
# Rebuilds the subject from the commit, then checks with `gh attestation verify`
# that a Sigstore-signed attestation for it exists, was signed by this
# repository's CI workflow on a GitHub-hosted runner, carries the quality-gate
# predicate type and comes from the given ref. Exits non-zero otherwise.
# Needs gh (any login; attestations of a public repository are public) and jq.
set -euo pipefail

sha="${1:?usage: verify-quality-gate.sh <commit-sha> [ref]}"
ref="${2:-refs/heads/main}"
repo="LinuxHello/linux-hello"
predicate="https://github.com/LinuxHello/linux-hello/blob/main/docs/adr/0006-attested-quality-gates-and-releases.md#quality-gate-v1"

command -v gh >/dev/null || { echo "gh is not installed" >&2; exit 1; }
root="$(git rev-parse --show-toplevel)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

git -C "$root" cat-file -e "$sha^{commit}" 2>/dev/null || git -C "$root" fetch --quiet origin "$sha"
"$root/scripts/ci/quality-gate-subject.sh" "$sha" > "$work/quality-gate-$sha.json"

args=(
  --repo "$repo"
  --signer-workflow "$repo/.github/workflows/ci.yml"
  --predicate-type "$predicate"
  --source-ref "$ref"
  --deny-self-hosted-runners
)
# On main the signing run's commit is the commit itself. A pull request run
# signs from the merge ref, whose commit differs from the head named in the subject.
[[ "$ref" = "refs/heads/main" ]] && args+=(--source-digest "$sha")

gh attestation verify "$work/quality-gate-$sha.json" "${args[@]}"
echo "Quality gate attested for $sha ($ref)."
