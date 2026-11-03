#!/usr/bin/env bash
# Verify that CI attested a passed quality gate for a commit (ADR-0006).
#
#   scripts/ci/verify-quality-gate.sh <commit-sha>                     a commit on main
#   scripts/ci/verify-quality-gate.sh <merge-sha> refs/pull/N/merge    a pull request run
#
# Rebuilds the subject from the commit, downloads the attestations for it, and
# checks the bundle locally with `gh attestation verify`: signed with Sigstore by
# this repository's CI workflow on a GitHub-hosted runner, quality-gate predicate
# type, from the given ref and that exact commit. Exits non-zero otherwise.
# The bundle is verified locally because the attestations API refuses a custom
# predicate type as a lookup filter (HTTP 422).
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
  --source-digest "$sha"
  --signer-workflow "$repo/.github/workflows/ci.yml"
  --predicate-type "$predicate"
  --source-ref "$ref"
  --deny-self-hosted-runners
)
subject="$work/quality-gate-$sha.json"
digest="$(sha256sum "$subject" | cut -d' ' -f1)"
(cd "$work" && gh attestation download "$subject" --repo "$repo" >/dev/null)
bundle="$work/sha256:$digest.jsonl"
[[ -s "$bundle" ]] || { echo "No attestation found for $sha" >&2; exit 1; }

gh attestation verify "$subject" --bundle "$bundle" "${args[@]}"
echo "Quality gate attested for $sha ($ref)."
