#!/usr/bin/env bash
# Print the quality-gate attestation subject for a commit: canonical JSON naming
# the repository, the commit and the gates listed in scripts/ci/quality-gates.txt
# at that commit. Deterministic, so a verifier can rebuild it from the commit alone.
#
#   scripts/ci/quality-gate-subject.sh <commit-sha> > quality-gate.json
set -euo pipefail

sha="${1:?usage: quality-gate-subject.sh <commit-sha>}"
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "Not a full commit SHA: $sha" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq is not installed" >&2; exit 1; }

gates="$(git show "$sha:scripts/ci/quality-gates.txt" | grep -Ev '^\s*(#|$)')" || {
  echo "Commit $sha has no scripts/ci/quality-gates.txt; it predates quality-gate attestations" >&2
  exit 1
}

jq -cnS --arg repo "LinuxHello/linux-hello" --arg sha "$sha" --arg gates "$gates" \
  '{type: "quality-gate/v1", repository: $repo, commit: $sha, gates: ($gates | split("\n"))}'
