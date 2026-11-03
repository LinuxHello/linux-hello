#!/usr/bin/env bash
# Apply the repository settings ADR-0006 depends on. Run by the maintainer with
# his own gh login; idempotent. Prints what it changed or what to change by hand.
#
#   scripts/admin/apply-merge-settings.sh
set -euo pipefail

repo="LinuxHello/linux-hello"
checks=(quality-gate fuzz)

command -v gh >/dev/null || { echo "gh is not installed" >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "Log in first: gh auth login" >&2; exit 1; }

# Squash commits carry the pull request title and its structured body.
gh api -X PATCH "repos/$repo" \
  -f squash_merge_commit_title=PR_TITLE -f squash_merge_commit_message=PR_BODY >/dev/null
echo "Squash commit message: pull request title and body."

# Required checks: classic branch protection if main has it, otherwise rulesets.
if gh api "repos/$repo/branches/main/protection/required_status_checks" >/dev/null 2>&1; then
  current="$(gh api "repos/$repo/branches/main/protection/required_status_checks" --jq '.contexts[]')"
  for check in "${checks[@]}"; do
    if grep -qx "$check" <<<"$current"; then
      echo "Required check already set: $check"
    else
      gh api -X POST "repos/$repo/branches/main/protection/required_status_checks/contexts" \
        --input - <<<"[\"$check\"]" >/dev/null
      echo "Required check added: $check"
    fi
  done
else
  echo "main has no classic required status checks; checking rulesets."
  gh api "repos/$repo/rulesets" --jq '.[] | "\(.id)\t\(.name)\t\(.target)\t\(.enforcement)"'
  echo "Add these as required status checks to the ruleset that protects main:"
  printf '  %s\n' "${checks[@]}"
  echo "Settings > Rules > Rulesets > <ruleset> > Require status checks to pass."
fi
