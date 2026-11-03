#!/usr/bin/env bash
# Apply the repository settings ADR-0006 depends on. Run by the maintainer with
# his own gh login; idempotent. Prints what it changed.
#
#   scripts/admin/apply-merge-settings.sh [--dry-run]
#
# --dry-run   print each change instead of applying it.
# RULESET_ID  pick the ruleset to update when more than one active ruleset protects main;
#             it must be one of them.
#
# Required checks are pinned to the GitHub Actions app, so that no other app or
# commit status can satisfy them by posting a passing result with the same name.
set -euo pipefail

repo="LinuxHello/linux-hello"
checks=(quality-gate fuzz)
github_actions_app_id=15368

dry_run=false
case "${1:-}" in
  "") ;;
  --dry-run) dry_run=true ;;
  *) echo "usage: $0 [--dry-run]" >&2; exit 2 ;;
esac

die() { echo "$*" >&2; exit 1; }

command -v gh >/dev/null || { echo "gh is not installed" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq is not installed" >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "Log in first: gh auth login" >&2; exit 1; }

# The ruleset conditions below are matched against main, so main must be the default branch.
default_branch="$(gh api "repos/$repo" --jq .default_branch)" || die "Could not read $repo."
[[ "$default_branch" == main ]] || die "The default branch is '$default_branch', not main; nothing pinned."

checks_json="$(printf '%s\n' "${checks[@]}" | jq -R . | jq -sc .)"

# Pin each required check to the app in the list at $list, under the id field
# $field ("integration_id" in rulesets, "app_id" in classic protection). Entries
# for other checks keep their place; missing checks are appended; duplicates go.
# shellcheck disable=SC2016 # jq variables, not shell ones
pin_filter='
  def dedupe: reduce .[] as $x ([]; if any(.[]; . == $x) then . else . + [$x] end);
  def pin($field):
    (map(if (.context | IN($checks[])) then {context, ($field): $app} else . end)) as $kept
    | ($kept + [ $checks[] | select(IN($kept[].context) | not) | {context: ., ($field): $app} ])
    | dedupe;
'

apply() { # method path body description
  if $dry_run; then
    echo "Would $1 $2: $4"
    jq . <<<"$3"
  else
    gh api -X "$1" "$2" --input - <<<"$3" >/dev/null
    echo "$4"
  fi
}

# Squash commits carry the pull request title and its structured body.
apply PATCH "repos/$repo" \
  '{"squash_merge_commit_title":"PR_TITLE","squash_merge_commit_message":"PR_BODY"}' \
  "Squash commit message: pull request title and body."

pin_classic() {
  local path="repos/$repo/branches/main/protection/required_status_checks" current wanted
  current="$(gh api "$path" --jq '.checks // []')"
  wanted="$(jq -c --argjson checks "$checks_json" --argjson app "$github_actions_app_id" \
    "$pin_filter .|pin(\"app_id\")" <<<"$current")"
  if [[ "$(jq -c . <<<"$current")" == "$wanted" ]]; then
    echo "Required checks already pinned to GitHub Actions in branch protection: ${checks[*]}"
  else
    apply PATCH "$path" "$(jq -c '{checks: .}' <<<"$wanted")" \
      "Required checks pinned to GitHub Actions in branch protection: ${checks[*]}"
  fi
}

# Does a ref_name pattern of a ruleset condition match refs/heads/main? GitHub
# matches these patterns with fnmatch; bash pattern matching covers * ? and [].
pattern_matches_main() {
  case "$1" in
    "~ALL" | "~DEFAULT_BRANCH") return 0 ;;
  esac
  # shellcheck disable=SC2053 # the right-hand side is a pattern on purpose
  [[ "refs/heads/main" == $1 ]]
}

# Does this ruleset (JSON) include main and not exclude it?
covers_main() {
  local p included=false
  while IFS= read -r p; do
    [[ -n "$p" ]] && pattern_matches_main "$p" && included=true
  done < <(jq -r '.conditions.ref_name.include // [] | .[]' <<<"$1")
  $included || return 1
  while IFS= read -r p; do
    [[ -n "$p" ]] && pattern_matches_main "$p" && return 1
  done < <(jq -r '.conditions.ref_name.exclude // [] | .[]' <<<"$1")
  return 0
}

# Active repository rulesets (not inherited from the organisation) that target
# branches and cover main, one id per line. Rulesets that cover main but do not
# enforce are reported on stderr and left out. Any failed read fails the run.
rulesets_for_main() {
  local list id detail enforcement
  list="$(gh api "repos/$repo/rulesets" \
    --jq '.[] | select(.source_type == "Repository" and .target == "branch") | .id')" \
    || die "Could not list the rulesets of $repo; nothing pinned."
  for id in $list; do
    detail="$(gh api "repos/$repo/rulesets/$id")" || die "Could not read ruleset $id; nothing pinned."
    covers_main "$detail" || continue
    enforcement="$(jq -r .enforcement <<<"$detail")"
    if [[ "$enforcement" == active ]]; then
      echo "$id"
    else
      echo "Ruleset $id covers main but is not enforced (enforcement: $enforcement); skipped." >&2
    fi
  done
}

# The fields of a ruleset that its update endpoint accepts; absent ones stay absent.
updatable='{name, target, enforcement, conditions, bypass_actors, rules} | with_entries(select(.value != null))'

pin_ruleset() {
  local id="$1" current wanted path="repos/$repo/rulesets/$1"
  current="$(gh api "$path")" || die "Could not read ruleset $id; nothing pinned."
  # Pinning checks in a ruleset that does not enforce them would protect nothing.
  [[ "$(jq -r .enforcement <<<"$current")" == active ]] \
    || die "Ruleset $id is not enforced; enable it first. Nothing pinned."
  wanted="$(jq -c --argjson checks "$checks_json" --argjson app "$github_actions_app_id" "$pin_filter"'
    if any((.rules // [])[]; .type == "required_status_checks") then
      .rules |= map(if .type == "required_status_checks"
                    then .parameters.required_status_checks |= pin("integration_id")
                    else . end)
    else
      .rules += [{type: "required_status_checks",
                  parameters: {strict_required_status_checks_policy: false,
                               required_status_checks: ([] | pin("integration_id"))}}]
    end
    | '"$updatable" <<<"$current")"
  if [[ "$(jq -c "$updatable" <<<"$current")" == "$wanted" ]]; then
    echo "Required checks already pinned to GitHub Actions in ruleset $id: ${checks[*]}"
  else
    apply PUT "$path" "$wanted" "Required checks pinned to GitHub Actions in ruleset $id: ${checks[*]}"
  fi
}

# Required checks: classic branch protection if main has it, otherwise rulesets.
if gh api "repos/$repo/branches/main/protection/required_status_checks" >/dev/null 2>&1; then
  pin_classic
else
  ids="$(rulesets_for_main)"
  if [[ -n "${RULESET_ID:-}" ]]; then
    # RULESET_ID only chooses among the eligible rulesets; it cannot widen them.
    grep -qx -- "$RULESET_ID" <<<"$ids" \
      || die "RULESET_ID=$RULESET_ID is not an active repository ruleset that covers main; nothing pinned."
    ids="$RULESET_ID"
  fi
  case "$(wc -w <<<"$ids")" in
    0)
      echo "No active repository ruleset or branch protection covers main; nothing pinned." >&2
      echo "Create or enable a branch ruleset for main, then run this again." >&2
      exit 1 ;;
    1) pin_ruleset "$ids" ;;
    *)
      echo "Several rulesets cover main: $(tr '\n' ' ' <<<"$ids")" >&2
      echo "Pick one: RULESET_ID=<id> $0" >&2
      exit 1 ;;
  esac
fi
