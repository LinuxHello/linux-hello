#!/usr/bin/env bash
# Apply the repository settings ADR-0006 depends on. Run by the maintainer with
# his own gh login; idempotent. Prints what it changed.
#
#   scripts/admin/apply-merge-settings.sh [--dry-run]
#
# --dry-run   print each change instead of applying it.
# RULESET_ID  pick the ruleset to update when more than one protects main.
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

command -v gh >/dev/null || { echo "gh is not installed" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq is not installed" >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "Log in first: gh auth login" >&2; exit 1; }

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

# Rulesets defined on this repository (not inherited from the organisation)
# that target branches and include main.
rulesets_for_main() {
  local id
  for id in $(gh api "repos/$repo/rulesets" \
      --jq '.[] | select(.source_type == "Repository" and .target == "branch") | .id'); do
    gh api "repos/$repo/rulesets/$id" --jq '
      select((.conditions.ref_name.include // [])
               | any(. == "~DEFAULT_BRANCH" or . == "refs/heads/main" or . == "~ALL"))
      | select((.conditions.ref_name.exclude // [])
               | any(. == "~DEFAULT_BRANCH" or . == "refs/heads/main") | not)
      | .id'
  done
}

# The fields of a ruleset that its update endpoint accepts; absent ones stay absent.
updatable='{name, target, enforcement, conditions, bypass_actors, rules} | with_entries(select(.value != null))'

pin_ruleset() {
  local id="$1" current wanted path="repos/$repo/rulesets/$1"
  current="$(gh api "$path")"
  if [[ "$(jq -r .enforcement <<<"$current")" != active ]]; then
    echo "Warning: ruleset $id is not enforced (enforcement: $(jq -r .enforcement <<<"$current"))." >&2
  fi
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
  if [[ -n "${RULESET_ID:-}" ]]; then
    ids="$RULESET_ID"
  else
    ids="$(rulesets_for_main)"
  fi
  case "$(wc -w <<<"$ids")" in
    0)
      echo "No repository ruleset or branch protection covers main; nothing pinned." >&2
      echo "Create a branch ruleset for main, then run this again." >&2
      exit 1 ;;
    1) pin_ruleset "$ids" ;;
    *)
      echo "Several rulesets cover main: $(tr '\n' ' ' <<<"$ids")" >&2
      echo "Pick one: RULESET_ID=<id> $0" >&2
      exit 1 ;;
  esac
fi
