#!/usr/bin/env bash
# Tests for apply-merge-settings.sh against a fake gh that serves fixtures and
# records every write. Needs bash and jq; never calls GitHub.
#
#   scripts/admin/test-apply-merge-settings.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/apply-merge-settings.sh"
command -v jq >/dev/null || { echo "jq is not installed" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"

# Fake gh: `gh auth status` succeeds; `gh api [-X M] PATH [--input -] [--jq F]`
# answers GETs from $FIXTURES/<PATH with / as _>.json (missing file: HTTP 404)
# and appends writes to $WRITES as "METHOD PATH BODY".
cat >"$work/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == auth ]] && exit 0
shift # api
method=GET path="" filter="" body=""
while (($#)); do
  case "$1" in
    -X) method="$2"; shift 2 ;;
    --jq) filter="$2"; shift 2 ;;
    --input) body="$(cat)"; shift 2 ;;
    *) path="$1"; shift ;;
  esac
done
if [[ "$method" != GET ]]; then
  printf '%s %s %s\n' "$method" "$path" "$(jq -c . <<<"$body")" >>"$WRITES"
  exit 0
fi
file="$FIXTURES/${path//\//_}.json"
[[ -f "$file" ]] || { echo "gh: Not Found (HTTP 404)" >&2; exit 1; }
if [[ -n "$filter" ]]; then jq -r "$filter" "$file"; else cat "$file"; fi
EOF
chmod +x "$work/bin/gh"

pass=0 fail=0
fixtures="" writes="" out="" status=0

new_case() {
  fixtures="$work/$1"; writes="$fixtures.writes"; mkdir -p "$fixtures"; : >"$writes"
  fixture repos/LinuxHello/linux-hello '{"default_branch":"main"}'
}
fixture() { # api-path json
  jq . <<<"$2" >"$fixtures/${1//\//_}.json"
}
run() {
  status=0
  out="$(PATH="$work/bin:$PATH" FIXTURES="$fixtures" WRITES="$writes" "$script" "$@" 2>&1)" || status=$?
}
ok()   { pass=$((pass + 1)); echo "ok   $1"; }
nok()  { fail=$((fail + 1)); echo "FAIL $1: $2"; echo "     ${out//$'\n'/$'\n'     }"; }
# The required_status_checks list sent in the one PUT to ruleset $1.
put_checks() {
  grep "^PUT repos/LinuxHello/linux-hello/rulesets/$1 " "$writes" | cut -d' ' -f3- \
    | jq -c '[.rules[] | select(.type == "required_status_checks") | .parameters.required_status_checks[]]'
}
ruleset_writes() { grep -c "rulesets" "$writes" || true; }

ruleset() { # id rules-json [include] [exclude] [enforcement]
  local include="${3:-[\"~DEFAULT_BRANCH\"]}" exclude="${4:-[]}" enforcement="${5:-active}"
  jq -n --argjson id "$1" --argjson rules "$2" --argjson inc "$include" --argjson exc "$exclude" \
        --arg enf "$enforcement" '{
    id: $id, name: "main", target: "branch", source_type: "Repository", enforcement: $enf,
    conditions: {ref_name: {include: $inc, exclude: $exc}},
    bypass_actors: [], rules: $rules}'
}
list() { jq -sc 'map({id, name, target, source_type, enforcement})' ; }
pinned='[{"context":"quality-gate","integration_id":15368},{"context":"fuzz","integration_id":15368},{"context":"unsafe-policy","integration_id":15368}]'

# ---------------------------------------------------------------------------
t=ruleset_without_status_check_rule_gains_the_checks_pinned_to_github_actions
new_case "$t"
fixture repos/LinuxHello/linux-hello/rulesets/7 "$(ruleset 7 '[{"type":"deletion"}]')"
fixture repos/LinuxHello/linux-hello/rulesets "$(ruleset 7 '[]' | list)"
run
if [[ $status == 0 && "$(put_checks 7)" == "$(jq -c . <<<"$pinned")" ]] \
   && grep -q '"type":"deletion"' "$writes"; then ok "$t"; else nok "$t" "status $status, sent $(put_checks 7)"; fi

t=unpinned_check_is_pinned_and_other_checks_keep_their_settings
new_case "$t"
fixture repos/LinuxHello/linux-hello/rulesets/7 "$(ruleset 7 '[{"type":"required_status_checks","parameters":{
  "strict_required_status_checks_policy":true,
  "required_status_checks":[{"context":"fmt"},{"context":"quality-gate"},{"context":"dco","integration_id":15368}]}}]')"
fixture repos/LinuxHello/linux-hello/rulesets "$(ruleset 7 '[]' | list)"
run
want='[{"context":"fmt"},{"context":"quality-gate","integration_id":15368},{"context":"dco","integration_id":15368},{"context":"fuzz","integration_id":15368},{"context":"unsafe-policy","integration_id":15368}]'
strict="$(grep '^PUT' "$writes" | cut -d' ' -f3- | jq '.rules[0].parameters.strict_required_status_checks_policy' 2>/dev/null || true)"
if [[ $status == 0 && "$(put_checks 7)" == "$(jq -c . <<<"$want")" && "$strict" == true ]]; then ok "$t"
else nok "$t" "sent $(put_checks 7), strict $strict"; fi

t=check_pinned_to_another_app_is_repinned_to_github_actions
new_case "$t"
fixture repos/LinuxHello/linux-hello/rulesets/7 "$(ruleset 7 '[{"type":"required_status_checks","parameters":{
  "strict_required_status_checks_policy":false,
  "required_status_checks":[{"context":"quality-gate","integration_id":999},{"context":"fuzz","integration_id":15368},{"context":"fuzz"}]}}]')"
fixture repos/LinuxHello/linux-hello/rulesets "$(ruleset 7 '[]' | list)"
run
if [[ $status == 0 && "$(put_checks 7)" == "$(jq -c . <<<"$pinned")" ]]; then ok "$t"
else nok "$t" "sent $(put_checks 7)"; fi

t=already_pinned_ruleset_is_not_written
new_case "$t"
fixture repos/LinuxHello/linux-hello/rulesets/7 "$(ruleset 7 "$(jq -c --argjson c "$pinned" -n \
  '[{type:"required_status_checks",parameters:{strict_required_status_checks_policy:false,required_status_checks:$c}},
    {type:"pull_request",parameters:{required_approving_review_count:0,allowed_merge_methods:["squash"]}}]')")"
fixture repos/LinuxHello/linux-hello/rulesets "$(ruleset 7 '[]' | list)"
run
if [[ $status == 0 && "$(ruleset_writes)" == 0 ]] && grep -q "already pinned" <<<"$out"; then ok "$t"
else nok "$t" "status $status, writes $(ruleset_writes)"; fi

t=organisation_and_tag_rulesets_are_not_touched
new_case "$t"
fixture repos/LinuxHello/linux-hello/rulesets/7 "$(ruleset 7 '[]')"
fixture repos/LinuxHello/linux-hello/rulesets '[
  {"id":7,"target":"branch","source_type":"Repository"},
  {"id":8,"target":"branch","source_type":"Organization"},
  {"id":9,"target":"tag","source_type":"Repository"}]'
run
if [[ $status == 0 && "$(ruleset_writes)" == 1 ]] && grep -q "rulesets/7 " "$writes"; then ok "$t"
else nok "$t" "writes: $(cat "$writes")"; fi

t=ruleset_for_other_branches_only_fails_closed
new_case "$t"
fixture repos/LinuxHello/linux-hello/rulesets/7 "$(ruleset 7 '[]' '["refs/heads/release/*"]')"
fixture repos/LinuxHello/linux-hello/rulesets "$(ruleset 7 '[]' | list)"
run
if [[ $status != 0 && "$(ruleset_writes)" == 0 ]]; then ok "$t"; else nok "$t" "status $status"; fi

t=two_rulesets_for_main_fail_closed_unless_one_is_named
new_case "$t"
fixture repos/LinuxHello/linux-hello/rulesets/7 "$(ruleset 7 '[]')"
fixture repos/LinuxHello/linux-hello/rulesets/8 "$(ruleset 8 '[]' '["refs/heads/main"]')"
fixture repos/LinuxHello/linux-hello/rulesets "$( (ruleset 7 '[]'; ruleset 8 '[]') | list)"
run
first_status=$status first_writes="$(ruleset_writes)"
RULESET_ID=8 run
if [[ $first_status != 0 && $first_writes == 0 && $status == 0 ]] \
   && grep -q "rulesets/8 " "$writes" && ! grep -q "rulesets/7 " "$writes"; then ok "$t"
else nok "$t" "first $first_status/$first_writes, then $status: $(cat "$writes")"; fi

t=classic_branch_protection_pins_checks_by_app_id
new_case "$t"
fixture repos/LinuxHello/linux-hello/branches/main/protection/required_status_checks \
  '{"strict":true,"contexts":["fmt","quality-gate"],"checks":[{"context":"fmt","app_id":null},{"context":"quality-gate","app_id":null}]}'
run
sent="$(grep '^PATCH repos/LinuxHello/linux-hello/branches' "$writes" | cut -d' ' -f3- | jq -c .checks)"
want='[{"context":"fmt","app_id":null},{"context":"quality-gate","app_id":15368},{"context":"fuzz","app_id":15368},{"context":"unsafe-policy","app_id":15368}]'
if [[ $status == 0 && "$sent" == "$(jq -c . <<<"$want")" ]]; then ok "$t"; else nok "$t" "sent $sent"; fi

t=dry_run_writes_nothing
new_case "$t"
fixture repos/LinuxHello/linux-hello/rulesets/7 "$(ruleset 7 '[]')"
fixture repos/LinuxHello/linux-hello/rulesets "$(ruleset 7 '[]' | list)"
run --dry-run
if [[ $status == 0 && ! -s "$writes" ]] && grep -q "Would PUT" <<<"$out"; then ok "$t"
else nok "$t" "status $status, writes $(cat "$writes")"; fi

t=repository_allows_squash_merges_only_with_title_and_body
new_case "$t"
fixture repos/LinuxHello/linux-hello/rulesets/7 "$(ruleset 7 '[]')"
fixture repos/LinuxHello/linux-hello/rulesets "$(ruleset 7 '[]' | list)"
run
if grep -q '^PATCH repos/LinuxHello/linux-hello {"allow_squash_merge":true,"allow_merge_commit":false,"allow_rebase_merge":false,"squash_merge_commit_title":"PR_TITLE","squash_merge_commit_message":"PR_BODY"}$' "$writes"
then ok "$t"; else nok "$t" "writes $(cat "$writes")"; fi

t=ruleset_allows_squash_merges_only_and_keeps_its_review_settings
new_case "$t"
fixture repos/LinuxHello/linux-hello/rulesets/7 "$(ruleset 7 '[{"type":"pull_request","parameters":{
  "required_approving_review_count":0,"required_review_thread_resolution":true,
  "allowed_merge_methods":["merge","squash","rebase"]}}]')"
fixture repos/LinuxHello/linux-hello/rulesets "$(ruleset 7 '[]' | list)"
run
pr_rule="$(grep '^PUT' "$writes" | cut -d' ' -f3- | jq -c '.rules[] | select(.type == "pull_request") | .parameters' 2>/dev/null || true)"
if [[ $status == 0 && "$pr_rule" == '{"required_approving_review_count":0,"required_review_thread_resolution":true,"allowed_merge_methods":["squash"]}' ]]
then ok "$t"; else nok "$t" "sent $pr_rule"; fi

t=ruleset_without_pull_request_rule_is_not_given_one
new_case "$t"
fixture repos/LinuxHello/linux-hello/rulesets/7 "$(ruleset 7 '[]')"
fixture repos/LinuxHello/linux-hello/rulesets "$(ruleset 7 '[]' | list)"
run
added="$(grep '^PUT' "$writes" | cut -d' ' -f3- | jq '[.rules[] | select(.type == "pull_request")] | length' 2>/dev/null || true)"
if [[ $status == 0 && "$added" == 0 ]] && grep -q "no pull_request rule" <<<"$out"; then ok "$t"
else nok "$t" "status $status, pull_request rules sent: $added"; fi

t=ruleset_excluding_main_by_pattern_is_not_selected
new_case "$t"
fixture repos/LinuxHello/linux-hello/rulesets/7 "$(ruleset 7 '[]' '["~ALL"]' '["refs/heads/m*"]')"
fixture repos/LinuxHello/linux-hello/rulesets "$(ruleset 7 '[]' | list)"
run
if [[ $status != 0 && "$(ruleset_writes)" == 0 ]]; then ok "$t"; else nok "$t" "status $status, writes $(ruleset_writes)"; fi

t=ruleset_including_main_by_wildcard_is_selected
new_case "$t"
fixture repos/LinuxHello/linux-hello/rulesets/7 "$(ruleset 7 '[]' '["refs/heads/*"]')"
fixture repos/LinuxHello/linux-hello/rulesets "$(ruleset 7 '[]' | list)"
run
if [[ $status == 0 && "$(put_checks 7)" == "$(jq -c . <<<"$pinned")" ]]; then ok "$t"; else nok "$t" "status $status"; fi

t=wildcard_ruleset_makes_selection_ambiguous
new_case "$t"
fixture repos/LinuxHello/linux-hello/rulesets/7 "$(ruleset 7 '[]')"
fixture repos/LinuxHello/linux-hello/rulesets/8 "$(ruleset 8 '[]' '["refs/heads/*"]')"
fixture repos/LinuxHello/linux-hello/rulesets "$( (ruleset 7 '[]'; ruleset 8 '[]') | list)"
run
if [[ $status != 0 && "$(ruleset_writes)" == 0 ]] && grep -q "Several rulesets" <<<"$out"; then ok "$t"
else nok "$t" "status $status"; fi

t=failed_ruleset_read_fails_closed
new_case "$t"
fixture repos/LinuxHello/linux-hello/rulesets/8 "$(ruleset 8 '[]')"
fixture repos/LinuxHello/linux-hello/rulesets "$( (ruleset 7 '[]'; ruleset 8 '[]') | list)"
run
if [[ $status != 0 && "$(ruleset_writes)" == 0 ]] && grep -q "Could not read ruleset 7" <<<"$out"; then ok "$t"
else nok "$t" "status $status, writes $(ruleset_writes)"; fi

t=failed_ruleset_list_fails_closed
new_case "$t"
run
if [[ $status != 0 && "$(ruleset_writes)" == 0 ]] && grep -q "Could not list the rulesets" <<<"$out"; then ok "$t"
else nok "$t" "status $status"; fi

t=ruleset_that_does_not_enforce_is_refused
new_case "$t"
fixture repos/LinuxHello/linux-hello/rulesets/7 "$(ruleset 7 '[]' '["~DEFAULT_BRANCH"]' '[]' evaluate)"
fixture repos/LinuxHello/linux-hello/rulesets "$(ruleset 7 '[]' | list)"
run
if [[ $status != 0 && "$(ruleset_writes)" == 0 ]] && grep -q "not enforced" <<<"$out"; then ok "$t"
else nok "$t" "status $status, writes $(ruleset_writes)"; fi

t=disabled_ruleset_beside_an_active_one_is_skipped
new_case "$t"
fixture repos/LinuxHello/linux-hello/rulesets/7 "$(ruleset 7 '[]')"
fixture repos/LinuxHello/linux-hello/rulesets/8 "$(ruleset 8 '[]' '["~DEFAULT_BRANCH"]' '[]' disabled)"
fixture repos/LinuxHello/linux-hello/rulesets "$( (ruleset 7 '[]'; ruleset 8 '[]') | list)"
run
if [[ $status == 0 ]] && grep -q "rulesets/7 " "$writes" && ! grep -q "rulesets/8 " "$writes"; then ok "$t"
else nok "$t" "status $status, writes $(cat "$writes")"; fi

t=ruleset_id_outside_the_eligible_rulesets_is_refused
new_case "$t"
fixture repos/LinuxHello/linux-hello/rulesets/7 "$(ruleset 7 '[]')"
fixture repos/LinuxHello/linux-hello/rulesets/9 "$(ruleset 9 '[]' '["refs/heads/release/*"]')"
fixture repos/LinuxHello/linux-hello/rulesets "$( (ruleset 7 '[]'; ruleset 9 '[]') | list)"
RULESET_ID=9 run
if [[ $status != 0 && "$(ruleset_writes)" == 0 ]]; then ok "$t"; else nok "$t" "status $status, writes $(cat "$writes")"; fi

t=default_branch_other_than_main_fails_closed
new_case "$t"
fixture repos/LinuxHello/linux-hello '{"default_branch":"trunk"}'
fixture repos/LinuxHello/linux-hello/rulesets/7 "$(ruleset 7 '[]')"
fixture repos/LinuxHello/linux-hello/rulesets "$(ruleset 7 '[]' | list)"
run
if [[ $status != 0 && ! -s "$writes" ]]; then ok "$t"; else nok "$t" "status $status, writes $(cat "$writes")"; fi

echo "$pass passed, $fail failed"
((fail == 0))
