#!/usr/bin/env bash
# shellcheck disable=SC2015  # ok() always succeeds, so "test && ok || nok" never runs both
# Tests for backlog.sh with a fake gh that serves fixture issues. Needs bash and jq; no network.
#   bash scripts/backlog/test-backlog.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"
pass=0; fail=0
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
nok() { fail=$((fail + 1)); printf 'FAIL %s\n%s\n' "$1" "${2:-}"; }

# Fixture: a page of open issues as the REST API returns them (fields backlog.sh reads), plus one PR.
issue() { # number title blocked_by label...
  local n=$1 t=$2 b=$3; shift 3
  jq -cn --argjson n "$n" --arg t "$t" --argjson b "$b" --args \
    '{number: $n, title: $t, labels: [$ARGS.positional[] | {name: .}], milestone: null,
      issue_dependencies_summary: {blocked_by: $b}}' "$@"
}
{
  echo '['
  issue 10 "Later ready"         0 status:ready priority:later;       echo ,
  issue 11 "Now ready"           0 status:ready priority:now;         echo ,
  issue 12 "Now ready, waiting"  1 status:ready priority:now;         echo ,
  issue 13 "Now ready, older"    0 status:ready priority:now;         echo ,
  issue 9  "Next ready"          0 status:ready priority:next;        echo ,
  issue 20 "Brief me"            0 status:needs-brief priority:next;  echo ,
  issue 21 "A spike"             0 status:needs-brief priority:now type:spike; echo ,
  issue 30 "No labels"           0 type:docs;                         echo ,
  issue 31 "Two statuses"        0 status:ready status:in-review priority:now; echo ,
  echo '{"number": 40, "title": "A pull request", "labels": [], "pull_request": {}}'
  echo ']'
} >"$work/issues.json"
# Fixture order within a priority is deliberately not by number (#13 after #11).

cat >"$work/bin/gh" <<EOF
#!/usr/bin/env bash
case "\$*" in
  *"/dependencies/blocked_by"*) echo '#11' ;;
  "api --paginate repos/"*"/issues?state=open&per_page=100") cat "$work/issues.json" ;;
  *) echo "unexpected gh \$*" >&2; exit 1 ;;
esac
EOF
chmod +x "$work/bin/gh"
run() { PATH="$work/bin:$PATH" bash "$HERE/backlog.sh" "$@"; }

t="order: priority first, then lowest number; blocked and multi-status issues left out"
got=$(run order ready | tr '\n' ' ')
[[ "$got" == "11 13 9 10 " ]] && ok "$t" || nok "$t" "got: $got"

t="order: pull requests are not issues"
got=$(run order ready)
grep -qx 40 <<<"$got" && nok "$t" "#40 listed" || ok "$t"

t="next: implement lane shows the top unblocked ready issue"
out=$(run next)
grep -A1 '^implement' <<<"$out" | grep -q '#11 ' && ok "$t" || nok "$t" "$out"

t="next: spikes have their own lane, apart from briefs"
grep -A1 '^spike' <<<"$out" | grep -q '#21 ' && grep -A1 '^brief' <<<"$out" | grep -q '#20 ' \
  && ok "$t" || nok "$t" "$out"

t="next: an issue without exactly one status is untriaged, by priority (#31 now before #30 none)"
grep -A1 '^untriaged' <<<"$out" | grep -q '#31 ' && ok "$t" || nok "$t" "$out"

t="list: a blocked issue names what it waits for"
out=$(run list)
grep -q '#12 .*(waits for #11)' <<<"$out" && ok "$t" || nok "$t" "$out"

t="list: untriaged lists every issue without exactly one status"
grep -A2 '^untriaged' <<<"$out" | grep -q '#30 ' && grep -A2 '^untriaged' <<<"$out" | grep -q '#31 ' \
  && ok "$t" || nok "$t" "$out"

t="json: lane, order and blockers for every open issue"
out=$(run json)
if [[ "$(jq -r '.[] | select(.number == 12) | [.lane, .order, .waiting_for] | @tsv' <<<"$out")" == $'implement\t12\t#11' ]] \
   && [[ "$(jq -r '.[] | select(.number == 21) | .lane' <<<"$out")" == spike ]] \
   && [[ "$(jq -r '.[] | select(.number == 30) | [.lane, .order] | @tsv' <<<"$out")" == $'untriaged\t300030' ]]; then
  ok "$t"; else nok "$t" "$out"; fi

t="check: reports missing and duplicate labels and a blocked ready issue, exits 1"
rc=0; out=$(run check) || rc=$?
if [[ $rc == 1 ]] && grep -q '#30: no status' <<<"$out" && grep -q '#30: no priority' <<<"$out" \
   && grep -q '#31: more than one status' <<<"$out" && grep -q '#12: status:ready but blocked' <<<"$out"; then
  ok "$t"; else nok "$t" "rc=$rc $out"; fi

t="check: a tidy backlog exits 0"
jq '[.[] | select(.number == 11 or .number == 13)]' "$work/issues.json" >"$work/tidy" && mv "$work/tidy" "$work/issues.json"
rc=0; out=$(run check) || rc=$?
[[ $rc == 0 ]] && ok "$t" || nok "$t" "rc=$rc $out"

t="usage: an unknown command exits 2"
rc=0; run frobnicate >/dev/null 2>&1 || rc=$?
[[ $rc == 2 ]] && ok "$t" || nok "$t" "rc=$rc"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ $fail == 0 ]]
