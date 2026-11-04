#!/usr/bin/env bash
# The backlog in one place: what is next, in which order, and what is untidy.
# Reads open issues from GitHub (read-only). Needs gh (logged in) and jq.
#
#   backlog.sh next            the top issue in each lane: what to pick up now
#   backlog.sh list            every open issue, by lane, in pick-up order
#   backlog.sh order <status>  issue numbers with that status: label, unblocked, in pick-up order
#   backlog.sh check           issues that break the labelling rules; exits 1 if any
#   backlog.sh json            every open issue with its lane, rank and blockers, for other tools
#
# Pick-up order (docs/project/backlog.md): priority:now, then priority:next, then
# priority:later, then no priority; within a priority, the lowest issue number first.
# An issue with an open "blocked by" link on GitHub waits, whatever its labels say.
set -euo pipefail

REPO_SLUG="${REPO_SLUG:-LinuxHello/linux-hello}"
die() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
for c in gh jq; do command -v "$c" >/dev/null || die "$c not installed"; done

usage() { sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

# Open issues (not pull requests) reduced to the fields the lanes need, sorted in pick-up order.
issues_json() {
  gh api --paginate "repos/$REPO_SLUG/issues?state=open&per_page=100" \
    | jq -s '
        add // []
        | map(select(.pull_request == null))
        | map({
            number, title,
            labels: [.labels[].name],
            milestone: (.milestone.title // null),
            blocked_by: (.issue_dependencies_summary.blocked_by // 0)
          })
        | map(. + {
            status:   [.labels[] | select(startswith("status:"))   | ltrimstr("status:")],
            priority: [.labels[] | select(startswith("priority:")) | ltrimstr("priority:")],
            spike:    (.labels | index("type:spike") != null)
          })
        | map(. + {rank: ({"now":0,"next":1,"later":2}[.priority[0] // ""] // 3)})
        | sort_by(.rank, .number)'
}

# Open issues that block issue $1, as "#n #m".
blockers() {
  gh api "repos/$REPO_SLUG/issues/$1/dependencies/blocked_by" \
    --jq '[.[] | select(.state == "open") | "#\(.number)"] | join(" ")'
}

# Lanes: who acts next on an issue, from its status label.
#   implement  status:ready              implementer (agent or contributor) codes it from the brief
#   brief      status:needs-brief        lead writes the brief (not a spike)
#   spike      status:needs-brief spike  lead or a contributor with the hardware runs the spike
#   review     status:in-review          lead reviews; maintainer merges
#   doing      status:in-progress        someone has it
#   stuck      status:blocked            failed unattended; lead diagnoses
LANE_JQ='
  def lane:
    if   (.status | length) != 1          then "untriaged"
    elif .status[0] == "ready"            then "implement"
    elif .status[0] == "needs-brief"      then (if .spike then "spike" else "brief" end)
    elif .status[0] == "in-review"        then "review"
    elif .status[0] == "in-progress"      then "doing"
    elif .status[0] == "blocked"          then "stuck"
    else "untriaged" end;'

LANES=(implement brief spike review doing stuck untriaged)
declare -A WHO=(
  [implement]="implementer: code it from the brief"
  [brief]="lead: write the implementation brief"
  [spike]="lead or contributor with the hardware: run the spike"
  [review]="lead reviews, maintainer merges"
  [doing]="in progress"
  [stuck]="lead: diagnose the failed run"
  [untriaged]="lead: set one status: and one priority: label"
)

line() { # number title priority milestone [waiting-on]
  local pr="${3:--}" ms="${4:--}"
  printf '  #%-4s %-7s %-62.62s %s%s\n' "$1" "$pr" "$2" "$ms" "${5:+  (waits for $5)}"
}

cmd_next() {
  local data; data=$(issues_json)
  printf 'Next in each lane for %s (rule: docs/project/backlog.md)\n\n' "$REPO_SLUG"
  local lane
  for lane in implement brief spike review stuck untriaged; do
    local top
    top=$(jq -r "$LANE_JQ"' map(select(lane == $l and .blocked_by == 0)) | first // empty
                 | [.number, .title, (.priority[0] // "-"), (.milestone // "-")] | @tsv' \
          --arg l "$lane" <<<"$data")
    printf '%-10s %s\n' "$lane" "${WHO[$lane]}"
    if [[ -n "$top" ]]; then
      IFS=$'\t' read -r n t p m <<<"$top"; line "$n" "$t" "$p" "$m"
    else
      echo "  (nothing)"
    fi
  done
}

cmd_list() {
  local data; data=$(issues_json)
  local lane
  for lane in "${LANES[@]}"; do
    local rows
    rows=$(jq -r "$LANE_JQ"' map(select(lane == $l))[]
                  | [.number, .title, (.priority[0] // "-"), (.milestone // "-"), .blocked_by] | @tsv' \
           --arg l "$lane" <<<"$data")
    [[ -n "$rows" ]] || continue
    printf '\n%s: %s\n' "$lane" "${WHO[$lane]}"
    while IFS=$'\t' read -r n t p m b; do
      if [[ "$b" != 0 ]]; then line "$n" "$t" "$p" "$m" "$(blockers "$n")"; else line "$n" "$t" "$p" "$m"; fi
    done <<<"$rows"
  done
}

cmd_order() {
  [[ $# -eq 1 ]] || usage
  issues_json | jq -r --arg s "$1" '.[] | select(.status == [$s] and .blocked_by == 0) | .number'
}

# Rank: one sortable number for "pick-up order" (priority, then issue number).
cmd_json() {
  local data n waits
  data=$(issues_json | jq "$LANE_JQ"' map(. + {lane: lane, order: (.rank * 100000 + .number), waiting_for: ""})')
  for n in $(jq -r '.[] | select(.blocked_by > 0) | .number' <<<"$data"); do
    waits=$(blockers "$n")
    data=$(jq --argjson n "$n" --arg w "$waits" 'map(if .number == $n then .waiting_for = $w else . end)' <<<"$data")
  done
  jq '.' <<<"$data"
}

cmd_check() {
  local problems
  problems=$(issues_json | jq -r '
    .[] |
    ( if (.status | length) == 0 then "#\(.number): no status: label"
      elif (.status | length) > 1 then "#\(.number): more than one status: label (\(.status | join(", ")))"
      else empty end ),
    ( if (.priority | length) == 0 then "#\(.number): no priority: label"
      elif (.priority | length) > 1 then "#\(.number): more than one priority: label"
      else empty end ),
    ( if .status == ["ready"] and .blocked_by > 0
      then "#\(.number): status:ready but blocked by an open issue" else empty end )')
  if [[ -n "$problems" ]]; then
    printf '%s\n' "$problems"
    printf '\n%s issue(s) break the rules in docs/project/backlog.md\n' "$(grep -o '^#[0-9]*' <<<"$problems" | sort -u | wc -l)"
    exit 1
  fi
  echo "Every open issue has one status: and one priority: label."
}

case "${1:-}" in
  next)  shift; cmd_next "$@" ;;
  list)  shift; cmd_list "$@" ;;
  order) shift; cmd_order "$@" ;;
  check) shift; cmd_check "$@" ;;
  json)  shift; cmd_json "$@" ;;
  *) usage ;;
esac
