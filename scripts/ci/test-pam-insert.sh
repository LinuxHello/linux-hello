#!/usr/bin/env bash
# Tests of scripts/prototype/pam-insert.awk, which puts the Linux Hello line into a PAM file, on
# the stock files of Ubuntu's login, sudo and kde services (#359). Needs bash and awk.
#
#   scripts/ci/test-pam-insert.sh
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
awkfile="$here/../prototype/pam-insert.awk"
mark='# linux-hello prototype'
line="auth [success=done authinfo_unavail=ignore module_unknown=ignore default=die] pam_linuxhello.so context=x $mark"
pass=0; fail=0
dir="$(mktemp -d)"; trap 'rm -rf "$dir"' EXIT

insert() { awk -v line="$line" -v mark="$mark" -f "$awkfile" "$1"; }
ok() { pass=$((pass + 1)); echo "ok   $1"; }
bad() { fail=$((fail + 1)); echo "FAIL $1: $2"; }
# position <file> <text>: the line number of the first line that holds <text>, or 0.
position() { awk -v t="$2" 'index($0, t) { print NR; found = 1; exit } END { if (!found) print 0 }' "$1"; }

# Ubuntu's /etc/pam.d/login, shortened to what matters: the delay and /etc/nologin come before the
# include of common-auth.
cat > "$dir/login" <<'EOF'
#%PAM-1.0
auth       optional   pam_faildelay.so  delay=3000000
auth       requisite  pam_nologin.so
@include common-auth
auth       optional   pam_group.so
session    required   pam_limits.so
EOF
cat > "$dir/sudo" <<'EOF'
#%PAM-1.0
session    required   pam_env.so readenv=1 user_readenv=0
@include common-auth
@include common-account
EOF
cat > "$dir/plain" <<'EOF'
# no include of common-auth
account    required   pam_permit.so
auth       required   pam_unix.so
EOF
printf 'session required pam_permit.so\n' > "$dir/none"

insert "$dir/login" > "$dir/login.out"
at=$(position "$dir/login.out" "pam_linuxhello"); include=$(position "$dir/login.out" "@include common-auth")
nologin=$(position "$dir/login.out" "pam_nologin"); delay=$(position "$dir/login.out" "pam_faildelay")
if [[ $at -gt $nologin && $at -gt $delay && $at -eq $((include - 1)) ]]; then
  ok the_line_comes_after_nologin_and_the_delay_and_directly_before_common_auth
else bad the_line_comes_after_nologin_and_the_delay_and_directly_before_common_auth "line $at, include $include, nologin $nologin, delay $delay"; fi

insert "$dir/sudo" > "$dir/sudo.out"
if [[ $(position "$dir/sudo.out" "pam_linuxhello") -eq $(($(position "$dir/sudo.out" "@include common-auth") - 1)) ]]; then
  ok sudo_gets_the_line_before_its_include
else bad sudo_gets_the_line_before_its_include "$(cat "$dir/sudo.out")"; fi

insert "$dir/plain" > "$dir/plain.out"
if [[ $(position "$dir/plain.out" "pam_linuxhello") -eq $(($(position "$dir/plain.out" "pam_unix.so") - 1)) ]]; then
  ok a_file_without_the_include_gets_it_before_its_first_auth_line
else bad a_file_without_the_include_gets_it_before_its_first_auth_line "$(cat "$dir/plain.out")"; fi

# Idempotent: a second run leaves one line, in the same place.
insert "$dir/login.out" > "$dir/login.twice"
if cmp -s "$dir/login.out" "$dir/login.twice" && [[ $(grep -cF "$mark" "$dir/login.twice") -eq 1 ]]; then
  ok running_it_again_leaves_one_line_in_the_same_place
else bad running_it_again_leaves_one_line_in_the_same_place "$(diff "$dir/login.out" "$dir/login.twice")"; fi

# Nothing else changes.
if diff <(grep -vF "$mark" "$dir/login.out") "$dir/login" >/dev/null; then
  ok nothing_but_the_one_line_changes
else bad nothing_but_the_one_line_changes "$(diff <(grep -vF "$mark" "$dir/login.out") "$dir/login")"; fi

# A file with no auth line is an error and prints nothing.
insert "$dir/none" > "$dir/none.out"; status=$?
if [[ $status -eq 3 && ! -s "$dir/none.out" ]]; then ok a_file_with_no_auth_line_is_an_error
else bad a_file_with_no_auth_line_is_an_error "status $status, output $(cat "$dir/none.out")"; fi

echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
