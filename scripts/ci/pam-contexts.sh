#!/usr/bin/env bash
# The checks are strings run by eval, which shellcheck does not read, so it cannot see their uses.
# shellcheck disable=SC2016,SC2034,SC2059,SC2329
# The PAM module in the PAM stacks of the text console's login (/etc/pam.d/login, context login),
# the Plasma lock screen (/etc/pam.d/kde, context unlock) and sudo (/etc/pam.d/sudo, context
# sudo), as the prototype installs them. pamtester, a small program that runs one PAM service for
# one user as root (as login and the lock screen's helper do), drives each stack with answers on
# standard input. The checks state ADR-0023: the right PIN signs in without the password; a wrong
# PIN fails the attempt and never falls through to the password; an empty answer, a stopped Agent
# and an Agent that hangs fall through to the password, the last two within the module's deadline.
# Prints PASS or FAIL per check and exits non-zero if any failed.
#
#   scripts/ci/pam-contexts.sh   run in a throwaway VM with /dev/tpmrm0 (make vm-test-pam-contexts in
#                                the workstation repository)
#
# It changes the machine it runs on (the installer's changes with --lock-screen and --console,
# pamtester, a user lhpam with a password, and a stand-in /etc/pam.d/kde where Plasma is not
# installed), so it refuses to run anywhere but a throwaway VM (LH_CONFINEMENT_INSTALL=yes). Needs
# what scripts/prototype/install.sh --no-build needs, already built under target/. Not covered: the
# graphical login screen (SDDM) itself, and a person typing at a real console.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 2

if [[ "${LH_CONFINEMENT_INSTALL:-}" != yes ]]; then
  echo "refusing to change this machine: this script is for a throwaway VM (LH_CONFINEMENT_INSTALL=yes)." >&2
  exit 2
fi

command -v pamtester >/dev/null || sudo apt-get install -y pamtester >/dev/null 2>&1 \
  || { echo "pamtester is missing and could not be installed" >&2; exit 2; }
# Plasma's own file is this on Ubuntu; without Plasma the stand-in gives the installer the same stack.
if [[ ! -f /etc/pam.d/kde ]]; then
  printf '# stand-in for the Plasma lock screen (scripts/ci/pam-contexts.sh)\n@include common-auth\n@include common-account\n' \
    | sudo tee /etc/pam.d/kde >/dev/null
fi
bash scripts/prototype/install.sh --no-build --lock-screen --console || exit 2

user=lhpam
pin=246810
pass=$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16)
id "$user" >/dev/null 2>&1 || sudo useradd --create-home --shell /bin/bash "$user"
printf '%s:%s\n' "$user" "$pass" | sudo chpasswd
uid=$(id -u "$user")

# A clean state: no PIN record or lockout of an earlier run, a software TPM that allows many tries.
sudo tpm2_dictionarylockout --clear-lockout >/dev/null 2>&1
sudo tpm2_dictionarylockout --setup-parameters --max-tries=100 --recovery-time=10 --lockout-recovery-time=10 >/dev/null 2>&1
sudo systemctl stop linuxhello-agent
sudo rm -rf "/var/lib/linuxhello/users/$uid" /var/lib/linuxhello/pinlock.toml
sudo systemctl start linuxhello-agent
sleep 2
T0=$(date +%s)

fail=0
check() { # name, command that succeeds when the property holds
  local out
  if out=$(eval "$2" 2>&1); then echo "PASS $1"; else echo "FAIL $1"; fail=$((fail + 1)); printf '     %s\n' "$(printf '%s' "$out" | tail -4)"; fi
}
# Runs PAM service $1 for the user with the answers printf "${@:3}" on standard input; prints what
# was asked and said, and returns pamtester's exit code. pam_unix asks "Password: "; the module
# asks a question with "PIN" in it. pamtester does not set PAM_SILENT, so the module's messages show.
attempt() { local service=$1; shift; printf "$@" | sudo timeout 90 pamtester "$service" "$user" authenticate 2>&1; }
passwords() { grep -o "Password:" <<<"$1" | wc -l; }
# Like attempt, and prints the time it took in milliseconds on the last line.
timed() { local start out code; start=$(date +%s%N); out=$(attempt "$@"); code=$?; printf '%s\n%s\n' "$out" "$(( ($(date +%s%N) - start) / 1000000 ))"; return "$code"; }

services="login kde sudo"

for s in $services; do
  check "${s}_a_user_without_a_pin_gets_the_password" \
    'out=$(attempt '"$s"' "%s\n" "$pass") && ! grep -q "PIN" <<<"$out" && [ "$(passwords "$out")" -eq 1 ]'
done

check "pin_set_for_the_user" \
  'printf "%s\n%s\n" "$pin" "$pin" | sudo -u "$user" /usr/bin/linuxhello-ctl pin set 2>&1 | grep -q "Done\.$"'

for s in $services; do
  check "${s}_the_right_pin_signs_in_without_the_password" \
    'out=$(attempt '"$s"' "%s\n" "$pin") && grep -q "PIN" <<<"$out" && [ "$(passwords "$out")" -eq 0 ]'
  check "${s}_an_empty_answer_falls_through_to_the_password" \
    'out=$(attempt '"$s"' "\n%s\n" "$pass") && grep -q "PIN" <<<"$out" && [ "$(passwords "$out")" -eq 1 ]'
  # The password follows the wrong PIN; were a wrong PIN to fall through, it would sign in with it.
  check "${s}_a_wrong_pin_never_falls_through_to_the_password" \
    '! out=$(attempt '"$s"' "999999\n%s\n" "$pass") && [ "$(passwords "$out")" -eq 0 ]'
  check "${s}_the_right_pin_still_works_after_a_wrong_one" \
    'attempt '"$s"' "%s\n" "$pin" >/dev/null'
done

# An Agent that hangs: the process is stopped (SIGSTOP), so the bus takes the call and nobody
# answers. The module's call deadline is 2 s (ADR-0023).
sudo systemctl kill -s STOP linuxhello-agent
for s in $services; do
  check "${s}_a_hung_agent_falls_through_to_the_password_within_its_deadline" \
    'out=$(timed '"$s"' "%s\n" "$pass") && took=$(tail -1 <<<"$out") && echo "took ${took} ms" && ! grep -q "PIN" <<<"$out" && [ "$took" -lt 3500 ]'
done
sudo systemctl kill -s CONT linuxhello-agent

sudo systemctl stop linuxhello-agent
for s in $services; do
  check "${s}_a_stopped_agent_falls_through_to_the_password_within_its_deadline" \
    'out=$(timed '"$s"' "%s\n" "$pass") && took=$(tail -1 <<<"$out") && echo "took ${took} ms" && ! grep -q "PIN" <<<"$out" && [ "$took" -lt 3000 ]'
done
sudo systemctl start linuxhello-agent
sleep 2

check "the_agent_answers_again_after_the_hang_and_the_stop" \
  'out=$(attempt login "%s\n" "$pin") && [ "$(passwords "$out")" -eq 0 ]'

check "no_confinement_denial_in_the_log" \
  '! sudo journalctl -k --no-pager --since "@$T0" 2>/dev/null | grep -E "apparmor=\"DENIED\".*linuxhello" | head -3 | grep .'

echo
if [[ $fail -eq 0 ]]; then echo "all checks passed"; else echo "$fail check(s) failed"; fi
exit $(( fail > 0 ))
