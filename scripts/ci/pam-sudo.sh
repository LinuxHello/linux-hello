#!/usr/bin/env bash
# The checks are strings run by eval, which shellcheck does not read, so it cannot see their uses.
# shellcheck disable=SC2016,SC2034,SC2059,SC2329
# The PAM module inside real sudo: the prototype installed by scripts/prototype/install.sh, then
# sudo driven with -S (answers read from standard input) by a throwaway user with a password. The
# checks state ADR-0023: the right PIN unlocks sudo; a wrong PIN fails the attempt and never falls
# through to the password; an empty answer, a user without a PIN and a stopped Agent fall through
# to the password, the last within the module's deadline. Prints PASS or FAIL per check and exits
# non-zero if any failed.
#
#   scripts/ci/pam-sudo.sh     run in a throwaway VM with /dev/tpmrm0 (make vm-test-pam-sudo in the
#                              workstation repository)
#
# It changes the machine it runs on (the installer's changes, a user lhpam with a password and a
# sudoers rule), so it refuses to run anywhere but a throwaway VM (LH_CONFINEMENT_INSTALL=yes).
# Needs what scripts/prototype/install.sh --no-build needs, already built under target/.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 2

if [[ "${LH_CONFINEMENT_INSTALL:-}" != yes ]]; then
  echo "refusing to change this machine: this script is for a throwaway VM (LH_CONFINEMENT_INSTALL=yes)." >&2
  exit 2
fi

bash scripts/prototype/install.sh --no-build || exit 2

user=lhpam
pin=246810
pass=$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16)
id "$user" >/dev/null 2>&1 || sudo useradd --create-home --shell /bin/bash "$user"
printf '%s:%s\n' "$user" "$pass" | sudo chpasswd
printf '%s ALL=(ALL) ALL\n' "$user" | sudo tee /etc/sudoers.d/lhpam >/dev/null
sudo chmod 440 /etc/sudoers.d/lhpam
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
# Runs `sudo true` as the user with the answers printf "$@" on standard input; prints what
# sudo and the module said and returns sudo's exit code. sudo shows the module's question as
# "[sudo: PASSWORD:] PIN: ..." and its own password question as "PASSWORD:", so the number of
# "PASSWORD:" in the output is the number of questions asked. sudo calls PAM with PAM_SILENT (its
# pam_silent default), so the module's messages ("Wrong PIN.") do not appear.
attempt() { printf "$1" "${@:2}" | sudo -u "$user" -H timeout 90 sudo -S -k -p 'PASSWORD:' true 2>&1; }
asked() { grep -o "PASSWORD:" <<<"$1" | wc -l; }

check "a_user_without_a_pin_gets_the_password" \
  'out=$(attempt "%s\n" "$pass") && ! grep -q "PIN" <<<"$out"'

check "pin_set_for_the_user" \
  'printf "%s\n%s\n" "$pin" "$pin" | sudo -u "$user" /usr/bin/linuxhello-ctl pin set 2>&1 | grep -q "Done\.$"'

check "the_right_pin_unlocks_sudo" \
  'out=$(attempt "%s\n" "$pin") && grep -q "PIN" <<<"$out" && [ "$(asked "$out")" -eq 1 ]'

check "an_empty_answer_falls_through_to_the_password" \
  'out=$(attempt "\n%s\n" "$pass") && grep -q "PIN" <<<"$out" && [ "$(asked "$out")" -eq 2 ]'

# Three attempts, each a PIN that is wrong; the password follows the first. Were a wrong PIN to fall
# through, the first attempt would succeed with it.
check "a_wrong_pin_never_falls_through_to_the_password" \
  '! out=$(attempt "999999\n%s\n%s\n%s\n" "$pass" "$pass" "$pass") && grep -q "3 incorrect" <<<"$out" && [ "$(grep -c "PIN" <<<"$out")" -eq 3 ]'

check "the_right_pin_still_works_after_wrong_ones" \
  'attempt "%s\n" "$pin" >/dev/null'

sudo systemctl stop linuxhello-agent
check "a_stopped_agent_falls_through_to_the_password_within_its_deadline" \
  'start=$(date +%s%N); out=$(attempt "%s\n" "$pass"); code=$?; took=$(( ($(date +%s%N) - start) / 1000000 )); echo "took ${took} ms"; [ $code -eq 0 ] && ! grep -q "PIN" <<<"$out" && [ $took -lt 3000 ]'
sudo systemctl start linuxhello-agent

check "no_confinement_denial_in_the_log" \
  '! sudo journalctl -k --no-pager --since "@$T0" 2>/dev/null | grep -E "apparmor=\"DENIED\".*linuxhello" | head -3 | grep .'

echo
if [[ $fail -eq 0 ]]; then echo "all checks passed"; else echo "$fail check(s) failed"; fi
exit $(( fail > 0 ))
