#!/usr/bin/env bash
# The whole PIN chain on a real machine: the Agent and the TPM provider installed as packages would
# install them, on a real system bus, under their enforcing AppArmor profiles, with a TPM behind the
# provider. `linuxhello-ctl pin set` and `pin change` run as an ordinary user and must set the PIN,
# refuse a wrong current PIN, and change the key's authorisation in the TPM: after a change only the
# new PIN works. Prints PASS or FAIL per check and exits non-zero if any failed.
#
#   scripts/ci/pin-chain.sh     run in a throwaway VM that has /dev/tpmrm0 (make vm-test-pin in the
#                               workstation repository)
#
# It changes the machine it runs on: it creates users, installs files under /usr, /etc and /var,
# loads AppArmor profiles and starts two units, so it refuses to run anywhere but a throwaway VM
# (LH_CONFINEMENT_INSTALL=yes). The provider is a dynamic binary: build it on the release of the VM.
#
# Needs: the static Agent and CLI (cargo build --release --target x86_64-unknown-linux-musl
# -p linuxhello-agent -p linuxhello-ctl), the provider (cargo build --release -p
# linuxhello-tpm-provider), the libtss2 runtime libraries, sudo, systemd, AppArmor.
set -uo pipefail
cd "$(dirname "$0")/../.."

if [[ "${LH_CONFINEMENT_INSTALL:-}" != yes ]]; then
  echo "refusing to install the Agent and the provider on this machine: this script is for a throwaway VM." >&2
  echo "Set LH_CONFINEMENT_INSTALL=yes only in a VM you can delete." >&2
  exit 2
fi

root=$PWD
sec=$root/security
musl=$root/target/x86_64-unknown-linux-musl/release
agent=$musl/linuxhello-agent
ctl=$musl/linuxhello-ctl
prov=$root/target/release/linuxhello-tpm-provider
for f in "$agent" "$ctl" "$prov" "$sec/dbus/io.github.LinuxHello.Agent1.conf" \
         "$sec/dbus/io.github.LinuxHello.Agent1.service" "$sec/systemd/linuxhello-agent.service" \
         "$sec/systemd/linuxhello-tpm-provider.service" "$sec/systemd/linuxhello.sysusers" \
         "$sec/apparmor/linuxhello-agent" "$sec/apparmor/linuxhello-tpm-provider"; do
  [[ -f "$f" ]] || { echo "$f not found" >&2; exit 2; }
done
[[ -c /dev/tpmrm0 ]] || { echo "no /dev/tpmrm0 on this machine" >&2; exit 2; }

id lh >/dev/null 2>&1 || sudo useradd --create-home --shell /usr/sbin/nologin lh
set +e +o pipefail
fail=0
check() { # name, command that succeeds when the property holds; a failure shows what it said
  local out
  if out=$(eval "$2" 2>&1); then echo "PASS $1"; else echo "FAIL $1"; fail=$((fail + 1)); printf '     %s\n' "$(printf '%s' "$out" | head -3)"; fi
}

# A throwaway software TPM: clear its lockout and let it allow many wrong tries, so that repeated runs
# of this script do not lock it (its default is three wrong authorisations for the whole TPM).
sudo tpm2_dictionarylockout --clear-lockout >/dev/null 2>&1
sudo tpm2_dictionarylockout --setup-parameters --max-tries=100 --recovery-time=10 --lockout-recovery-time=10 >/dev/null 2>&1

sudo systemd-sysusers "$sec/systemd/linuxhello.sysusers"
sudo install -D -m755 "$agent" /usr/libexec/linuxhello/linuxhello-agent
sudo install -D -m755 "$prov" /usr/libexec/linuxhello/linuxhello-tpm-provider
sudo install -D -m755 "$ctl" /usr/bin/linuxhello-ctl
sudo install -D -m644 "$sec/dbus/io.github.LinuxHello.Agent1.conf" /usr/share/dbus-1/system.d/io.github.LinuxHello.Agent1.conf
sudo install -D -m644 "$sec/dbus/io.github.LinuxHello.Agent1.service" /usr/share/dbus-1/system-services/io.github.LinuxHello.Agent1.service
sudo install -m644 "$sec/apparmor/linuxhello-agent" /etc/apparmor.d/linuxhello-agent
sudo install -m644 "$sec/apparmor/linuxhello-tpm-provider" /etc/apparmor.d/linuxhello-tpm-provider
sudo install -D -m644 "$sec/polkit/50-linuxhello-agent.rules" /etc/polkit-1/rules.d/50-linuxhello-agent.rules
sudo systemctl restart polkit; sleep 1
sudo install -m644 "$sec/systemd/linuxhello-agent.service" /usr/lib/systemd/system/linuxhello-agent.service
sudo install -m644 "$sec/systemd/linuxhello-tpm-provider.service" /usr/lib/systemd/system/linuxhello-tpm-provider.service
sudo apparmor_parser -r /etc/apparmor.d/linuxhello-agent /etc/apparmor.d/linuxhello-tpm-provider
sudo systemctl reload dbus; sudo systemctl daemon-reload
sudo systemctl stop linuxhello-agent linuxhello-tpm-provider 2>/dev/null
sudo systemctl reset-failed linuxhello-agent linuxhello-tpm-provider 2>/dev/null
# A clean state: no PIN records from an earlier run.
sudo rm -rf /var/lib/linuxhello/users /var/lib/linuxhello/pinlock.toml
# The provider first: the Agent asks it for the TPM's limit when it starts.
sudo systemctl start linuxhello-tpm-provider; sleep 2
sudo systemctl start linuxhello-agent
for _ in 1 2 3 4 5 6 7 8 9 10; do busctl --system list --no-pager 2>/dev/null | grep -q "^io.github.LinuxHello.Agent1 " && break; sleep 1; done

check "both_units_run_confined" '[ "$(systemctl is-active linuxhello-tpm-provider)" = active ] && [ "$(systemctl is-active linuxhello-agent)" = active ] && sudo grep -qx "linuxhello-agent (enforce)" /sys/kernel/security/apparmor/profiles && sudo grep -qx "linuxhello-tpm-provider (enforce)" /sys/kernel/security/apparmor/profiles'

LHUID=$(id -u lh)
# The command reads the PINs from standard input when it is not a terminal: the new PIN, and again.
pin() { # arguments: set|change, then the lines to type
  local cmd=$1; shift
  printf '%s\n' "$@" | sudo -u lh /usr/bin/linuxhello-ctl pin "$cmd" 2>&1
}
RECORD=/var/lib/linuxhello/users/$LHUID/pin-root.toml

check "pin_change_before_a_pin_is_set_is_refused" 'pin change 111111 222222 222222 | grep -q "refused"'
check "pin_set_sets_the_first_pin_in_the_tpm" 'pin set 111111 111111 | grep -q "Done\.$"'
check "the_record_is_private_to_the_agent" '[ "$(sudo stat -c "%U %a" $RECORD)" = "linuxhello 600" ]'
check "the_record_holds_no_pin" '! sudo grep -q 111111 $RECORD'
check "pin_set_twice_is_refused" 'pin set 333333 333333 | grep -q "refused"'
check "two_different_new_pins_change_nothing" 'pin change 111111 222222 222223 | grep -q "not the same"'
check "a_wrong_current_pin_is_refused_by_the_tpm_path" 'pin change 999999 222222 222222 | grep -q "current PIN is wrong"'
check "the_right_current_pin_changes_the_pin" 'pin change 111111 222222 222222 | grep -q "Done\.$"'
check "after_a_change_the_old_pin_no_longer_works" 'pin change 111111 333333 333333 | grep -q "current PIN is wrong"'
check "after_a_change_the_new_pin_works" 'pin change 222222 333333 333333 | grep -q "Done\.$"'
check "a_pin_that_is_too_short_is_not_accepted" 'pin change 333333 1 1 | grep -q "not accepted"'
check "a_pin_without_a_digit_is_not_accepted_by_the_default_policy" 'pin change 333333 abcdefgh abcdefgh | grep -q "not accepted"'
check "the_pin_still_works_after_a_refused_change" 'pin change 333333 444444 444444 | grep -q "Done\.$"'
check "the_current_pin_cannot_be_chosen_as_the_new_pin" 'pin change 444444 444444 444444 | grep -q "not accepted"'
check "no_confinement_denial_in_the_log" '! sudo journalctl -k --no-pager --since "-10min" 2>/dev/null | grep -E "apparmor=\"DENIED\".*(linuxhello-agent|linuxhello-tpm-provider|linuxhello-ctl)" | head -3 | grep .'

# P-14 on a real machine. The TPM counts wrong tries for every user together and locks all of them at
# its own limit; here it allows three. The Agent reads that limit when it starts and keeps its own at
# half of it (one), so one user's wrong PINs are stopped by the Agent before they reach the TPM and
# leave the other user's PIN working.
id lh2 >/dev/null 2>&1 || sudo useradd --create-home --shell /usr/sbin/nologin lh2
pin_as() { # arguments: user, set|change, then the lines to type
  local user=$1 cmd=$2; shift 2
  printf '%s\n' "$@" | sudo -u "$user" /usr/bin/linuxhello-ctl pin "$cmd" 2>&1
}
sudo tpm2_dictionarylockout --clear-lockout >/dev/null 2>&1
sudo tpm2_dictionarylockout --setup-parameters --max-tries=3 --recovery-time=10 --lockout-recovery-time=10 >/dev/null 2>&1
# The provider reads the TPM's properties once, when it starts, and the Agent asks it when the Agent
# starts: both restart, the provider first, to see the new limit.
sudo systemctl restart linuxhello-tpm-provider; sleep 2
sudo systemctl restart linuxhello-agent
for _ in 1 2 3 4 5 6 7 8 9 10; do busctl --system list --no-pager 2>/dev/null | grep -q "^io.github.LinuxHello.Agent1 " && break; sleep 1; done
check "the_status_says_the_tpm_lowered_the_pin_limit" 'sudo -u lh /usr/bin/linuxhello-ctl status | grep -q tpm-dictionary-limit-low'
check "a_second_user_sets_a_pin" 'pin_as lh2 set 555555 555555 | grep -q "Done\.$"'
check "one_users_wrong_pins_are_stopped_by_the_agent_not_the_tpm" 'pin_as lh change 000000 666666 666666 | grep -q "Too many wrong PINs" && pin_as lh change 000000 666666 666666 | grep -q "Too many wrong PINs" && pin_as lh change 000000 666666 666666 | grep -q "Too many wrong PINs"'
check "the_other_users_pin_still_works_while_the_first_is_locked" 'pin_as lh2 change 555555 777777 777777 | grep -q "Done\.$"'
check "the_tpm_itself_is_not_in_lockout" '! sudo tpm2_getcap properties-variable 2>/dev/null | grep -A1 TPM2_PT_PERMANENT | grep -q "inLockout: *1"'
# Back to a TPM that tolerates repeated runs of this script, and a clean lock.
sudo tpm2_dictionarylockout --clear-lockout >/dev/null 2>&1
sudo tpm2_dictionarylockout --setup-parameters --max-tries=100 --recovery-time=10 --lockout-recovery-time=10 >/dev/null 2>&1
sudo systemctl stop linuxhello-agent; sudo rm -f /var/lib/linuxhello/pinlock.toml
sudo systemctl restart linuxhello-tpm-provider; sleep 2; sudo systemctl start linuxhello-agent

echo
if [[ $fail -eq 0 ]]; then echo "All checks passed."; else echo "$fail check(s) failed."; exit 1; fi
