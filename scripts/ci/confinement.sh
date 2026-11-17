#!/usr/bin/env bash
# The confinement checks of the Agent on a real system bus: install the unit, the bus policy, the
# sysusers entry and the AppArmor profile of security/ exactly as a package would, start the
# Agent under an enforcing profile, and check with real users what ADR-0014 and section 8 of the
# architecture say. Prints PASS or FAIL per check and exits non-zero if any failed.
#
#   scripts/ci/confinement.sh        run by the `confinement` job of ci.yml on a GitHub-hosted runner
#
# It changes the machine it runs on: it creates the users linuxhello and lh, installs files under
# /usr, /etc and /var, loads an AppArmor profile and starts a unit. It therefore refuses to run
# anywhere but a CI runner (GITHUB_ACTIONS=true) or a throwaway VM (LH_CONFINEMENT_INSTALL=yes).
# The maintainer's VM run of the same checks (make vm-test-agent in the workstation repository)
# stays for Ubuntu 26.04 and other releases.
#
# Needs: the static binary of the Agent (cargo build --release --target x86_64-unknown-linux-musl
# -p linuxhello-agent), sudo, systemd, AppArmor, python3-dbus and python3-gi.
set -uo pipefail
cd "$(dirname "$0")/../.."

if [[ "${GITHUB_ACTIONS:-}" != true && "${LH_CONFINEMENT_INSTALL:-}" != yes ]]; then
  echo "refusing to install the Agent on this machine: this script is for a CI runner or a throwaway VM." >&2
  echo "Set LH_CONFINEMENT_INSTALL=yes only in a VM you can delete." >&2
  exit 2
fi

root=$PWD
sec=$root/security
bin=$root/target/x86_64-unknown-linux-musl/release/linuxhello-agent
for f in "$bin" "$sec/dbus/io.github.LinuxHello.Agent1.conf" "$sec/systemd/linuxhello-agent.service" \
         "$sec/systemd/linuxhello.sysusers" "$sec/apparmor/linuxhello-agent"; do
  [[ -f "$f" ]] || { echo "$f not found" >&2; exit 2; }
done

# The test users of the checks below: lh is an ordinary user, nobody exists already.
id lh >/dev/null 2>&1 || sudo useradd --create-home --shell /usr/sbin/nologin lh

# The checks pipe an answer into `grep -q`, which quits at the first match: with pipefail the
# writer would then fail with SIGPIPE and the check with it.
set +e +o pipefail
N=io.github.LinuxHello.Agent1; P=/io/github/LinuxHello/Agent1; fail=0
check() { # name, command that succeeds when the property holds; a failure shows what the command said
  local out
  if out=$(eval "$2" 2>&1); then echo "PASS $1"; else echo "FAIL $1"; fail=$((fail + 1)); printf '     %s\n' "$(printf '%s' "$out" | head -3)"; fi
}
call() { sudo -u "$1" busctl --system call "${@:2}" 2>&1; }

sudo systemd-sysusers $sec/systemd/linuxhello.sysusers
sudo install -D -m755 $bin /usr/libexec/linuxhello/linuxhello-agent
sudo install -D -m644 $sec/dbus/io.github.LinuxHello.Agent1.conf /usr/share/dbus-1/system.d/io.github.LinuxHello.Agent1.conf
sudo install -m644 $sec/apparmor/linuxhello-agent /etc/apparmor.d/linuxhello-agent
sudo install -m644 $sec/systemd/linuxhello-agent.service /usr/lib/systemd/system/linuxhello-agent.service
sudo apparmor_parser -r /etc/apparmor.d/linuxhello-agent
sudo systemctl reload dbus; sudo systemctl daemon-reload
sudo apt-get install -y --no-install-recommends python3-dbus python3-gi >/dev/null 2>&1
sudo systemctl stop linuxhello-agent 2>/dev/null; sudo systemctl reset-failed linuxhello-agent 2>/dev/null
T0=$(date +%s)
sudo systemctl start linuxhello-agent
for _ in 1 2 3 4 5 6 7 8 9 10; do busctl --system list --no-pager 2>/dev/null | grep -q "^$N " && break; sleep 1; done

PID=$(systemctl show -p MainPID --value linuxhello-agent)
check "unit_starts_with_the_profile_enforcing" '[ "$(systemctl is-active linuxhello-agent)" = active ] && sudo grep -qx "linuxhello-agent (enforce)" /sys/kernel/security/apparmor/profiles'
# Ubuntu 26.04 (systemd 259, kernel 7.0) stacks the profile with "unconfined": the label is
# "linuxhello-agent//&unconfined (enforce)", which is the profile's restrictions and no more.
check "agent_process_runs_confined_in_enforce_mode" 'sudo cat /proc/$PID/attr/current | grep -Eq "^linuxhello-agent(//&[a-z]+)? \(enforce\)$"'
check "name_is_owned_by_the_agents_user" 'busctl --system list --no-pager | grep -q "$N .*linuxhello .*linuxhello-agent.service"'
for u in lh nobody; do
  check "any_user_reaches_the_agents_methods_($u)" 'call $u $N $P $N GetState s bad | grep -q "invalid argument"'
  check "properties_are_denied_($u)" 'call $u $N $P org.freedesktop.DBus.Properties GetAll s $N | grep -q "Access denied"'
done

ID=$(python3 -c 'import hashlib;d=hashlib.sha256();d.update(b"io.github.LinuxHello.PromptId1")
for a in ["vmtest","tty2","s9"]:
    d.update(len(a).to_bytes(8,"big"));d.update(a.encode())
print(d.hexdigest())')
LHUID=$(id -u lh)
check "a_user_opens_a_prompt_for_itself" 'call lh $N $P $N OpenPrompt sx $ID $LHUID; [ $? -eq 0 ]'
check "the_user_reads_its_own_prompt" 'call lh $N $P $N GetState s $ID | grep -q idle'
for op in "GetState s $ID" "Subscribe s $ID" "ReportState ssas $ID State 1 scanning"; do
  check "another_user_is_refused_(${op%% *})" 'call nobody $N $P $N $op | grep -q "Access denied"'
done
check "another_user_cannot_open_a_prompt_for_someone_else" 'call nobody $N $P $N OpenPrompt sx $(echo $ID | tr 0-9a-f 1-9a-f0) $LHUID | grep -q "Access denied"'
check "another_user_cannot_take_the_name" 'call nobody org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus RequestName su $N 0 | grep -q "Access denied"'

# The user policy layer (ADR-0018): kept by the Agent under its state directory, set over the bus.
POLICY='[methods]
biometrics_allowed = false'
check "a_user_sets_its_own_policy_layer" 'call lh $N $P $N SetUserPolicy s "$POLICY"; [ $? -eq 0 ]'
check "the_user_reads_its_own_policy_layer" 'call lh $N $P $N GetUserPolicy | grep -q "biometrics_allowed = false"'
check "another_user_sees_only_its_own_empty_layer" 'call nobody $N $P $N GetUserPolicy | grep -qx "s \"\""'
check "a_policy_the_schema_rejects_is_refused" 'call lh $N $P $N SetUserPolicy s "invalid = toml" | grep -q "invalid argument"'
check "the_refused_policy_left_the_stored_layer_alone" 'call lh $N $P $N GetUserPolicy | grep -q "biometrics_allowed = false"'
check "the_layer_is_a_private_file_of_the_agents_user" '[ "$(sudo stat -c "%U %a" /var/lib/linuxhello/users/$LHUID/policy.toml)" = "linuxhello 600" ]'

# A subscriber hears the Agent's real signal; a bystander and two forgers cause nothing.
cat > /tmp/flow.py <<'PY'
import sys, dbus, dbus.mainloop.glib
from gi.repository import GLib
dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
role, prompt = sys.argv[1], sys.argv[2]
N, P = "io.github.LinuxHello.Agent1", "/io/github/LinuxHello/Agent1"
bus = dbus.SystemBus()
bus.add_signal_receiver(lambda *a, member=None, **k: print(role, "HEARD", member, [str(x) for x in a], flush=True),
                        dbus_interface=N, member_keyword="member")
if role == "subscriber":
    dbus.Interface(bus.get_object(N, P), N).Subscribe(prompt)
loop = GLib.MainLoop(); GLib.timeout_add(6000, loop.quit); loop.run()
PY
chmod 644 /tmp/flow.py
sudo -u lh python3 /tmp/flow.py subscriber $ID > /tmp/sub.out 2>&1 &
sudo -u nobody python3 /tmp/flow.py bystander $ID > /tmp/by.out 2>&1 &
sleep 2
sudo -u nobody busctl --system emit $P $N State ss $ID forged-by-nobody >/dev/null 2>&1
sudo -u lh busctl --system emit $P $N State ss $ID forged-by-lh >/dev/null 2>&1
call lh $N $P $N ReportState ssas $ID State 1 scanning >/dev/null
wait
check "a_subscriber_hears_the_agents_signal" 'grep -c "HEARD State .*scanning" /tmp/sub.out | grep -qx 1'
check "forged_signals_reach_nobody" '! grep -q forged /tmp/sub.out /tmp/by.out'
check "a_bystander_hears_nothing" '! grep -q HEARD /tmp/by.out'

# Fail closed: the unit must refuse to start unless the profile is loaded and enforcing.
sudo systemctl stop linuxhello-agent; sudo systemctl reset-failed linuxhello-agent 2>/dev/null
sudo apparmor_parser -r -C /etc/apparmor.d/linuxhello-agent
sudo systemctl start linuxhello-agent >/dev/null 2>&1
check "the_unit_refuses_to_start_with_the_profile_in_complain_mode" '[ "$(systemctl is-active linuxhello-agent)" != active ]'
sudo systemctl stop linuxhello-agent; sudo systemctl reset-failed linuxhello-agent 2>/dev/null
sudo apparmor_parser -R /etc/apparmor.d/linuxhello-agent
sudo systemctl start linuxhello-agent >/dev/null 2>&1
check "the_unit_refuses_to_start_with_the_profile_not_loaded" '[ "$(systemctl is-active linuxhello-agent)" != active ]'
sudo systemctl stop linuxhello-agent; sudo systemctl reset-failed linuxhello-agent 2>/dev/null
sudo apparmor_parser -r /etc/apparmor.d/linuxhello-agent; sudo systemctl start linuxhello-agent; sleep 1
check "the_unit_starts_again_once_the_profile_is_enforcing" '[ "$(systemctl is-active linuxhello-agent)" = active ]'

# No AppArmor denial except the probes of this test (the Properties calls that the policy refuses).
D=$(sudo journalctl -k --no-pager --since "@$T0" | grep "apparmor=\"DENIED\"" | grep "linuxhello-agent" | grep -vc "interface=\"org.freedesktop.DBus.Properties\"")
check "apparmor_denies_nothing_the_agent_needs" '[ "$D" = 0 ]'
# The profile really denies: run an ordinary binary under it. It grants /usr/bin/cat nothing, so the
# kernel must refuse to start it and log the denial. Done last so it does not count above.
sudo systemd-run --quiet --wait --pipe -p AppArmorProfile=linuxhello-agent -p User=linuxhello /usr/bin/cat /etc/hostname >/dev/null 2>&1
RC=$?
check "the_profile_really_denies_what_it_does_not_grant" '[ "$RC" -ne 0 ] && sudo journalctl -k --no-pager --since "-30sec" | grep "apparmor=\"DENIED\"" | grep -q "linuxhello-agent"'
SC=$(systemd-analyze security linuxhello-agent --no-pager 2>&1 | tail -1)
echo "INFO $SC"
[[ "$fail" -eq 0 ]] && echo "ALL PASSED" || echo "$fail FAILED"

if [[ "$fail" -ne 0 ]]; then
  echo "---- journal of the unit"; sudo journalctl -u linuxhello-agent --no-pager | tail -40
  echo "---- AppArmor denials"; sudo journalctl -k --no-pager | grep 'apparmor="DENIED"' | tail -20
fi
exit "$fail"
