#!/usr/bin/env bash
# The fingerprint method against the real fprintd, with libfprint's virtual fingerprint device: the
# Agent installed as a package would install it, on a real system bus, under its enforcing AppArmor
# profile, and the real fprintd service with the polkit rule of security/polkit. A virtual finger is
# enrolled, and a match, a mismatch and a cancel run through the Agent's `Authenticate`. Prints PASS or
# FAIL per check and exits non-zero if any failed.
#
#   scripts/ci/fingerprint-real.sh     run in a throwaway VM (make vm-test-fingerprint in the workstation
#                                      repository)
#
# It changes the machine it runs on: it installs fprintd (apt), creates the users linuxhello and lh,
# installs files under /usr, /etc and /var, loads an AppArmor profile, adds a systemd drop-in that gives
# fprintd the virtual device, and starts units. It therefore refuses to run anywhere but a throwaway VM
# (LH_CONFINEMENT_INSTALL=yes).
#
# The virtual device is libfprint's `virtual_device` driver: fprintd listens for it on a socket named
# by FP_VIRTUAL_DEVICE, and a client sends one command per connection, `SCAN <name>`, which stands for a
# finger. Enrolling takes five scans of one name; a verify matches when the scan has the enrolled name.
#
# Needs: the static Agent (cargo build --release --target x86_64-unknown-linux-musl -p linuxhello-agent),
# sudo, systemd, AppArmor, and network access for apt in the VM.
set -uo pipefail
cd "$(dirname "$0")/../.."

if [[ "${LH_CONFINEMENT_INSTALL:-}" != yes ]]; then
  echo "refusing to install the Agent and fprintd on this machine: this script is for a throwaway VM." >&2
  echo "Set LH_CONFINEMENT_INSTALL=yes only in a VM you can delete." >&2
  exit 2
fi

root=$PWD
sec=$root/security
agent=$root/target/x86_64-unknown-linux-musl/release/linuxhello-agent
for f in "$agent" "$sec/dbus/io.github.LinuxHello.Agent1.conf" "$sec/dbus/io.github.LinuxHello.Agent1.service" \
         "$sec/systemd/linuxhello-agent.service" "$sec/systemd/linuxhello.sysusers" \
         "$sec/apparmor/linuxhello-agent" "$sec/polkit/50-linuxhello-agent.rules"; do
  [[ -f "$f" ]] || { echo "$f not found" >&2; exit 2; }
done

id lh >/dev/null 2>&1 || sudo useradd --create-home --shell /usr/sbin/nologin lh
sudo apt-get install -y --no-install-recommends fprintd python3-dbus >/dev/null 2>&1 \
  || { echo "could not install fprintd and python3-dbus with apt" >&2; exit 2; }

set +e +o pipefail
fail=0
check() { # name, command that succeeds when the property holds; a failure shows what it said
  local out
  if out=$(eval "$2" 2>&1); then echo "PASS $1"; else echo "FAIL $1"; fail=$((fail + 1)); printf '     %s\n' "$(printf '%s' "$out" | head -3)"; fi
}

# The Agent, as a package installs it.
sudo systemd-sysusers "$sec/systemd/linuxhello.sysusers"
sudo install -D -m755 "$agent" /usr/libexec/linuxhello/linuxhello-agent
sudo install -D -m644 "$sec/dbus/io.github.LinuxHello.Agent1.conf" /usr/share/dbus-1/system.d/io.github.LinuxHello.Agent1.conf
sudo install -D -m644 "$sec/dbus/io.github.LinuxHello.Agent1.service" /usr/share/dbus-1/system-services/io.github.LinuxHello.Agent1.service
sudo install -m644 "$sec/apparmor/linuxhello-agent" /etc/apparmor.d/linuxhello-agent
sudo install -D -m644 "$sec/polkit/50-linuxhello-agent.rules" /etc/polkit-1/rules.d/50-linuxhello-agent.rules
sudo systemctl restart polkit; sleep 1
sudo install -m644 "$sec/systemd/linuxhello-agent.service" /usr/lib/systemd/system/linuxhello-agent.service
sudo apparmor_parser -r /etc/apparmor.d/linuxhello-agent
sudo systemctl reload dbus; sudo systemctl daemon-reload
sudo rm -rf /var/lib/linuxhello/users /var/lib/linuxhello/pinlock.toml

# fprintd with the virtual device. It runs as root with a read-only file system, so the socket goes in a
# runtime directory of its own.
sudo install -d /etc/systemd/system/fprintd.service.d
printf '[Service]\nEnvironment=FP_VIRTUAL_DEVICE=/run/fprint-virtual/dev.sock\nRuntimeDirectory=fprint-virtual\nRuntimeDirectoryMode=0755\nRuntimeDirectoryPreserve=yes\n' \
  | sudo tee /etc/systemd/system/fprintd.service.d/virtual.conf >/dev/null
sudo systemctl daemon-reload
sudo systemctl restart fprintd; sleep 1

# One command per connection; the connection is retried until the driver listens (it opens the socket
# when a client claims the device).
cat > /tmp/vscan.py <<'PY'
import socket, sys, time
name = sys.argv[1]
delay = float(sys.argv[2]) if len(sys.argv) > 2 else 0.0
time.sleep(delay)
for _ in range(50):
    try:
        s = socket.socket(socket.AF_UNIX); s.connect("/run/fprint-virtual/dev.sock"); break
    except OSError:
        time.sleep(0.2)
else:
    sys.exit(1)
s.sendall(("SCAN %s\n" % name).encode()); time.sleep(0.3); s.close()
PY
chmod 644 /tmp/vscan.py

# One process opens a prompt, authenticates and waits for the result, as the login screen's client would.
# The optional second argument closes the prompt after that many seconds (a cancel).
cat > /tmp/auth_flow.py <<'PY'
import hashlib, sys, time, dbus
N, P = "io.github.LinuxHello.Agent1", "/io/github/LinuxHello/Agent1"
d = hashlib.sha256(); d.update(b"io.github.LinuxHello.PromptId1")
for a in ["vmtest", "tty5", sys.argv[3] if len(sys.argv) > 3 else "fp%f" % time.time()]:
    d.update(len(a).to_bytes(8, "big")); d.update(a.encode())
prompt = d.hexdigest()
agent = dbus.Interface(dbus.SystemBus().get_object(N, P), N)
agent.OpenPrompt(prompt, dbus.Int64(int(sys.argv[1])))
agent.Authenticate(prompt, "login")
cancel_after = float(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2] != "-" else None
start = time.time()
while time.time() - start < 20:
    state = agent.GetState(prompt)
    if str(state[3]):
        print("RESULT", str(state[3]), repr(str(state[4])), flush=True)
        break
    if cancel_after is not None and time.time() - start > cancel_after:
        agent.ClosePrompt(prompt)
        print("CANCELLED", flush=True)
        break
    time.sleep(0.1)
else:
    print("NORESULT", flush=True)
PY
chmod 644 /tmp/auth_flow.py

sudo systemctl stop linuxhello-agent 2>/dev/null; sudo systemctl reset-failed linuxhello-agent 2>/dev/null
T0=$(date +%s)
sudo systemctl start linuxhello-agent
N=io.github.LinuxHello.Agent1
for _ in 1 2 3 4 5 6 7 8 9 10; do busctl --system list --no-pager 2>/dev/null | grep -q "^$N " && break; sleep 1; done
LHUID=$(id -u lh)
check "the_agent_runs_confined_and_fprintd_has_the_virtual_device" '[ "$(systemctl is-active linuxhello-agent)" = active ] && sudo grep -qx "linuxhello-agent (enforce)" /sys/kernel/security/apparmor/profiles && busctl --system call net.reactivated.Fprint /net/reactivated/Fprint/Manager net.reactivated.Fprint.Manager GetDevices | grep -q "^ao 1"'

# Enrol a virtual finger of user lh: five scans of one name.
sudo fprintd-delete lh >/dev/null 2>&1
(sudo fprintd-enroll lh > /tmp/enroll.out 2>&1 &)
for _ in 1 2 3 4 5 6; do sudo python3 /tmp/vscan.py lh-finger 0.5; done
sleep 1
check "a_virtual_finger_is_enrolled" 'sudo fprintd-list lh | grep -q "right-index-finger"'

# The user's layer: take away what an earlier run may have left, so that fingerprint is allowed.
busctl --system call $N /io/github/LinuxHello/Agent1 $N SetUserPolicy s "" >/dev/null 2>&1
sudo -u lh busctl --system call $N /io/github/LinuxHello/Agent1 $N SetUserPolicy s "" >/dev/null 2>&1

check "a_matching_finger_signs_in" '(sudo python3 /tmp/vscan.py lh-finger 2.5 &) ; sudo -u lh python3 /tmp/auth_flow.py $LHUID - | grep -q "^RESULT success"'
sleep 1
check "a_finger_that_does_not_match_is_a_failure_with_a_reason" '(sudo python3 /tmp/vscan.py somebody-else 2.5 &) ; sudo -u lh python3 /tmp/auth_flow.py $LHUID - | grep -q "RESULT failure .not-recognised"'
sleep 1
check "a_cancel_ends_the_wait_and_frees_the_reader" 'sudo -u lh python3 /tmp/auth_flow.py $LHUID 2 | grep -q "^CANCELLED"; sleep 1; (sudo python3 /tmp/vscan.py lh-finger 2.5 &) ; sudo -u lh python3 /tmp/auth_flow.py $LHUID - | grep -q "^RESULT success"'

# What polkit says about the real actions, for the Agent's user and for another user.
AGENT_PID=$(systemctl show -p MainPID --value linuxhello-agent)
for action in net.reactivated.fprint.device.verify net.reactivated.fprint.device.setusername; do
  check "polkit_lets_the_agent_use_$action" 'sudo -u linuxhello pkcheck --action-id '$action' --process $AGENT_PID'
done
check "polkit_does_not_let_another_user_pick_whose_finger_is_checked" '! sudo -u lh pkcheck --action-id net.reactivated.fprint.device.setusername --process $$'

check "the_profile_denied_nothing_the_real_service_needed" '! sudo journalctl -k --no-pager --since "@$T0" 2>/dev/null | grep -E "apparmor=\"DENIED\".*linuxhello-agent" | head -3 | grep .'

echo
if [[ $fail -eq 0 ]]; then echo "All checks passed."; else echo "$fail check(s) failed."; exit 1; fi
