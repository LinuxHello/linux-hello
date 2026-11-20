#!/usr/bin/env bash
# The confinement checks of the TPM provider on a real TPM interface: install its unit, sysusers entry
# and AppArmor profile exactly as a package would, start it under an enforcing profile, and check with
# real users that only the Agent's user is served, that the TPM answers right and wrong PINs, and that
# the profile denies the provider nothing it needs. Prints PASS or FAIL per check and exits non-zero if
# any failed.
#
#   scripts/ci/provider-confinement.sh     run in a throwaway VM that has /dev/tpmrm0 (make vm-test-provider
#                                           in the workstation repository)
#
# It changes the machine it runs on: it creates the users linuxhello, linuxhello-tpm and lh, installs
# files under /usr and /etc, loads an AppArmor profile and starts a unit. It therefore refuses to run
# anywhere but a throwaway VM (LH_CONFINEMENT_INSTALL=yes). Unlike the Agent's, the provider is a
# dynamic binary (it links the TSS2 libraries), so the binary must be built on the same release as the
# machine it runs on.
#
# Needs: the binary (cargo build --release -p linuxhello-tpm-provider), the libtss2 runtime libraries,
# sudo, systemd, AppArmor and python3.
set -uo pipefail
cd "$(dirname "$0")/../.."

if [[ "${LH_CONFINEMENT_INSTALL:-}" != yes ]]; then
  echo "refusing to install the provider on this machine: this script is for a throwaway VM." >&2
  echo "Set LH_CONFINEMENT_INSTALL=yes only in a VM you can delete." >&2
  exit 2
fi

root=$PWD
sec=$root/security
bin=$root/target/release/linuxhello-tpm-provider
for f in "$bin" "$sec/systemd/linuxhello-tpm-provider.service" "$sec/systemd/linuxhello.sysusers" \
         "$sec/apparmor/linuxhello-tpm-provider"; do
  [[ -f "$f" ]] || { echo "$f not found" >&2; exit 2; }
done
[[ -c /dev/tpmrm0 ]] || { echo "no /dev/tpmrm0 on this machine" >&2; exit 2; }

id lh >/dev/null 2>&1 || sudo useradd --create-home --shell /usr/sbin/nologin lh
set +e +o pipefail
fail=0
T0=$(date +%s)
check() { # name, command that succeeds when the property holds
  local out
  if out=$(eval "$2" 2>&1); then echo "PASS $1"; else echo "FAIL $1"; fail=$((fail + 1)); printf '     %s\n' "$(printf '%s' "$out" | head -3)"; fi
}

# The TPM of the VM is software and throwaway. Its dictionary-attack defaults (swtpm: three wrong
# authorisations, then a lockout of a thousand seconds for the whole TPM) would lock it after three runs of
# this script, which makes one wrong PIN each, so clear it and allow many tries. A real TPM's limit
# is a finding for the Agent's own limit (#271), not something this script may change on a real machine:
# it is for a throwaway VM only.
sudo tpm2_dictionarylockout --clear-lockout >/dev/null 2>&1
sudo tpm2_dictionarylockout --setup-parameters --max-tries=100 --recovery-time=10 --lockout-recovery-time=10 >/dev/null 2>&1

sudo systemd-sysusers "$sec/systemd/linuxhello.sysusers"
sudo install -D -m755 "$bin" /usr/libexec/linuxhello/linuxhello-tpm-provider
sudo install -m644 "$sec/apparmor/linuxhello-tpm-provider" /etc/apparmor.d/linuxhello-tpm-provider
sudo install -m644 "$sec/systemd/linuxhello-tpm-provider.service" /usr/lib/systemd/system/linuxhello-tpm-provider.service
sudo apparmor_parser -r /etc/apparmor.d/linuxhello-tpm-provider
sudo systemctl daemon-reload
sudo systemctl restart linuxhello-tpm-provider; sleep 2

check "the_unit_starts_with_the_profile_enforcing" '[ "$(systemctl is-active linuxhello-tpm-provider)" = active ] && sudo grep -qx "linuxhello-tpm-provider (enforce)" /sys/kernel/security/apparmor/profiles'
PID=$(systemctl show -p MainPID --value linuxhello-tpm-provider)
check "the_process_runs_confined_in_enforce_mode" 'sudo cat /proc/$PID/attr/current | grep -Eq "^linuxhello-tpm-provider(//&[a-z]+)? \(enforce\)$"'
check "the_provider_runs_as_its_own_user" '[ "$(ps -o user= -p $PID)" = linuxhello-tpm ]'
check "the_socket_is_the_providers_and_nobody_else_can_change_its_directory" '[ "$(stat -c "%U %a" /run/linuxhello-tpm)" = "linuxhello-tpm 755" ] && [ "$(stat -c "%U" /run/linuxhello-tpm/tpm.sock)" = linuxhello-tpm ]'
check "the_socket_is_open_to_the_agents_group_only" '[ "$(stat -c "%U:%G %a" /run/linuxhello-tpm/tpm.sock)" = "linuxhello-tpm:linuxhello 660" ]'
check "another_user_cannot_replace_the_socket" '! sudo -u lh rm /run/linuxhello-tpm/tpm.sock 2>/dev/null && [ -S /run/linuxhello-tpm/tpm.sock ]'

# A client in Python: one request, one answer. The request is the operation byte and the fields, each a
# two-byte length and the bytes, in a frame of a four-byte length (linuxhello-tpm-provider wire.rs).
cat > /tmp/tpm_client.py <<'PY'
import socket, struct, sys
def frame(body): return struct.pack(">I", len(body)) + body
def field(b): return struct.pack(">H", len(b)) + b
def call(body):
    s = socket.socket(socket.AF_UNIX); s.settimeout(20)
    s.connect("/run/linuxhello-tpm/tpm.sock")
    try:
        s.sendall(frame(body))
        head = s.recv(4)
        if len(head) < 4: return None
        n = struct.unpack(">I", head)[0]
        data = b""
        while len(data) < n:
            chunk = s.recv(n - len(data))
            if not chunk: break
            data += chunk
        return data
    except (ConnectionResetError, BrokenPipeError):
        return None
def enrol(auth): return call(bytes([1]) + field(auth))
def verify(blobs, auth): return call(bytes([2]) + field(blobs[0]) + field(blobs[1]) + field(auth))
def parse_blobs(answer):
    pub_len = struct.unpack(">H", answer[1:3])[0]
    pub = answer[3:3 + pub_len]
    rest = answer[3 + pub_len:]
    prv_len = struct.unpack(">H", rest[:2])[0]
    return pub, rest[2:2 + prv_len]
role = sys.argv[1]
if role == "enrol-and-verify":
    right, wrong = bytes([1]) * 32, bytes([2]) * 32
    made = enrol(right)
    print("ENROL", None if made is None else made[0])
    blobs = parse_blobs(made)
    a = verify(blobs, right); b = verify(blobs, wrong)
    print("RIGHT", None if a is None else a[0], "WRONG", None if b is None else b[0])
elif role == "enrol-only":
    made = enrol(bytes([1]) * 32)
    print("ENROL", None if made is None else made[0])
elif role == "garbage":
    s = socket.socket(socket.AF_UNIX); s.settimeout(10); s.connect("/run/linuxhello-tpm/tpm.sock")
    s.sendall(b"\x00\x00\x00\x05\x09\x00\x00\x00\x00"); s.shutdown(socket.SHUT_WR)
    print("ANSWER", repr(s.recv(16)))
PY
chmod 644 /tmp/tpm_client.py
check "the_agents_user_gets_a_key_and_the_tpm_tells_a_right_pin_from_a_wrong_one" 'sudo -u linuxhello python3 /tmp/tpm_client.py enrol-and-verify | tr "\n" " " | grep -q "ENROL 0 RIGHT 0 WRONG 1"'
check "another_user_cannot_even_connect" 'sudo -u lh python3 /tmp/tpm_client.py enrol-only 2>&1 | grep -q "PermissionError"'
check "nonsense_gets_no_answer_and_the_provider_goes_on" 'sudo -u linuxhello python3 /tmp/tpm_client.py garbage | grep -q "ANSWER b..$" && sudo -u linuxhello python3 /tmp/tpm_client.py enrol-only | grep -q "ENROL 0"'
check "the_provider_cannot_read_the_agents_state" 'sudo install -d -m700 -o linuxhello /var/lib/linuxhello && echo secret | sudo -u linuxhello tee /var/lib/linuxhello/probe >/dev/null; ! sudo -u linuxhello-tpm cat /var/lib/linuxhello/probe 2>/dev/null; sudo rm -f /var/lib/linuxhello/probe'

D=$(sudo journalctl -k --no-pager --since "@$T0" | grep "apparmor=\"DENIED\"" | grep -c "linuxhello-tpm-provider")
check "apparmor_denies_the_provider_nothing_it_needs" '[ "$D" = 0 ]'
SC=$(systemd-analyze security linuxhello-tpm-provider --no-pager 2>&1 | tail -1)
echo "INFO $SC"
[[ "$fail" -eq 0 ]] && echo "ALL PASSED" || echo "$fail FAILED"
if [[ "$fail" -ne 0 ]]; then
  echo "---- journal of the unit"; sudo journalctl -u linuxhello-tpm-provider --no-pager | tail -30
  echo "---- AppArmor denials"; sudo journalctl -k --no-pager | grep 'apparmor="DENIED"' | tail -15
fi
exit "$fail"
