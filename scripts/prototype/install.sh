#!/usr/bin/env bash
# Installs the Linux Hello prototype on this machine: the Agent, the TPM provider, the CLI and the
# PAM module, and adds Linux Hello to the PAM stack of sudo (and, with --lock-screen, of the Plasma
# lock screen; with --console, of the text console's login). Read docs/prototype.md first.
#
#   scripts/prototype/install.sh                 build, install, enable for sudo
#   scripts/prototype/install.sh --lock-screen   also enable for the Plasma lock screen (/etc/pam.d/kde)
#   scripts/prototype/install.sh --console       also enable for login on a text console (/etc/pam.d/login)
#   scripts/prototype/install.sh --no-build      install what target/ already holds
#
# It changes the machine: it creates two system users, installs files under /usr, /etc and /var,
# loads two AppArmor profiles, enables and starts two units, and edits /etc/pam.d/sudo (and kde, login),
# keeping a copy of each original next to it. scripts/prototype/uninstall.sh undoes all of it.
# Keep a root shell open while you try it: `sudo -s` in another terminal.
#
# Needs: Ubuntu 24.04 or 26.04 with AppArmor, systemd and a TPM 2.0 (/dev/tpmrm0); cargo with the
# x86_64-unknown-linux-musl target; the TSS2 runtime libraries (the script names the packages if
# they are missing). Idempotent: running it again reinstalls and leaves one Linux Hello line per
# PAM file.
set -euo pipefail
cd "$(dirname "$0")/../.."
root=$PWD

lock=no
console=no
build=yes
for arg in "$@"; do
  case "$arg" in
    --lock-screen) lock=yes ;;
    --console) console=yes ;;
    --no-build) build=no ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

die() { echo "install: $*" >&2; exit 1; }
step() { printf '\n==> %s\n' "$*"; }

# The line every PAM file gets, and the marker that finds it again.
MARK="# linux-hello prototype"
pam_line() { printf 'auth [success=done authinfo_unavail=ignore default=die] pam_linuxhello.so context=%s %s\n' "$1" "$MARK"; }

[[ $EUID -ne 0 ]] || die "run as your own user, not root; the script asks sudo for each change"
[[ -c /dev/tpmrm0 ]] || die "no TPM (/dev/tpmrm0): Linux Hello keeps the PIN key in the TPM"
[[ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" == Y ]] || die "AppArmor is not enabled; the Agent refuses to start without its profile in enforce mode"
command -v systemctl >/dev/null || die "systemd is needed"
[[ -f /etc/pam.d/sudo ]] || die "/etc/pam.d/sudo not found"
if [[ $lock == yes ]]; then [[ -f /etc/pam.d/kde ]] || die "/etc/pam.d/kde not found: is Plasma's lock screen installed?"; fi
if [[ $console == yes ]]; then [[ -f /etc/pam.d/login ]] || die "/etc/pam.d/login not found"; fi

musl=$root/target/x86_64-unknown-linux-musl/release
rel=$root/target/release
if [[ $build == yes ]]; then
  step "building (release): the Agent and the CLI static, the provider and the PAM module for this system"
  cargo build --release --target x86_64-unknown-linux-musl -p linuxhello-agent -p linuxhello-ctl
  cargo build --release -p linuxhello-tpm-provider -p pam-linuxhello
fi
for f in "$musl/linuxhello-agent" "$musl/linuxhello-ctl" "$rel/linuxhello-tpm-provider" "$rel/libpam_linuxhello.so"; do
  [[ -f "$f" ]] || die "$f not found (run without --no-build)"
done
if ldd "$rel/linuxhello-tpm-provider" | grep -q "not found"; then
  ldd "$rel/linuxhello-tpm-provider" | grep "not found" >&2
  die "the TPM provider needs the TSS2 runtime libraries named above (apt search libtss2 finds their packages)"
fi

step "installing the services (the same files and places a package would use)"
sec=$root/security
sudo systemd-sysusers "$sec/systemd/linuxhello.sysusers"
sudo install -D -m755 "$musl/linuxhello-agent" /usr/libexec/linuxhello/linuxhello-agent
sudo install -D -m755 "$rel/linuxhello-tpm-provider" /usr/libexec/linuxhello/linuxhello-tpm-provider
sudo install -D -m755 "$musl/linuxhello-ctl" /usr/bin/linuxhello-ctl
sudo install -D -m644 "$sec/dbus/io.github.LinuxHello.Agent1.conf" /usr/share/dbus-1/system.d/io.github.LinuxHello.Agent1.conf
sudo install -D -m644 "$sec/dbus/io.github.LinuxHello.Agent1.service" /usr/share/dbus-1/system-services/io.github.LinuxHello.Agent1.service
sudo install -m644 "$sec/apparmor/linuxhello-agent" /etc/apparmor.d/linuxhello-agent
sudo install -m644 "$sec/apparmor/linuxhello-tpm-provider" /etc/apparmor.d/linuxhello-tpm-provider
sudo install -D -m644 "$sec/polkit/50-linuxhello-agent.rules" /etc/polkit-1/rules.d/50-linuxhello-agent.rules
sudo install -m644 "$sec/systemd/linuxhello-agent.service" /usr/lib/systemd/system/linuxhello-agent.service
sudo install -m644 "$sec/systemd/linuxhello-tpm-provider.service" /usr/lib/systemd/system/linuxhello-tpm-provider.service
security_dir=/usr/lib/x86_64-linux-gnu/security
sudo install -D -m644 "$rel/libpam_linuxhello.so" "$security_dir/pam_linuxhello.so"

step "loading the profiles and starting the services"
sudo apparmor_parser -r /etc/apparmor.d/linuxhello-agent /etc/apparmor.d/linuxhello-tpm-provider
sudo systemctl reload dbus
sudo systemctl try-restart polkit || true
sudo systemctl daemon-reload
sudo systemctl enable linuxhello-tpm-provider linuxhello-agent >/dev/null 2>&1
sudo systemctl restart linuxhello-tpm-provider
sleep 1
sudo systemctl restart linuxhello-agent
for _ in $(seq 10); do
  busctl --system list --no-pager 2>/dev/null | grep -q '^io.github.LinuxHello.Agent1 ' && break
  sleep 1
done
busctl --system list --no-pager 2>/dev/null | grep -q '^io.github.LinuxHello.Agent1 ' \
  || die "the Agent did not start: journalctl -u linuxhello-agent -u linuxhello-tpm-provider -b"

# Adds the Linux Hello line before the first auth line (or "@include common-auth") of a PAM file,
# once, keeping the original as <file>.linuxhello-orig the first time.
add_to_pam() { # file, context
  local file=$1 context=$2
  [[ -f "$file.linuxhello-orig" ]] || sudo cp -p "$file" "$file.linuxhello-orig"
  local line tmp; line=$(pam_line "$context"); tmp=$(mktemp)
  awk -v line="$line" -v mark="$MARK" '
    index($0, mark) { next }                       # an earlier Linux Hello line goes
    !done && ($1 == "auth" || $0 ~ /^@include[ \t]+common-auth/) { print line; done = 1 }
    { print }
    END { if (!done) exit 3 }' "$file" > "$tmp" \
    || { rm -f "$tmp"; die "$file has no auth line to put Linux Hello before"; }
  sudo install -m644 "$tmp" "$file"
  rm -f "$tmp"
  echo "   $file: $(grep -F "$MARK" "$file")"
}

step "adding Linux Hello to PAM (the account password keeps working after it)"
add_to_pam /etc/pam.d/sudo sudo
if [[ $lock == yes ]]; then add_to_pam /etc/pam.d/kde unlock; fi
if [[ $console == yes ]]; then add_to_pam /etc/pam.d/login login; fi

cat <<'EOF'

Installed. Next:

  linuxhello-ctl pin set        set your PIN (it is kept by the TPM)
  sudo -k; sudo true            try it: type the PIN, or press Enter for your password
  linuxhello-ctl status         what Linux Hello says about your account

Undo everything with scripts/prototype/uninstall.sh. See docs/prototype.md.
EOF
