#!/usr/bin/env bash
# Installs the Linux Hello prototype on this machine: the Agent, the TPM provider, the CLI and the
# PAM module, and adds Linux Hello to the PAM stack of sudo (and, with --lock-screen, of the Plasma
# lock screen; with --console, of the text console's login; with --greeter, Linux Hello's own login
# screen for greetd). Read docs/prototype.md first.
#
#   scripts/prototype/install.sh                 build, install, enable for sudo
#   scripts/prototype/install.sh --lock-screen   also enable for the Plasma lock screen (/etc/pam.d/kde)
#   scripts/prototype/install.sh --console       also enable for login on a text console (/etc/pam.d/login)
#   scripts/prototype/install.sh --greeter       also install the Linux Hello Greeter, the login screen
#                                                for greetd, and enable for greetd's login (/etc/pam.d/login)
#   scripts/prototype/install.sh --face          let Howdy, which the Agent starts, use the camera
#   scripts/prototype/install.sh --no-build      install what target/ already holds
#
# It changes the machine: it creates two system users, installs files under /usr, /etc and /var,
# loads two AppArmor profiles, enables and starts two units, and edits /etc/pam.d/sudo (and kde, login,
# and with --greeter /etc/greetd/config.toml), keeping a copy of each original next to it.
# scripts/prototype/uninstall.sh undoes all of it.
# Keep a root shell open while you try it: `sudo -s` in another terminal.
#
# Needs: Ubuntu 24.04 or 26.04 with AppArmor, systemd and a TPM 2.0 (/dev/tpmrm0); cargo with the
# x86_64-unknown-linux-musl target; the TSS2 runtime libraries (the script names the packages if
# they are missing); for --greeter, greetd, cage and Qt 6 (the script names the packages).
# Idempotent: running it again reinstalls and leaves one Linux Hello line per PAM file.
set -euo pipefail
cd "$(dirname "$0")/../.."
root=$PWD

lock=no
console=no
greeter=no
face=no
build=yes
for arg in "$@"; do
  case "$arg" in
    --lock-screen) lock=yes ;;
    --console) console=yes ;;
    --greeter) greeter=yes ;;
    --face) face=yes ;;
    --no-build) build=no ;;
    -h|--help) sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

die() { echo "install: $*" >&2; exit 1; }
step() { printf '\n==> %s\n' "$*"; }

# The line every PAM file gets, and the marker that finds it again.
MARK="# linux-hello prototype"
# module_unknown=ignore: a module that cannot be loaded (a library upgrade that broke it) must not end
# the stack, or nobody could sign in to sudo or the console (#359).
pam_line() { printf 'auth [success=done authinfo_unavail=ignore module_unknown=ignore default=die] pam_linuxhello.so context=%s %s\n' "$1" "$MARK"; }

[[ $EUID -ne 0 ]] || die "run as your own user, not root; the script asks sudo for each change"
[[ -c /dev/tpmrm0 ]] || die "no TPM (/dev/tpmrm0): Linux Hello keeps the PIN key in the TPM"
[[ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" == Y ]] || die "AppArmor is not enabled; the Agent refuses to start without its profile in enforce mode"
command -v systemctl >/dev/null || die "systemd is needed"
[[ -f /etc/pam.d/sudo ]] || die "/etc/pam.d/sudo not found"
if [[ $lock == yes ]]; then [[ -f /etc/pam.d/kde ]] || die "/etc/pam.d/kde not found: is Plasma's lock screen installed?"; fi
if [[ $console == yes ]]; then [[ -f /etc/pam.d/login ]] || die "/etc/pam.d/login not found"; fi
greeter_packages="greetd cage qt6-base-dev qt6-base-dev-tools qt6-declarative-dev qml6-module-qtquick qml6-module-qtquick-controls qml6-module-qtquick-templates qml6-module-qtquick-window"
if [[ $greeter == yes ]]; then
  [[ -f /etc/greetd/config.toml ]] && command -v cage >/dev/null && [[ -x /usr/lib/qt6/bin/qmake ]] \
    || die "--greeter needs greetd, cage and Qt 6: sudo apt install $greeter_packages"
  [[ -f /etc/pam.d/greetd ]] || die "/etc/pam.d/greetd not found"
fi

musl=$root/target/x86_64-unknown-linux-musl/release
rel=$root/target/release
if [[ $build == yes ]]; then
  step "building (release): the Agent and the CLI static, the provider and the PAM module for this system"
  cargo build --release --target x86_64-unknown-linux-musl -p linuxhello-agent -p linuxhello-ctl
  cargo build --release -p linuxhello-tpm-provider -p pam-linuxhello
fi
plasma=$root/plasma/target/release
if [[ $greeter == yes && $build == yes ]]; then
  step "building (release): the greeter and the Agent Link plugin, against this system's Qt"
  (cd "$root/plasma" && QMAKE=/usr/lib/qt6/bin/qmake cargo build --release)
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
# An earlier install put the Agent's user in the group of the TPM device; sysusers never removes a
# member. The Agent reaches the TPM only through the provider's socket (R-09, #351).
if id -nG linuxhello 2>/dev/null | tr ' ' '\n' | grep -qx tss; then sudo gpasswd -d linuxhello tss >/dev/null; fi
sudo install -D -m755 "$musl/linuxhello-agent" /usr/libexec/linuxhello/linuxhello-agent
sudo install -D -m755 "$rel/linuxhello-tpm-provider" /usr/libexec/linuxhello/linuxhello-tpm-provider
sudo install -D -m755 "$musl/linuxhello-ctl" /usr/bin/linuxhello-ctl
sudo install -D -m644 "$root/plasma/autostart/linuxhello-notify.desktop" /etc/xdg/autostart/linuxhello-notify.desktop
sudo install -D -m644 "$sec/dbus/io.github.LinuxHello.Agent1.conf" /usr/share/dbus-1/system.d/io.github.LinuxHello.Agent1.conf
sudo install -D -m644 "$sec/dbus/io.github.LinuxHello.Agent1.service" /usr/share/dbus-1/system-services/io.github.LinuxHello.Agent1.service
sudo install -m644 "$sec/apparmor/linuxhello-agent" /etc/apparmor.d/linuxhello-agent
sudo install -m644 "$sec/apparmor/linuxhello-tpm-provider" /etc/apparmor.d/linuxhello-tpm-provider
sudo install -D -m644 "$sec/polkit/50-linuxhello-agent.rules" /etc/polkit-1/rules.d/50-linuxhello-agent.rules
sudo install -D -m644 "$sec/polkit/io.github.LinuxHello.policy" /usr/share/polkit-1/actions/io.github.LinuxHello.policy
sudo install -m644 "$sec/systemd/linuxhello-agent.service" /usr/lib/systemd/system/linuxhello-agent.service
sudo install -m644 "$sec/systemd/linuxhello-tpm-provider.service" /usr/lib/systemd/system/linuxhello-tpm-provider.service
security_dir=/usr/lib/x86_64-linux-gnu/security
sudo install -D -m644 "$rel/libpam_linuxhello.so" "$security_dir/pam_linuxhello.so"

# The face method runs Howdy's compare script as a child of the Agent, inside the Agent's unit. The
# unit admits no device but the TPM, and Howdy keeps its face models for root, so without these two
# changes a face is never checked. Both are for this prototype only; a helper unit for Howdy with its
# own rights replaces them (#272).
face_dropin=/etc/systemd/system/linuxhello-agent.service.d/50-face-prototype.conf
howdy=/lib/security/howdy
if [[ $face == yes ]]; then
  step "letting Howdy use the camera (--face)"
  [[ -f $howdy/compare.py ]] || echo "   warning: $howdy/compare.py not found: install Howdy first, or the face method stays unavailable"
  printf '%s\n' "$MARK: lets Howdy, which the Agent starts, open the camera" '[Service]' \
    'DeviceAllow=char-video4linux rw' 'SupplementaryGroups=video' \
    | sudo install -D -m644 /dev/stdin "$face_dropin"
  if [[ -d $howdy/models ]] && ! sudo -u linuxhello test -r "$howdy/models"; then
    command -v setfacl >/dev/null || die "setfacl is needed to let the Agent read Howdy's models (sudo apt install acl)"
    sudo setfacl -R -m u:linuxhello:rX "$howdy/models"
    echo "   $howdy/models: readable by the Agent's user (an ACL; uninstall.sh removes it)"
  fi
else
  sudo rm -f "$face_dropin"
fi

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

# Adds the Linux Hello line to a PAM file, once, keeping the original as <file>.linuxhello-orig the
# first time. Where it goes is pam-insert.awk's rule: directly before "@include common-auth", so that
# /etc/nologin and the delay after a failure still apply to a Linux Hello sign-in.
add_to_pam() { # file, context
  local file=$1 context=$2
  [[ -f "$file.linuxhello-orig" ]] || sudo cp -p "$file" "$file.linuxhello-orig"
  local line tmp; line=$(pam_line "$context"); tmp=$(mktemp)
  awk -v line="$line" -v mark="$MARK" -f "$root/scripts/prototype/pam-insert.awk" "$file" > "$tmp" \
    || { rm -f "$tmp"; die "$file has no auth line to put Linux Hello before"; }
  sudo install -m644 "$tmp" "$file"
  rm -f "$tmp"
  echo "   $file: $(grep -F "$MARK" "$file")"
}

step "adding Linux Hello to PAM (the account password keeps working after it)"
add_to_pam /etc/pam.d/sudo sudo
if [[ $lock == yes ]]; then add_to_pam /etc/pam.d/kde unlock; fi
if [[ $console == yes ]]; then add_to_pam /etc/pam.d/login login; fi
# greetd's PAM file includes login on Ubuntu; then the line goes there, once, as for --console.
if [[ $greeter == yes ]]; then
  if grep -qE '^[[:space:]]*(@include|auth[[:space:]]+(include|substack))[[:space:]]+login([[:space:]]|$)' /etc/pam.d/greetd; then
    add_to_pam /etc/pam.d/login login
  else
    add_to_pam /etc/pam.d/greetd login
  fi
fi

# The Linux Hello Greeter: the program, the Agent Link plugin and the Auth Prompt under
# /usr/lib/linuxhello/qml, the window's QML files, and greetd told to run it under cage as its own
# user. greetd starts the chosen desktop; the greeter starts no program (ADR-0028, amendment of
# 2026-11-22).
if [[ $greeter == yes ]]; then
  step "installing the Linux Hello Greeter for greetd"
  [[ -f "$plasma/linuxhello-greeter" && -f "$plasma/liblinuxhello_plasma.so" ]] || die "the greeter is not built (run without --no-build)"
  module=$(find "$plasma"/build -path '*/qml_modules/io/github/LinuxHello/AgentLink' -type d -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)
  [[ -n "$module" && -f "$module/qmldir" ]] || die "the Agent Link's qmldir is not in $plasma/build (run without --no-build)"
  qml=/usr/lib/linuxhello/qml/io/github/LinuxHello
  sudo install -D -m755 "$plasma/linuxhello-greeter" /usr/bin/linuxhello-greeter
  sudo install -D -m644 "$plasma/liblinuxhello_plasma.so" "$qml/AgentLink/libio_github_LinuxHello_AgentLink.so"
  sudo install -m644 "$module/qmldir" "$module/plugin.qmltypes" "$qml/AgentLink/"
  sudo install -D -m644 -t "$qml/AuthPrompt" "$root"/plasma/auth-prompt/io/github/LinuxHello/AuthPrompt/*
  sudo install -D -m644 -t /usr/share/linuxhello/greeter "$root"/plasma/linuxhello-greeter/qml/*
  config=/etc/greetd/config.toml
  [[ -f "$config.linuxhello-orig" ]] || sudo cp -p "$config" "$config.linuxhello-orig"
  tmp=$(mktemp)
  awk -v mark="$MARK" '
    /^\[/ { section = $0 }
    section == "[default_session]" && $1 == "command" && !done {
      # greetd reads no comment after a value, so the marker has a line of its own.
      print mark ": greetd runs the Linux Hello Greeter"
      print "command = \"cage -s -- linuxhello-greeter\""; done = 1; next
    }
    index($0, mark) { next }
    { print }
    END { if (!done) exit 3 }' "$config" > "$tmp" \
    || { rm -f "$tmp"; die "$config has no command in [default_session]"; }
  sudo install -m644 "$tmp" "$config"
  rm -f "$tmp"
  echo "   $config: $(grep -A1 -F "$MARK" "$config" | tail -1)"
  if systemctl is-enabled --quiet greetd 2>/dev/null; then
    greeter_next="  sudo systemctl restart greetd     show the new login screen (ends the sessions greetd runs)"
  elif [[ -e /etc/systemd/system/display-manager.service ]]; then
    dm=$(basename "$(readlink -f /etc/systemd/system/display-manager.service)")
    greeter_next="  sudo systemctl disable $dm && sudo systemctl enable greetd && sudo reboot
                                    make greetd the login screen instead of $dm"
  else
    sudo systemctl enable greetd >/dev/null 2>&1
    greeter_next="  sudo systemctl start greetd       show the new login screen"
  fi
fi

cat <<'EOF'

Installed. Next:

  linuxhello-ctl pin set        set your PIN (it is kept by the TPM)
  sudo -k; sudo true            try it: type the PIN, or press Enter for your password
  linuxhello-ctl status         what Linux Hello says about your account

Undo everything with scripts/prototype/uninstall.sh. See docs/prototype.md.
EOF
if [[ $greeter == yes ]]; then printf '\nThe greeter is installed. To use it:\n\n%s\n' "$greeter_next"; fi
