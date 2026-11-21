#!/usr/bin/env bash
# Removes the Linux Hello prototype that scripts/prototype/install.sh installed: the Linux Hello
# lines in /etc/pam.d/sudo, kde and login first, then the services and their files.
#
#   scripts/prototype/uninstall.sh            remove; keep the PIN records in /var/lib/linuxhello
#   scripts/prototype/uninstall.sh --purge    also delete /var/lib/linuxhello (the PIN key blobs
#                                             and the lockout record; a PIN set later starts afresh)
#
# The PAM lines go first, so that sudo never points at a module that is gone. Each PAM file keeps
# everything else as it is now; the copy install.sh made (<file>.linuxhello-orig) is removed only
# when the file then equals it again.
set -euo pipefail

purge=no
for arg in "$@"; do
  case "$arg" in
    --purge) purge=yes ;;
    -h|--help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done
[[ $EUID -ne 0 ]] || { echo "run as your own user, not root" >&2; exit 1; }

MARK="# linux-hello prototype"
for file in /etc/pam.d/sudo /etc/pam.d/kde /etc/pam.d/login; do
  [[ -f "$file" ]] || continue
  if grep -qF "$MARK" "$file"; then
    tmp=$(mktemp)
    grep -vF "$MARK" "$file" > "$tmp"
    sudo install -m644 "$tmp" "$file"
    rm -f "$tmp"
    echo "removed the Linux Hello line from $file"
  fi
  if [[ -f "$file.linuxhello-orig" ]] && sudo cmp -s "$file" "$file.linuxhello-orig"; then
    sudo rm -f "$file.linuxhello-orig"
  fi
done

sudo systemctl disable --now linuxhello-agent linuxhello-tpm-provider >/dev/null 2>&1 || true
sudo apparmor_parser -R /etc/apparmor.d/linuxhello-agent /etc/apparmor.d/linuxhello-tpm-provider 2>/dev/null || true
sudo rm -f /usr/lib/x86_64-linux-gnu/security/pam_linuxhello.so \
  /usr/libexec/linuxhello/linuxhello-agent /usr/libexec/linuxhello/linuxhello-tpm-provider \
  /usr/bin/linuxhello-ctl \
  /usr/share/dbus-1/system.d/io.github.LinuxHello.Agent1.conf \
  /usr/share/dbus-1/system-services/io.github.LinuxHello.Agent1.service \
  /etc/apparmor.d/linuxhello-agent /etc/apparmor.d/linuxhello-tpm-provider \
  /etc/polkit-1/rules.d/50-linuxhello-agent.rules \
  /usr/lib/systemd/system/linuxhello-agent.service /usr/lib/systemd/system/linuxhello-tpm-provider.service
sudo rmdir /usr/libexec/linuxhello 2>/dev/null || true
sudo systemctl daemon-reload
sudo systemctl reload dbus
if [[ $purge == yes ]]; then
  sudo rm -rf /var/lib/linuxhello
  echo "deleted /var/lib/linuxhello"
fi
echo "Linux Hello is removed. The system users linuxhello and linuxhello-tpm stay; userdel removes them."
