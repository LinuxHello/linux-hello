---
type: guide
subject: How to install the first Linux Hello prototype on your own machine, try it with sudo and the lock screen, and remove it again
artifact: guide
status: draft
owner: "@atterdag"
concepts: [prototype, pam, pin, tpm, fingerprint, install]
tags: [guide, prototype]
sources: ["../scripts/prototype/install.sh", "../scripts/prototype/uninstall.sh", "https://github.com/LinuxHello/linux-hello-architecture/blob/main/adr/0023-pam-module-and-login-failure.md"]
date: 2026-11-21
---

# Trying the first prototype

This guide is for someone who wants to try Linux Hello on their own computer before it is finished. It says what the prototype can do, how to install it with one script, how to try it, what to do when something goes wrong, and how to remove it. After reading it you can unlock `sudo` with a PIN or a fingerprint and know which parts are not there yet.

## What the prototype is

Linux Hello lets you prove who you are on a Linux desktop with a PIN, a fingerprint or your face instead of your account password. The PIN is not stored as text anywhere: it opens a key kept by the Trusted Platform Module (TPM), a chip in the computer that keeps keys so that no program can copy them. The fingerprint and the face are read by the usual Linux services, fprintd (the service that reads fingerprint sensors) and Howdy (a face-recognition program).

The prototype has these parts, all built and tested in a virtual machine:

- **The Agent**, a system service that runs the PIN, fingerprint and face checks and keeps the rules about which ones count. It runs as its own user, confined by an AppArmor profile (a set of kernel rules that limits what a program may touch); it refuses to start if that profile is not enforced.
- **The TPM provider**, a second small service, the only one that talks to the TPM.
- **`linuxhello-ctl`**, a command to set and change your PIN and to see what Linux Hello thinks of your account.
- **The PAM module**, `pam_linuxhello.so`. PAM (Pluggable Authentication Modules) is the library that `sudo`, the login screen and the lock screen use to ask "is this the user?". The module asks the Agent and passes its answer on.

What it does **not** do yet: passkeys in the browser (the virtual security key exists only as an experiment), the login screen and the system settings page of Plasma, a reminder that your PIN has expired, and resetting a forgotten PIN (for now, uninstall with `--purge` and set a new one).

## What happens at `sudo`

When you run `sudo`, the module asks the Agent to start the checks your policy allows. If the PIN is one of them you see:

```text
PIN (or touch the fingerprint sensor and press Enter):
```

`sudo` puts a label of its own in square brackets in front of a question it does not recognise as a password question, so the line starts with `[sudo: ...]`.

Type your PIN and press Enter, or touch the sensor and then press Enter on an empty line. If you press Enter on an empty line and no sensor or camera is in use, `sudo` asks for your account password as before.

The account password always stays available: whenever Linux Hello cannot answer (the Agent is stopped, no PIN is set, the TPM is locked), the module says "unavailable" and `sudo` asks for the password. A wrong PIN is different: it counts as a failed attempt and does not fall through to the password, so that guessing the PIN and then the password are not one attempt. `sudo` itself gives you three attempts and then says `sudo: maximum 3 incorrect authentication attempts`. After too many wrong PINs Linux Hello locks for some minutes; your password still works then. `sudo` hides the messages a PAM module shows (its `pam_silent` setting is on by default), so it says only "Authentication failed" after a wrong PIN, and `linuxhello-ctl status` tells you about a lockout.

Where a screen does show a module's messages, as the lock screen and a console login do, Linux Hello first says what may stop it from signing you in. For example, "The TPM no longer holds the key that your PIN opens…" or "login cannot be unlocked with the configured methods." appear above the question. After you sign in, it says whether your PIN expires soon or has expired. In `sudo` these lines are hidden like the others; `linuxhello-ctl status` shows the same sentences.

## Before you install

You need Ubuntu 24.04 or 26.04 with AppArmor (Ubuntu's default), a TPM 2.0 chip (`ls /dev/tpmrm0` shows it), Rust with the static target (`rustup target add x86_64-unknown-linux-musl`), and the TSS2 runtime libraries the TPM provider links to (the installer names any that are missing).

**Keep a root shell open while you try it.** Open a second terminal and run `sudo -s` there before you install. If something in the PAM stack goes wrong, that shell can still run the uninstaller.

## Install

From a clone of this repository:

```sh
scripts/prototype/install.sh
```

It builds the four programs, installs them where a package would (`/usr/libexec/linuxhello/`, `/usr/bin/linuxhello-ctl`, `/usr/lib/x86_64-linux-gnu/security/pam_linuxhello.so`), installs the bus policy, the AppArmor profiles, the polkit rule (which lets the Agent use the fingerprint sensor for you) and the two systemd units, starts the services and adds one line to `/etc/pam.d/sudo`. A copy of the original file is kept as `/etc/pam.d/sudo.linuxhello-orig`. Every step asks `sudo` for itself; nothing runs as root that you cannot see in the script.

To also use Linux Hello on the Plasma lock screen, add `--lock-screen`; it adds the same line to `/etc/pam.d/kde`, the PAM file of the lock screen.

## Try it

1. Set your PIN. It must follow the PIN rules of the policy (by default at least six characters):

   ```sh
   linuxhello-ctl pin set
   ```

2. Forget sudo's cached login and try it:

   ```sh
   sudo -k
   sudo true
   ```

   Type the PIN. Then try a wrong PIN, an empty answer, and, if you have a fingerprint enrolled with fprintd (`fprintd-enroll`), the sensor.

3. See what Linux Hello says about your account:

   ```sh
   linuxhello-ctl status
   ```

4. Change the PIN with `linuxhello-ctl pin change`.

## When something goes wrong

- **`sudo` asks only for the password.** Linux Hello was unavailable. `systemctl status linuxhello-agent linuxhello-tpm-provider` shows whether the services run; `journalctl -u linuxhello-agent -b` shows why not. No PIN set is also a reason.
- **The Agent does not start.** Its unit checks that its AppArmor profile is in enforce mode: `sudo grep linuxhello /sys/kernel/security/apparmor/profiles`. Denials are in `sudo journalctl -k | grep DENIED`.
- **Anything else.** Write down the command, what you saw, and the last lines of `journalctl -u linuxhello-agent -u linuxhello-tpm-provider -b`, and open an issue. Leave your PIN out of it.

## Remove it

```sh
scripts/prototype/uninstall.sh
```

It removes the Linux Hello lines from the PAM files first, then the services and their files. Your PIN record stays in `/var/lib/linuxhello`, so a reinstall keeps your PIN; `--purge` deletes it too.
