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

To also use Linux Hello on the Plasma lock screen, add `--lock-screen`; it adds the same line to `/etc/pam.d/kde`, the PAM file of the lock screen. To use it when you log in on a text console (the screen you reach with Ctrl+Alt+F3), add `--console`; it adds the line to `/etc/pam.d/login`, with the context `login`. Both keep the account password working after the PIN, exactly as for `sudo`.

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

## Try it with a fingerprint reader and a camera

This section is for a computer that has a fingerprint reader and a camera for face recognition, and it tests all three ways of signing in: the PIN, the fingerprint and the face. Linux Hello does not read the sensor or the camera itself. It asks fprintd (the Linux service that reads fingerprint readers) and Howdy (a face-recognition program for Linux), so both must work on their own before Linux Hello can use them.

What to expect today:

| Method | State in the prototype |
| :-- | :-- |
| PIN | Built, and tested on a software TPM in the test machines |
| Fingerprint | Built, and tested against a stand-in for fprintd; it has not yet run against a real reader |
| Face | Built, and tested against a stand-in for Howdy; it has not yet run against a real camera, and it needs `--face` when you install |

Your test is the first run of the fingerprint and the face on real hardware, so a failure there is a finding, not a mistake on your part.

### 1. Build tools

```sh
sudo apt install build-essential pkg-config clang libclang-dev libtss2-dev libpam0g-dev git acl
rustup target add --toolchain 1.99.1 x86_64-unknown-linux-musl
```

The first line installs the compilers and the development files of the TSS2 library (the library that talks to the TPM) and of PAM (Pluggable Authentication Modules, the system that `sudo` and the login screens use to check a person). `acl` gives `setfacl`, which `--face` uses. The second line adds the target for static programs to the Rust version this repository uses (`rust-toolchain.toml`). Install Rust itself with [rustup](https://rustup.rs) if you do not have it.

### 2. The fingerprint, on its own

```sh
sudo apt install fprintd
fprintd-enroll
fprintd-verify
```

`fprintd-enroll` asks you to touch the reader several times; `fprintd-verify` must then say `verify-match`. If it does not, Linux Hello cannot do better: the reader or its driver is the problem.

Ubuntu's package `libpam-fprintd` may also add fprintd's own PAM module to every sign-in. Turn it off, so that what you see is Linux Hello and not fprintd asking a second time: run `sudo pam-auth-update` and clear "Fingerprint authentication".

### 3. The face, on its own

Howdy is not in Ubuntu's archive. Install it the way its project describes (at the time of writing, a package archive of the Howdy project); that is your decision, because it is software from outside Ubuntu. Then add your face and check it:

```sh
sudo howdy add
sudo howdy test
```

Howdy also puts its own line into the PAM files when it is installed. Remove that line, as for fprintd: `grep -rn howdy /etc/pam.d/` shows where it is. Linux Hello runs Howdy's own compare script, `/lib/security/howdy/compare.py`, and needs nothing else of Howdy's.

A camera with an infrared light is what Howdy is made for. The policy setting `methods.face_requires_ir` (default: true) is not checked by the prototype yet, so an ordinary camera will also be tried; Howdy itself refuses frames that are too dark.

### 4. Install

```sh
git clone --recurse-submodules https://github.com/LinuxHello/linux-hello
cd linux-hello
scripts/prototype/install.sh --lock-screen --console --face
linuxhello-ctl pin set
```

`--lock-screen` adds Linux Hello to the Plasma lock screen, `--console` to the login on a text console, and `--face` lets Howdy use the camera from inside the Agent. In detail, `--face` makes two changes. A file `/etc/systemd/system/linuxhello-agent.service.d/50-face-prototype.conf` lets the Agent's service open video devices and gives it the `video` group. And if the Agent's user cannot read Howdy's face models in `/lib/security/howdy/models`, an access-control entry lets it. Both are for this prototype only: later, Howdy gets a helper service with its own rights (#272), and the Agent keeps no camera access.

### 5. Which method each sign-in offers

The built-in policy offers the PIN, the fingerprint and the face at the login screen, at the lock screen and on the console, and only the PIN and the fingerprint for `sudo`. To try the face with `sudo` too, add an administrator policy file:

```sh
sudo install -d -m755 /etc/linuxhello/policy.d
printf '[context.sudo]\nmethods = ["pin", "fingerprint", "face"]\n' | sudo tee /etc/linuxhello/policy.d/50-face-sudo.toml
```

`linuxhello-ctl status` says if a policy file cannot be used; then the PIN is the only method everywhere.

### 6. What to try

The question names the methods that run. While it waits for your PIN, the fingerprint reader and the camera are already working. This is how the prototype behaves:

- **A finger or a face that matches** signs you in once you press Enter.
- **A finger or a face that does not match** ends only that method. The question comes back without it, and the other methods, the PIN among them, still work. The attempt fails only when every method has failed.
- **An empty Enter** with only the PIN left gives you the password. While the reader or the camera is still working, it waits for them; when they end without a match, or after 30 seconds, you get the password.
- **A wrong PIN** ends the PIN for this attempt. If the reader is still working, the module says "Touch the fingerprint sensor." (or "Touch the fingerprint sensor or look at the camera." when the camera is working too) and waits for it. Without a match the attempt fails, and you are not given the password in its place.

| Where | How | The question you should see |
| :-- | :-- | :-- |
| `sudo` | `sudo -k; sudo true` in a terminal | `PIN (or touch the fingerprint sensor and press Enter):` |
| Text console | Ctrl+Alt+F3, then your user name | `PIN (or use the fingerprint sensor or the camera, then press Enter):` |
| Lock screen | Meta+L, then the password field | the same, or Plasma's own text for it |

For each place, try a finger that is enrolled, a finger that is not, your face, someone else's face or a covered camera, a wrong PIN, and an empty Enter. Note anything that feels wrong, even when it does what the list above says: this is the first time anyone uses these flows.

One thing to watch on the lock screen: Plasma has its own fingerprint check, which also asks fprintd for the reader. If both want the reader at once, one of them may be refused. Write down which one shows a message.

### 7. What to send back

```sh
linuxhello-ctl status
journalctl -u linuxhello-agent -u linuxhello-tpm-provider -b --no-pager > lh-journal.txt
sudo journalctl -k -b --no-pager | grep 'apparmor="DENIED"' | grep linuxhello > lh-denials.txt
```

The first shows what Linux Hello says about your account. The two files hold the services' log and every denial by the AppArmor profiles since the computer started. A denial is the most likely finding: the profile rules for fprintd and Howdy were written without a real reader and camera. The log files name your computer and your user name, so share them privately, not in a public issue.

## When something goes wrong

- **The question does not name the fingerprint or the camera.** The method is not available: `fprintd-verify` or `sudo howdy test` fails on its own, `--face` was not given, or the policy does not offer it there (section 5 above). The Agent's log says which.
- **`sudo` asks only for the password.** Linux Hello was unavailable. On the text console and the lock screen the module says so first: "Linux Hello is not available. Use your account password." (`sudo` hides the module's messages.) `systemctl status linuxhello-agent linuxhello-tpm-provider` shows whether the services run; `journalctl -u linuxhello-agent -b` shows why not. No PIN set is also a reason.
- **The Agent does not start.** Its unit checks that its AppArmor profile is in enforce mode: `sudo grep linuxhello /sys/kernel/security/apparmor/profiles`. Denials are in `sudo journalctl -k | grep DENIED`.
- **Anything else.** Write down the command, what you saw, and the last lines of `journalctl -u linuxhello-agent -u linuxhello-tpm-provider -b`, and open an issue. Leave your PIN out of it.

## Remove it

```sh
scripts/prototype/uninstall.sh
```

It removes the Linux Hello lines from the PAM files first, then the services and their files. Your PIN record stays in `/var/lib/linuxhello`, so a reinstall keeps your PIN; `--purge` deletes it too.
