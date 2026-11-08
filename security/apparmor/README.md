# AppArmor profiles

One profile per daemon and for linuxhello-ctl, shipped in enforce mode. Units refuse to start unconfined. CI fails on any DENIED line.

## Profiles

| Profile | Confines | Grants |
| :-- | :-- | :-- |
| [`linuxhello-agent`](linuxhello-agent) | the Agent ([ADR-0014](https://github.com/LinuxHello/architecture/blob/main/adr/0014-agent-bus.md)) | the system bus over a unix socket and its name, `/dev/tpmrm0`, `/var/lib/linuxhello`, the admin policy read-only; no network, no capability, no ptrace, no home directories |

The Agent's systemd unit, sysusers entry and bus policy are in [`../systemd/`](../systemd/) and [`../dbus/`](../dbus/). Install paths are in the header of each file. The tests are `crates/linuxhello-agent/tests/profiles.rs` (what the files grant and refuse, and the real parsers) and `bus_policy.rs` (the bus policy on a real private bus). The profile was loaded in enforce mode and the unit started in the test VM (Ubuntu 24.04, kernel 6.8) on 2026-11-08, which found that it needs `flags=(attach_disconnected)`: under systemd's mount namespace AppArmor sees the bus socket path without its leading slash and denied the connect. Repeat that run after every change to the profile, the unit or the bus policy.

