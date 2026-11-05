---
type: architecture
subject: "Arc42 section 8: crosscutting concepts of Linux Hello (trust chain, security hardening, user experience, policy)"
artifact: arc42-08-crosscutting-concepts
status: active
owner: "@atterdag"
concepts: [trust-chain, threat-model, confinement, user-experience, policy, arc42]
tags: [architecture, arc42, security, policy]
sources: ["README.md", "policy-semantics.md", "../security/README.md", "../adr/0003-destructive-reset.md", "https://docs.arc42.org/section-8/"]
date: 2026-11-05
---

# 8. Crosscutting concepts

Part of the [Arc42 architecture documentation](README.md). Concepts with a note of their own:

- Routing policy semantics, precise enough to implement and test: [policy-semantics.md](policy-semantics.md).
- Security properties, each with the test that states it: [docs/security/](../security/README.md).

## Trust chain

The PIN is the root, biometrics are a shortcut, and the account password is a destructive reset. This follows the Windows Hello default.

| Tier | Linux Hello | Windows Hello parallel |
| :-- | :-- | :-- |
| Root | PIN = TPM2 authorisation on a per-user root key; every passkey key hangs off it; TPM anti-hammering limits guessing; PIN never leaves the device | PIN unlocks the TPM-protected Windows Hello container; TPM anti-hammering |
| Shortcut | fprintd / Howdy satisfy a TPM policy for the session; never the root; failure falls back to PIN | Windows Biometric Framework, templates local only; a match releases the container |
| Passkeys | Stored by the TPM provider, served by credentialsd | Stored in the Hello container, served by `webauthn.dll` |
| Reset | Account or admin password authorises destroying the root key and enrolling a new PIN; it never unlocks keys | "I forgot my PIN": re-authenticate with Microsoft/Entra account; default reset deletes the container |
| Recovery | Through relying parties: re-register passkeys with each service (account recovery, second credential) | Same; Entra's non-destructive PIN reset service is the exception |

### Decision LH-1: destructive reset, no recovery key

A reset wipes the root key and every TPM-bound passkey; there is no recovery key, and recovery goes through the relying parties. Recorded as [ADR-0003](../adr/0003-destructive-reset.md).

## Security hardening

Write Linux Hello in Rust, and treat logic flaws as a bigger risk than memory bugs. The maintainer reviews behaviour rather than Rust code, so assurance has to come from behaviour tests, CI gates and outside reviewers.

### Language

Rust, matching credentialsd and libwebauthn (shared types and async stack). A long-running daemon that holds key material and parses input from untrusted callers is where memory safety matters most. Rust does not prevent logic flaws.

### Threats to design against

| Threat | Example | Mitigation |
| :-- | :-- | :-- |
| Caller impersonation | An app on D-Bus claims to be a browser, or asserts another site's origin | Verify the caller through the portal (sandbox app ID, peer credentials); never trust a caller-supplied origin from an unprivileged client |
| Unlock bypass | Biometric "match" accepted without the TPM policy actually being satisfied | Unlock state is enforced by the TPM policy session, never by a flag in the daemon |
| Key exfiltration | Private key material leaves the provider | TPM keys non-exportable; the broker only receives signatures |
| Silent use | A passkey signs without the user's knowledge | User-presence prompt rendered by the portal, outside the calling app |
| Parser exploit | Malformed CTAP/CBOR or D-Bus message | Fuzzing; no `unsafe` in parsers |
| Supply chain | Malicious or vulnerable crate | Pinned, audited dependencies |

### Controls

1. `#![forbid(unsafe_code)]` in every crate except one small, audited TPM FFI crate.
2. CI gates that block a merge: clippy (deny warnings), cargo-audit, cargo-deny (licences and advisories), fuzzing on every parser.
3. Each security property written in plain language and backed by a test whose name states it (e.g. "a caller from another origin is refused"). The operator reviews properties and test results, not code.
4. systemd sandboxing (dedicated user, `ProtectSystem=strict`, `NoNewPrivileges`, restricted address families, `DeviceAllow` for `/dev/tpmrm0` only) plus an AppArmor profile.
5. Providers contributed upstream to credentialsd so its maintainers review them.
6. External security audit of the TPM provider and broker before anyone relies on it.

### Runtime confinement and detection

**AppArmor (mandatory).** One profile per daemon and for `linuxhello-ctl`, shipped in **enforce** mode.

- Only the TPM Provider and the Agent may open `/dev/tpmrm0`; only the Face Client path may reach Howdy; only the Face Enrolment Module may open the camera.
- Policy files: admin layer read-only for every profile; user layer writable only by the Settings Module.
- Deny `ptrace` and `/proc/<pid>/mem` access to the Agent and providers.
- CI loads every profile (`apparmor_parser`), runs the property tests under them, and fails on any `DENIED` line or on a profile left in complain mode.

**Tetragon (optional, defence in depth).** Sample TracingPolicies shipped with the project; Linux Hello must not depend on them.

- Alert on any process other than the Agent or TPM Provider opening `/dev/tpmrm0`.
- Alert on writes to `/etc/linuxhello/policy.d/` or to the PAM stack files (`/etc/pam.d/*`).
- Sigkill on non-loopback network connects from any Linux Hello process (none of them needs the network).
- Alert on `ptrace` or `process_vm_readv` targeting the Agent or providers.
- Without BPF-LSM, kprobe tracing and Sigkill enforcement work today; BPF-LSM hooks need `bpf` added to the kernel's active LSM list.

CI check: the Tetragon policies are applied in a test VM and each alert is triggered once by a negative test.

**Rules.**

- Confinement fails closed: each unit checks that its AppArmor profile is loaded in enforce mode and refuses to start otherwise.
- Detection is only useful if watched: Tetragon events and the Agent's audit log are shipped to the log stack (e.g. Alloy → Loki → Grafana) with alert rules, not just written to disk.
- Enabling BPF-LSM is a kernel command-line (bootloader) change, documented per deployment.

Open question: who owns the threat model and the property list. Proposed: the maintainer, with tests written by Claude and reviewed upstream.

## User experience

At every prompt the user can see which method is active, switch to another, and enrol a method from a graphical wizard. This usability is what makes Windows Hello adoptable by ordinary users and enterprises, and it sets the bar.

### Requirements

| ID | Requirement | Surfaces |
| :-- | :-- | :-- |
| UX1 | The active method is always visible: face (camera live, scanning), fingerprint (touch sensor), PIN (field focused) | Login manager, lock screen, in-session prompts |
| UX2 | The user can switch method at any prompt ("Sign-in options"), with PIN always offered | All prompts |
| UX3 | Face and fingerprint run in parallel, first match wins; no sequential PAM timeouts | All prompts |
| UX4 | Clear failure feedback ("Face not recognised — try again or use PIN") and lockout state from the TPM ("PIN locked for N min") | All prompts |
| UX5 | Identical look and behaviour on the login manager, lock screen and in-session prompts | Plasma login manager, kscreenlocker, Prompt UI |
| UX6 | Face enrolment wizard: live camera preview, guided capture, an immediate recognition test, re-enrol and delete | System Settings |
| UX7 | Fingerprint enrolment reuses KDE's existing fingerprint UI in the Users settings page, linked from the same Linux Hello page | System Settings |
| UX8 | First-run wizard: PIN first (the root), then optional face and fingerprint | Enrolment Wizard |

**UX6a — Face enrolment preview.** The wizard shows the regular (RGB) camera feed as the user's view, while Howdy captures from the infrared (IR) sensor, as Windows Hello does. Rules:

- Guidance overlay (face found, too close, turn slightly, captured) is driven by Howdy's IR detection, never by the RGB image, so the feedback reflects what is actually enrolled.
- The RGB feed is display only: never stored, never passed to Howdy.
- No RGB camera present → show the IR feed in greyscale.
- Some cameras may not stream RGB and IR at once — **to test on real hardware**; fall back to IR preview if so.

**UX7a — One place for sign-in methods.** Face recognition sits beside fingerprint in KDE's Users settings page, where fingerprint enrolment already lives; KDE's fingerprint flow stays unchanged.

- Add a "Configure Face Recognition" entry next to the existing "Configure Fingerprint Authentication" entry, opening the Face Enrolment Module.
- Delivered as an upstream contribution to KDE's Users settings module (plasma-desktop), not a fork (C4). Whether that module offers an extension point is **unverified**; assumed not.
- Interim until accepted upstream: a separate Linux Hello page in System Settings, linked from the same area.

**UX7b — PIN management.** A "Change PIN" entry sits in the same area, beside fingerprint and face.

- Change PIN: enter the current PIN, then the new one twice. The TPM root key's authorisation value is changed in place, so passkeys survive (non-destructive).
- PIN rules shown up front (minimum length, digits only or alphanumeric) and checked as the user types.
- "I forgot my PIN" links to the destructive reset (ADR-0003), with a clear warning that device-bound passkeys will be wiped.
- Lockout state from the TPM is shown ("PIN locked for N min").

### Design consequence

A PAM conversation is text only, so a greeter cannot tell which method is running. Linux Hello therefore adds a side channel: `pam_linuxhello` runs fprintd and Howdy concurrently itself (instead of stacking `pam_fprintd` and `pam_howdy`) and publishes the live state on the Agent's D-Bus API (`MethodsAvailable`, `ActiveMethod`, `State`, `Result`). The login manager, lock screen and Prompt UI all render from that one state through a shared QML component.

### Additions to the C4 model

| Container | New component | Role |
| :-- | :-- | :-- |
| `pam_linuxhello` | Method Orchestrator | Runs face, fingerprint and PIN in parallel; first success wins; cancels the rest |
| Linux Hello Agent | Auth State Publisher | D-Bus signals for method, state and result per prompt |
| Plasma Integration | Auth Prompt QML Component | Shared method indicator and switcher for the greeter, lock screen and Prompt UI |
| Plasma Integration | Face Enrolment Module | Camera preview (PipeWire camera portal), guided capture and test; drives Howdy |
| Plasma Integration | Greeter and Lock Screen Integration | Embeds the shared component in the Plasma login manager and kscreenlocker |

New external dependencies: Howdy's enrolment and test interfaces (currently CLI only, so the module needs a stable interface; contribute one upstream if none exists), the camera via PipeWire, KDE's fingerprint enrolment UI. All of these are in [workspace.dsl](workspace.dsl).

Open questions: whether Howdy exposes a library or D-Bus interface usable for live preview — **unverified**; how the Plasma login manager and kscreenlocker allow a third-party prompt component — **unverified**.

## Policy

The Routing Policy Engine in the Agent answers one question before every credential operation: for this context, caller and relying party, which methods and provider are allowed, and how strong must the prompt be. It mirrors the Windows Hello for Business policy set (Group Policy / Intune) and adds per-context rules.

### How it is engaged

| Caller | Asks | Gets back |
| :-- | :-- | :-- |
| `pam_linuxhello` | Allowed methods for context `login`, `unlock`, `sudo`, … | Method set, factor count |
| TPM Provider / KeePassXC Bridge | Decision for relying party + operation (create, get) + verified caller app ID | Provider, prompt level (none, presence, re-verify), factors |
| Prompt UI / Auth Prompt | Which methods to offer and switch between | Method list, locked options |
| PIN Manager | PIN rules | Complexity rules, lockout threshold |
| Settings Module | Effective policy and which keys are admin-locked | Values + `managed` flags |

### Layers and precedence

1. Built-in defaults.
2. User layer `~/.config/linuxhello/policy.toml`, editable in Settings.
3. Admin layer `/etc/linuxhello/policy.d/*.toml` (root-owned, 0644). Any key set here wins and is shown greyed out as "Managed by your organisation". Later: delivered by a management system, as Intune does on Windows.

Most restrictive wins when two admin files conflict. The engine fails closed: a policy file that does not parse denies every operation except PIN.

### Settings

| Group | Setting | Windows Hello for Business parallel |
| :-- | :-- | :-- |
| PIN | `min_length`, `max_length` | Minimum / Maximum PIN length |
| PIN | `digits`, `lowercase`, `uppercase`, `special` (`required` / `allowed` / `disallowed`) | Digits, Lowercase, Uppercase, Special characters |
| PIN | `history`, `expiry_days` | History, Expiration |
| PIN | `lockout_attempts`, `lockout_minutes` (TPM dictionary-attack parameters) | TPM anti-hammering |
| Methods | `biometrics_allowed` | Allow use of biometrics |
| Methods | `face_requires_ir` (anti-spoofing) | Enhanced anti-spoofing |
| Methods | `require_hardware_tpm` | Use a hardware security device |
| Context | per context: `methods`, `factors`, `reverify_after` | No direct parallel (extension) |
| Relying party | per RP or RP class: `provider` (tpm / keepassxc / any), `prompt`, `require_second_credential` | No direct parallel (extension) |

### Example (admin layer)

```toml
[pin]
min_length = 6
digits = "required"
special = "allowed"
lockout_attempts = 5

[methods]
biometrics_allowed = true
face_requires_ir = true

[context.sudo]
methods = ["pin"]

[context.unlock]
methods = ["face", "fingerprint", "pin"]
reverify_after = "8h"

[rp_class.banking]
match = ["*.bank.example"]
provider = "tpm"
factors = 2          # e.g. fingerprint + PIN
require_second_credential = true
```

Schema is a draft; key names are proposals, **untested**.
