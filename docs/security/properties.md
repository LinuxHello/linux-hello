---
type: security
subject: Planned security properties, each with the name of its test and the container that owns it
artifact: security-properties
status: draft
owner: "@atterdag"
concepts: [security-properties, tests, threat-model]
tags: [security, properties, tests]
sources: ["threat-model.md", "README.md", "../../SECURITY.md", "https://github.com/LinuxHello/architecture/blob/main/workspace.dsl"]
date: 2026-11-08
---

# Security properties (planned)

Each property answers a threat in the [threat model](threat-model.md) and is stated in plain language. Its test is named after it and lives in the crate of the container that owns it. **Every test below is a placeholder unless its *Blocked by* cell says it is tested:** a placeholder is marked `#[ignore]` with the reason it cannot run yet and fails if someone runs it without writing it, and is not a passing test. P-02, P-04 and P-05 are tested at the layers named in their rows.

Properties that already have a passing test are in the [README](README.md#properties) (quality gate, unsafe policy, release provenance, routing policy).

How to read the table:

- **Test**: the function name in the owner's `tests/security_properties.rs`. A name with a *CI job* mark is not a Rust test and has no placeholder yet.
- **Owner**: the container id in [workspace.dsl](https://github.com/LinuxHello/architecture/blob/main/workspace.dsl) and its crate.
- **Blocked by**: what has to be decided or built before the test can be written for real.

## Callers and the D-Bus API

| Id | Property | Test | Owner | Blocked by |
| :-- | :-- | :-- | :-- | :-- |
| P-01 | A caller whose claimed origin differs from the identity the portal or bus verified is refused | `caller_from_other_origin_is_refused` | `agent`, crate `linuxhello-agent` | Origin verification ([threat model, open question 4](threat-model.md#open-questions)); the Agent's D-Bus API |
| P-02 | A caller whose peer credentials cannot be read is refused | `caller_without_peer_credentials_is_refused` | `agent` | **Tested** at the request layer (`api.rs`, `tests/security_properties.rs`); remaining: the Agent running as a system service that supplies the uid ([ADR-0014](https://github.com/LinuxHello/architecture/blob/main/adr/0014-agent-bus.md)) |
| P-03 | A request for one relying party is never answered with another relying party's credential | `credential_for_another_relying_party_is_never_returned` (TPM), `kpxc_credential_for_another_relying_party_is_never_returned` (KeePassXC) | `tpmProvider`, crate `linuxhello-tpm-provider`; `kpxcBridge`, crate `linuxhello-kpxc-bridge` | Provider interface ([ADR-0005](https://github.com/LinuxHello/architecture/blob/main/adr/0005-provider-path.md)) |
| P-04 | A process other than the PAM module of the user being authenticated cannot publish method state for that user | `unprivileged_process_cannot_publish_method_state_for_another_user` | `agent` | **Tested** at the store layer (`state.rs`); remaining: the system-bus policy that lets only the Agent's user own the name ([open question 3](threat-model.md#open-questions)) |
| P-05 | Method state is delivered to the user who is authenticating and to nobody else | `method_state_is_not_broadcast_to_other_users` | `agent` | **Tested** at the store layer, and as `signals_reach_only_the_subscribed_peer` over a private bus (`tests/bus.rs`); remaining: the same bus policy |

## Unlock and keys

| Id | Property | Test | Owner | Blocked by |
| :-- | :-- | :-- | :-- | :-- |
| P-06 | A biometric match alone never releases a key | `biometric_match_alone_never_releases_a_key` | `tpmProvider` | How a match satisfies a TPM policy ([open question 1](threat-model.md#open-questions)) |
| P-07 | Unlock state is a satisfied TPM policy session, never a flag in the daemon | `unlock_requires_a_satisfied_tpm_policy_session` | `agent` | Same |
| P-08 | Every key is created non-exportable | `tpm_keys_are_created_non_exportable` | `tpmProvider` | TPM key service |
| P-09 | No interface of the TPM provider returns private key material | `no_interface_returns_private_key_material` | `tpmProvider` | TPM key service |
| P-10 | The KeePassXC bridge never receives a passkey private key, only assertions | `kpxc_bridge_never_receives_private_key_material` | `kpxcBridge` | The bridge's protocol client |
| P-11 | A signature without a user-presence confirmation is refused | `signature_without_user_presence_is_refused` | `tpmProvider` | Provider interface (ADR-0005) |
| P-12 | The PIN is checked by the TPM's authorisation, never compared in software | `pin_is_never_compared_outside_the_tpm` | `pamModule`, crate `pam-linuxhello` | PIN verifier |
| P-13 | The PIN and key material never appear in logs, errors or audit events | `secrets_never_appear_in_logs_errors_or_audit` | `agent` | Audit logger |
| P-14 | One user's failed PIN attempts cannot lock another user out | `one_users_failed_pins_cannot_lock_out_another_user` | `agent` | Whether the TPM lockout is shared ([open question 2](threat-model.md#open-questions)); PIN manager |
| P-15 | An unlock ends after its configured duration and when the session locks | `unlock_expires_after_the_configured_duration`, `unlock_ends_when_the_session_locks` | `agent` | Unlock state manager |
| P-16 | Changing the PIN keeps every child key loadable, and the old PIN stops working | `pin_change_keeps_child_keys_loadable`, `old_pin_is_refused_after_a_change` | `tpmProvider` | Spike [#11](https://github.com/LinuxHello/linux-hello/issues/11) (change the root key's authorisation in place) |

## Reset

| Id | Property | Test | Owner | Blocked by |
| :-- | :-- | :-- | :-- | :-- |
| P-17 | The account password never unlocks a key | `account_password_never_unlocks_a_key` | `agent` | Reset coordinator ([ADR-0003](https://github.com/LinuxHello/architecture/blob/main/adr/0003-destructive-reset.md)) |
| P-18 | A reset destroys the root key and every child key | `reset_destroys_root_key_and_every_child_key` | `tpmProvider` | Same; TPM key service |
| P-19 | A reset without the account or admin authentication is refused | `reset_without_account_authentication_is_refused` | `agent` | Reset coordinator |

## PAM

| Id | Property | Test | Owner | Blocked by |
| :-- | :-- | :-- | :-- | :-- |
| P-20 | The PAM module never reports success when the Agent is unreachable or returns an error | `pam_never_succeeds_when_agent_is_unreachable` | `pamModule` | PAM entry points; spike [#7](https://github.com/LinuxHello/linux-hello/issues/7) runs |
| P-21 | The PAM module reports success only for the user being authenticated | `pam_success_for_another_user_is_not_success` | `pamModule` | PAM entry points |

## Parsers

Each parser also gets a cargo-fuzz target, as [AGENTS.md](../../AGENTS.md#gates) requires; the target is added with the parser.

| Id | Property | Test | Owner | Blocked by |
| :-- | :-- | :-- | :-- | :-- |
| P-22 | A malformed CTAP/CBOR request is refused, never a panic | `malformed_ctap_request_is_refused` | `tpmProvider` | Provider interface (ADR-0005) |
| P-23 | A malformed KeePassXC protocol message is refused, never a panic | `malformed_kpxc_message_is_refused` | `kpxcBridge` | The bridge's protocol client |

## Confinement and evidence

| Id | Property | Test | Owner | Blocked by |
| :-- | :-- | :-- | :-- | :-- |
| P-24 | A daemon whose AppArmor profile is not loaded in enforce mode refuses to start | `agent_refuses_to_start_without_enforced_apparmor_profile`, `tpm_provider_refuses_to_start_without_enforced_apparmor_profile`, `kpxc_bridge_refuses_to_start_without_enforced_apparmor_profile` | `agent`, `tpmProvider`, `kpxcBridge` | The daemons' start-up code |
| P-25 | Only the Agent and the TPM provider may open the TPM device, and no process may trace them | *CI job:* `apparmor_only_agent_and_tpm_provider_open_tpm_device`, `apparmor_denies_ptrace_of_agent_and_providers` | `secProfiles`, directory `security/apparmor` | The CI job that loads the profiles ([Arc42 section 8](https://github.com/LinuxHello/architecture/blob/main/arc42/08-crosscutting-concepts.md#runtime-confinement-and-detection)) |
| P-26 | No Linux Hello process may open an internet socket | *CI job:* `apparmor_denies_inet_sockets_to_every_daemon` | `secProfiles` | Same |
| P-27 | Every unlock, signature, PIN change and reset is audited | `every_unlock_signature_pin_change_and_reset_is_audited` | `agent` | Audit logger |

## Coverage

Every threat in the [threat model](threat-model.md#threats) is answered by at least one property above or by one that already has a passing test. Threat T8 (biometric spoofing) is answered only in part: P-06 limits what a spoof achieves, and resisting the spoof is the sensors' job.

The placeholder tests are `#[ignore]` so that `cargo test --workspace` stays green and lists them as ignored. When a property's blocker is resolved, the implementer removes the `#[ignore]`, writes the test and watches it fail before writing the code, as [AGENTS.md](../../AGENTS.md#how-to-work) requires.

See [index](README.md).
