---
type: security
subject: Planned security properties, each with the name of its test and the container that owns it
artifact: security-properties
status: draft
owner: "@atterdag"
concepts: [security-properties, tests, threat-model]
tags: [security, properties, tests]
sources: ["threat-model.md", "README.md", "../../SECURITY.md", "https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl"]
date: 2026-11-08
---

# Security properties (planned)

Each property answers a threat in the [threat model](threat-model.md) and is stated in plain language. Its test is named after it and lives in the crate of the container that owns it. **Every test below is a placeholder unless its *Blocked by* cell says it is tested:** a placeholder is marked `#[ignore]` with the reason it cannot run yet and fails if someone runs it without writing it, and is not a passing test. P-02, P-04 and P-05 are tested at the layers named in their rows.

Properties that already have a passing test are in the [README](README.md#properties) (quality gate, unsafe policy, release provenance, routing policy).

How to read the table:

- **Test**: the function name in the owner's `tests/security_properties.rs`. A name with a *CI job* mark is not a Rust test and has no placeholder yet.
- **Owner**: the container id in [workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl) and its crate.
- **Blocked by**: what has to be decided or built before the test can be written for real.

## Callers and the D-Bus API

| Id | Property | Test | Owner | Blocked by |
| :-- | :-- | :-- | :-- | :-- |
| P-01 | A caller whose claimed origin differs from the identity the portal or bus verified is refused | `caller_from_other_origin_is_refused` | `agent`, crate `linuxhello-agent` | Origin verification ([threat model, open question 4](threat-model.md#open-questions)); the Agent's D-Bus API |
| P-02 | A caller whose peer credentials cannot be read is refused | `caller_without_peer_credentials_is_refused` | `agent` | **Tested** at the request layer (`api.rs`, `tests/security_properties.rs`); remaining: the Agent running as a system service that supplies the uid ([ADR-0014](https://github.com/LinuxHello/linux-hello-architecture/blob/main/adr/0014-agent-bus.md)) |
| P-03 | A request for one relying party is never answered with another relying party's credential | `credential_for_another_relying_party_is_never_returned` (TPM), `kpxc_credential_for_another_relying_party_is_never_returned` (KeePassXC) | `tpmProvider`, crate `linuxhello-tpm-provider`; `kpxcBridge`, crate `linuxhello-kpxc-bridge` | Provider interface ([ADR-0005](https://github.com/LinuxHello/linux-hello-architecture/blob/main/adr/0005-provider-path.md)) |
| P-04 | A process of another user cannot open, publish, read or change method state for a user, and no answer says whether a prompt exists; processes of the same user are not told apart, by decision ([ADR-0014](https://github.com/LinuxHello/linux-hello-architecture/blob/main/adr/0014-agent-bus.md), amendment 2026-11-16), so method state is an indicator and never an input to a decision | `unprivileged_process_cannot_publish_method_state_for_another_user` | `agent` | **Tested** at the store layer (`state.rs`); remaining: the system-bus policy that lets only the Agent's user own the name ([open question 3](threat-model.md#open-questions)) |
| P-05 | Method state is delivered to the user who is authenticating and to nobody else | `method_state_is_not_broadcast_to_other_users` | `agent` | **Tested** at the store layer, and as `signals_reach_only_the_subscribed_peer` over a private bus (`tests/bus.rs`). The `Closed` signal obeys the same rule: `a_subscriber_is_told_when_the_prompt_closes` (store), `a_subscriber_is_told_over_the_bus_when_the_prompt_closes` (bus, including that a peer that unsubscribed or never subscribed hears nothing) and `unsubscribe_stops_the_signals`; remaining: the same bus policy |

## Unlock and keys

| Id | Property | Test | Owner | Blocked by |
| :-- | :-- | :-- | :-- | :-- |
| P-06 | A biometric match alone never releases a key | `biometric_match_alone_never_releases_a_key` | `tpmProvider` | How a match satisfies a TPM policy ([open question 1](threat-model.md#open-questions)) |
| P-07 | Unlock state is a satisfied TPM policy session, never a flag in the daemon | `unlock_requires_a_satisfied_tpm_policy_session` | `agent` | Same |
| P-08 | Every key is created non-exportable | `tpm_keys_are_created_non_exportable` | `tpmProvider` | TPM key service |
| P-09 | No interface of the TPM provider returns private key material | `no_interface_returns_private_key_material` | `tpmProvider` | TPM key service |
| P-10 | The KeePassXC bridge never receives a passkey private key, only assertions | `kpxc_bridge_never_receives_private_key_material` | `kpxcBridge` | The bridge's protocol client |
| P-11 | A signature without a user-presence confirmation is refused | `signature_without_user_presence_is_refused` | `tpmProvider` | The virtual CTAP authenticator and the provider interface behind it (ADR-0005, decided, not built yet) |
| P-12 | The PIN is checked by the TPM's authorisation, never compared in software | `pin_is_never_compared_outside_the_tpm` | `pamModule`, crate `pam-linuxhello` | PIN verifier |
| P-13 | The PIN and key material never appear in logs, errors or audit events | `secrets_never_appear_in_logs_errors_or_audit` | `agent` | Audit logger (the five events that exist are tested; the rest wait for their components) |
| P-14 | One user's failed PIN attempts cannot lock another user out (tested at the counter level) | `one_users_failed_pins_cannot_lock_out_another_user` | `agent` | Wiring the counter into the PIN path and the software-TPM test (#137) |
| P-29 | A restart of the Agent does not clear a PIN lockout, and a lockout file that cannot be trusted refuses every attempt instead of starting from an empty counter | `saved_records_are_read_back_after_a_restart`, `a_file_that_cannot_be_trusted_refuses_every_attempt` | `agent` | **Tested** for the file module (`src/pinlock/store.rs`); remaining: the Agent writes the file on every failure and success and reads it at start-up, once the PIN path exists (#180) |
| P-30 | A policy that falls back to PIN-only is audited, once per load, with the uid and one of two fixed words naming the layer at fault; the record never carries a file name, a path or any text from a policy | `pin_only_fallback_is_audited_with_its_reason`, `a_sound_policy_is_not_audited` | `agent` | **Tested** (`Api::policy_of`); remaining: the Agent's decisions (methods per context, relying-party answers) call it, once the orchestrator and the PIN path exist (#172, #151) |
| P-31 | A PIN reaches the Agent only on its own socket, from the process that made the control call and for the subject that call named; a process of another user, a process that made no control call, a reused or expired control call and a frame that is not exactly one PIN are refused with the same single byte; the bus interface has no method, signal, property or argument that names a PIN | `pin_is_never_a_dbus_message_body`, `a_caller_of_another_user_cannot_use_the_socket`, `the_pin_is_accepted_only_for_the_subject_the_bus_named`, `a_control_call_is_used_once`, `a_frame_that_is_not_exactly_one_pin_is_refused`, `every_refusal_is_the_same_single_byte`, `the_directory_must_be_private_to_the_agent` | `agent` | **Tested** for the socket module (`src/pinsocket.rs`) and the bus interface; remaining: the control call on the bus, the PIN verifier, the AppArmor rule and the unit settings, and the PAM module's client, once the PIN path exists (#186 follows, #195) |
| P-32 | When Linux Hello is unavailable, login, unlock and `sudo` still accept the account password, and when it is available a wrong PIN or a refused face never falls through to the password: the shipped snippets put `pam_unix` right after `pam_linuxhello`, whose control is `[success=done authinfo_unavail=ignore default=die]` (ADR-0023, decision 2) | `login_falls_through_to_the_account_password_when_linux_hello_is_unavailable` | `pam` | **Tested** on the snippet text (`crates/pam-linuxhello/tests/snippets.rs`); remaining: the same on a real PAM stack in the test VM, once the module exists (#198) |
| P-15 | An unlock ends after its configured duration and when the session locks | `unlock_expires_after_the_configured_duration`, `unlock_ends_when_the_session_locks` | `agent` | Unlock state manager |
| P-16 | Changing the PIN keeps every child key loadable, and the old PIN stops working | `pin_change_keeps_child_keys_loadable`, `old_pin_is_refused_after_a_change` | `tpmProvider` | Spike [#11](https://github.com/LinuxHello/linux-hello/issues/11) (change the root key's authorisation in place) |

## Reset

| Id | Property | Test | Owner | Blocked by |
| :-- | :-- | :-- | :-- | :-- |
| P-17 | The account password never unlocks a key | `account_password_never_unlocks_a_key` | `agent` | Reset coordinator ([ADR-0003](https://github.com/LinuxHello/linux-hello-architecture/blob/main/adr/0003-destructive-reset.md)) |
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
| P-22 | A malformed CTAP/CBOR request is refused, never a panic | `malformed_ctap_request_is_refused` | `tpmProvider` | The virtual CTAP authenticator and the provider interface behind it (ADR-0005, decided, not built yet) |
| P-23 | A malformed KeePassXC protocol message is refused, never a panic | `malformed_kpxc_message_is_refused` | `kpxcBridge` | The bridge's protocol client |

## Confinement and evidence

| Id | Property | Test | Owner | Blocked by |
| :-- | :-- | :-- | :-- | :-- |
| P-24 | A daemon whose AppArmor profile is not loaded in enforce mode refuses to start | `agent_refuses_to_start_without_enforced_apparmor_profile`, `tpm_provider_refuses_to_start_without_enforced_apparmor_profile`, `kpxc_bridge_refuses_to_start_without_enforced_apparmor_profile` | `agent`, `tpmProvider`, `kpxcBridge` | The daemons' start-up code |
| P-25 | Only the Agent and the TPM provider may open the TPM device, and no process may trace them | *CI job:* `apparmor_only_agent_and_tpm_provider_open_tpm_device`, `apparmor_denies_ptrace_of_agent_and_providers` | `secProfiles`, directory `security/apparmor` | The CI job that loads the profiles ([Arc42 section 8](https://github.com/LinuxHello/linux-hello-architecture/blob/main/arc42/08-crosscutting-concepts.md#runtime-confinement-and-detection)) |
| P-26 | No Linux Hello process may open an internet socket | *CI job:* `apparmor_denies_inet_sockets_to_every_daemon` | `secProfiles` | Same |
| P-27 | Every unlock, signature, PIN change and reset is audited | `every_unlock_signature_pin_change_and_reset_is_audited` | `agent` | Audit logger (the five events that exist are tested; the rest wait for their components) |
| P-28 | Every status condition has one stable code, a severity and one fixed sentence. `status --user` computes conditions only from the policy files on disk through the Agent's own loader and probes nothing. `status` without `--user` makes one call, `GetStatus` to the running Agent; when the Agent does not answer it prints `agent-unreachable` and falls back to the policy files. `doctor` also reads four facts of the machine (the Agent unit, the AppArmor profile list, the fingerprint service, Howdy) and names the file. `status` never prints a file name or a path; neither command writes | `status_prints_one_line_per_condition_with_code_severity_and_sentence`, `status_never_prints_a_file_name`, `status_probes_nothing`, `status_without_a_user_shows_what_the_agent_says`, `an_agent_that_does_not_answer_is_a_condition_and_the_files_are_read`, `doctor_probes_only_the_named_commands_and_files`, `doctor_exits_nonzero_and_names_the_file_for_a_policy_that_does_not_parse`, `status_and_doctor_never_write`; fuzz target `status_reply` | `cli` | **Tested** in `crates/linuxhello-ctl/src/status/tests.rs` (the container's own tests, not `tests/security_properties.rs`) |

## Coverage

Every threat in the [threat model](threat-model.md#threats) is answered by at least one property above or by one that already has a passing test. Threat T8 (biometric spoofing) is answered only in part: P-06 limits what a spoof achieves, and resisting the spoof is the sensors' job.

The placeholder tests are `#[ignore]` so that `cargo test --workspace` stays green and lists them as ignored. When a property's blocker is resolved, the implementer removes the `#[ignore]`, writes the test and watches it fail before writing the code, as [AGENTS.md](../../AGENTS.md#how-to-work) requires.

See [index](README.md).
