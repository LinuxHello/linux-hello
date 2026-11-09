---
type: index
subject: Index of the threat model and security properties
artifact: security-index
status: active
owner: "@atterdag"
concepts: [threat-model, security-properties]
tags: [security, index]
sources: ["../../SECURITY.md"]
date: 2026-11-08
---

# Security

The threat model and the security properties live here; each property is stated in plain language and has a test named after it. The disclosure policy and a summary of the security model are in [SECURITY.md](../../SECURITY.md).

- [Threat model](threat-model.md): assets, actors, trust boundaries, entry points and threats, and the questions the design has not settled.
- [Planned properties](properties.md): 27 properties, each with the name of its test and the container that owns it. Every test is a placeholder (`#[ignore]`) until its blocker is resolved.
- The tables below list the properties that already have a passing test.

See [index](../index.md).

## Properties

| Property | Enforced by |
| :-- | :-- |
| Unsafe code exists only in allow-listed modules of the TPM provider and the PAM module | CI job `unsafe-policy` ([script](../../scripts/ci/unsafe-policy.sh), [allow-list](../../scripts/ci/unsafe-allowlist.txt)); `#![forbid(unsafe_code)]` in every other crate root |
| No commit merges and no release is published without a verified attestation that it passed every quality gate | CI job `quality-gate` ([ADR-0006](../adr/0006-attested-quality-gates-and-releases.md)); release job `gate` ([release.yml](../../.github/workflows/release.yml)) |
| Every release file has Sigstore-signed build provenance, and every binary an attested SBOM, verified before publication | Release job `publish` ([release.yml](../../.github/workflows/release.yml)) |

### Routing policy

Semantics: [policy-semantics.md](../architecture/policy-semantics.md). Tests live in `crates/linuxhello-agent/src/policy/`.

| Property | Test |
| :-- | :-- |
| An unparseable, unreadable or schema-breaking policy file leaves only the PIN | `unparseable_user_file_leaves_only_pin`, `unparseable_admin_file_leaves_only_pin`, `non_utf8_file_leaves_only_pin` |
| A policy directory or file that cannot be examined is a failure, never "absent"; a file that is not a regular file or is over 1 MiB leaves only the PIN | `admin_dir_that_cannot_be_examined_leaves_only_pin`, `admin_file_that_is_not_a_regular_file_leaves_only_pin`, `symlinked_admin_file_leaves_only_pin`, `oversized_admin_file_leaves_only_pin` |
| An unknown key or out-of-range value makes a policy file unparseable | `unknown_key_makes_file_unparseable`, `out_of_range_value_makes_file_unparseable`, `invalid_rp_pattern_makes_file_unparseable` |
| An admin policy file or directory that is not root-owned, or is writable by group or others, leaves only the PIN | `admin_file_writable_by_others_leaves_only_pin`, `admin_dir_parent_writable_by_others_leaves_only_pin` |
| The user can tighten a default but never loosen it | `user_can_tighten_a_default`, `user_cannot_loosen_a_default` |
| A user's relying-party class can tighten a decision but never lower a default or an admin class, by its values, its name or a more specific pattern | `user_layer_can_tighten_an_rp_decision`, `user_layer_cannot_lower_rp_prompt_below_default`, `user_patterns_do_not_join_an_admin_class`, `user_class_cannot_shadow_a_stricter_admin_class` |
| A damaged or contradictory user layer never lowers an admin rule: the PIN-only state keeps the admin's PIN rules, factor counts and relying-party classes | `damaged_user_layer_does_not_remove_admin_rules`, `pin_only_state_is_never_weaker_than_the_admin_layer` |
| An admin setting overrides the user's | `user_cannot_override_admin_setting` |
| Conflicting admin files resolve to the most restrictive value; contradictions leave only the PIN | `conflicting_admin_files_resolve_to_most_restrictive`, `contradictory_merge_leaves_only_pin` |
| The PIN is always an allowed method | `pin_is_always_allowed` |
| Disabling biometrics removes face and fingerprint from every context | `biometrics_disabled_leaves_only_pin` |
| In the PIN-only state every relying party gets the TPM provider and re-verification | `pin_only_state_requires_tpm_and_reverify` |
| A duration too large to count in seconds makes a policy file unparseable | `overflowing_duration_makes_file_unparseable` |
| A policy file of any content is parsed or refused; the parser never panics | Fuzz target `policy_parse` ([crates/linuxhello-agent/fuzz](../../crates/linuxhello-agent/fuzz/fuzz_targets/policy_parse.rs)), CI job `fuzz` |
| A relying-party pattern matches only what it names | `wildcard_does_not_match_apex`, `wildcard_does_not_match_lookalike_suffix`, `rp_ids_compared_case_insensitively` |

### Method state (Agent)

[ADR-0014](https://github.com/LinuxHello/architecture/blob/main/adr/0014-agent-bus.md). Tests live in `crates/linuxhello-agent/` (`src/state.rs`, `src/api.rs`, `tests/`). The system-bus policy and the Agent as a system service are not shipped yet, so these hold for the code, not yet for a deployment.

| Property | Test |
| :-- | :-- |
| A caller whose peer credentials cannot be read is refused by every operation, and nothing changes (P-02) | `caller_without_peer_credentials_is_refused` |
| Only root or the user being authenticated can open a prompt for that user, and only the opener can change or close it (P-04) | `unprivileged_process_cannot_publish_method_state_for_another_user`, `prompt_cannot_be_hijacked_by_reopening`, `closed_prompt_is_gone` |
| State is read by and told to only the opener, the subject user and the configured prompt hosts; a refusal does not say whether the prompt exists (P-05) | `method_state_is_not_broadcast_to_other_users`, `prompt_without_subject_is_visible_only_to_hosts_and_opener` |
| A signal goes only to the peer that subscribed, as a unicast message on a real bus | `signals_reach_only_the_subscribed_peer` |
| The caller's uid comes from the bus, not from the message | `a_prompt_for_another_user_is_refused_with_access_denied` |
| A malformed prompt id, signal, value or peer name is refused before the state changes | `malformed_prompt_id_is_an_invalid_argument`, `bad_wire_values_are_refused_before_the_store_changes`, `invalid_peer_names_are_refused`, `malformed_requests_get_invalid_args_errors` |
| No user can fill the store | `reporter_cannot_exceed_its_prompt_limit`, `subscriber_limit_is_enforced` |

### User policy layer (Agent)

[ADR-0018](https://github.com/LinuxHello/architecture/blob/main/adr/0018-user-policy-layer.md). Tests are in `crates/linuxhello-agent/src/policy/user_store.rs` (the store) and `src/api.rs`, `tests/bus.rs` (the D-Bus methods). The names `unparseable_user_policy_is_refused_on_write` and `oversized_user_policy_is_refused_on_write` exist at both levels.

| Property | Test |
| :-- | :-- |
| A user policy the schema rejects is refused on write and the previous layer stays | `unparseable_user_policy_is_refused_on_write` |
| A user policy over 64 KiB is refused on write | `oversized_user_policy_is_refused_on_write` |
| A user policy that contradicts the defaults or the admin layers is refused on write | `user_layer_contradicting_defaults_is_refused_on_write`, `user_layer_contradicting_the_admin_layer_is_refused_on_write` |
| A user policy that would leave a context needing more methods than it allows is refused on write, so a user's layer cannot lock its user out | `user_policy_that_makes_a_context_unsatisfiable_is_refused_on_write`, `context_the_admin_made_unsatisfiable_is_not_held_against_the_user` |
| One user's policy is never visible under another uid | `user_policies_are_kept_apart_by_uid` |
| A write never leaves a half-written or temporary file, and the files are private to the Agent | `a_write_leaves_no_temporary_file_and_private_modes` |
| The user layer is available without a home directory | `user_policy_is_available_without_a_home_directory` |
| A caller can read and change only its own user policy layer | `user_cannot_set_another_users_policy`, `user_policy_is_set_and_read_over_the_bus` |
| A user policy that does not parse, or is over 64 KiB, is refused over D-Bus with InvalidArgs and the stored layer stays | `unparseable_user_policy_is_refused_on_write`, `oversized_user_policy_is_refused_on_write` (`api.rs`), `user_policy_is_set_and_read_over_the_bus` |
| A caller whose peer credentials cannot be read cannot read or set a user policy | `user_policy_without_peer_credentials_is_refused` |

### Confinement of the Agent

Files: [`security/`](../../security/). Tests: `crates/linuxhello-agent/tests/bus_policy.rs` (a real private bus with the default rules of the system bus and the policy included after them) and `profiles.rs`. The files were also installed in the test VM and exercised on a real system bus under an enforcing AppArmor profile (2026-11-08): the name is owned by the Agent's user, `nobody` is refused every call on another user's prompt, a signal reaches only the subscribed peer, forged signals reach nobody, and the unit does not start with the profile in complain mode or not loaded. That run is by hand, not a CI test.

| Property | Test |
| :-- | :-- |
| Only the Agent's user can own the Agent's bus name | `only_the_agents_user_may_own_the_name` |
| Only the Agent's user can send a signal of the Agent's interface; a forged signal reaches nobody, and the Agent's own signals are not blocked | `only_the_agents_user_can_send_the_agents_signals`, `a_subscriber_hears_the_agent_under_the_policy` |
| Any user can call the Agent's methods; its properties and every other interface are denied | `any_user_can_call_the_agents_methods_but_not_its_other_interfaces` |
| The unit runs as its own user with no capability and a strict sandbox, and allows only `/dev/tpmrm0` | `agent_unit_runs_as_its_own_user_with_no_privileges`, `agent_unit_sandbox_is_strict`, `agent_unit_allows_only_the_tpm_device` |
| The unit refuses to start unless its AppArmor profile is loaded in enforce mode | `agent_unit_refuses_to_start_unless_apparmor_enforces_its_profile` |
| The profile grants no network but the unix socket, no capability, no tracing, no home directory and no device but the TPM | `agent_profile_grants_no_network_but_the_unix_socket`, `agent_profile_grants_no_capability_and_denies_tracing`, `agent_profile_denies_home_directories_and_names_the_registered_bus_name`, `agent_profile_grants_the_tpm_and_no_other_device` |
| The unit and the profile are accepted by `systemd-analyze verify` and `apparmor_parser` (skipped, and said so, if a tool is missing) | `agent_unit_passes_systemd_analyze_verify`, `agent_profile_parses` |
