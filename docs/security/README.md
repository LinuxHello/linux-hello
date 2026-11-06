---
type: index
subject: Index of the threat model and security properties
artifact: security-index
status: active
owner: "@atterdag"
concepts: [threat-model, security-properties]
tags: [security, index]
sources: ["../../SECURITY.md"]
date: 2026-11-01
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
| An unknown key or out-of-range value makes a policy file unparseable | `unknown_key_makes_file_unparseable`, `out_of_range_value_makes_file_unparseable`, `invalid_rp_pattern_makes_file_unparseable` |
| An admin policy file or directory that is not root-owned, or is writable by group or others, leaves only the PIN | `admin_file_writable_by_others_leaves_only_pin` |
| The user can tighten a default but never loosen it | `user_can_tighten_a_default`, `user_cannot_loosen_a_default` |
| An admin setting overrides the user's | `user_cannot_override_admin_setting` |
| Conflicting admin files resolve to the most restrictive value; contradictions leave only the PIN | `conflicting_admin_files_resolve_to_most_restrictive`, `contradictory_merge_leaves_only_pin` |
| The PIN is always an allowed method | `pin_is_always_allowed` |
| Disabling biometrics removes face and fingerprint from every context | `biometrics_disabled_leaves_only_pin` |
| In the PIN-only state every relying party gets the TPM provider and re-verification | `pin_only_state_requires_tpm_and_reverify` |
| A duration too large to count in seconds makes a policy file unparseable | `overflowing_duration_makes_file_unparseable` |
| A policy file of any content is parsed or refused; the parser never panics | Fuzz target `policy_parse` ([crates/linuxhello-agent/fuzz](../../crates/linuxhello-agent/fuzz/fuzz_targets/policy_parse.rs)), CI job `fuzz` |
| A relying-party pattern matches only what it names | `wildcard_does_not_match_apex`, `wildcard_does_not_match_lookalike_suffix`, `rp_ids_compared_case_insensitively` |
