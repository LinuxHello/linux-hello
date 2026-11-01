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

The threat model and the security properties will live here; each property is stated in plain language and has a test named after it. The disclosure policy and a summary of the security model are in [SECURITY.md](../../SECURITY.md).

See [index](../index.md).

## Properties

| Property | Enforced by |
| :-- | :-- |
| Unsafe code exists only in allow-listed modules of the TPM provider and the PAM module | CI job `unsafe-policy` ([script](../../scripts/ci/unsafe-policy.sh), [allow-list](../../scripts/ci/unsafe-allowlist.txt)); `#![forbid(unsafe_code)]` in every other crate root |
