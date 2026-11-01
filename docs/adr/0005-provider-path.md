---
type: adr
subject: How the TPM provider and the KeePassXC bridge attach while credentialsd has no provider API
artifact: adr
status: accepted
owner: "@atterdag"
concepts: [credentialsd, provider-api, upstream, tpm, keepassxc]
tags: [adr, upstream]
sources: ["../spikes/0005-credentialsd-provider-api.md", "../architecture/target-architecture.md", "https://github.com/linux-credentials/credentialsd/issues/26"]
date: 2026-11-01
---

# ADR-0005: How providers attach while credentialsd has no provider API

## Status

Accepted, 2026-11-01 (option A).

## Context

[Spike 0005](../spikes/0005-credentialsd-provider-api.md) answered No: credentialsd v0.3.1 has no interface for third-party credential providers, and no KDE portal backend. Its authenticators (hybrid, NFC, USB) are compiled into the daemon. The credentialsd maintainer has drafted a provider API in [credentialsd#26](https://github.com/linux-credentials/credentialsd/issues/26): a `CredentialProvider` interface credentialsd calls, a `CredentialProviderManager` providers register with, a privileged interface so only a trusted settings app enables providers, and a Noise-protected channel. No implementation exists.

Constraint C1 assumed Linux Hello only adds providers to an existing API. Both the TPM provider and the KeePassXC bridge are blocked until one of the options below is chosen. KeePassXC is GPL, so it must stay across a process boundary whatever the choice (C3).

The options:

| Option | Pros | Cons |
| :-- | :-- | :-- |
| **A. Contribute the provider API upstream**, starting from the maintainer's draft in #26, then build both providers against it | Keeps C1 and C4; one mechanism for TPM and KeePassXC; KeePassXC stays out of process; the trusted-registration design matches our threat model; other password managers benefit | Critical path runs through upstream review and release; the Noise handshake and registration add design work; credentialsd is pre-release, so the API can still move |
| **B. Virtual CTAP authenticator** (`uhid`) backed by the TPM or KeePassXC, as kpasskey and tpm-fido do | Works with unmodified browsers today; reachable through credentialsd's USB transport too (assumption, untested) | Browsers treat it as a roaming security key, not a platform authenticator; creating `uhid` devices needs privilege, enlarging the attack surface; no clean place for per-relying-party routing; a second mechanism to retire later |
| **C. In-process backends contributed to credentialsd** | TPM as a first-party platform authenticator fits credentialsd's own "nice-to-have" goal | Impossible for KeePassXC (GPL, C3); puts our TPM code under upstream's LGPL-3.0-only and release cycle; still needs A for KeePassXC |
| D. Own broker or a fork | Full control | Breaks C1 and C4; duplicates upstream's CTAP and portal work; rejected |

## Decision

**Option A.** Engage before code: offer upstream to implement the #26 draft, agree the interface, then implement it in credentialsd and build the TPM provider as its first consumer. Keep **C** open for the TPM side only, if upstream prefers a first-party platform authenticator in-tree. Do not build **B** as a product path.

Upstream engagement started on 2026-11-01 with an offer to implement the draft and three questions on design, PR sequencing and an in-tree TPM authenticator ([comment on credentialsd#26](https://github.com/linux-credentials/credentialsd/issues/26#issuecomment-6559782108)). The answer is recorded here when it arrives.

Until upstream agrees an interface, Linux Hello work that does not depend on it continues: routing policy, PIN and TPM root key (spike on in-place auth change), PAM and Agent, Plasma prompts.

## Consequences

**Easier:** one provider mechanism for every custody option; upstream reviews the security-critical interface; KeePassXC and other managers can use the same API; Linux Hello stays an integration layer.

**Harder:** the TPM provider and the KeePassXC bridge wait for upstream agreement and a credentialsd release; Linux Hello must carry contributions in Rust under LGPL-3.0-only into another project's review process; the KDE portal backend remains a separate gap, owned by the Plasma spikes.
