---
type: architecture
subject: "Arc42 section 1: introduction and goals of Linux Hello"
artifact: arc42-01-introduction-and-goals
status: draft
owner: "@atterdag"
concepts: [credential-broker, passkeys, arc42]
tags: [architecture, arc42]
sources: ["README.md", "https://docs.arc42.org/section-1/"]
date: 2026-11-05
---

# 1. Introduction and goals

Part of the [Arc42 architecture documentation](README.md).

## 1.1 Requirements overview

### Recommendation

Build one **session credential broker** for the whole desktop, not a browser feature. It is unlocked once by biometrics through PAM, serves passkeys (WebAuthn/CTAP2) and secrets (Secret Service API) to browsers, native apps and Electron apps over an xdg-desktop-portal, and routes each relying party to a key provider by policy: TPM2 (device-bound) or KeePassXC (portable). Build it as an integration layer on credentialsd, not a reimplementation.

### Situation

Windows Hello combines three layers: TPM-held non-exportable keys, local user verification (biometric or PIN) that only unlocks those keys, and an OS platform-authenticator API (`webauthn.dll`) that browsers and apps call. Third-party providers (1Password, others) plug in beside it.

### Complication

Linux has the first two layers and lacks the third.

- TPM2: available (`tpm2-tss`); many systems already use TPM2/PCR 7 for LUKS.
- User verification: `fprintd` (fingerprint), Howdy (face), both via PAM.
- Platform authenticator: **none system-wide.** Each browser implements WebAuthn itself and mostly talks only to roaming USB/HID authenticators.
- KeePassXC (≥ 2.7.7) stores passkeys, but serves them only through its browser extension, so native apps are not covered. Its keys are software keys unlocked by the master password.
- Native and Electron apps (e.g. Claude Desktop) re-authenticate through the browser when their token expires. KWallet is open on the reference machine; the observed cause is a server-side token lifetime under 24 h, which no client store can extend.

The user-facing requirements UX1–UX8 are in [section 8, User experience](08-crosscutting-concepts.md#user-experience).

## 1.2 Quality goals

**Gap.** No quality goals are written down yet. The invariants in [AGENTS.md](../../AGENTS.md#invariants) and the design rules in [section 4](04-solution-strategy.md#design-rules) constrain the design but are not stated as ranked quality goals.

## 1.3 Stakeholders

**Gap.** The people in the C4 model (desktop user, administrator; [workspace.dsl](workspace.dsl)) and the roles in [ADR-0004](../adr/0004-agent-roles.md) are not yet described with their expectations of the architecture.
