---
type: adr
subject: Destructive reset of the trust chain, no recovery key
artifact: adr
status: accepted
owner: "@atterdag"
concepts: [trust-chain, tpm, reset, recovery]
tags: [adr, one-way-door, security]
sources: ["../architecture/target-architecture.md"]
date: 2026-10-27
---

# ADR-0003: Destructive reset, no recovery key

Formerly decision LH-1 in the [target architecture](../architecture/target-architecture.md#trust-chain).

## Status

Accepted, 2026-10-27 (scoping). Moved to `docs/adr/` on 2026-11-01 without change.

## Context

The PIN is the root of trust: it is the TPM 2.0 authorisation on a per-user root key, and every TPM-bound passkey hangs off that key. A user who forgets the PIN needs a way back.

A non-destructive reset needs a second protector on the root key, such as a recovery key or a LUKS-style QR code. For that, the root key has to be created outside the TPM or be duplicable, so it is less sealed. Reusing the LUKS recovery key is ruled out: a forgotten PIN must never touch disk encryption.

## Decision

A reset wipes the user's root key and every TPM-bound passkey, then enrols a new PIN. The account or admin password authorises the reset and never unlocks keys. There is no recovery key. Recovery happens through the relying parties: the user re-registers a passkey with each service, using account recovery or a second registered credential.

Changing the PIN while it is known is not a reset and stays non-destructive.

## Consequences

**Easier:** root keys are generated in the TPM and never exportable; there is no recovery secret to store, rotate or leak; the model matches the Windows Hello default.

**Harder:** a reset orphans every TPM-bound passkey; each high-value account needs a second registered credential (a hardware key or a portable passkey in KeePassXC); re-registration is manual, per service; the UI must warn clearly before a reset.
