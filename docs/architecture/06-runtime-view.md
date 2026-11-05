---
type: architecture
subject: "Arc42 section 6: runtime view of Linux Hello (user journeys)"
artifact: arc42-06-runtime-view
status: draft
owner: "@atterdag"
concepts: [user-journeys, arc42]
tags: [architecture, arc42]
sources: ["README.md", "https://docs.arc42.org/section-6/"]
date: 2026-11-05
---

# 6. Runtime view

Part of the [Arc42 architecture documentation](README.md).

## User journeys

1. **Session login.** Face or fingerprint at the Plasma login manager or lock screen → PAM unlocks the session and the broker together; PIN on failure.
2. **Passkey sign-in in a browser.** Site calls WebAuthn → credentialsd → routing policy picks TPM or KeePassXC → signed silently, or after one touch for high-value relying parties.
3. **Native app re-auth (Claude Desktop).** Token expires → browser OAuth login → passkey assertion after one fingerprint → token stored in the Secret Service. Target: DBSC makes this invisible.
4. **Passkey enrolment.** Site offers passkey creation → policy, or the user, chooses device-bound (TPM) or portable (KeePassXC) → prompt to register a second credential for high-value accounts.
5. **Reset.** PIN forgotten or TPM cleared → account or admin password → root key and TPM-bound passkeys wiped → new PIN enrolled → user re-registers with each relying party, using the second credential or the service's account recovery.

## Scenarios at container level

**Gap.** No journey is yet traced through the containers and components of [section 5](05-building-block-view.md) (for example as a Mermaid sequence diagram or a C4 dynamic view in [workspace.dsl](workspace.dsl)).
