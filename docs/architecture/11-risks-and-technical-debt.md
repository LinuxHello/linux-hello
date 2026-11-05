---
type: architecture
subject: "Arc42 section 11: risks and technical debt of Linux Hello (open questions)"
artifact: arc42-11-risks-and-technical-debt
status: draft
owner: "@atterdag"
concepts: [risks, open-questions, spikes, arc42]
tags: [architecture, arc42]
sources: ["README.md", "../spikes/README.md", "https://docs.arc42.org/section-11/"]
date: 2026-11-05
---

# 11. Risks and technical debt

Part of the [Arc42 architecture documentation](README.md). Unverified assumptions are answered by the spikes in [docs/spikes/](../spikes/README.md); implementation that depends on an open spike waits for it.

## Open questions

- Maturity and API of credentialsd and its portal on KDE Plasma — [spike 0005](../spikes/0005-credentialsd-provider-api.md): v0.3.1 has **no third-party provider API** (upstream issue is a stub) and no KDE portal backend. Providers need upstream design work first; build and run untested.
- Whether Firefox and Chromium on Linux call a portal WebAuthn API today — [spike 0006](../spikes/0006-browser-webauthn-portal.md): **No** in current source (Firefox 161.0a1, Chromium main). Only add-ons and an experimental patched Firefox reach credentialsd, so the browser-extension fallback stays on the 1.0 critical path. Source read only; upstream trackers and a live run were not available.
- Claude Desktop token lifetime and storage backend (KWallet vs libsecret) — observed by operator, not measured.
- Classification rule for which accounts must be device-bound — needs a data-classification rule.
- Who owns the threat model and the security property list.

Open questions on the user-experience design (Howdy's interfaces, third-party prompts in the login manager and lock screen) are in [section 8, User experience](08-crosscutting-concepts.md#user-experience).

## Risk register and technical debt

**Gap.** Risks are not yet rated (probability, impact, mitigation), and no technical debt is recorded. The consequences in [section 4](04-solution-strategy.md#consequences) and the threats in [section 8](08-crosscutting-concepts.md#threats-to-design-against) are inputs for it.
