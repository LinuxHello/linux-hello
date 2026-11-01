---
type: spike
subject: credentialsd provider API and portal on KDE Plasma
artifact: spike
status: answered
owner: "@atterdag"
concepts: [credentialsd, provider-api, xdg-desktop-portal, kde-plasma]
tags: [spike, m0, upstream]
sources:
  - https://github.com/linux-credentials/credentialsd/tree/v0.3.1
  - https://github.com/linux-credentials/credentialsd/issues/26
  - https://github.com/linux-credentials/xdg-desktop-portal
date: 2026-11-01
issue: https://github.com/LinuxHello/linux-hello/issues/5
---

# Spike: credentialsd provider API and portal on KDE Plasma

## Question

Can a third-party credential provider register with credentialsd v0.3.x and serve a WebAuthn create/get request that arrives through xdg-desktop-portal on KDE Plasma?

## Time box

2 working days proposed. This note covers a source and docs read only (under one day); the stub-provider run was not possible, see Method.

## Method

Read upstream at tag `v0.3.1` (commit `861e04c`, published 2026-09-07, marked pre-release on GitHub):

```sh
git clone --depth 1 --branch v0.3.1 https://github.com/linux-credentials/credentialsd
grep -rn -i -E "provider|register_|plugin" --include=*.rs --include=*.xml --include=*.build credentialsd credentialsd-common doc/*.xml portal dbus
grep -n "<interface" doc/*.xml
gh api repos/linux-credentials/credentialsd/issues/26
```

All three: **tested** (ran on the maintainer's workstation, Kubuntu, `git` and `gh` only).

**Not done:** building credentialsd and the patched xdg-desktop-portal, the stub provider, and the test-client request. No Rust toolchain is installed on the machine used, and there is nothing to register a stub with (see Evidence 1). Those steps are **untested**.

## Evidence

1. **No provider interface exists in v0.3.1.** The grep for `provider`, `register_` and `plugin` over all Rust sources, D-Bus XML, portal and service files returns no matches. The only D-Bus interfaces defined are the client-facing portal (`org.freedesktop.portal.experimental.Credential`), the handler (`org.freedesktop.handler.portal.experimental.Credential`) and the UI backend (`org.freedesktop.impl.portal.experimental.Credential` with `.Ceremony`), in `doc/*.xml`.
2. **Authenticators are compiled in.** `credentialsd/src/credential_service/mod.rs` defines `CredentialService<H: HybridHandler, N: NfcHandler, U: UsbHandler>`; the `ManageDevice` trait covers those three transports. Nothing there discovers D-Bus services.
3. **Upstream treats it as undesigned.** Issue [credentialsd#26](https://github.com/linux-credentials/credentialsd/issues/26), "Design third-party password management", is open and its body reads "This is a stub." The thread (2025-05 to 2025-11) discusses a D-Bus `Authenticator` interface, and registration by opt-in through a trusted settings app so a malicious program cannot self-register. No interface is specified. `GOALS.md` lists "a uniform interface for third-party credential providers" as a goal.
4. **`doc/api.md` mentions providers only in prose** (a "locked passkey provider" as a kind of device in `GetAvailablePublicKeyDevices`). It defines no provider-side methods.
5. **The portal path needs a patched xdg-desktop-portal.** `CHANGELOG.md` for 0.3.0 states a dependency on [linux-credentials/xdg-desktop-portal](https://github.com/linux-credentials/xdg-desktop-portal) (branch `credentials-portal`) "while we work on upstreaming the changes". xdg-desktop-portal is the trusted caller.
6. **No KDE backend.** `portal/credentialsd.portal` declares `Interfaces=org.freedesktop.impl.portal.experimental.Credential`, served by `credentialsd-ui`, a GTK application. A code search of the KDE organisation for that interface name returns nothing. Upstream `GOALS.md` lists full desktop-environment integration as a non-goal and leaves it to others. Whether the GTK backend runs under Plasma was not tested.
7. **Local state.** The workstation runs `org.freedesktop.impl.portal.desktop.kde` and stock `org.freedesktop.portal.Desktop` with no credentials interface (`busctl --user list`), as expected for an unpatched portal.

## Answer

**No, not at v0.3.1.**

- A third-party provider cannot register or serve requests: there is no provider API to implement, only an open design stub.
- The KDE portal path does not exist: it needs the patched xdg-desktop-portal and a Credential backend; only a GTK reference one exists.

What this changes (constraint C1, "integration layer on credentialsd"):

- The TPM provider and KeePassXC bridge are blocked on upstream work, which we would have to design and contribute (invariant 6, upstream first), starting with credentialsd#26. The architecture note already lists this as a risk; it is now confirmed rather than unverified.
- Candidate fallbacks for the maintainer to decide, each needing its own spike or ADR: (a) contribute the provider API upstream; (b) a virtual CTAP authenticator, as the [kpasskey](https://github.com/Tojori/kpasskey) prototype does, which sits below credentialsd; (c) add TPM and KeePassXC as in-process authenticator backends in a credentialsd contribution.
- Milestone 0 should not schedule provider implementation until one of these is chosen. The routing policy is not blocked by this spike, since it sits above the providers.

Not answered here: whether a stub registered through a future API would work end to end, and how the GTK backend behaves on Plasma. Both need the build that this spike could not do.
