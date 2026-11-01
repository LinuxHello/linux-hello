---
type: spike
subject: Browser WebAuthn through the portal (Firefox, Chromium)
artifact: spike
status: answered
owner: "@atterdag"
concepts: [webauthn, firefox, chromium, credentialsd, xdg-desktop-portal, browser-extension]
tags: [spike, m0, upstream]
sources:
  - https://github.com/linux-credentials/credentialsd/tree/v0.3.1
  - https://github.com/mozilla-firefox/firefox/tree/e924f94175311819d7b549a732d0d8ee1263b31d/dom/webauthn
  - https://github.com/chromium/chromium/tree/1d3439ea5035e6e95a54218cfbf3dd7f14b6a50d/device/fido
date: 2026-11-01
issue: https://github.com/LinuxHello/linux-hello/issues/6
---

# Spike: browser WebAuthn through the portal (Firefox, Chromium)

## Question

Do Firefox and Chromium on Linux send WebAuthn requests to xdg-desktop-portal or credentialsd today, without an add-on? If not, what is the shortest upstream path?

## Time box

2 working days proposed. This note covers a source read only (under one day). The demo-site run against a stub provider was not possible; see Method.

## Method

Read upstream source at the commits below (default branch heads, 2026-11-01) and the credentialsd tag `v0.3.1` (commit `861e04c`):

| Project | Ref | Version |
| :-- | :-- | :-- |
| Firefox (`mozilla-firefox/firefox`) | `main` at `e924f94` | 161.0a1 (`browser/config/version.txt`) |
| Chromium (`chromium/chromium`) | `main` at `1d3439e` | not read |
| credentialsd | `v0.3.1` | 0.3.1 |

```sh
# Firefox: which platforms get a platform-authenticator service, and what the Rust bridge links
B=https://raw.githubusercontent.com/mozilla-firefox/firefox/main
curl -sS $B/dom/webauthn/moz.build
curl -sS $B/dom/webauthn/authrs_bridge/Cargo.toml
curl -sS $B/dom/webauthn/WebAuthnService.cpp | grep -n -i -E "portal|dbus|credentialsd|xdg"

# Chromium: where platform discoveries are created, and for which OS
C=https://raw.githubusercontent.com/chromium/chromium/main
curl -sS $C/device/fido/fido_discovery_factory.cc | grep -n -E "BUILDFLAG|MaybeCreatePlatformDiscovery"
curl -sS $C/device/fido/fido_discovery_factory.h  | grep -n -E "BUILDFLAG|MaybeCreatePlatformDiscovery"
curl -sS $C/device/fido/BUILD.gn | grep -n -i -E "portal|dbus"

# credentialsd: what it ships for browsers
git clone --depth 1 --branch v0.3.1 https://github.com/linux-credentials/credentialsd
grep -n -i -E "firefox|chromium|chrome|browser" credentialsd/README.md
```

All commands: **tested** (run from a cloud container with `git`, `curl`, `gh`; no browser installed).

**Not done, so untested:**

- Running Firefox or Chromium against webauthn.io-style sites with a credentialsd stub provider. Spike [0005](0005-credentialsd-provider-api.md) found no provider API to register a stub with, and no browser build with portal support was available here.
- The credentialsd web extension and the patched Firefox Flatpak: read, not run.
- Release notes, Bugzilla and the Chromium issue tracker: not reachable from the container (proxy denied `searchfox.org`, `chromium.googlesource.com`). Absence of an upstream bug or patch in flight is therefore **not established**.

## Evidence

1. **Firefox has no Linux platform-authenticator path.** In `dom/webauthn/moz.build` the platform-specific services are `AndroidWebAuthnService` (Android), `WinWebAuthnService` (Windows) and the macOS `AuthenticationServices` framework. Nothing is added for Linux or GTK. The shared `WebAuthnService.cpp` has platform branches only for macOS and Android, and no match for `portal`, `dbus`, `credentialsd` or `xdg`. Its comment states "authrs has no platform authenticator to offer".
2. **Firefox's Rust bridge talks only to authrs.** `dom/webauthn/authrs_bridge/Cargo.toml` depends on the in-tree `authenticator` crate (authenticator-rs) and no D-Bus crate. That crate drives USB HID, not a portal. I did not read the vendored crate's own dependency list; Firefox is therefore a **No** at the bridge level, not proven at the crate level.
3. **Chromium creates platform discoveries only for macOS and ChromeOS.** `device/fido/fido_discovery_factory.cc` calls `MaybeCreatePlatformDiscovery()` under `BUILDFLAG(IS_MAC) || BUILDFLAG(IS_CHROMEOS)`; Windows has its own plugin-authenticator path. There is no `IS_LINUX` branch. The `dbus` and `tpm_manager` matches in `device/fido/BUILD.gn` sit under `chromeos/` targets.
4. **credentialsd's browser support is an add-on plus one experimental build.** `README.md` at `v0.3.1` lists (a) a web extension that overrides `navigator.credentials.create()` and `get()` and calls the D-Bus service through a native-messaging helper, for Firefox 140+ and Chrome/Edge 111+ (Chromium loaded unpacked); (b) an experimental Firefox build with a patch that talks to credentialsd directly, shipped as a Flatpak on OBS. The README states the extension "only works for https://webauthn.io and https://demo.yubico.com". Both are described as testing aids.
5. **The extension supplies the origin itself.** `webext/app/credential_manager_shim.py` passes `origin` and `top_origin` from the page script to `CreateCredential`. In this path the trusted caller is a native-messaging helper, not the browser. This bears on the "Caller impersonation" threat in the [target architecture](../architecture/target-architecture.md): origin must not be trusted from an unprivileged client.

## Answer

**Partly.** No for stock browsers today; yes only through add-ons and an experimental Firefox build.

| Browser | Stock build calls portal or credentialsd | Works through credentialsd today |
| :-- | :-- | :-- |
| Firefox (161.0a1 source) | **No** | Add-on (140+, two demo sites only); experimental patched build (untested here) |
| Chromium (main) | **No** | Add-on (111+, unpacked, two demo sites only) |

Shortest upstream path, by reading the structure of each codebase (assumptions, not confirmed with maintainers):

- **Firefox:** add a Linux `nsIWebAuthnService` implementation that calls the credentials portal, beside `WinWebAuthnService` and `AndroidWebAuthnService`. The patched build in evidence 4 is the starting point; the work is to land it in `mozilla-firefox/firefox` (invariant 6: upstream first). It also needs the portal itself to ship unpatched, which is not the case at credentialsd v0.3.1 (see spike 0005, evidence 5).
- **Chromium:** add a Linux platform discovery in `device/fido`, in the style of the ChromeOS one. I found no existing patch and could not search the tracker; whether one is in flight is unknown.

What this changes:

- Design rule 4 ("one path for all clients") does not hold for browsers on any near-term horizon. The browser-extension path is not a transitional fallback; it is the only browser path until Firefox and Chromium land portal support.
- The KeePassXC browser-extension fallback **stays on the critical path for browser coverage in 1.0**. The credentialsd extension is a second candidate fallback, but it is limited to two sites today and sits on the origin-trust issue in evidence 5.
- The routing policy and PAM work are not affected.
- Combined with spike 0005, browser coverage depends on three upstream deliverables: a provider API in credentialsd, an unpatched portal, and browser clients. None exists in a release.

Not answered here: behaviour of the patched Firefox on Plasma, whether the extension works with arbitrary sites once its site allow-list is removed, and whether Chromium upstream has accepted or rejected a Linux platform authenticator.

## Lead review (2026-11-01)

Spot-checked at the pinned commits: Firefox `dom/webauthn/moz.build` (Android and Windows services only) and the "no platform authenticator to offer" comment in `WebAuthnService.cpp`; Chromium `fido_discovery_factory.cc` (platform discoveries under `IS_MAC` and `IS_CHROMEOS`, Windows separately); credentialsd `README.md` (extension limited to webauthn.io and demo.yubico.com, experimental Firefox Flatpak) and `webext/app/credential_manager_shim.py` (origin passed from the page side). **Tested** by reading source; nothing run.

- **Confirmed:** the answer (Partly) and the consequence for design rule 4.
- **Removed:** an inference about the identity of an upstream author. It added nothing to the answer and a public spike note should not speculate about individuals.
- **Follow-up:** which browser fallback ships in 1.0 (KeePassXC-Browser or the credentialsd extension) is a decision once the origin-trust issue in evidence 5 is understood; tracked as a new issue.
