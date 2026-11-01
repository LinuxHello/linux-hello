---
type: spike
subject: Licences of libwebauthn, KeePassXC, fprintd and Howdy
artifact: spike
status: answered
owner: "@atterdag"
concepts: [licensing, libwebauthn, keepassxc, fprintd, howdy, credentialsd]
tags: [spike, m0, one-way-door]
sources:
  - https://github.com/linux-credentials/libwebauthn/tree/libwebauthn-v0.9.0
  - https://github.com/keepassxreboot/keepassxc/tree/2.8.0
  - https://gitlab.freedesktop.org/libfprint/fprintd
  - https://github.com/boltgolt/howdy/tree/v2.6.1
  - https://github.com/davisking/dlib-models
date: 2026-11-01
issue: https://github.com/LinuxHello/linux-hello/issues/13
---

# Spike: licences of libwebauthn, KeePassXC, fprintd and Howdy

## Question

What are the exact licences of libwebauthn, KeePassXC, fprintd and Howdy, and does each fit constraints C2 and C3: link only to LGPL or permissive code, reach GPL code across a process boundary only?

## Time box

2 working days proposed. Done in under one day: licence files and package metadata only.

## Method

Read the licence files and package metadata at the versions below (2026-11-01):

```sh
git clone --depth 1 --branch libwebauthn-v0.9.0 https://github.com/linux-credentials/libwebauthn
grep -n '^license' libwebauthn/libwebauthn/Cargo.toml; head -3 libwebauthn/COPYING
git clone --depth 1 --branch 2.8.0 https://github.com/keepassxreboot/keepassxc
sed -n 1,12p keepassxc/COPYING
git clone --depth 1 https://gitlab.freedesktop.org/libfprint/fprintd.git
head -3 fprintd/COPYING; grep -n license fprintd/meson.build
git clone --depth 1 https://github.com/boltgolt/howdy
head -3 howdy/LICENSE; grep -n license howdy/meson.build; cat howdy/howdy/src/dlib-data/install.sh
curl -sS https://raw.githubusercontent.com/davisking/dlib-models/master/README.md
```

All commands: **tested** (cloud container, `git` and `curl`). Nothing was built or linked.

## Evidence

| Component | Version read | Licence | Source of the statement | How Linux Hello uses it |
| :-- | :-- | :-- | :-- | :-- |
| credentialsd | v0.3.1 | LGPL-3.0-only | `credentialsd/Cargo.toml` (spike 0005) | Library and D-Bus service |
| libwebauthn | v0.9.0 (also `main` at `d71fb7c`) | **LGPL-2.1-or-later** | `libwebauthn/Cargo.toml`, `COPYING`, README | Library (linked) |
| KeePassXC | 2.8.0 | **GPL-2.0 or GPL-3.0**, not "or later" | `COPYING` header; bundled third-party files carry their own licences | Separate process, browser protocol |
| fprintd | `main` at `5731b9a` (latest tag v1.94.5) | **GPL-2.0-or-later** | `COPYING` (GPL v2), `meson.build` (`GPLv2+`) | Separate process, D-Bus and PAM |
| Howdy | v2.6.1 (`master` at `d3ab993` says version "beta") | **MIT** | `LICENSE`, `meson.build` | Separate process, PAM |
| Howdy's face models | dlib-models `master` | Public domain, by the author's statement | dlib-models README | Data files Howdy downloads at install |

Notes:

1. **libwebauthn is LGPL-2.1-or-later**, not unverified as the architecture note said. Linking it from LGPL-3.0-or-later code is compatible.
2. **KeePassXC is "GPL-2 or GPL-3" at the licensee's option**, without "or later". It stays across a process boundary (C3), so this changes nothing today; it matters only if code were ever copied from it.
3. **fprintd is GPL-2.0-or-later**; libfprint (its library) was not read, and Linux Hello does not link it.
4. **Howdy downloads three dlib models**: `dlib_face_recognition_resnet_model_v1`, `mmod_human_face_detector` and `shape_predictor_5_face_landmarks`. The dlib-models README states the author released them into the public domain. They were trained on third-party image sets (VGG, FaceScrub, ImageNet and others), whose own terms were not read. Howdy does not use the 68-point model, which was trained on the iBUG 300-W set.
5. **Howdy's release state:** the last release tag is v2.6.1; `master` merged the beta branch on 2025-06-22 and declares version "beta". Whether a 3.0 release is planned was not checked.

## Answer

**Yes, as designed.** Every component fits C2 and C3:

- Linked: credentialsd (LGPL-3.0-only) and libwebauthn (LGPL-2.1-or-later). Both are compatible with Linux Hello's LGPL-3.0-or-later; the combined work is distributed under LGPL-3.0 terms.
- Across a process boundary: KeePassXC (GPL-2.0 or GPL-3.0), fprintd (GPL-2.0-or-later). Linking either would break C3.
- Howdy is MIT and reached through PAM; linking would be allowed but is not planned.

What this changes:

- `deny.toml` and the dependency-review workflow allow only `LGPL-3.0-or-later` among the LGPL family. Both now also allow `LGPL-3.0-only` (credentialsd) and `LGPL-2.1-or-later` (libwebauthn), so adding either crate does not fail CI. No GPL licence is added.
- The architecture note's licence line is replaced by a link to this note.

Not answered: libfprint's licence; the terms of the image sets behind Howdy's models; transitive dependency licences, which `cargo-deny` checks per crate once dependencies exist. Not legal advice.
