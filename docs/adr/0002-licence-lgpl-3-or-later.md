# ADR-0002: Licence LGPL-3.0-or-later

## Status

Accepted, 2026-11-01.

## Context

Linux Hello links to LGPL libraries (credentialsd, libwebauthn) and reaches GPL components (KeePassXC, fprintd) only across process boundaries. Relicensing becomes impractical once outside contributions land, so the licence is a one-way door.

## Decision

LGPL-3.0-or-later for all code in this repository, with contributions under the DCO.

## Consequences

Easier: other projects, including non-GPL ones, can link Linux Hello libraries; matches credentialsd; no compatibility questions with LGPL dependencies.

Harder: modified versions of Linux Hello libraries that are distributed must publish their changes; "or-later" lets the FSF's future LGPL versions apply, which is a trust decision.
