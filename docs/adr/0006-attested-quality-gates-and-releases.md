---
type: adr
subject: Stub for ADR-0006, which moved to LinuxHello/architecture
artifact: adr-stub
status: active
owner: "@atterdag"
concepts: [supply-chain, governance]
tags: [adr, stub]
sources: ["https://github.com/LinuxHello/architecture/blob/main/adr/0006-attested-quality-gates-and-releases.md", "https://github.com/LinuxHello/architecture/blob/main/adr/0011-architecture-repository.md"]
date: 2026-11-05
---

# ADR-0006: Attested quality gates and releases (moved)

ADR-0006 is now in the architecture repository: [ADR-0006](https://github.com/LinuxHello/architecture/blob/main/adr/0006-attested-quality-gates-and-releases.md). This stub stays here because its URL is an identifier, not only a link ([ADR-0011](https://github.com/LinuxHello/architecture/blob/main/adr/0011-architecture-repository.md)).

### quality-gate-v1

`https://github.com/LinuxHello/linux-hello/blob/main/docs/adr/0006-attested-quality-gates-and-releases.md#quality-gate-v1` is the predicate type of every quality-gate attestation. `.github/workflows/ci.yml` signs with it, and `scripts/ci/verify-quality-gate.sh` and the release workflow match it exactly. Its definition: [ADR-0006, *quality-gate-v1*](https://github.com/LinuxHello/architecture/blob/main/adr/0006-attested-quality-gates-and-releases.md#quality-gate-v1).

Do not move or rename this file, or remove this heading.
