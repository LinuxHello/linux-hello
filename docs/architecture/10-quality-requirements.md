---
type: architecture
subject: "Arc42 section 10: quality requirements of Linux Hello"
artifact: arc42-10-quality-requirements
status: draft
owner: "@atterdag"
concepts: [quality, security-properties, arc42]
tags: [architecture, arc42, arc42-gap]
sources: ["README.md", "../security/README.md", "https://docs.arc42.org/section-10/"]
date: 2026-11-05
---

# 10. Quality requirements

Part of the [Arc42 architecture documentation](README.md).

## 10.1 Quality requirements overview

**Gap.** There is no quality tree yet; it depends on the quality goals that [section 1.2](01-introduction-and-goals.md#12-quality-goals) still lacks.

## 10.2 Quality scenarios

The security properties in [docs/security/](../security/README.md) are the testable scenarios that exist today: each is a plain-language statement with the test or CI job that checks it. The usability requirements UX1–UX8 are in [section 8, User experience](08-crosscutting-concepts.md#user-experience).

**Gap.** No scenarios yet for qualities other than security and usability (for example prompt latency or availability when an upstream daemon is missing).
