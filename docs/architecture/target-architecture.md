---
type: architecture
subject: Former target architecture of Linux Hello, now split into the Arc42 sections
artifact: target-architecture
status: superseded
owner: "@atterdag"
concepts: [arc42]
tags: [architecture, redirect]
sources: ["README.md", "../adr/0010-arc42-architecture-documentation.md"]
date: 2026-11-05
---

# Linux Hello — Target Architecture (moved)

This note was split into the [Arc42 sections](README.md) ([ADR-0010](../adr/0010-arc42-architecture-documentation.md)). The content moved unchanged; only the embedded copy of the C4 workspace was dropped, because [workspace.dsl](workspace.dsl) is the only copy.

| Former heading | Now in |
| :-- | :-- |
| Recommendation, Situation, Complication | [1. Introduction and goals](01-introduction-and-goals.md) |
| Constraints | [2. Constraints](02-constraints.md) |
| Layers, Diagram, Design rules, Token reissue | [4. Solution strategy](04-solution-strategy.md) |
| Prior art, Alternatives, Consequences | [4. Solution strategy](04-solution-strategy.md) |
| Trust chain, Decision LH-1 | [8. Crosscutting concepts](08-crosscutting-concepts.md#trust-chain); LH-1 is [ADR-0003](../adr/0003-destructive-reset.md) |
| User journeys | [6. Runtime view](06-runtime-view.md) |
| Security hardening | [8. Crosscutting concepts](08-crosscutting-concepts.md#security-hardening) |
| User experience | [8. Crosscutting concepts](08-crosscutting-concepts.md#user-experience) |
| Policy | [8. Crosscutting concepts](08-crosscutting-concepts.md#policy) |
| C4 model: containers | [5. Building block view](05-building-block-view.md) |
| C4 model: workspace | [workspace.dsl](workspace.dsl) |
| Open questions | [11. Risks and technical debt](11-risks-and-technical-debt.md) |
