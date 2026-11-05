---
type: index
subject: Linux Hello architecture documentation, structured by the Arc42 template
artifact: architecture-index
status: active
owner: "@atterdag"
concepts: [arc42, c4, architecture]
tags: [architecture, arc42, index]
sources: ["workspace.dsl", "../adr/0010-arc42-architecture-documentation.md", "../adr/0008-code-documentation-mapped-to-c4.md", "https://arc42.org/overview"]
date: 2026-11-05
---

# Linux Hello architecture (Arc42)

The architecture documentation follows the twelve sections of the [Arc42 template](https://arc42.org/overview) ([ADR-0010](../adr/0010-arc42-architecture-documentation.md)). C4 diagrams live only in [workspace.dsl](workspace.dsl) ([ADR-0008](../adr/0008-code-documentation-mapped-to-c4.md)); sections 3, 5 and 7 name its views and do not redraw them. Decisions stay in [docs/adr/](../adr/README.md).

A section marked **gap** has no content yet; nothing has been invented to fill it.

| Arc42 section | Note | State |
| :-- | :-- | :-- |
| 1. Introduction and goals | [01-introduction-and-goals.md](01-introduction-and-goals.md) | Requirements overview; quality goals and stakeholders are gaps |
| 2. Constraints | [02-constraints.md](02-constraints.md) | Written |
| 3. Context and scope | [03-context-and-scope.md](03-context-and-scope.md) | Business context: C4 `Context` view; technical context is a gap |
| 4. Solution strategy | [04-solution-strategy.md](04-solution-strategy.md) | Written |
| 5. Building block view | [05-building-block-view.md](05-building-block-view.md) | Written; C4 `Containers` and component views |
| 6. Runtime view | [06-runtime-view.md](06-runtime-view.md) | User journeys; scenarios at container level are a gap |
| 7. Deployment view | [07-deployment-view.md](07-deployment-view.md) | Gap |
| 8. Crosscutting concepts | [08-crosscutting-concepts.md](08-crosscutting-concepts.md), [policy-semantics.md](policy-semantics.md), [docs/security/](../security/README.md) | Written |
| 9. Architecture decisions | [09-architecture-decisions.md](09-architecture-decisions.md) → [docs/adr/](../adr/README.md) | Written |
| 10. Quality requirements | [10-quality-requirements.md](10-quality-requirements.md) | Scenarios: the security properties; quality tree is a gap |
| 11. Risks and technical debt | [11-risks-and-technical-debt.md](11-risks-and-technical-debt.md) | Open questions; risk register is a gap |
| 12. Glossary | [12-glossary.md](12-glossary.md) | Gap |

New section content goes into the matching note; a new crosscutting concept large enough for its own note sits beside them, like [policy-semantics.md](policy-semantics.md), and section 8 links it.
