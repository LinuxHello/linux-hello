---
type: adr
subject: Structure the architecture documentation by the Arc42 template
artifact: adr
status: proposed
owner: "@atterdag"
concepts: [arc42, c4, documentation, governance]
tags: [adr, architecture, docs]
sources: ["../architecture/README.md", "0008-code-documentation-mapped-to-c4.md", "../../AGENTS.md", "https://arc42.org/overview", "https://docs.arc42.org/home/"]
date: 2026-11-05
---

# ADR-0010: Structure the architecture documentation by the Arc42 template

## Status

Proposed, 2026-11-05. [ADR-0011](0011-architecture-repository.md) (proposed) would move the Arc42 sections, `workspace.dsl`, the ADRs and the spikes to `LinuxHello/architecture`; the structure decided here stays.

## Context

The architecture lived in one note, `docs/architecture/target-architecture.md` (about 600 lines), written as a recommendation: situation, layers, constraints, trust chain, user journeys, security hardening, user experience, policy, a copy of the C4 workspace, prior art, alternatives and open questions in one file. Three problems followed:

- A reader, or an agent with a small context window, has to load the whole note to find one concern, and briefs link into it by heading anchors that change when the note is edited.
- It is not visible what is missing. The note has no quality goals, stakeholders, deployment view, risk register or glossary, and nothing says so.
- It held a second copy of `workspace.dsl`, identical today but free to drift, against the rule that diagrams stay in `workspace.dsl` ([ADR-0008](0008-code-documentation-mapped-to-c4.md)).

[Arc42](https://arc42.org/overview) is a widely used template for architecture documentation, free to use (CC BY-SA 4.0). Its twelve sections (introduction and goals, constraints, context and scope, solution strategy, building block view, runtime view, deployment view, crosscutting concepts, architecture decisions, quality requirements, risks and technical debt, glossary) fit C4: sections 3, 5 and 7 are where C4 views are referenced.

| Option | For | Against |
| :-- | :-- | :-- |
| **A. One note per Arc42 section in `docs/architecture/`, an index note, C4 stays in `workspace.dsl`** (chosen) | Each concern loads alone; gaps are explicit; `workspace.dsl` keeps its path, so the C4 check and the links in the code are unchanged | Twelve notes instead of one; content that spans sections needs cross-links |
| B. One Arc42 file | One file to load | Keeps the size problem; anchors still move |
| C. Keep the target architecture as it is | No work | Gaps stay invisible; the DSL copy stays |

## Decision

1. `docs/architecture/` holds one note per Arc42 section, named `NN-<section>.md` (`01-introduction-and-goals.md` to `12-glossary.md`), and an index, [README.md](../architecture/README.md), that lists the sections and their state.
2. Existing content was moved into the sections, not rewritten. A section, or a sub-section, with no content says **Gap** and what it would need; nothing is invented to fill it.
3. C4 stays in [workspace.dsl](../architecture/workspace.dsl) at its current path. Sections 3, 5 and 7 name its views and do not redraw them. Other diagrams are Mermaid.
4. ADRs stay in [docs/adr/](README.md). Section 9 links the ADR index and does not copy it.
5. A crosscutting concept with a note of its own stays beside the sections and section 8 links it: today [policy-semantics.md](../architecture/policy-semantics.md). The security properties stay in [docs/security/](../security/README.md); section 10 links them as quality scenarios.
6. `target-architecture.md` is kept as a short note that maps its former headings to the new sections, so links in issues and briefs still lead somewhere. Source of truth item 3 in [AGENTS.md](../../AGENTS.md#source-of-truth) becomes the Arc42 notes and `workspace.dsl`.

## Consequences

**Easier:**

- A brief can link the one section it relies on.
- The gaps (quality goals, stakeholders, technical context, deployment view, runtime scenarios, quality tree, risk register, glossary) are listed in one place and can become issues.
- Contributors who know Arc42 find their way without reading this repository's conventions first.

**Harder:**

- A change to one concern can touch several notes (for example a new container: section 5, its concept in section 8, and `workspace.dsl`).
- Anchors into the old note break; the mapping note in `target-architecture.md` has to be kept until links to it are gone.
- The Arc42 section names become a convention to keep: renaming or renumbering a section note is a change to this ADR.
