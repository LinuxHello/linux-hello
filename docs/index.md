---
type: index
subject: Linux Hello documentation map
artifact: index
status: active
owner: "@atterdag"
concepts: []
tags: [index]
sources: []
date: 2026-11-01
---

# Linux Hello documentation

This folder is an Obsidian vault and renders on GitHub. Links are standard relative Markdown links, never `[[wikilinks]]`, so both work.

| Area | Start here |
| :-- | :-- |
| Architecture | [Arc42 sections](architecture/README.md), [Policy semantics](architecture/policy-semantics.md), [C4 workspace](architecture/workspace.dsl) |
| Decisions | [ADR index](adr/) |
| Spikes (Milestone 0) | [Spikes](spikes/) |
| Security | [Threat model and properties](security/) |
| Governance | [GOVERNANCE.md](../GOVERNANCE.md), [SECURITY.md](../SECURITY.md), [CONTRIBUTING.md](../CONTRIBUTING.md) |
| Backlog | [How the backlog is ordered and what is next](project/backlog.md) |
| Working with Claude | [Project instructions](project/claude-project-instructions.md) |

## Conventions

- Every note carries the frontmatter from [templates](templates/).
- Diagrams: Mermaid in notes, Structurizr DSL for C4 (`architecture/workspace.dsl`).
- Scripts and commands are marked **tested** or **untested**.
- `main` is protected: edit on a branch, commit with `git commit -s`, open a pull request.
