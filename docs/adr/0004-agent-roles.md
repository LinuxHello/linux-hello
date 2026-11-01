---
type: adr
subject: Roles of the coding agents and the delivery workflow
artifact: adr
status: accepted
owner: "@atterdag"
concepts: [ai-assisted-development, governance, code-review]
tags: [adr, process]
sources: ["../../AGENTS.md", "../../CONTRIBUTING.md", "../../GOVERNANCE.md"]
date: 2026-11-01
---

# ADR-0004: Roles of the coding agents

## Status

Accepted, 2026-11-01. Amended 2026-11-01: Copilot may commit accepted suggestions.

## Context

Code is written with AI assistance and reviewed by behaviour ([GOVERNANCE.md](../../GOVERNANCE.md)). Three agents are available: a local model on the maintainer's own hardware, Claude (cloud) and GitHub Copilot. They differ in cost, privacy and capability: the local model is free to run and private but has a smaller context window and is weaker at multi-step work; Claude is stronger at design, review and security-sensitive code; Copilot is built into GitHub and the editor. Without fixed roles, work drifts to whichever tool is open, and nobody owns the backlog or the review.

## Decision

| Role | Agent | Owns |
| :-- | :-- | :-- |
| **Implementer** | Local model, through Claude Code | Writes the code and tests for one issue at a time, from a brief; opens the pull request |
| **Lead** | Claude | Turns issues into briefs, keeps the backlog and labels current, reviews every pull request, fixes what the implementer got wrong, keeps `docs/` in step with the code, runs the Milestone 0 spikes |
| **Assistant** | GitHub Copilot | Pull request summaries, commit messages for hand-made commits, a second automated review with suggested changes on every pull request; commits only when the maintainer accepts a suggestion or asks it to fix something |
| **Maintainer** | @atterdag | Decides; merges; owns the architecture, threat model and security properties |

The workflow, the brief format and the status labels are in [AGENTS.md](../../AGENTS.md#roles-and-workflow). Every change still passes the same required checks and is merged by the maintainer.

Spikes stay with the lead: they need upstream research the local model cannot do offline.

## Consequences

**Easier:** most implementation runs locally at no cost and without sending code anywhere; briefs make each task small and checkable; review has one owner; the backlog and docs stay current because one agent is responsible for them.

**Harder:** Copilot commits made by its coding agent carry no DCO sign-off, so the maintainer certifies them before merge (AGENTS.md, Copilot suggestions and the DCO); the lead must write briefs small enough for the implementer's context window, which adds a step before every issue; review load on the lead grows with the implementer's error rate; security-sensitive code written by a weaker model needs closer review; three agents mean three sets of instructions to keep in line with `AGENTS.md`.
