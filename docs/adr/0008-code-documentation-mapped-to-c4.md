---
type: adr
subject: Every Rust item is documented, and the code names the C4 element it implements
artifact: adr
status: proposed
owner: "@atterdag"
concepts: [governance, documentation, c4-model, ai-assisted-development]
tags: [adr, documentation, ci]
sources: ["../../AGENTS.md", "../../GOVERNANCE.md", "../architecture/workspace.dsl", "0006-attested-quality-gates-and-releases.md"]
date: 2026-11-04
---

# ADR-0008: Code documentation mapped to the C4 model

## Status

Proposed, 2026-11-04.

## Context

The maintainer reviews behaviour, not Rust ([GOVERNANCE.md](../../GOVERNANCE.md)). Doc comments are the part of the code he and reviewers can read without reading the implementation, and most code here is written by agents, which skip documentation unless a gate demands it. On `main` (3e4bf10) the Agent crate had 38 undocumented items, including every field of the policy file it parses.

The architecture is already modelled in C4: system context, containers and components in [workspace.dsl](../architecture/workspace.dsl), one crate per container ([ADR-0001](0001-monorepo-with-split-guardrails.md)). Nothing ties the code back to that model, so the two can drift without anyone noticing.

Rust has no classes. The items that play that role are structs, enums, traits, unions and type aliases; their fields, variants, functions and methods carry the behaviour.

Options considered for the link between code and C4:

| Option | For | Against |
| :-- | :-- | :-- |
| **A. Doc lints, plus a C4 tag in crate and module docs checked against `workspace.dsl`** (chosen) | One source of truth for diagrams stays `workspace.dsl`; the check is a short bash script, like the other CI checks; drift fails CI | rustdoc shows a name, not a picture; the picture is one link away |
| B. Mermaid C4 diagrams in rustdoc (`aquamarine` or `--html-in-header`) | Diagram next to the API | A second copy of every component diagram that drifts from `workspace.dsl`; a proc-macro dependency, or JavaScript injected into the docs; Mermaid's C4 support is marked experimental |
| C. mdBook for Level 1–2 | Rendered site | Duplicates the Obsidian vault in `docs/`, which is already the system of record |
| D. Lints only, no C4 link | Least work | Leaves the drift between code and model undetected |

## Decision

1. **Every item is documented.** The workspace denies `missing_docs` (rustc: public items and crate roots) and `clippy::missing_docs_in_private_items` (every private item: structs, enums, traits, fields, variants, functions, methods, constants, modules). Test code is exempt; a test's name states its property. Fuzz crates are separate workspaces and are not covered yet.
2. **Every `unsafe` block states why it is sound.** The workspace denies `clippy::undocumented_unsafe_blocks` (a `// SAFETY:` comment); `clippy::missing_safety_doc`, already on through `clippy::all`, requires a `# Safety` section on every `unsafe fn`.
3. **The documentation builds clean.** A `docs` CI job runs `cargo doc --workspace --no-deps --document-private-items` with `RUSTDOCFLAGS="-D warnings"`, so a broken intra-doc link fails.
4. **The code names its C4 element**, levels mapped as follows:

   | C4 level | Rust | Where it is documented |
   | :-- | :-- | :-- |
   | 1 System context | — | `workspace.dsl`, [target architecture](../architecture/target-architecture.md) |
   | 2 Container | crate | crate root `//!`: ``//! C4 container: `<id>` `` |
   | 3 Component | top-level module (declared in the crate root) | module `//!`: ``//! C4 component: `<id>` `` |
   | 4 Code | nested modules, types, functions | `///` on every item; no diagram |

   `<id>` is the element's identifier in `workspace.dsl`. A module's component must belong to the crate's container. A crate that implements a component rather than a container (today only `linuxhello-dbus`, the contract of `dbusApi`) says ``C4 component: `<id>` `` in its root, and its modules need no tag. Component modules live in their own files; inline modules are allowed only under `#[cfg(test)]`.
5. **`scripts/ci/c4-docs.sh` checks rule 4** against `workspace.dsl`, and `scripts/ci/test-c4-docs.sh` tests the checker. Both run in the `docs` job, which joins `scripts/ci/quality-gates.txt`, so the `quality-gate` attestation ([ADR-0006](0006-attested-quality-gates-and-releases.md)) now also claims documentation.
6. **Diagrams stay in `workspace.dsl`.** Rustdoc links to it and does not copy diagrams.

## Consequences

**Easier:**

- Reviewing without reading Rust: every type, field and function has a sentence saying what it is for, and `cargo doc --document-private-items` renders them.
- Finding the code for a box in a C4 view, and the box for a module: ``grep 'C4 component: `policyEngine`'``.
- Spotting drift: renaming or removing a container or component in `workspace.dsl` fails CI until the code follows, and a new top-level module fails until it is placed in the model.
- Writing briefs: the implementer's acceptance commands already include the doc gates through `make gates`.

**Harder:**

- Every new item costs a doc comment, private helpers included. For agents this is cheap; for human contributors it is a rule to learn, and `make fix` cannot write the comment for them.
- A new top-level module needs a component in `workspace.dsl` first, so a structural change in code is also a change to the model. That is intended, and it means the lead touches `workspace.dsl` more often.
- Doc comments can be wrong while the gate stays green: the lints check that a comment exists, not that it is true. Review still has to read them.
- `linuxhello-dbus` has no element of its own in `workspace.dsl`; it maps to `dbusApi` of the Agent. If the shared crate grows beyond the Agent's contract, the model needs a decision on how to show a library linked into several containers.
- One more required gate job on every pull request.
