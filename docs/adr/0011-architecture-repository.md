---
type: adr
subject: Move the system, container and component architecture and the ADRs to their own repository
artifact: adr
status: proposed
owner: "@atterdag"
concepts: [arc42, c4, documentation, governance, ci, repository-topology]
tags: [adr, architecture, docs, ci]
sources: ["0001-monorepo-with-split-guardrails.md", "0006-attested-quality-gates-and-releases.md", "0008-code-documentation-mapped-to-c4.md", "0010-arc42-architecture-documentation.md", "../../AGENTS.md", "../../GOVERNANCE.md", "../../scripts/ci/c4-docs.sh", "https://docs.github.com/en/code-security/dependabot/ecosystems-supported-by-dependabot/supported-ecosystems-and-repositories"]
date: 2026-11-05
---

# ADR-0011: An architecture repository

## Status

Proposed, 2026-11-05.

## Context

`linux-hello` holds the code and all architecture documentation: the Arc42 sections ([ADR-0010](0010-arc42-architecture-documentation.md)), the C4 model in `docs/architecture/workspace.dsl`, the ADRs and the spikes. CI runs every gate on every pull request ([ADR-0006](0006-attested-quality-gates-and-releases.md)), so a change to an architecture note or an ADR waits for the Rust gates (about two minutes) and gets a quality-gate attestation for code it did not touch.

The maintainer wants architecture at the system context, container and component levels (C4 levels 1 to 3) and the decisions behind it to change without the code repository's gates. Only the code level (C4 level 4) stays with the code, as ADR-0008's doc comments already do.

Three couplings constrain a split:

1. **The C4 model is an input to a gate.** `scripts/ci/c4-docs.sh` checks that every crate and component module names an element of `workspace.dsl` ([ADR-0008](0008-code-documentation-mapped-to-c4.md)). Renaming a container or component is a code change, whichever repository the model lives in.
2. **Some notes are specifications of code.** Each property in `docs/security/` is the name of a test, and the policy doc comments use the words of `policy-semantics.md`.
3. **An ADR URL is a signed identifier.** The quality-gate predicate type is `https://github.com/LinuxHello/linux-hello/blob/main/docs/adr/0006-attested-quality-gates-and-releases.md#quality-gate-v1`. It is written into every attestation and matched exactly by `verify-quality-gate.sh` and the release workflow. Moving the file must not change it.

[ADR-0001](0001-monorepo-with-split-guardrails.md) keeps the containers in one repository and is not changed here: this ADR moves documentation, not code. Splitting the code repository was considered and rejected below.

## Decision

### A new repository: `LinuxHello/architecture`

Public, with the same licence as the content it receives (LGPL-3.0-or-later, [ADR-0002](0002-licence-lgpl-3-or-later.md)); moving the files does not relicense them. It is the Obsidian vault for the architecture, with the frontmatter, link and Mermaid rules of AGENTS.md.

| Moves to `architecture` | Stays in `linux-hello` |
| :-- | :-- |
| Arc42 sections 1 to 12 and their index (`docs/architecture/`) | `docs/security/`: properties named after tests |
| `workspace.dsl`, the C4 model (levels 1 to 3) | `policy-semantics.md`: the specification the policy code quotes |
| All ADRs and their index (`docs/adr/`); numbering continues there | `docs/project/`: backlog and process notes for this repository |
| All spikes (`docs/spikes/`) | The code level: doc comments (ADR-0008) |
| The ADR, spike and note templates | A note template for the notes that stay |

Arc42 section 8 (crosscutting concepts) and section 10 (quality requirements) link to `policy-semantics.md` and `docs/security/` in `linux-hello` by URL.

### `linux-hello` pins the C4 model

`linux-hello` includes `architecture` as a Git submodule at `architecture/`, pinned to a commit. `c4-docs.sh` reads `architecture/workspace.dsl`, and CI checks out submodules. Dependabot (`gitsubmodule` ecosystem) opens a pull request when `architecture`'s `main` moves; that pull request runs the gates once for whatever changed.

So a change to an architecture note or an ADR runs no Rust gate when it is made. The gates run at most once per Dependabot interval, on the pin bump, and they matter there only if a container or component changed, which is a code change (coupling 1).

### Links that must keep working

- **ADR-0006's path stays.** `docs/adr/0006-attested-quality-gates-and-releases.md` remains in `linux-hello` as a short stub with the `quality-gate-v1` heading and a link to the ADR's new home, so the predicate type keeps resolving and its string stays the same.
- `docs/adr/README.md` in `linux-hello` becomes a stub that points to the ADR index in `architecture`.
- The `workspace.dsl` links in crate-root doc comments point to `architecture`.

### `architecture`'s own checks

No Rust gates. Required checks: DCO, frontmatter on every note, relative links resolve, `workspace.dsl` parses. One advisory check runs `linux-hello`'s `c4-docs.sh` from `main` against the proposed `workspace.dsl`, so a pull request that would break the code's C4 references says so before it merges; it does not block, because the code may follow in its own pull request. Merging uses the rules of `linux-hello`: pull request, squash, signed commits on `main`, DCO, the roles of [ADR-0004](0004-agent-roles.md).

### How the rules in AGENTS.md change

- **Source of truth.** Items 2 and 3 become the accepted ADRs and the Arc42 notes and `workspace.dsl` in `LinuxHello/architecture`, at the commit `linux-hello` pins.
- **Docs change with code** becomes: a behaviour change that alters a container, component, interface or decision has an `architecture` pull request; the `linux-hello` pull request links it. The architecture pull request merges first, and the code pull request bumps the pin. A change inside a component updates only doc comments, in the same pull request as the code.
- **Briefs** already quote constraints rather than reference them, so an implementer still needs only the brief.
- **Issues** stay in `linux-hello` for now, so `make next` and `make backlog-check` keep one backlog. An issue whose work lands in `architecture` carries `type:docs` or `type:spike`, and its pull request goes to the repository that holds the files.

### Implementation, as separate issues

1. Create `LinuxHello/architecture` with branch rules, DCO and the Claude GitHub App installed (maintainer: organisation and repository settings).
2. Move the files with their history (`git filter-repo` on a copy, then push), add the checks above.
3. In `linux-hello`: add the submodule, repoint `c4-docs.sh`, `test-c4-docs.sh` and the crate-root links, add the stubs, enable Dependabot for the submodule, check out submodules in CI.
4. Update AGENTS.md, CONTRIBUTING.md, GOVERNANCE.md, README.md, SECURITY.md, the pull request template and the Copilot instructions.
5. Point the organisation profile and the branding repository to `architecture`.

### Rejected

- **Splitting `linux-hello` into one repository per container, to make CI faster.** The slowest gate is `fuzz` (about 1.5 minutes, 60 s of it fixed), and it belongs to the agent crate, so a change to the agent would wait just as long in its own repository. Each repository adds its own runner start-up, toolchain install and attestation, and a change across containers becomes several coordinated pull requests. ADR-0001's split trigger (own maintainer, release cadence or distribution packaging) is not met. Path-filtered CI (GOVERNANCE.md, topology rule 3) shortens the code repository's runs without a split.
- **Skipping the gates for documentation-only pull requests in one repository.** It reaches the CI goal with less work, but it changes what a quality-gate attestation claims (ADR-0006) and does not give the architecture a repository of its own for the other repositories of the organisation to refer to.
- **A copy of `workspace.dsl` synchronised by a workflow.** A pull request opened with `GITHUB_TOKEN` does not trigger CI, so the required checks would never report; a credential to avoid that is one more secret to hold. Dependabot's pull requests run CI.
- **Moving `docs/security/` and `policy-semantics.md`.** They specify tests and code, and must change in the same pull request.

## Consequences

**Easier:**

- Architecture notes and ADRs change in minutes, with no Rust gate and no attestation for code that did not change.
- The architecture has one home that the other repositories of the organisation (branding, workstation, the `.github` profile) can link to.
- The code repository's history and CI carry code changes only.

**Harder:**

- A change that alters a component and its code takes two pull requests in two repositories, merged in order. The lead's review checks that they agree.
- Contributors clone with `--recurse-submodules`, and a pin that lags `architecture`'s `main` means the code is checked against an older model until Dependabot's pull request merges.
- Links in existing issues, pull requests and commits to `docs/adr/`, `docs/architecture/` and `docs/spikes/` in `linux-hello` stop resolving, except ADR-0006 and the ADR index, which keep stubs.
- One more repository to protect, with its own checks to maintain.
- Dependabot support for Git submodules at the needed interval, and Dependabot pull requests satisfying `linux-hello`'s required checks including `dco`, have not been checked (assumption). Dependabot commits carry no sign-off, so the maintainer certifies them as for other bot commits.
