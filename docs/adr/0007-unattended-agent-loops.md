---
type: adr
subject: Unattended agent loops for the lead and the implementer
artifact: adr
status: proposed
owner: "@atterdag"
concepts: [ai-assisted-development, governance, supply-chain]
tags: [adr, process, agents]
sources: ["0004-agent-roles.md", "0006-attested-quality-gates-and-releases.md", "../../AGENTS.md", "../../GOVERNANCE.md"]
date: 2026-11-03
---

# ADR-0007: Unattended agent loops

## Status

Proposed, 2026-11-03.

## Context

[ADR-0004](0004-agent-roles.md) fixes the roles: the lead (Claude, cloud) writes briefs and reviews; the implementer (a local model on the maintainer's workstation) implements one issue from its brief; the maintainer decides and merges. Today every step starts when the maintainer starts it. He cannot attend the workstation all the time, so the backlog stops whenever he does.

What exists:

- **Lead.** Since the [ADR-0004 amendment of 2026-11-03](0004-agent-roles.md#amendment-2026-11-03-the-lead-works-in-github-directly) the lead works in GitHub directly through the Claude GitHub App, and Claude Code can run as a scheduled cloud task with this repository attached.
- **Implementer.** Workstation tooling, kept in a private repository of the organisation because it names local models and paths (invariant 8), implements one issue on demand. The model only edits the files the brief lists. A shell script does everything else deterministically: it reads the brief, runs the gates with a bounded number of repair rounds, checks that every test the brief names exists, refuses changes outside the brief's files, pushes the branch, opens a draft pull request and moves the status labels. It has been dry-run with a stand-in model, not with a live one.

What is missing for unattended work:

1. **No loop.** Nothing picks the next `status:ready` issue on a schedule.
2. **Sign-off.** The tooling commits with `-s` and a commit signature under the maintainer's name. A sign-off certifies the DCO for code that nobody has reviewed yet, and a signing key that needs a touch or a PIN stalls an unattended run.
3. **Harness not chosen by evidence.** The implementer runs through Aider because Claude Code would not accept a context window below its default. Setting Claude Code's maximum context explicitly has since made it accept a 64k window on a read-only task; long runs that need compaction are untested. Neither harness has completed a real brief.
4. **Shared GPU.** The workstation's GPU serves other workloads, so a run can find it busy.

## Decision

GitHub issues and their `status:` labels are the only shared state between the loops. Neither loop holds state that the other needs.

### Lead loop (cloud)

A scheduled Claude Code task with this repository attached runs a few times a day, within the ADR-0004 amendment's limits (no merging, no pushes to `main`, no settings). Each run:

1. turns `status:needs-brief` issues into briefs ([AGENTS.md, The brief](../../AGENTS.md#the-brief)) and moves them to `status:ready`;
2. reviews `status:in-review` pull requests against their briefs, pushes small fixes, and returns larger ones with a review comment;
3. comments on `status:blocked` issues with a diagnosis, and rewrites or splits the brief when the brief was the cause;
4. keeps `docs/` current;
5. posts a short digest to one pinned status issue: what moved, what is blocked, what waits for the maintainer.

### Implementer loop (workstation)

A systemd user timer on the maintainer's workstation runs a loop script around the existing implementer tooling. The loop and its configuration live in the private workstation repository. Machine-specific values (model names, context sizes, paths, endpoints) live in an untracked environment file there, and only its example is committed. This repository records only the contract below.

1. **Isolation.** It runs as a dedicated, unprivileged Linux user with its own clone, not as the maintainer's user. That user holds a GitHub credential scoped to this repository (contents, pull requests and issues; no administration), created and stored by the maintainer. The lead never sees it (invariant 9). The model's process gets no GitHub credential and reaches the model server on loopback only.
2. **One run at a time.** A lock prevents overlapping runs, and the run holds a sleep inhibitor so that the machine does not suspend mid-run.
3. **Preconditions.** It checks that the GPU is not serving another workload before it claims an issue. If it is busy, the run exits without claiming anything and the next timer tick tries again.
4. **Claim.** It claims the oldest `status:ready` issue that has a brief, by moving it to `status:in-progress`.
5. **Implement.** It starts from a fresh branch off `main` in a clean tree. The harness gets the brief, the brief's files, a turn or round limit and a wall-clock timeout.
6. **Gates from the script, not the model.** The script runs `make gates`, the test-name check and the scope check. The model's own claim that it passed counts for nothing.
7. **Publish.** On success it pushes the branch, opens a draft pull request that follows the template, and moves the issue to `status:in-review`.
8. **Fail.** On failure it moves the issue back to `status:ready` and keeps the branch for inspection. After a set number of failed attempts on the same issue, it moves the issue to `status:blocked` and comments with the tail of the log. A comment carries no secrets, paths or model names (invariant 8).

### Sign-off and signatures

Unattended commits carry **no `Signed-off-by:`** and need no commit signature, because nobody has reviewed them when they are made. The maintainer certifies them at merge, as for the lead's and Copilot's commits ([AGENTS.md, Copilot suggestions and the DCO](../../AGENTS.md#copilot-suggestions-and-the-dco)). The commit on `main` is GitHub's signed squash commit, so the ruleset's signature requirement on `main` still holds. Runs started by hand while the maintainer watches may still sign off.

### Harness by evidence

The harness is chosen by measurement, not by assumption. The lead writes three trial briefs within the current limit (about 300 changed lines, at most five files). Each runs through both candidate harnesses, Aider and Claude Code, on the same local model with the same context window. The harness that passes `make gates` and the test-name check more often becomes the default, and this ADR records the result before acceptance. The brief limit in AGENTS.md stays until the trials show what the model completes within its context.

### What stays with the maintainer

Merging, DCO certification, accepting ADRs, releases, repository and organisation settings, and creating the implementer's credential.

### Rejected

- **A self-hosted GitHub Actions runner on the workstation.** On a public repository, pull-request events can run code on the runner, which here is the maintainer's machine. [ADR-0009](0009-self-hosted-runner.md) admits one for CI jobs only, in an ephemeral VM and with no pull-request triggers. The implementer loop still does not run through it.
- **Scheduled tasks on the workstation that run a cloud model.** The implementer's point is local, private and free inference on the workstation's GPU.
- **Running the loop as the maintainer's own user.** That would expose his signing keys, his GitHub login and his home directory to a model-driven process.
- **Signing off unattended commits under the maintainer's name.** That would certify code before anyone reviewed it.
- **Keeping the loop's configuration in this repository.** It names models, paths and endpoints (invariant 8).

## Consequences

**Easier:** the backlog moves while the maintainer is away; each issue reaches him as a draft pull request that has passed the gates and the lead's review; failures are visible as `status:blocked` with a diagnosis instead of being silent; the harness and model can change in the private repository without touching this one.

**Harder:** a new label, `status:blocked`, joins the status flow, and AGENTS.md's status diagram changes on acceptance; the maintainer creates and rotates a scoped credential for the implementer's user; certification at merge becomes the norm for implementer commits, so the merge step carries more weight; the lead's review load grows with the implementer's failure rate; an unattended model run is a new process on the workstation that the isolation above must contain; the trial briefs must be written and run before the default harness is fixed.
