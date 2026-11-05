---
type: adr
subject: A self-hosted GitHub Actions runner on the maintainer's workstation
artifact: adr
status: proposed
owner: "@atterdag"
concepts: [supply-chain, governance, ci, sovereignty]
tags: [adr, ci, security, release]
sources: ["0006-attested-quality-gates-and-releases.md", "0007-unattended-agent-loops.md", "../../.github/workflows/ci.yml", "../../.github/workflows/release.yml", "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#hardening-for-self-hosted-runners", "https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/managing-access-to-self-hosted-runners-using-groups", "https://reproducible-builds.org/docs/definition/"]
date: 2026-11-05
---

# ADR-0009: A self-hosted runner on the maintainer's workstation

## Status

Proposed, 2026-11-05.

## Context

Every CI job runs on GitHub-hosted runners. The maintainer wants some of the project's work to run on hardware the maintainer controls. This is a sovereignty goal: the project should not depend only on GitHub's computers for evidence about its own code.

A self-hosted runner moves compute, not control. GitHub still hosts the code, starts the workflows, holds the logs and issues the tokens. What a runner on the workstation can add:

- evidence that does not come only from GitHub's machines, by running the gates a second time;
- compute that GitHub-hosted runners do not offer for free: long fuzzing runs;
- access to real hardware (TPM, camera, fingerprint reader), which hosted runners lack;
- an independent check of release binaries.

Three constraints apply.

1. **The repository is public.** On a public repository, a pull request can change a workflow and run it, and GitHub warns against self-hosted runners for that reason. [ADR-0007](0007-unattended-agent-loops.md) rejected a runner on the workstation for the same reason.
2. **The attested gates must stay on GitHub-hosted runners.** [ADR-0006](0006-attested-quality-gates-and-releases.md) signs the quality gate and the release provenance on GitHub-hosted runners, and every verifier passes `--deny-self-hosted-runners`. Those signatures mean "built on an isolated builder that the maintainer does not control". A workstation build cannot mean that.
3. **The workstation holds the maintainer's keys, the maintainer's GitHub login and the implementer loop.** [ADR-0007](0007-unattended-agent-loops.md) already isolates the implementer from them, and a runner needs the same isolation.

## Decision

The workstation hosts a self-hosted runner for four kinds of job. None of them is a gate, none is a required check, and none signs anything.

### What runs on it

| Job | Trigger | Result |
| :-- | :-- | :-- |
| **Mirror gates** | push to `main` | `make gates` on the pushed commit, a second time on the maintainer's hardware. The run record is evidence; nothing is attested. |
| **Long fuzzing** | schedule (nightly), `workflow_dispatch` | every fuzz target for much longer than the gate's 60 s. Crashing inputs are kept as workflow artifacts. A crash fails the run, and the maintainer files the issue. |
| **Hardware tests** | `workflow_dispatch` only | tests against the real TPM, camera and fingerprint reader, once such tests exist. |
| **Release rebuild** | the release workflow, before publishing | rebuilds the tagged commit from source and reports its `SHA256SUMS`. See below. |

### Release rebuild: a veto, not a pen

Release binaries are still built, signed and published by [`release.yml`](../../.github/workflows/release.yml) on GitHub-hosted runners, as ADR-0006 decides. The workstation adds an independent rebuild:

1. A `rebuild` job on the workstation builds the tagged commit with the same script and toolchain, then uploads only its `SHA256SUMS`.
2. The `publish` job compares those checksums with the hosted build's. It publishes only if they are identical.

The workstation never uploads a binary and never signs. A compromised workstation can block a release, but it cannot change one. A release now needs both GitHub's builder and the maintainer's hardware to agree.

This works only if release builds are bit-for-bit reproducible across the two environments. That has not been tested. A spike tests it first. Until the spike shows the builds match, the comparison is recorded in the release notes and does not block publishing.

### Isolation

1. **Ephemeral VM.** Each job runs in a fresh virtual machine started from a base image, and the VM is destroyed afterwards. The runner is registered with a just-in-time configuration for exactly one job. Nothing runs on the host as the maintainer's user, and the VM gets no access to the maintainer's home directory, keys, agents or the implementer's user.
2. **Network.** The VM reaches GitHub, crates.io and the Rust toolchain servers only, and nothing on the local network.
3. **Registration credential on the host.** A host service outside the VM requests the just-in-time configuration. It uses a GitHub App credential limited to the organisation's self-hosted runners. The maintainer creates and stores it, and the lead never sees it (invariant 9). The VM receives only the one-job configuration.
4. **Hardware jobs** use a separate VM with only the devices under test passed through. The workstation's own TPM holds the maintainer's real keys, so it is not passed through. Hardware tests run on test hardware that holds no real keys.
5. **Resources.** The VM's CPU and memory are capped. Long fuzzing runs only when the implementer loop ([ADR-0007](0007-unattended-agent-loops.md)) is not running.

### Who can reach it

1. **Runner group.** The runner sits in its own runner group, open to this repository only and to **selected workflows only**: the workflow files above, at `refs/heads/main`, plus `release.yml` at release tags. A workflow that a pull request changes is not on that list. Because this repository is public, the group must allow public repositories. That setting is safe only together with the workflow restriction.
2. **Tags.** A ruleset lets only the maintainer create release tags, since a tag ref is where the release rebuild runs.
3. **No pull-request triggers.** A workflow with a job for the runner's label has no `pull_request`, `pull_request_target`, `issue_comment` or `workflow_run` trigger. A CI check enforces this, so a change that breaks the rule cannot merge.
4. **Minimal token.** Self-hosted jobs run with `permissions: contents: read`. They never get `id-token: write`, `attestations: write` or `contents: write`.
5. **Labels.** The runner carries its own labels (`workstation`, `workstation-hw`), and no hosted job targets them. Gate jobs keep `ubuntu-24.04`.

### Where things live

This repository holds the workflows, the CI check that enforces the trigger rule, and this ADR. The VM image, the host service and the network rules live in the private workstation repository (invariant 8). This repository records only the contract above.

### Implementation, as separate issues

1. A CI check that a job targeting a workstation label has no pull-request trigger and no write permission. It becomes a gate in `quality-gates.txt`.
2. Workstation provisioning, in the private repository: base image, host service with just-in-time registration, network rules.
3. Runner group, workflow restriction and tag ruleset (maintainer: organisation and repository settings).
4. The mirror-gates workflow.
5. The long-fuzzing workflow.
6. Spike: are release builds reproducible between `ubuntu-24.04` and the workstation VM?
7. The release `rebuild` job and the checksum comparison in `publish`.
8. The hardware-test workflow, blocked until hardware tests exist.

### Rejected

- **Gates or attestations on the workstation.** A signature from the maintainer's machine would ask verifiers to trust that machine, and ADR-0006's `--deny-self-hosted-runners` exists to rule that out.
- **Building, signing or uploading release binaries on the workstation.** Same reason. The rebuild above gives the workstation a veto without that trust.
- **A persistent runner, or one on the host.** Each job could leave something behind for the next one, and the host holds the maintainer's keys.
- **Any pull-request trigger on a workstation job**, including with approval gates. One mistaken approval would run a stranger's code on the maintainer's hardware.
- **Passing the workstation's own TPM to a test VM.** It holds the maintainer's real keys.

## Consequences

**Easier:**

- The gates on `main` have a second record, made on hardware outside GitHub.
- Fuzz targets get hours instead of a minute, at no cost.
- Hardware behaviour can be tested at all.
- Once builds are reproducible, a release cannot ship unless two independent builders agree.

**Harder:**

- The maintainer runs and maintains a VM host, a base image, a host service and a GitHub App credential, and keeps them patched.
- The runner group has to allow public repositories. The workflow restriction becomes the main control. GitHub's support for restricting a runner group to selected workflows, including at tag refs, on this organisation's plan has not been checked (assumption); without it this ADR cannot be implemented as written.
- Once the comparison blocks, a release waits for the workstation to be online.
- Hardware tests need test hardware separate from the workstation's own TPM: a spare machine or a discrete test TPM.
- Reproducible builds may need build changes: path remapping, a fixed timestamp, the same linker. The spike will show how many.
- A new CI check joins the gates, and `quality-gates.txt` changes with it, so later attestations claim one more gate.
- ADR-0006 gains a release step. The text of ADR-0006 changes when the rebuild job is implemented.
