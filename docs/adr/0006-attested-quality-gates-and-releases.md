---
type: adr
subject: Attested quality gates, fuzzing, SBOMs and signed releases
artifact: adr
status: proposed
owner: "@atterdag"
concepts: [supply-chain, governance, ci, fuzzing]
tags: [adr, ci, security, release]
sources: ["../../GOVERNANCE.md", "../../AGENTS.md", "../../.github/workflows/ci.yml", "../../.github/workflows/release.yml", "https://github.com/actions/attest/tree/v4.2.2", "https://slsa.dev/spec/v1.0/provenance"]
date: 2026-11-03
---

# ADR-0006: Attested quality gates and releases

## Status

Proposed, 2026-11-03.

## Context

Most code here is written by coding agents and reviewed by behaviour ([GOVERNANCE.md](../../GOVERNANCE.md)). Required checks already block a merge on fmt, clippy (`-D warnings`), tests, cargo-deny, cargo-audit, unsafe-policy and DCO. Three gaps remain:

1. **No fuzzing.** [AGENTS.md](../../AGENTS.md) requires fuzzing for every parser once one exists. The routing-policy parser (`policy::schema::parse`) exists and was not fuzzed. Writing the fuzz target exposed an unchecked multiplication: `reverify_after = "213503982334602d"` parsed, then `total_seconds()` panicked in debug builds and wrapped to an arbitrary value in release builds.
2. **No evidence outside GitHub's check UI.** A green check is a mutable record in one web interface; nobody can later prove that a given commit passed the gates.
3. **No release process.** Nothing is released yet, but once it is, users need to verify what is in a binary and where it was built.

GitHub artifact attestations (`actions/attest`, v4.2.2 checked) sign in-toto statements with a short-lived Sigstore certificate. For a public repository the public-good Sigstore instance is used, and the signature is recorded in its transparency log. The certificate names the workflow, the ref and the commit of the run. `gh attestation verify` checks them.

## Decision

### Quality gate

A **passed quality gate** for a commit means every CI job listed in [`scripts/ci/quality-gates.txt`](../../scripts/ci/quality-gates.txt) succeeded on it: `fmt`, `clippy`, `test`, `cargo-deny`, `cargo-audit`, `unsafe-policy`, `fuzz`. On a pull request, `dco` must also succeed.

- **`fuzz`** runs every cargo-fuzz target for 60 seconds ([`scripts/ci/fuzz.sh`](../../scripts/ci/fuzz.sh)) on a pinned nightly. A crash fails the job and the crashing input is kept as a workflow artifact. Each target is seeded with inputs near the limits it checks. The smoke run is a regression net, not exhaustive fuzzing, so every crash it finds also gets a named unit test.
- **`quality-gate`** is the aggregate required check. It always runs, so a skipped gate cannot count as passed. It fails unless every gate succeeded and its `needs:` list matches `quality-gates.txt`. It then signs an attestation and verifies it.

### quality-gate-v1

- **Subject:** a canonical JSON file `{"commit","gates","repository","type":"quality-gate/v1"}`, printed by [`scripts/ci/quality-gate-subject.sh`](../../scripts/ci/quality-gate-subject.sh). It is deterministic, so anyone can rebuild it from the commit. A Git commit cannot be the subject directly, because `actions/attest` takes only sha256 digests.
- **Predicate type:** `https://github.com/LinuxHello/linux-hello/blob/main/docs/adr/0006-attested-quality-gates-and-releases.md#quality-gate-v1`
- **Predicate:** commit, ref, event, run URL, Rust toolchain, gates passed.
- **Signed by:** `.github/workflows/ci.yml` on a GitHub-hosted runner. A commit on `main` is bound by `source-ref refs/heads/main` and `source-digest <commit>`. A pull request head is bound by `source-ref refs/pull/<n>/merge`.
- **Verify:** `scripts/ci/verify-quality-gate.sh <commit> [ref]` or `make verify-gate SHA=<commit>`.

### Merge and release requirements

- **Merge:** `quality-gate` is a required status check. Because it succeeds only after the attestation for the pull request's head commit is signed and verified, a pull request cannot merge without one. Reviewers (lead, Copilot, maintainer) confirm the check passed. Anyone can re-verify with the script.
- **Squash commits:** a squash merge creates a new commit, so the push to `main` runs CI again and attests the commit that actually ships. Squash commit messages take the pull request title and body (repository setting, [`scripts/admin/apply-merge-settings.sh`](../../scripts/admin/apply-merge-settings.sh)).
- **Release:** a crate tag (`agent-v0.1.0`) triggers [`release.yml`](../../.github/workflows/release.yml). Nothing is published unless:
  1. the tagged commit is on `main` and its quality-gate attestation verifies;
  2. binaries (bin and cdylib targets), a source archive, `SHA256SUMS` and a CycloneDX 1.5 SBOM (`cargo-cyclonedx` 0.5.9, every dependency at its `Cargo.lock` version) are built from it;
  3. SLSA build provenance is signed for every file, and an SBOM attestation for the binaries and the source archive;
  4. a separate publish job, which alone can write releases, re-checks every checksum and attestation before it creates the GitHub release.

### What this ADR does not adopt from the original proposal

- **Separate cosign signatures.** Artifact attestations already sign with Sigstore (Fulcio certificate, Rekor log). Signing the same files again with `cosign sign-blob` would add a second key path to verify and no new assurance.
- **A per-PR "attestation present" check separate from the gates.** It would verify a statement that the same workflow just produced. The required `quality-gate` check is that gate.
- **Aider-specific rules.** Aider has no role in [ADR-0004](0004-agent-roles.md). The pull request structure is set in the template and [AGENTS.md](../../AGENTS.md) for every agent; adding Aider would amend ADR-0004.

## Consequences

**Easier:**

- Anyone can prove, without trusting GitHub's UI, that a commit on `main` passed every gate, and which gates those were.
- Users can verify a released file's origin (repository, workflow, tag, commit) and contents (SBOM) with one `gh attestation verify` command.
- Parser crashes are caught before merge; the policy parser now refuses durations that overflow.
- One aggregate required check survives the per-crate path filtering planned in GOVERNANCE.md (topology rule 3).
- `make fix` and `make gates` give agents and humans the same local entry point as CI.

**Harder:**

- Pull requests from forks cannot be attested (forks get no OIDC token), so their `quality-gate` fails. The maintainer pushes the reviewed branch to this repository to attest it.
- CI takes longer: about two minutes for the fuzz build and run, plus the attestation job.
- A nightly toolchain is pinned for fuzzing and must be bumped by pull request. The fuzz crate is a separate workspace, so the root `cargo deny` and `cargo audit` do not cover its `Cargo.lock` (libfuzzer-sys only); Dependabot does.
- Changing `quality-gates.txt` changes what later attestations claim, so it needs the same review as a gate change.
- A tag pushed before CI on `main` finishes fails the release gate and must be re-run.
- The release workflow has not run yet. The first tag is its first test.
