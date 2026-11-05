# Contributing

## Developer Certificate of Origin

Every commit must be signed off (`git commit -s`), certifying the [DCO](https://developercertificate.org/). CI rejects pull requests with commits that lack `Signed-off-by:`.

## Workflow

1. Pick the next issue: run `make next`, or open the **Next up** view of the Roadmap board. [The backlog](docs/project/backlog.md) explains the lanes, labels and order. Code only an issue that is `status:ready` and has an `## Implementation brief`.
2. Branch from `main`, keep the change to one container where possible. Run `make hooks` once so commits with unformatted code are refused.
3. Run `make fix`, then `make gates`, which runs every CI gate locally, fuzzing included.
4. Open a pull request using the template: intent, process mapping, acceptance criteria met. All required checks must pass, `quality-gate` included; it is squash merged.

## Rules

- `unsafe` is forbidden in every crate except the TPM provider and the PAM module, where it is denied except in one small, audited module listed in `scripts/ci/unsafe-allowlist.txt` (checked by the `unsafe-policy` CI job).
- Every item is documented, private ones included, and every crate root and top-level module names its C4 element from `architecture/workspace.dsl`, the C4 model in the [`LinuxHello/architecture`](https://github.com/LinuxHello/architecture) submodule (clone with `--recurse-submodules`) ([AGENTS.md](AGENTS.md#code-documentation), [ADR-0008](https://github.com/LinuxHello/architecture/blob/main/adr/0008-code-documentation-mapped-to-c4.md)). `make docs` checks it.
- A security property change needs a test whose name states the property, e.g. `caller_from_other_origin_is_refused`.
- New dependencies must pass `cargo-deny` (licences and advisories).
- Changes to an upstream project go upstream first.

## AI-assisted contributions

Code here is largely written with coding agents (Claude Code, GitHub Copilot, local models). The same rules apply whoever or whatever wrote a line:

- Agents follow [AGENTS.md](AGENTS.md), the single source of agent rules; their roles are fixed in [ADR-0004](https://github.com/LinuxHello/architecture/blob/main/adr/0004-agent-roles.md).
- The human who submits a commit signs it off and is accountable for it under the DCO. An agent never signs off.
- The same required checks apply; generated code gets no exemption.
- Name the tool behind a substantial part of a change with an `Assisted-by:` trailer (see [AGENTS.md](AGENTS.md#commits-and-pull-requests)). Name a local model by family and size at most, never by host or endpoint.

## Licence

By contributing you agree that your contribution is licensed under LGPL-3.0-or-later.
