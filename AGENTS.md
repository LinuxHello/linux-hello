# AGENTS.md

Rules for every coding agent working in this repository: Claude Code (cloud or pointed at a local model), GitHub Copilot, and any other tool that reads `AGENTS.md`. Human contributors follow the same rules; see [CONTRIBUTING.md](CONTRIBUTING.md).

This file is the single source of agent rules. Tool-specific files ([CLAUDE.md](CLAUDE.md), [.github/copilot-instructions.md](.github/copilot-instructions.md)) only point here and add what is specific to that tool. Change the rules here, by pull request.

## What this is

Linux Hello is a session credential broker for the Linux desktop. The user unlocks once with face, fingerprint or PIN; passkeys then work in browsers, native and Electron apps through the credentialsd portal; a routing policy decides per relying party whether a key is device-bound (TPM) or portable (KeePassXC).

The maintainer (@atterdag) owns the architecture, the threat model and every merge, and reviews **behaviour, tests and test results**, not Rust. Write code that can be trusted without being read: the tests and their names are the review surface.

| Path | Container |
| :-- | :-- |
| `crates/linuxhello-dbus` | Shared D-Bus names and types; the only coupling between containers |
| `crates/linuxhello-agent` | Agent: unlock and auth state, routing policy, PIN, enrolment, reset |
| `crates/pam-linuxhello` | PAM module: parallel face, fingerprint and PIN |
| `crates/linuxhello-tpm-provider` | credentialsd provider for device-bound passkeys |
| `crates/linuxhello-kpxc-bridge` | credentialsd provider for portable passkeys from KeePassXC |
| `crates/linuxhello-ctl` | CLI |
| `plasma/`, `security/`, `policy/` | Plasma integration; AppArmor, Tetragon, alerts; policy schema |
| `docs/` | Obsidian vault: architecture, ADRs, spikes, threat model, security properties |

## Source of truth

Resolve conflicts in this order, and say which source you used:

1. `main`: code, tests, CI results
2. Accepted ADRs in [docs/adr/](docs/adr/)
3. [docs/architecture/target-architecture.md](docs/architecture/target-architecture.md) and `docs/architecture/workspace.dsl`
4. Upstream documentation and source (credentialsd, libwebauthn, Howdy, fprintd, KeePassXC, tss-esapi, zbus, KDE) at the version in `Cargo.lock`

Upstream behaviour you have not checked in source or docs is an assumption. Say so.

## Invariants

Never propose or write anything that breaks these. If a task seems to need it, stop and say so.

1. **The PIN is the root.** Keys hang off a TPM root key authorised by the PIN. Biometrics only satisfy a TPM policy; they are never the root and never a flag in a daemon.
2. **Keys sign, never leave.** Private key material never leaves the TPM or KeePassXC. The Secret Service stores tokens, never passkey private keys.
3. **Fail closed.** Unparseable policy denies everything except the PIN. A daemon whose AppArmor profile is not loaded in enforce mode refuses to start. No fallback silently weakens authentication.
4. **No `unsafe`**, except the TPM FFI module and the PAM entry-point module, each small and audited. The workspace currently sets `unsafe_code = "forbid"`, which cannot be relaxed by a module-level override; those exceptions require an explicitly reviewed lint arrangement before implementation.
5. **Licence boundaries.** Link only to LGPL or permissive code. Reach GPL components (KeePassXC, fprintd) across a process boundary only. All code here is LGPL-3.0-or-later ([ADR-0002](docs/adr/0002-licence-lgpl-3-or-later.md)).
6. **Upstream first.** Changes to upstream projects go upstream as contributions, not into forks or vendored patches.
7. **One-way doors need an ADR:** licence, names, D-Bus names (`io.github.LinuxHello.*`), crate and package names, the reset model ([ADR-0003](docs/adr/0003-destructive-reset.md)), repository topology.
8. **Public repository.** Never write secrets, tokens, personal data, or details of anyone's machines (hostnames, home paths, hardware, local endpoints, model names) into code, docs, issues, commit messages or PR descriptions.
9. **No secrets in the loop.** Never ask for, read, print or store a token or key. GitHub operations run through `gh` on the maintainer's machine; produce scripts, not requests for credentials.

## How to work

- **Spikes before code.** Milestone 0 answers the unverified assumptions in `docs/spikes/`. Do not write implementation that depends on an open spike; name the spike that blocks it.
- **Security properties first.** Every security behaviour is a plain-language property in `docs/security/` with a test whose name states it, e.g. `caller_from_other_origin_is_refused`. Write the property and the failing test before the code.
- **Small PRs, one container where possible.** Each PR states intent, affected containers, tests added, how to verify, and rollback.
- **Docs change with code.** A behaviour change updates the architecture note, the C4 workspace or an ADR in the same PR. Flag drift when you see it.
- **Check versions before trusting an API.** credentialsd is pre-release; tss-esapi, zbus, cxx-qt and the PAM crates change between versions. Read `Cargo.lock`, then the docs for that version.
- **Automate.** Prefer Makefile targets and scripts that check their own prerequisites over sequences of manual commands. Scripts are idempotent and fail closed.
- **Dependencies** must pass `cargo-deny` (licences, advisories, sources). Do not add one to work around a missing feature without saying why.

## Gates

CI runs these on every pull request; all are required. Run them before you call a change done:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
cargo audit
```

Fuzzing is required for every parser once one exists. Never weaken, skip or bypass a gate, a lint level or a test to get green; fix the cause or stop and report it.

**Report results honestly.** Mark every change *tested* or *untested*, with the toolchain version and the exact command. "Compiles" is not "tested". A test you did not run did not pass.

## Commits and pull requests

- `main` is protected: branch, open a pull request, squash merge. Never push to `main`.
- Every commit carries `Signed-off-by:` (`git commit -s`) from the human who submits it. An agent never signs off on someone's behalf; the human who runs the commit certifies the [DCO](https://developercertificate.org/).
- Commits on `main` are signed.
- Name the tool that produced a substantial part of a change with a trailer, one per tool:

  ```text
  Assisted-by: Claude Code (claude-opus-5-5)
  Assisted-by: GitHub Copilot
  Assisted-by: Claude Code with a local model
  ```

  Name a local model by family and size at most; never by host or endpoint (invariant 8).

## Documentation (`docs/`)

- Frontmatter on every note: `type`, `subject`, `artifact`, `status`, `owner`, `concepts`, `tags`, `sources`, `date`. Templates in [docs/templates/](docs/templates/).
- Standard relative Markdown links, never `[[wikilinks]]`, so notes render on GitHub and in Obsidian.
- Diagrams in Mermaid; C4 in Structurizr DSL (`docs/architecture/workspace.dsl`).
- ADRs: Title, Status, Context, Decision, Consequences (what becomes easier and what becomes harder).
- No preamble, closing offers or unfalsifiable superlatives ("bulletproof", "fully secure").

## Communication

Lead with the answer or diagnosis. Put commands in code blocks with one line on what each touches. Say what you verified and what you assumed. Disagree when the evidence says so, including with the architecture and with the maintainer. Ask one sharp question when a request is ambiguous.
