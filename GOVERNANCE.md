# Governance

## Roles

| Role | Who | Responsibilities |
| :-- | :-- | :-- |
| Maintainer and architect | @atterdag (Valdemar Lemche) | Owns the architecture, threat model and security properties; final say on merges and releases |
| Contributors | Anyone, under the DCO | Issues, pull requests, reviews |

Code is largely written with AI assistance. The maintainer reviews **behaviour**: every security property is written in plain language and backed by a test whose name states it. Upstream maintainers (credentialsd, Howdy, KDE) review contributions made to their projects, and an external security audit precedes any release that anyone should rely on.

## Decisions

- Architecture decisions are recorded as ADRs in [`LinuxHello/architecture`](https://github.com/LinuxHello/architecture/blob/main/adr/README.md) (Title, Status, Context, Decision, Consequences).
- The architecture documentation (Arc42) and the C4 workspace in [`LinuxHello/architecture`](https://github.com/LinuxHello/architecture), at the commit this repository pins in `architecture/`, are the source of truth for structure ([ADR-0011](https://github.com/LinuxHello/architecture/blob/main/adr/0011-architecture-repository.md)). The code names the C4 element it implements, checked against the workspace in CI ([ADR-0008](https://github.com/LinuxHello/architecture/blob/main/adr/0008-code-documentation-mapped-to-c4.md)).

### One-way doors

These need an ADR before they change, because they are hard or impossible to reverse:

| Decision | Current value |
| :-- | :-- |
| Licence | LGPL-3.0-or-later |
| Project and organisation name | Linux Hello, github.com/LinuxHello |
| D-Bus names | `io.github.LinuxHello.*` |
| Crate and package names | Not published; `publish = false` until decided |
| Reset model | Destructive, no recovery key ([ADR-0003](https://github.com/LinuxHello/architecture/blob/main/adr/0003-destructive-reset.md)) |

## Repository topology

One monorepo, one crate per container, kept splittable:

1. Containers talk only through `linuxhello-dbus` or over D-Bus, never through each other's internals.
2. Each crate is versioned and tagged on its own (`agent-v0.1.0`).
3. CI is filtered by path, one job per crate. Deferred until the crates hold real code: it then needs one aggregate required check, because a required check whose workflow a path filter skips stays pending and blocks the merge.
4. Every issue carries a `container:` label.

**Split trigger:** a crate leaves the monorepo when it gets its own maintainer, its own release cadence, or a distribution packages it separately. Reviewed before 1.0 at the latest.

## Upstream first

Changes to upstream components (credentialsd, libwebauthn, Howdy, fprintd, KeePassXC, plasma-desktop) go upstream as contributions, not into private forks.

## Merging

- All changes reach `main` through a pull request; squash merge only, set in both the repository settings and the ruleset ([`scripts/admin/apply-merge-settings.sh`](scripts/admin/apply-merge-settings.sh)).
- Required checks: fmt, clippy, test, cargo-deny, cargo-audit, unsafe-policy, fuzz, docs, DCO, and the aggregate `quality-gate`. `quality-gate`, `fuzz` and `unsafe-policy` are pinned to the GitHub Actions app, so a status with the same name from another app or a commit status does not satisfy them ([`scripts/admin/apply-merge-settings.sh`](scripts/admin/apply-merge-settings.sh)).
- `quality-gate` passes only if every gate passed, and then signs a Sigstore attestation that the commit passed them. No pull request merges and no release is published without a valid quality-gate attestation ([ADR-0006](https://github.com/LinuxHello/architecture/blob/main/adr/0006-attested-quality-gates-and-releases.md)). Pull requests from forks are attested after the maintainer pushes the reviewed branch to this repository.
- Squash commits take the pull request title and its structured body ([pull request template](.github/pull_request_template.md)).
- Code scanning: CodeQL (default setup) blocks a merge on errors and on high or critical security alerts. Dependency review and SonarQube Cloud run on every pull request; Sonar's quality gate becomes required once its check name is stable.
- Roles of the coding agents and the review flow: [ADR-0004](https://github.com/LinuxHello/architecture/blob/main/adr/0004-agent-roles.md).
- Commits on `main` are signed.

## Releases

A release is a crate tag (`agent-v0.1.0`) on a commit on `main`. The release workflow publishes it only after it has verified that commit's quality-gate attestation, built the binaries, a source archive and a CycloneDX SBOM, signed build provenance and an SBOM attestation, and verified both ([ADR-0006](https://github.com/LinuxHello/architecture/blob/main/adr/0006-attested-quality-gates-and-releases.md)). How users verify a release: [SECURITY.md](SECURITY.md#verifying-a-release). Until an external audit, every release is marked pre-release.
