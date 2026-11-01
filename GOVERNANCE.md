# Governance

## Roles

| Role | Who | Responsibilities |
| :-- | :-- | :-- |
| Maintainer and architect | @atterdag (Valdemar Lemche) | Owns the architecture, threat model and security properties; final say on merges and releases |
| Contributors | Anyone, under the DCO | Issues, pull requests, reviews |

Code is largely written with AI assistance. The maintainer reviews **behaviour**: every security property is written in plain language and backed by a test whose name states it. Upstream maintainers (credentialsd, Howdy, KDE) review contributions made to their projects, and an external security audit precedes any release that anyone should rely on.

## Decisions

- Architecture decisions are recorded as ADRs in `docs/adr/` (Title, Status, Context, Decision, Consequences).
- The target architecture and the C4 workspace in `docs/architecture/` are the source of truth for structure.

### One-way doors

These need an ADR before they change, because they are hard or impossible to reverse:

| Decision | Current value |
| :-- | :-- |
| Licence | LGPL-3.0-or-later |
| Project and organisation name | Linux Hello, github.com/LinuxHello |
| D-Bus names | `io.github.LinuxHello.*` |
| Crate and package names | Not published; `publish = false` until decided |
| Reset model | Destructive, no recovery key ([ADR-0003](docs/adr/0003-destructive-reset.md)) |

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

- All changes reach `main` through a pull request; squash merge only.
- Required checks: format, clippy, tests, cargo-deny, cargo-audit, DCO.
- Code scanning: CodeQL (default setup) blocks a merge on errors and on high or critical security alerts. Dependency review and SonarQube Cloud run on every pull request; Sonar's quality gate becomes required once its check name is stable.
- Roles of the coding agents and the review flow: [ADR-0004](docs/adr/0004-agent-roles.md).
- Commits on `main` are signed.
