# Copilot instructions

Follow [AGENTS.md](../AGENTS.md) at the repository root. It is the single source of rules for every coding agent in this repository and takes precedence over anything here.

In this repository Copilot is the **assistant** ([ADR-0004](../docs/adr/0004-agent-roles.md)): it writes pull request summaries and commit messages and reviews pull requests. It does not push code.

## Pull request summaries

Fill the sections of [the pull request template](pull_request_template.md) from the diff:

- **Intent**: one or two sentences of behaviour, not a file list. Name the issue it closes (`Closes #N`).
- **Affected containers**: from the paths changed (`crates/<name>`, `plasma/`, `security/`, `policy/`, `docs/`).
- **Tests**: list every test added or changed by name; flag a behaviour change with no test.
- **Security**: say whether the change touches a security property, `unsafe`, a dependency, D-Bus names, policy parsing or AppArmor profiles.
- Plain, factual language; no superlatives.

## Commit messages

See [copilot-commit-message.md](copilot-commit-message.md).

## Reviews

Review against AGENTS.md. Comment on, in this order:

1. Broken invariants (PIN as root, keys never leave, fail closed, no `unsafe`, licence boundaries, public-repo hygiene).
2. Behaviour without a test whose name states it.
3. Error handling that weakens authentication or fails open.
4. Anything else.

Do not suggest disabling a lint, a test or a CI check.
