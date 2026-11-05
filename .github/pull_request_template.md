## Intent

<!-- The goal and the behaviour it achieves, in one or two sentences. Not a list of functions, parameters or files. This body becomes the squash commit message. -->

Closes #

## Process mapping

<!-- How the change fits the defined architecture and process. Link every source. -->

- **Containers:** <!-- crates/<name>, plasma/, security/, policy/, docs/ -->
- **Architecture and decisions:** <!-- the ADRs, Arc42 sections in docs/architecture/, workspace.dsl elements, policy-semantics rules, spike or brief this implements or relies on -->
- **Security properties:** <!-- properties in docs/security/ added, changed or relied on, or "none". Say whether it touches unsafe, a dependency, D-Bus names, policy parsing or AppArmor. -->
- **Docs changed with the code:** <!-- the notes, ADRs or workspace.dsl updated, or why none needed it -->
- **Rollback:** <!-- how to undo it, and anything a revert does not undo -->

## Acceptance criteria met

<!-- One line per criterion from the brief or issue, each with its proof: the test that states it, a command and its result, or a link. -->

- [ ] <!-- criterion --> — proof: <!-- test name, or command and result -->

**Tests added or changed:** <!-- every one, by name; a behaviour change needs a test named after its property -->

**How to verify:** <!-- commands, with the toolchain they were run on -->

- [ ] `make gates` passes locally: fmt, clippy, test, cargo-deny, cargo-audit, unsafe-policy, fuzz, docs
- [ ] Every new item has a doc comment; every new crate root or top-level module names its C4 element, and `workspace.dsl` has it ([ADR-0008](../docs/adr/0008-code-documentation-mapped-to-c4.md))
- [ ] The `quality-gate` check passed, so its attestation for the tested merge commit is signed and verified ([ADR-0006](../docs/adr/0006-attested-quality-gates-and-releases.md))
- [ ] Every commit is signed off (`git commit -s`); tools named with `Assisted-by:`
