## Intent

<!-- One or two sentences of behaviour. -->

Closes #

## Affected containers

<!-- crates/<name>, plasma/, security/, policy/, docs/ -->

## Tests

<!-- Every test added or changed, by name. A behaviour change needs a test named after its property. -->

## Security

<!-- Does this touch a security property, unsafe, a dependency, D-Bus names, policy parsing or AppArmor? -->

## How to verify

## Rollback

## Checklist

- [ ] Gates pass locally: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo deny check`, `cargo audit`
- [ ] Docs, architecture note, `workspace.dsl` or an ADR updated if behaviour changed
- [ ] Every commit is signed off (`git commit -s`); tools named with `Assisted-by:`
