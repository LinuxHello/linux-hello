#!/usr/bin/env bash
# Tests of scripts/ci/unsafe-policy.sh on small trees made for the purpose (R-23, #365): the policy
# must hold for a clean tree and must fail for every spelling of unsafe code outside the allow-list.
#
#   scripts/ci/test-unsafe-policy.sh
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
script="$here/unsafe-policy.sh"
pass=0; fail=0
ok() { pass=$((pass + 1)); echo "ok   $1"; }
bad() { fail=$((fail + 1)); echo "FAIL $1"; }

# A tree with one crate that forbids unsafe code, the Agent Link and greeter roots, and an empty
# allow-list.
make_tree() {
  local d; d="$(mktemp -d)"
  mkdir -p "$d/crates/app/src" "$d/scripts/ci" "$d/plasma/linuxhello-plasma/src" "$d/plasma/linuxhello-greeter/src"
  : > "$d/Cargo.toml"
  : > "$d/scripts/ci/unsafe-allowlist.txt"
  printf '#![forbid(unsafe_code)]\nfn main() {}\n' > "$d/crates/app/src/main.rs"
  printf '#![deny(unsafe_code)]\n' > "$d/plasma/linuxhello-plasma/src/lib.rs"
  printf '#![forbid(unsafe_code)]\nfn main() {}\n' > "$d/plasma/linuxhello-greeter/src/main.rs"
  echo "$d"
}
# expect <name> <holds|fails> <tree>
expect() {
  local out status
  out="$(UNSAFE_POLICY_ROOT="$3" bash "$script" 2>&1)"; status=$?
  if [[ "$2" == holds && $status == 0 ]] || [[ "$2" == fails && $status != 0 ]]; then ok "$1"; else bad "$1: $out"; fi
  rm -rf "$3"
}

expect "a clean tree holds" holds "$(make_tree)"

t="$(make_tree)"; printf 'fn f() { unsafe { core::hint::unreachable_unchecked() } }\n' > "$t/crates/app/src/extra.rs"
expect "an unsafe block fails" fails "$t"

t="$(make_tree)"; printf 'pub unsafe fn f() {}\n' > "$t/crates/app/src/extra.rs"
expect "an unsafe function fails" fails "$t"

t="$(make_tree)"; printf '#[expect(unsafe_code)]\nfn f() {}\n' > "$t/crates/app/src/extra.rs"
expect "#[expect(unsafe_code)] fails" fails "$t"

t="$(make_tree)"; printf '#[cfg_attr(all(), allow(unsafe_code))]\nfn f() {}\n' > "$t/crates/app/src/extra.rs"
expect "a cfg_attr allow fails" fails "$t"

t="$(make_tree)"; printf '#[allow(\n    unsafe_code\n)]\nfn f() {}\n' > "$t/crates/app/src/extra.rs"
expect "an attribute split over lines fails" fails "$t"

t="$(make_tree)"; mkdir -p "$t/crates/app/tests"; printf 'unsafe impl Send for X {}\n' > "$t/crates/app/tests/t.rs"
expect "unsafe in an integration test fails" fails "$t"

t="$(make_tree)"; printf '// unsafe { this is only a comment }\nfn f() {}\n' > "$t/crates/app/src/extra.rs"
expect "a comment about unsafe holds" holds "$t"

t="$(make_tree)"; sed -i 's/forbid/deny/' "$t/crates/app/src/main.rs"
expect "a root that denies and does not forbid fails" fails "$t"

t="$(make_tree)"; mkdir -p "$t/crates/pam-linuxhello/src"; printf '#![deny(unsafe_code)]\n' > "$t/crates/pam-linuxhello/src/lib.rs"
printf '#![allow(unsafe_code)]\nunsafe fn f() {}\n' > "$t/crates/pam-linuxhello/src/entry.rs"
echo "crates/pam-linuxhello/src/entry.rs" > "$t/scripts/ci/unsafe-allowlist.txt"
expect "the listed module may hold unsafe code" holds "$t"

echo "$pass passed, $fail failed"
[[ $fail == 0 ]]
