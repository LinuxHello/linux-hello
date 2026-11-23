#!/usr/bin/env bash
# Property: unsafe code exists only in allow-listed modules of the PAM module and the Agent Link (the
# cxx-qt bridge of the Plasma screens, ADR-0028). The TPM provider has none and forbids it.
#  1. Every crate root under crates/ outside the PAM module sets #![forbid(unsafe_code)]; the Agent
#     Link, which is outside the main workspace, sets #![deny(unsafe_code)] at its root, and the
#     greeter program beside it #![forbid(unsafe_code)].
#  2. Outside the files listed in scripts/ci/unsafe-allowlist.txt, no Rust file under crates/ or
#     plasma/ contains an `unsafe` block, function, impl, trait or extern block, or names
#     `unsafe_code` in any way but forbid or deny: so `#[expect(unsafe_code)]`, a `cfg_attr` and an
#     attribute split over lines are caught as well (R-23, #365). Comments are not read.
#  3. Every listed file belongs to the PAM module or the Agent Link.
#
# The root of the tree can be given in UNSAFE_POLICY_ROOT (for scripts/ci/test-unsafe-policy.sh).
set -euo pipefail
cd "${UNSAFE_POLICY_ROOT:-$(dirname "$0")/../..}"
[[ -f Cargo.toml ]] || { echo "::error::run from the repository"; exit 1; }
EXEMPT=(crates/pam-linuxhello plasma/linuxhello-plasma)
AGENT_LINK_ROOT=plasma/linuxhello-plasma/src/lib.rs
GREETER_ROOT=plasma/linuxhello-greeter/src/main.rs
ALLOWLIST=scripts/ci/unsafe-allowlist.txt
fail=0
err() { echo "::error::$*"; fail=1; }
is_exempt() { local c; for c in "${EXEMPT[@]}"; do [[ "$1" == "$c" ]] && return 0; done; return 1; }

for dir in crates/*/; do
  dir=${dir%/}
  is_exempt "$dir" && continue
  for root in "$dir/src/lib.rs" "$dir/src/main.rs"; do
    [[ -f "$root" ]] || continue
    grep -q '^#!\[forbid(unsafe_code)\]' "$root" || err "$root does not set #![forbid(unsafe_code)]"
  done
done

[[ -f "$AGENT_LINK_ROOT" ]] && { grep -q '^#!\[deny(unsafe_code)\]' "$AGENT_LINK_ROOT" || err "$AGENT_LINK_ROOT does not set #![deny(unsafe_code)]"; }
[[ -f "$GREETER_ROOT" ]] && { grep -q '^#!\[forbid(unsafe_code)\]' "$GREETER_ROOT" || err "$GREETER_ROOT does not set #![forbid(unsafe_code)]"; }

mapfile -t allowed < <(grep -v '^\s*#' "$ALLOWLIST" | sed '/^\s*$/d')
for f in "${allowed[@]}"; do
  ok=0; for c in "${EXEMPT[@]}"; do [[ "$f" == "$c"/* ]] && ok=1; done
  [[ $ok == 1 ]] || err "$ALLOWLIST lists $f, outside the PAM module and the Agent Link"
done
# Every Rust file, tests and fuzz targets included (their crate roots are separate crates, which a
# forbid at the library root does not cover), except the listed ones.
while IFS= read -r f; do
  printf '%s\n' "${allowed[@]}" | grep -qxF "$f" && continue
  code=$(sed 's#//.*$##' "$f")
  if grep -qE '(^|[^[:alnum:]_])unsafe[[:space:]]*(\{|fn[[:space:]]|impl[[:space:]<]|trait[[:space:]]|extern[[:space:]])' <<<"$code"; then
    err "$f contains unsafe code but is not in $ALLOWLIST"
  fi
  if grep -E 'unsafe_code' <<<"$code" | grep -vqE '^[[:space:]]*#!\[(forbid|deny)\(unsafe_code\)\][[:space:]]*$'; then
    err "$f names unsafe_code other than as #![forbid(unsafe_code)] or #![deny(unsafe_code)], and is not in $ALLOWLIST"
  fi
done < <(find crates plasma -name '*.rs' -not -path '*/target/*' 2>/dev/null | sort)

if [[ $fail == 0 ]]; then echo "unsafe policy holds"; fi
exit "$fail"
