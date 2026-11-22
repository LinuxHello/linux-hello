#!/usr/bin/env bash
# Property: unsafe code exists only in allow-listed modules of the TPM provider, the PAM module and
# the Agent Link (the cxx-qt bridge of the Plasma screens, ADR-0028).
#  1. Every crate root under crates/ outside the first two sets #![forbid(unsafe_code)]; the Agent
#     Link, which is outside the main workspace, sets #![deny(unsafe_code)] at its root, and the
#     greeter program beside it #![forbid(unsafe_code)].
#  2. #[allow(unsafe_code)] appears only in files listed in scripts/ci/unsafe-allowlist.txt,
#     and every listed file belongs to one of those three crates.
set -euo pipefail
cd "$(dirname "$0")/../.."
[[ -f Cargo.toml ]] || { echo "::error::run from the repository"; exit 1; }
EXEMPT=(crates/linuxhello-tpm-provider crates/pam-linuxhello plasma/linuxhello-plasma)
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
  [[ $ok == 1 ]] || err "$ALLOWLIST lists $f, outside the TPM provider, the PAM module and the Agent Link"
done
while IFS= read -r f; do
  printf '%s\n' "${allowed[@]}" | grep -qxF "$f" || err "$f allows unsafe_code but is not in $ALLOWLIST"
done < <(grep -rlE '^[[:space:]]*#!?\[allow\(([^)]*[ ,])?unsafe_code' --include='*.rs' --exclude-dir=target crates plasma || true)

if [[ $fail == 0 ]]; then echo "unsafe policy holds"; fi
exit "$fail"
