#!/usr/bin/env bash
# Property: unsafe code exists only in allow-listed modules of the TPM provider and the PAM module.
#  1. Every crate root outside those two crates sets #![forbid(unsafe_code)].
#  2. #[allow(unsafe_code)] appears only in files listed in scripts/ci/unsafe-allowlist.txt,
#     and every listed file belongs to one of those two crates.
set -euo pipefail
cd "$(dirname "$0")/../.."
[[ -f Cargo.toml ]] || { echo "::error::run from the repository"; exit 1; }
EXEMPT=(crates/linuxhello-tpm-provider crates/pam-linuxhello)
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

mapfile -t allowed < <(grep -v '^\s*#' "$ALLOWLIST" | sed '/^\s*$/d')
for f in "${allowed[@]}"; do
  ok=0; for c in "${EXEMPT[@]}"; do [[ "$f" == "$c"/* ]] && ok=1; done
  [[ $ok == 1 ]] || err "$ALLOWLIST lists $f, outside the TPM provider and the PAM module"
done
while IFS= read -r f; do
  printf '%s\n' "${allowed[@]}" | grep -qxF "$f" || err "$f allows unsafe_code but is not in $ALLOWLIST"
done < <(grep -rlE '^[[:space:]]*#!?\[allow\(([^)]*[ ,])?unsafe_code' --include='*.rs' crates || true)

if [[ $fail == 0 ]]; then echo "unsafe policy holds"; fi
exit "$fail"
