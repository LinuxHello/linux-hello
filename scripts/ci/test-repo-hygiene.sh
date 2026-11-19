#!/usr/bin/env bash
# Tests for repo-hygiene.sh against small fixture repositories.
#
#   scripts/ci/test-repo-hygiene.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
check="$here/repo-hygiene.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0 fail=0

# A fixture repository with one source file.
fixture() {
  local d="$work/$1"
  rm -rf "$d"
  mkdir -p "$d/src" "$d/scripts/ci"
  git -C "$d" init -q
  echo 'fn main() {}' >"$d/src/main.rs"
  echo "$d"
}

# expect NAME EXIT-CODE REPO [TEXT]: runs the check on REPO; the exit code must be EXIT-CODE and,
# when TEXT is given, the output must contain it.
expect() {
  local name="$1" want="$2" repo="$3" text="${4:-}" out code=0
  git -C "$repo" add -A
  out="$(bash "$check" "$repo" 2>&1)" || code=$?
  if [[ "$code" -eq "$want" && ( -z "$text" || "$out" == *"$text"* ) ]]; then
    echo "ok   $name"
    pass=$((pass + 1))
  else
    echo "FAIL $name (exit $code, wanted $want): $out"
    fail=$((fail + 1))
  fi
}

d="$(fixture clean)"
expect a_clean_repository_passes 0 "$d"

d="$(fixture target)"
mkdir -p "$d/crates/ctl/fuzz/target/release" && echo x >"$d/crates/ctl/fuzz/target/release/out.d"
expect tracked_build_output_is_refused 1 "$d" "tracked build output: crates/ctl/fuzz/target/release/out.d"

d="$(fixture corpus)"
mkdir -p "$d/fuzz/corpus/t" && echo x >"$d/fuzz/corpus/t/abc"
expect a_fuzz_corpus_is_refused 1 "$d" "tracked build output"

d="$(fixture seeds)"
mkdir -p "$d/fuzz/seeds/t" && echo x >"$d/fuzz/seeds/t/abc"
expect fuzz_seeds_are_allowed 0 "$d"

d="$(fixture targets-in-a-name)"
echo x >"$d/src/targets.rs"; echo x >"$d/src/my_target"
expect a_name_that_only_contains_target_is_allowed 0 "$d"

d="$(fixture big)"
head -c 1048577 /dev/zero >"$d/big.bin"
expect a_file_over_one_mebibyte_is_refused 1 "$d" "tracked file over 1 MiB: big.bin"

d="$(fixture exactly)"
head -c 1048576 /dev/zero >"$d/limit.bin"
expect a_file_of_exactly_one_mebibyte_is_allowed 0 "$d"

d="$(fixture listed)"
head -c 2000000 /dev/zero >"$d/logo.bin"
echo logo.bin >"$d/scripts/ci/large-files-allowed.txt"
expect a_listed_big_file_is_allowed 0 "$d"

d="$(fixture untracked)"
mkdir -p "$d/target" && echo x >"$d/target/out"
head -c 2000000 /dev/zero >"$d/ignored.bin"
printf 'target/\nignored.bin\n' >"$d/.gitignore"
expect ignored_files_are_not_looked_at 0 "$d"

echo "$pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
