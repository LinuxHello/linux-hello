#!/usr/bin/env bash
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
pass=0; fail=0
classify() { printf '%b' "$1" | bash "$here/classify-changes.sh"; }
check() {   # check <name> <expected> <input with \n escapes>
  local got; got="$(classify "$3")"
  if [[ "$got" == "$2" ]]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1 (want $2, got $got)"; fi
}

check "docs_only_change_is_docs" "rust=false" "docs/adr/0001-x.md\nREADME.md\n"
check "each_root_document_is_docs" "rust=false" "README.md"
check "each_root_document_is_docs" "rust=false" "GOVERNANCE.md"
check "each_root_document_is_docs" "rust=false" "SECURITY.md"
check "each_root_document_is_docs" "rust=false" "CONTRIBUTING.md"
check "each_root_document_is_docs" "rust=false" "AGENTS.md"
check "each_root_document_is_docs" "rust=false" "CLAUDE.md"
check "any_code_path_is_code" "rust=true" "crates/linuxhello-dbus/src/lib.rs"
check "any_code_path_is_code" "rust=true" "Cargo.lock"
check "any_code_path_is_code" "rust=true" "architecture"
check "any_code_path_is_code" "rust=true" "policy/policy.example.toml"
check "any_code_path_is_code" "rust=true" "scripts/ci/fuzz.sh"
check "any_code_path_is_code" "rust=true" ".github/workflows/ci.yml"
check "any_code_path_is_code" "rust=true" "deny.toml"
check "any_code_path_is_code" "rust=true" "rust-toolchain.toml"
check "any_code_path_is_code" "rust=true" "Makefile"
check "any_code_path_is_code" "rust=true" "crates/linuxhello-agent/README.md"
check "one_code_path_among_docs_is_code" "rust=true" "docs/a.md\ncrates/x/src/lib.rs\n"
check "empty_input_is_code" "rust=true" ""
check "empty_input_is_code" "rust=true" "\n\n"
check "lookalike_paths_are_code" "rust=true" "docs-extra/x.md"
check "lookalike_paths_are_code" "rust=true" "README.md.bak"
check "lookalike_paths_are_code" "rust=true" "Docs/x.md"
check "lookalike_paths_are_code" "rust=true" "docs"
check "lookalike_paths_are_code" "rust=true" "/docs/a.md"
check "lookalike_paths_are_code" "rust=true" "xdocs/a.md"
check "parent_directory_segments_are_code" "rust=true" "docs/../Cargo.toml"
check "parent_directory_segments_are_code" "rust=true" "docs/a/../../Cargo.toml"
check "parent_directory_segments_are_code" "rust=true" "docs/.."

echo "$pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
