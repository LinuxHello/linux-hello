#!/usr/bin/env bash
# Tests for c4-docs.sh against small fixture repositories, each with its own copy of
# the script. Needs bash, awk, grep and sed.
#
#   scripts/ci/test-c4-docs.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
check="$here/c4-docs.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0 fail=0

# A fixture repository: one container `agent` with components `policyEngine` and
# `pinManager`, a second container `cli` with component `cliCommands`.
fixture() {
  local d="$work/$1"
  rm -rf "$d"
  mkdir -p "$d/docs/architecture" "$d/crates/agent/src/policy" "$d/crates/ctl/src" "$d/scripts/ci"
  cp "$check" "$d/scripts/ci/c4-docs.sh"
  cat >"$d/docs/architecture/workspace.dsl" <<'EOF'
/* comment */
workspace "W" {
    model {
        # People
        user = person "User"
        sys = softwareSystem "S" {
            agent = container "Agent" "" "Rust" {
                policyEngine = component "Policy" "" "Rust"
                pinManager = component "PIN" "" "Rust"
            }
            cli = container "CLI" {
                cliCommands = component "Commands"
            }
        }
    }
    views {
        component agent "Agent" {
            include *
        }
    }
}
EOF
  touch "$d/crates/agent/Cargo.toml" "$d/crates/ctl/Cargo.toml"
  printf '%s\n' '//! Agent library.' '//!' '//! C4 container: `agent`' '' '#![forbid(unsafe_code)]' '' 'pub mod policy;' '' \
    '#[cfg(test)]' 'mod tests {' '    mod nested;' '}' >"$d/crates/agent/src/lib.rs"
  printf '%s\n' '//! Agent daemon.' '//! C4 container: `agent`' '' 'fn main() {}' >"$d/crates/agent/src/main.rs"
  printf '%s\n' '//! Policy.' '//!' '//! C4 component: `policyEngine`' '' 'pub mod schema;' >"$d/crates/agent/src/policy/mod.rs"
  printf '%s\n' '//! Schema: code level, no tag needed.' >"$d/crates/agent/src/policy/schema.rs"
  printf '%s\n' '//! CLI.' '//! C4 container: `cli`' '' 'fn main() {}' >"$d/crates/ctl/src/main.rs"
  echo "$d"
}

expect() { # expect <0|1> <test name> <repo> [message the output must contain]
  local want="$1" name="$2" repo="$3" msg="${4:-}" out rc=0
  out="$(bash "$repo/scripts/ci/c4-docs.sh" 2>&1)" || rc=$?
  if [[ "$rc" == "$want" && ( -z "$msg" || "$out" == *"$msg"* ) ]]; then
    pass=$((pass + 1)); echo "ok   $name"
  else
    fail=$((fail + 1)); echo "FAIL $name (exit $rc, want $want)"; echo "$out" | sed 's/^/     /'
  fi
}

r="$(fixture valid)"
expect 0 documented_workspace_passes "$r"

r="$(fixture no_root_tag)"
sed -i '/C4 container/d' "$r/crates/ctl/src/main.rs"
expect 1 crate_root_without_c4_element_is_refused "$r" "crates/ctl/src/main.rs: needs exactly one"

r="$(fixture unknown_id)"
sed -i 's/`cli`/`commandLine`/' "$r/crates/ctl/src/main.rs"
expect 1 crate_root_naming_an_element_not_in_the_dsl_is_refused "$r" "is not a container"

r="$(fixture wrong_kind)"
sed -i 's/C4 container: `cli`/C4 container: `cliCommands`/' "$r/crates/ctl/src/main.rs"
expect 1 crate_root_naming_a_component_as_container_is_refused "$r" "is not a container"

r="$(fixture view_not_model)"
printf '%s\n' '//! C4 container: `user`' >"$r/crates/ctl/src/main.rs"
expect 1 person_is_not_accepted_as_container "$r" "is not a container"

r="$(fixture module_untagged)"
sed -i '/C4 component/d' "$r/crates/agent/src/policy/mod.rs"
expect 1 top_level_module_without_component_is_refused "$r" "policy/mod.rs: needs exactly one"

r="$(fixture module_other_container)"
sed -i 's/policyEngine/cliCommands/' "$r/crates/agent/src/policy/mod.rs"
expect 1 module_naming_component_of_another_container_is_refused "$r" "is not a component of container \`agent\`"

r="$(fixture inline_module)"
printf '%s\n' 'mod helpers {' '}' >>"$r/crates/agent/src/lib.rs"
expect 1 inline_non_test_module_is_refused "$r" "module \`helpers\` is inline"

r="$(fixture root_mismatch)"
sed -i 's/`agent`/`cli`/' "$r/crates/agent/src/main.rs"
expect 1 library_and_binary_naming_different_elements_are_refused "$r" "name different C4 elements"

r="$(fixture component_crate)"
printf '%s\n' '//! Shared contract.' '//! C4 component: `pinManager`' '' 'pub mod anything;' >"$r/crates/ctl/src/main.rs"
expect 0 crate_naming_a_component_needs_no_module_tags "$r"

r="$(fixture nested_brace)"
printf '%s\n' 'pub fn f() {' '    mod not_top_level {}' '}' >>"$r/crates/agent/src/lib.rs"
expect 0 modules_inside_functions_are_not_component_modules "$r"

echo "$pass passed, $fail failed"
[[ "$fail" == 0 ]]
