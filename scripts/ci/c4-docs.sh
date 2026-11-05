#!/usr/bin/env bash
# Property: the Rust code names the C4 element it implements (ADR-0008).
#  1. Every crate root (src/lib.rs, src/main.rs) has one "//! C4 container: `<id>`" or
#     "//! C4 component: `<id>`" line, and <id> is that kind of element in
#     architecture/workspace.dsl, the C4 model in the LinuxHello/architecture submodule
#     (ADR-0011).
#  2. In a crate whose root names a container, every module the root declares, except
#     #[cfg(test)] modules, is in its own file whose //! docs have one
#     "//! C4 component: `<id>`" line, and <id> is a component of that container.
#  3. A crate's library and binary roots name the same element.
# Checks the repository that holds this script. Needs bash, awk, grep and sed.
set -euo pipefail
cd "$(dirname "$0")/../.."
[[ -f architecture/workspace.dsl ]] || {
  echo "::error::architecture/workspace.dsl not found: the C4 model is the LinuxHello/architecture submodule; run git submodule update --init"
  exit 1
}
fail=0
err() { echo "::error::$*"; fail=1; }
count() { grep -c . <<<"$1" || true; }

# "id kind parent-container" for each element in the DSL; parent is "-" unless a component.
elements="$(awk '
  {
    s = $0
    if (inc) { i = index(s, "*/"); if (!i) next; s = substr(s, i + 2); inc = 0 }
    while ((i = index(s, "/*")) > 0) {
      rest = substr(s, i + 2); j = index(rest, "*/")
      if (j) { s = substr(s, 1, i - 1) substr(rest, j + 2) } else { s = substr(s, 1, i - 1); inc = 1 }
    }
    if (s ~ /^[[:space:]]*#/) next
    sub(/(^|[[:space:]])\/\/.*$/, "", s)
    kind = ""; id = ""
    if (s ~ /^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=[[:space:]]*(softwareSystem|container|component|person)([^A-Za-z0-9_]|$)/) {
      t = s; sub(/^[[:space:]]*/, "", t)
      id = t; sub(/[[:space:]]*=.*$/, "", id)
      kind = t; sub(/^[^=]*=[[:space:]]*/, "", kind); sub(/[^A-Za-z].*$/, "", kind)
      parent = "-"
      if (kind == "component") for (d = depth; d > 0; d--) if (sk[d] == "container") { parent = sid[d]; break }
      print id, kind, parent
    }
    first = 1
    for (c = 1; c <= length(s); c++) {
      ch = substr(s, c, 1)
      if (ch == "{") { depth++; if (first && kind != "") { sk[depth] = kind; sid[depth] = id } else { sk[depth] = ""; sid[depth] = "" }; first = 0 }
      else if (ch == "}" && depth > 0) depth--
    }
  }' architecture/workspace.dsl)"

element() { awk -v id="$1" '$1 == id { print $2, $3; exit }' <<<"$elements"; }

# "kind id" for each C4 tag among the leading //! lines of a file.
tags() {
  awk '{ s = $0; sub(/^[[:space:]]+/, "", s)
         if (s ~ /^\/\/!/) print s; else if (s != "" && s !~ /^#!\[/) exit }' "$1" |
    sed -nE 's/^\/\/![[:space:]]*C4 (container|component): `([A-Za-z_][A-Za-z0-9_]*)`.*/\1 \2/p'
}

# "name inline cfg_test" for each module declared at the top level of a crate root.
modules() {
  awk '{
    s = $0; sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s)
    if (depth == 0) {
      if (s ~ /^#\[cfg\(([^)]*[^A-Za-z0-9_])?test([^A-Za-z0-9_]|$)/) pending = 1
      else {
        if (s ~ /^(pub(\([^)]*\))?[[:space:]]+)?mod[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*[;{]/) {
          n = s; sub(/^(pub(\([^)]*\))?[[:space:]]+)?mod[[:space:]]+/, "", n)
          inl = (n ~ /^[A-Za-z0-9_]+[[:space:]]*\{/) ? 1 : 0
          sub(/[^A-Za-z0-9_].*$/, "", n)
          print n, inl, pending
        }
        if (s != "" && s !~ /^#\[/ && s !~ /^\/\//) pending = 0
      }
    }
    depth += gsub(/\{/, "{", $0) - gsub(/\}/, "}", $0)
  }' "$1"
}

crates=0
for dir in crates/*/; do
  dir=${dir%/}
  [[ -f "$dir/Cargo.toml" ]] || continue
  crates=$((crates + 1))
  named=()
  for root in "$dir/src/lib.rs" "$dir/src/main.rs"; do
    [[ -f "$root" ]] || continue
    found="$(tags "$root")"
    if [[ "$(count "$found")" != 1 ]]; then
      err "$root: needs exactly one '//! C4 container: \`<id>\`' or '//! C4 component: \`<id>\`' line, found $(count "$found")"
      continue
    fi
    read -r kind ident <<<"$found"
    read -r ekind _ <<<"$(element "$ident")" || true
    if [[ "${ekind:-}" != "$kind" ]]; then
      err "$root: C4 $kind \`$ident\` is not a $kind in architecture/workspace.dsl"
      continue
    fi
    named+=("$kind $ident")
    [[ "$kind" == container ]] || continue
    while read -r name inline cfg_test; do
      [[ -n "$name" && "$cfg_test" == 0 ]] || continue
      if [[ "$inline" == 1 ]]; then
        err "$root: module \`$name\` is inline; a component module lives in its own file"
        continue
      fi
      src="$(dirname "$root")"
      if [[ -f "$src/$name.rs" ]]; then mod_file="$src/$name.rs"
      elif [[ -f "$src/$name/mod.rs" ]]; then mod_file="$src/$name/mod.rs"
      else err "$root: module \`$name\` has no file"; continue; fi
      mtags="$(tags "$mod_file")"
      if [[ "$(count "$mtags")" != 1 || "$mtags" != component\ * ]]; then
        err "$mod_file: needs exactly one '//! C4 component: \`<id>\`' line (a component of \`$ident\`)"
        continue
      fi
      cid="${mtags#component }"
      if [[ "$(element "$cid")" != "component $ident" ]]; then
        err "$mod_file: C4 component \`$cid\` is not a component of container \`$ident\` in architecture/workspace.dsl"
      fi
    done < <(modules "$root")
  done
  if ((${#named[@]} > 1)) && [[ "$(printf '%s\n' "${named[@]}" | sort -u | wc -l)" -gt 1 ]]; then
    err "$dir: its library and binary roots name different C4 elements: ${named[*]}"
  fi
done

if [[ $fail == 0 ]]; then echo "C4 documentation property holds for $crates crates"; fi
exit "$fail"
