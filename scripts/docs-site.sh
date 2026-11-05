#!/usr/bin/env bash
# Build the code-level documentation site (ADR-0008, amendment 2026-11-05):
# rustdoc for every crate, private items included, plus a structure tree and a
# dependency graph for every crate target, generated from the code. Nothing here
# is drawn by hand or committed; the site describes the commit it was built from.
#
#   scripts/docs-site.sh [out-dir]    (default: target/docs-site)
#
# Needs: cargo, jq, cargo-modules (pinned version below) and Graphviz `dot`.
# Fails if any of them is missing, or if any target's diagram cannot be generated.
set -euo pipefail

cargo_modules_version=0.28.0
root="$(git rev-parse --show-toplevel)"
out="$(realpath -m "${1:-$root/target/docs-site}")"
cd "$root"

die() { echo "docs-site: $*" >&2; exit 1; }
command -v jq >/dev/null || die "jq is not installed"
command -v dot >/dev/null || die "Graphviz is not installed (dot not found)"
cargo modules --version 2>/dev/null | grep -qw "$cargo_modules_version" \
  || die "cargo-modules $cargo_modules_version is not installed: cargo install cargo-modules --version $cargo_modules_version --locked"

rm -rf "$out"
mkdir -p "$out/diagrams"

# 1. Rustdoc, as the docs gate builds it.
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items --quiet
cp -r target/doc "$out/rustdoc"

# html_escape <text>: the text, safe inside HTML.
html_escape() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g' <<<"$1"; }

# c4_of <file>: the C4 line of a crate root or module, e.g. "container agent".
c4_of() { sed -n 's/^\/\/! C4 \(container\|component\): `\([A-Za-z0-9_]*\)`.*/\1 \2/p' "$1" | head -n 1; }

# 2. Per target: structure tree and dependency graph.
rows=""
while IFS=$'\t' read -r package kind name src manifest; do
  case "$kind" in
    lib | cdylib | rlib) sel=(--lib) ;;
    bin) sel=(--bin "$name") ;;
    *) continue ;;
  esac
  id="${package}--${kind}-${name}"
  cargo modules structure --package "$package" "${sel[@]}" --manifest-path "$manifest" \
    | sed 's/\x1b\[[0-9;]*m//g' >"$out/diagrams/$id.txt" \
    || die "structure tree failed for $package ($kind $name)"
  # Record-shaped nodes crash dot's layout on some graphs; plain boxes do not.
  cargo modules dependencies --package "$package" "${sel[@]}" --manifest-path "$manifest" \
      --no-externs --no-sysroot --no-fns --layout dot --splines spline \
    | sed -e 's/shape="record"/shape="box"/' -e '/\[label="[^"]*|/ s/\(label="[^"|]*\)|/\1\\n/' \
    >"$out/diagrams/$id.dot" || die "dependency graph failed for $package ($kind $name)"
  dot -Tsvg "$out/diagrams/$id.dot" -o "$out/diagrams/$id.svg" \
    || die "Graphviz could not render $id.dot"

  c4="$(c4_of "$src")"
  crate_doc="rustdoc/${name//-/_}/index.html"
  rows+="<tr><td>$(html_escape "${c4:-—}")</td><td><code>$(html_escape "$package")</code> ($kind <code>$(html_escape "$name")</code>)</td>"
  rows+="<td><a href=\"$crate_doc\">rustdoc</a></td><td><a href=\"diagrams/$id.svg\">graph</a></td>"
  rows+="<td><a href=\"diagrams/$id.txt\">tree</a></td></tr>"$'\n'

  # Component modules declared in this target's root, with their C4 ids.
  while IFS= read -r mod_file; do
    mc4="$(c4_of "$mod_file")"
    [[ -n "$mc4" ]] || continue
    mod="$(basename "$(dirname "$mod_file")")"
    [[ "$mod_file" == */mod.rs ]] || mod="$(basename "$mod_file" .rs)"
    grep -Eq "^[[:space:]]*(pub(\([a-z]+\))?[[:space:]]+)?mod[[:space:]]+$mod[[:space:]]*;" "$src" || continue
    rows+="<tr><td>&nbsp;&nbsp;$(html_escape "$mc4")</td><td>&nbsp;&nbsp;module <code>$(html_escape "$mod")</code></td>"
    rows+="<td><a href=\"rustdoc/${name//-/_}/$mod/index.html\">rustdoc</a></td><td></td><td></td></tr>"$'\n'
  done < <(find "$(dirname "$src")" -maxdepth 2 \( -name mod.rs -o -name '*.rs' \) ! -samefile "$src" | sort)
done < <(cargo metadata --no-deps --format-version 1 | jq -r '
  .packages[] as $p | $p.targets[]
  | select(.kind[0] | IN("lib", "cdylib", "rlib", "bin"))
  | [$p.name, .kind[0], .name, .src_path, $p.manifest_path] | @tsv')

# 3. Index.
commit="$(git rev-parse HEAD)"
cat >"$out/index.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Linux Hello: code documentation</title>
<style>
body { font-family: sans-serif; max-width: 60rem; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: .3rem .6rem; border-bottom: 1px solid #ddd; }
code { font-size: .95em; }
</style>
</head>
<body>
<h1>Linux Hello: code documentation</h1>
<p>The code level (C4 level 4) of <a href="https://github.com/LinuxHello/linux-hello">linux-hello</a> at commit
<a href="https://github.com/LinuxHello/linux-hello/commit/$commit"><code>${commit:0:7}</code></a>.
Everything here is generated from that commit: rustdoc with private items, and for every crate target a dependency graph
(modules, types and traits; solid edges "owns", dashed "uses") and a structure tree, made with cargo-modules $cargo_modules_version
(<a href="https://github.com/LinuxHello/architecture/blob/main/adr/0008-code-documentation-mapped-to-c4.md">ADR-0008</a>).</p>
<p>Levels 1 to 3 (system context, containers, components) are in the C4 model,
<a href="https://github.com/LinuxHello/architecture/blob/main/workspace.dsl">workspace.dsl</a>, and the
<a href="https://github.com/LinuxHello/architecture/blob/main/arc42/README.md">Arc42 sections</a>.</p>
<table>
<thead><tr><th>C4 element</th><th>Crate target / module</th><th colspan="3">Code level</th></tr></thead>
<tbody>
$rows</tbody>
</table>
</body>
</html>
EOF
echo "docs-site: $out ($(find "$out/diagrams" -name '*.svg' | wc -l) graphs)"
