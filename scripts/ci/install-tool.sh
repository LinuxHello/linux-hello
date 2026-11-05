#!/usr/bin/env bash
# Install a pinned CI tool from its upstream release binary instead of compiling
# it with `cargo install`. The archive must match the SHA-256 pinned here, or
# nothing is installed and the script fails.
#
#   scripts/ci/install-tool.sh cargo-audit|cargo-fuzz [install-dir]
#
# install-dir defaults to ~/.cargo/bin, where cargo finds subcommands. Linux
# x86_64 only (the CI runners); elsewhere use `cargo install <tool> --locked`.
# To upgrade a tool, change its version, URL and hash together; the hash is the
# one GitHub shows for the release asset.
set -euo pipefail

tool="${1:?usage: install-tool.sh cargo-audit|cargo-fuzz [install-dir]}"
dest="${2:-${CARGO_HOME:-$HOME/.cargo}/bin}"

case "$tool" in
  cargo-audit)
    version=0.22.2
    url="https://github.com/rustsec/rustsec/releases/download/cargo-audit/v$version/cargo-audit-x86_64-unknown-linux-musl-v$version.tgz"
    sha256=7fb9497f8594b389e5fce5ef9b92db08432996895b2e0c5a0167a69ed445c428
    member="cargo-audit-x86_64-unknown-linux-musl-v$version/cargo-audit"
    ;;
  cargo-fuzz)
    version=0.13.2
    url="https://github.com/rust-fuzz/cargo-fuzz/releases/download/$version/cargo-fuzz-$version-x86_64-unknown-linux-musl.tar.gz"
    sha256=b5b704018b63e0f151c17a057ac53b5111e1db545d1b9f72fee79f08a545931c
    member="cargo-fuzz"
    ;;
  *)
    echo "unknown tool: $tool (known: cargo-audit, cargo-fuzz)" >&2
    exit 1
    ;;
esac

if [[ "$(uname -s)-$(uname -m)" != Linux-x86_64 ]]; then
  echo "$tool: prebuilt binary pinned for Linux x86_64 only; run: cargo install $tool --version $version --locked" >&2
  exit 1
fi

# Already installed at the pinned version: nothing to do.
if "$dest/$tool" "${tool#cargo-}" --version 2>/dev/null | grep -qw "$version"; then
  echo "$tool $version already installed in $dest"
  exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --retry 3 --output "$work/archive.tgz" "$url"
echo "$sha256  $work/archive.tgz" | sha256sum --check --strict --quiet -

tar -xzf "$work/archive.tgz" -C "$work" "$member"
mkdir -p "$dest"
install -m 0755 "$work/$member" "$dest/$tool"
"$dest/$tool" "${tool#cargo-}" --version
