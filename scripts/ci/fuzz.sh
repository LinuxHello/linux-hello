#!/usr/bin/env bash
# Run every cargo-fuzz target in the repository for a fixed time each.
# Used by the `fuzz` CI job and `make fuzz`. Exits non-zero if any target crashes.
#
#   scripts/ci/fuzz.sh [seconds-per-target]   (default 60)
#
# Each fuzz directory pins its nightly in rust-toolchain.toml; the script runs
# from that directory so rustup picks it up.
set -euo pipefail

seconds="${1:-60}"
root="$(git rev-parse --show-toplevel)"
cd "$root"

cargo fuzz --version >/dev/null 2>&1 || { # cargo finds subcommands in ~/.cargo/bin even when PATH does not
  echo "cargo-fuzz is not installed: cargo install cargo-fuzz --version 0.13.2 --locked" >&2
  exit 1
}

# Tracked and new (untracked, not ignored) fuzz crates, so `make gates` sees a
# target before it is committed.
mapfile -t fuzz_dirs < <(git ls-files --cached --others --exclude-standard '*/fuzz/Cargo.toml' |
  sort -u | xargs -r -n1 dirname)
if [[ "${#fuzz_dirs[@]}" -eq 0 ]]; then
  echo "No fuzz targets found." >&2
  exit 1
fi

# No subshell or `|| status=1` here: set -e is ignored inside a command list
# like that, and a crash would then pass. The first failing target stops the run.
for dir in "${fuzz_dirs[@]}"; do
  pushd "$dir" >/dev/null
  # Name the pinned channel explicitly: older rustup releases cannot install from
  # rust-toolchain.toml without one.
  channel="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml)"
  [[ -n "$channel" ]] || { echo "$dir/rust-toolchain.toml names no channel" >&2; exit 1; }
  rustup toolchain install "$channel" --profile minimal >/dev/null
  for target in $(cargo fuzz list --fuzz-dir .); do
    echo "::group::fuzz $dir/$target (${seconds}s)"
    mkdir -p "corpus/$target"
    seeds=()
    [[ -d "seeds/$target" ]] && seeds=("seeds/$target")
    cargo fuzz run --fuzz-dir . "$target" "corpus/$target" "${seeds[@]}" -- \
      -max_total_time="$seconds"
    echo "::endgroup::"
  done
  popd >/dev/null
done
