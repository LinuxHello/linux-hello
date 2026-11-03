#!/usr/bin/env bash
# Build the release artifacts for one crate tag and write them to dist/:
# the binaries (bin and cdylib targets), a source archive, a CycloneDX SBOM
# and SHA256SUMS. Used by the release workflow; runs the same way locally.
#
#   scripts/ci/release-build.sh <tag>      e.g. agent-v0.1.0
#
# Fails closed: unknown tag prefix, a tag version that differs from the crate
# version, a dirty tree or a crate with no binary targets stops the build.
set -euo pipefail

tag="${1:?usage: release-build.sh <tag>  e.g. agent-v0.1.0}"
root="$(git rev-parse --show-toplevel)"
cd "$root"

for tool in jq cargo-cyclonedx; do
  command -v "$tool" >/dev/null || { echo "$tool is not installed" >&2; exit 1; }
done

prefix="${tag%-v*}"
version="${tag##*-v}"
case "$prefix" in
  agent)        crate=linuxhello-agent ;;
  ctl)          crate=linuxhello-ctl ;;
  pam)          crate=pam-linuxhello ;;
  tpm-provider) crate=linuxhello-tpm-provider ;;
  kpxc-bridge)  crate=linuxhello-kpxc-bridge ;;
  *) echo "Unknown tag prefix '$prefix' in '$tag'" >&2; exit 1 ;;
esac

crate_version="$(cargo metadata --format-version 1 --no-deps --locked |
  jq -r --arg c "$crate" '.packages[] | select(.name == $c) | .version')"
if [ "$crate_version" != "$version" ]; then
  echo "Tag $tag says $version but $crate is $crate_version" >&2
  exit 1
fi

if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "Working tree is dirty; release builds come from a clean checkout" >&2
  exit 1
fi

rm -rf dist
mkdir -p dist

# Binaries: every bin or cdylib artifact of this crate, as cargo reports them.
mapfile -t artifacts < <(
  cargo build --release --locked -p "$crate" --message-format=json |
    jq -r --arg c "$crate" '
      select(.reason == "compiler-artifact" and .target.name != null)
      | select(.package_id | test("[/#]" + $c + "[@#]"))
      | select(any(.target.kind[]; . == "bin" or . == "cdylib"))
      | (.executable // (.filenames[] | select(endswith(".so"))))'
)
if [ "${#artifacts[@]}" -eq 0 ]; then
  echo "$crate has no bin or cdylib target; nothing to release" >&2
  exit 1
fi
cp "${artifacts[@]}" dist/

# Source archive of exactly the tagged commit.
git archive --format=tar.gz --prefix="$tag/" -o "dist/$tag-source.tar.gz" HEAD

# SBOM: every dependency of this crate at the exact version in Cargo.lock.
cargo cyclonedx --manifest-path "crates/$crate/Cargo.toml" --format json \
  --spec-version 1.5 --all --override-filename "$tag.cdx"
# cargo-cyclonedx 0.5.9 writes one SBOM per workspace member, whatever the
# manifest path; keep this crate's and remove the rest.
mv "crates/$crate/$tag.cdx.json" dist/
find crates -maxdepth 2 -name "$tag.cdx.json" -delete

(cd dist && sha256sum -- * > SHA256SUMS)
echo "Built $tag:"
cat dist/SHA256SUMS
