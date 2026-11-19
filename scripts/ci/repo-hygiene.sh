#!/usr/bin/env bash
# The repository tracks no build output and no big file by accident.
#
# Fails when a tracked file (one that `git ls-files` lists) is
#   - under a directory named target, corpus, artifacts or coverage, at any depth, or
#   - larger than 1 MiB, unless its path is listed in scripts/ci/large-files-allowed.txt.
#
# Why: a fuzz crate once went into main without its .gitignore, and 1,145 files of build output
# (35 MiB compressed) became part of the history for good. A gate that looks at what is tracked
# would have stopped that pull request.
#
#   scripts/ci/repo-hygiene.sh [repository-directory]     (default: the current directory)
set -euo pipefail

root="${1:-.}"
limit=1048576
allowed="$root/scripts/ci/large-files-allowed.txt"
status=0

while IFS= read -r -d '' path; do
  case "/$path" in
    */target/* | */corpus/* | */artifacts/* | */coverage/*)
      echo "tracked build output: $path (add its directory to a .gitignore and untrack it)" >&2
      status=1
      continue
      ;;
  esac
  file="$root/$path"
  [[ -f "$file" && ! -L "$file" ]] || continue
  size="$(stat -c %s "$file")"
  if [[ "$size" -gt "$limit" ]]; then
    if [[ -f "$allowed" ]] && grep -qxF "$path" "$allowed"; then
      continue
    fi
    echo "tracked file over 1 MiB: $path ($size bytes); list it in scripts/ci/large-files-allowed.txt if it belongs here" >&2
    status=1
  fi
done < <(git -C "$root" ls-files -z)

if [[ "$status" -eq 0 ]]; then
  echo "No tracked build output and no file over 1 MiB."
fi
exit "$status"
