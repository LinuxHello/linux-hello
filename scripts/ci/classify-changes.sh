#!/usr/bin/env bash
# Reads changed file paths from stdin and prints whether they are Rust code.
# Prints 'rust=false' if every non-blank line is a documentation path.
# Prints 'rust=true' otherwise (including empty input).
#
# Usage: stdin | classify-changes.sh
set -euo pipefail

is_doc_path() {
  local path="$1"
  case "$path" in
    README.md|GOVERNANCE.md|SECURITY.md|CONTRIBUTING.md|AGENTS.md|CLAUDE.md)
      return 0
      ;;
    docs/*)
      # Check for '..' in any segment of the path
      case "$path" in
        *..*) return 1 ;;
        *) return 0 ;;
      esac
      ;;
    *)
      return 1
      ;;
  esac
}

all_docs=true
has_content=false

while IFS= read -r line || [[ -n "$line" ]]; do
  # Skip blank lines
  [[ -z "${line// }" ]] && continue
  
  has_content=true
  if ! is_doc_path "$line"; then
    all_docs=false
    break
  fi
done

if [[ "$has_content" == "true" ]] && [[ "$all_docs" == "true" ]]; then
  echo "rust=false"
else
  echo "rust=true"
fi
