#!/usr/bin/env bash
# The rule of ADR-0026 for the Auth Prompt: its sources start no program and open nothing outside
# the module. Fails on any way QML or JavaScript could do it. Run by tests/run.sh.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
found=$(grep -rnE 'QProcess|Process *\{|Qt\.openUrlExternally|XMLHttpRequest|Qt\.createQmlObject|LocalStorage|execv|system\(' \
          "$here/io" "$here/demo"/*.qml "$here/demo"/*.js || true)
if [[ -n "$found" ]]; then
  echo "the Auth Prompt must start no program and open nothing (ADR-0026):" >&2
  echo "$found" >&2
  exit 1
fi
echo "PASS the_auth_prompt_starts_no_program"
