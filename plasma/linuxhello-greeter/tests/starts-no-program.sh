#!/usr/bin/env bash
# The rule of ADR-0026 for the greeter's window: its QML and JavaScript start no program and open
# nothing; greetd starts the desktop. Fails on any way QML or JavaScript could do it. Run by
# tests/run.sh.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
found=$(grep -rnE 'QProcess|Process *\{|Qt\.openUrlExternally|XMLHttpRequest|Qt\.createQmlObject|LocalStorage|execv|system\(' \
          "$here/qml" "$here/demo"/*.qml "$here/demo"/*.js || true)
if [[ -n "$found" ]]; then
  echo "the greeter must start no program and open nothing (ADR-0026):" >&2
  echo "$found" >&2
  exit 1
fi
echo "PASS the_greeter_starts_no_program"
