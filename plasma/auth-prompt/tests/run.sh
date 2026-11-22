#!/usr/bin/env bash
# Runs the Auth Prompt's Qt Quick tests without a screen. Needs Qt 6's qmltestrunner and the QtTest
# QML module (Ubuntu: qt6-declarative-dev-tools, qml6-module-qttest, qml6-module-qtquick).
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
runner=$(command -v qmltestrunner6 || command -v qmltestrunner || echo /usr/lib/qt6/bin/qmltestrunner)
[[ -x "$runner" ]] || { echo "qmltestrunner (Qt 6) not found: sudo apt install qt6-declarative-dev-tools qml6-module-qttest" >&2; exit 2; }
bash "$here/tests/starts-no-program.sh"
QT_QPA_PLATFORM=offscreen "$runner" -import "$here" -input "$here/tests"
