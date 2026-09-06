#!/usr/bin/env bash
# Runs everything: both engines on their own, then against each other.
# The two implementations must agree byte for byte, so the cross-check is the
# part that actually matters -- a change to one of them alone will fail here.
set -u
cd "$(dirname "$0")/.."

PYTHON="${PYTHON:-python3}"
[ -x .venv/bin/python ] && PYTHON=.venv/bin/python
NODE="${NODE:-node}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fail=0
step() { printf '\n=== %s ===\n' "$1"; }

step "python engine selftest"
"$PYTHON" stegocomms.py selftest || fail=1

step "browser engine selftest"
"$NODE" tests/js_selftest.mjs || fail=1

step "interop: browser encodes, python decodes"
"$NODE" tests/interop.mjs write "$tmp" || fail=1
"$PYTHON" tests/interop.py verify "$tmp" || fail=1

step "interop: python encodes, browser decodes"
"$PYTHON" tests/interop.py write "$tmp" || fail=1
"$NODE" tests/interop.mjs verify "$tmp" || fail=1

step "word lists: invariants and agreement between implementations"
"$PYTHON" tests/vocabulary.py || fail=1

step "passphrase strength: both sides must agree"
"$PYTHON" tests/passphrase.py || fail=1

if [ "$fail" -eq 0 ]; then
  printf '\nALL GREEN\n'
else
  printf '\nFAILURES -- see above\n'
fi
exit "$fail"
