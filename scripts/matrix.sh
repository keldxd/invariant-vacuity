#!/usr/bin/env bash
# Runs every fixture (and every compat profile) against one forge binary.
# usage: scripts/matrix.sh /path/to/forge
set -u
FORGE="$1"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
fail=0
run() { # name, fixture, extra...
  local name="$1"; shift
  if out=$(python3 "$REPO/tests/check_fixtures.py" "$@" --forge "$FORGE" 2>&1); then
    echo "PASS $name"
  else
    echo "FAIL $name"; echo "$out" | tail -25; fail=1
  fi
}
run seeded "$REPO/fixtures/seeded"
run edge "$REPO/fixtures/edge"
run layout "$REPO/fixtures/layout"
run fail-on-revert "$REPO/fixtures/fail-on-revert"
for p in default solc080 solc084 solc087 solc0813 solc0819 viair optimized denywarnings dynlink; do
  FOUNDRY_PROFILE=$p run "compat:$p" "$REPO/fixtures/compat"
done
exit $fail
