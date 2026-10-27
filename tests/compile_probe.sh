#!/usr/bin/env bash
# Compiles a generated probe with every solc binary found under ~/.svm and fails
# on any compiler warning other than contract/initcode size (which Forge ignores
# by default and which the probe cannot avoid because it embeds the test contract).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/test"
cat > "$WORK/test/User.t.sol" <<'SOL'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract C { uint256 public x; function inc() external { x += 1; } }
/// forge-config: default.invariant.runs = 5
contract UserTest {
    C internal c;
    function setUp() public { c = new C(); }
    /// forge-config: default.invariant.depth = 3
    function invariant_a() public view { require(c.x() < type(uint128).max, "a"); }
    function invariant_b() public view { require(c.x() < type(uint128).max, "b"); }
}
SOL
PYTHONPATH="$REPO" python3 - "$WORK" <<'PY'
import sys
from vacuity.probe_gen import generate_files, ProbeTarget
from vacuity.keccak import selector
w = sys.argv[1]
t = ProbeTarget(0, "UserTest", "test/User.t.sol", True, ["invariant_a()", "invariant_b()"],
                [selector("invariant_a()"), selector("invariant_b()")],
                ["forge-config: default.invariant.runs = 5"], [["forge-config: default.invariant.depth = 3"], []])
import os
os.makedirs(f"{w}/test/__vacuity__", exist_ok=True)
for fn, code in generate_files([t], 2**96 - 1):
    open(f"{w}/test/__vacuity__/{fn}", "w").write(code)
PY
status=0
found=0
for solc in "$HOME"/.svm/*/solc-*; do
  [ -x "$solc" ] || continue
  found=1
  ver="$(basename "$solc")"
  out="$(cd "$WORK" && "$solc" --allow-paths . --bin test/__vacuity__/VacuityProbe_0.t.sol 2>&1 >/dev/null || true)"
  if echo "$out" | grep -q "^Error"; then
    echo "FAIL $ver: compile error"; echo "$out" | head -20; status=1; continue
  fi
  warnings="$(echo "$out" | grep "^Warning" | grep -v "Contract code size" | grep -v "initcode size" || true)"
  if [ -n "$warnings" ]; then
    echo "FAIL $ver: warnings"; echo "$out" | grep -A3 "^Warning" | head -20; status=1
  else
    echo "ok   $ver"
  fi
done
[ "$found" = 1 ] || { echo "no solc binaries under ~/.svm"; exit 1; }
exit $status
