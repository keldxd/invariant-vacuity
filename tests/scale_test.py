#!/usr/bin/env python3
"""Scale test: generates a project with N test contracts x 3 invariants, runs vacuity,
and checks every verdict, the runtime and that nothing is left behind.

usage: scale_test.py [--contracts N] [--forge PATH] [--keep DIR]

Each contract i gets its own handler and three invariants:
  invariant_live   reads a counter the handler increments           -> live
  invariant_frozen reads values nothing can change (1 + --slots slots) -> frozen
  invariant_flag   reads a flag only set on an unreachable branch    -> frozen-guarded
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SHARED = os.path.join(REPO, "fixtures", "shared", "MiniInvariant.sol")

SRC = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Handler{i} {{
    uint256 public count;
    bool public broken;
    uint256 public immutable fixedValue = {i} + 1;
    uint256 public constValue;
    uint256[{slots}] internal table;
    constructor() {{
        constValue = {i};
        for (uint256 k = 0; k < {slots}; k++) table[k] = k + 1;
    }}
    function sumValues() external view returns (uint256 s) {{
        for (uint256 k = 0; k < {slots}; k++) s += table[k];
    }}
    function inc(uint256 x) external {{
        count += 1;
        // the flag is only set on a branch the fuzzer cannot reach (x would need to be
        // both above and below the same bound), so it stays false
        if (x > type(uint256).max - 1 && x < 5) broken = true;
    }}
}}
"""

TEST = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "../src/MiniInvariant.sol";
import "../src/Handler{i}.sol";

contract Scale{i} is MiniInvariant {{
    Handler{i} internal h;
    function setUp() public {{
        h = new Handler{i}();
        targetContract(address(h));
    }}
    function invariant_live() public view {{ require(h.count() < type(uint128).max, "a"); }}
    function invariant_frozen() public view {{
        require(h.constValue() == {i}, "b");
        require(h.sumValues() == {slots} * ({slots} + 1) / 2, "t");
    }}
    function invariant_flag() public view {{ require(!h.broken(), "c"); }}
}}
"""

TOML = """[profile.default]
src = "src"
test = "test"
libs = []
solc_version = "0.8.28"
offline = true

[profile.default.invariant]
runs = 32
depth = 25
"""


def generate(d: str, n: int, slots: int) -> None:
    os.makedirs(os.path.join(d, "src"))
    os.makedirs(os.path.join(d, "test"))
    shutil.copy(SHARED, os.path.join(d, "src", "MiniInvariant.sol"))
    with open(os.path.join(d, "foundry.toml"), "w") as fh:
        fh.write(TOML)
    for i in range(n):
        with open(os.path.join(d, "src", f"Handler{i}.sol"), "w") as fh:
            fh.write(SRC.format(i=i, slots=slots))
        with open(os.path.join(d, "test", f"Scale{i}.t.sol"), "w") as fh:
            fh.write(TEST.format(i=i, slots=slots))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--contracts", type=int, default=30)
    ap.add_argument("--forge", default=None)
    ap.add_argument("--keep", default=None)
    ap.add_argument("--slots", type=int, default=1,
                    help="storage slots each frozen invariant reads; large values force the probe "
                         "inputs to be split across several forge runs")
    a = ap.parse_args()

    d = a.keep or tempfile.mkdtemp(prefix="vacuity-scale-")
    if a.keep:
        shutil.rmtree(d, ignore_errors=True)
    generate(d, a.contracts, a.slots)
    cmd = [sys.executable, "-m", "vacuity", "--root", d, "--format", "json"]
    if a.forge:
        cmd += ["--forge", a.forge]
    env = dict(os.environ, PYTHONPATH=REPO)
    t0 = time.time()
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    took = time.time() - t0
    problems = []
    try:
        rep = json.loads(p.stdout)
    except json.JSONDecodeError:
        print(p.stderr[-3000:])
        print("FAIL: no JSON")
        return 1
    want = {"invariant_live()": "live", "invariant_frozen()": "frozen", "invariant_flag()": "frozen-guarded"}
    seen = 0
    for c in rep["contracts"]:
        for inv in c["invariants"]:
            seen += 1
            exp = want.get(inv["name"])
            if inv["verdict"] != exp:
                problems.append(f"{c['contract']} {inv['name']}: expected {exp}, got {inv['verdict']}")
    if seen != 3 * a.contracts:
        problems.append(f"expected {3 * a.contracts} invariants in the report, got {seen}")
    if p.returncode != 1:
        problems.append(f"exit code {p.returncode}, expected 1")
    if rep["summary"]["errors"] != a.contracts or rep["summary"]["warnings"] != a.contracts:
        problems.append(f"summary {rep['summary']}, expected {a.contracts} errors and {a.contracts} warnings")
    if os.path.exists(os.path.join(d, "test", "__vacuity__")):
        problems.append("probe directory left behind")
    if not a.keep:
        shutil.rmtree(d, ignore_errors=True)
    status = "PASS" if not problems else "FAIL"
    print(f"{status} scale: {a.contracts} contracts, {seen} invariants, {a.slots} slots each, {took:.0f}s")
    for pr in problems[:20]:
        print("  -", pr)
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
