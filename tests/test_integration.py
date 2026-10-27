"""Integration tests that need forge on PATH (skipped otherwise).

Covers behaviour around the user's files: the generated probe is always removed,
the user's own build output and cache are never touched, interruption cleans up,
and compile errors are reported clearly.
"""

from __future__ import annotations

import hashlib
import json
import re
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SHARED = os.path.join(REPO, "fixtures", "shared", "MiniInvariant.sol")
FORGE = shutil.which("forge") or os.path.expanduser("~/.foundry/bin/forge")
HAVE_FORGE = os.path.isfile(FORGE)

TOML = """[profile.default]
src = "src"
test = "test"
libs = []
solc_version = "0.8.28"
offline = true

[profile.default.invariant]
runs = {runs}
depth = {depth}
"""

SUITE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "../src/MiniInvariant.sol";

contract Suite is MiniInvariant {
    MiniCounter internal c;
    MiniNoop internal n;
    function setUp() public {
        c = new MiniCounter();
        n = new MiniNoop();
        targetContract(address(c));
    }
    function invariant_live() public view { require(c.count() < type(uint128).max, "x"); }
    function invariant_frozen() public view { require(n.value() == 7, "y"); }
}
"""


def make_project(d: str, suite: str = SUITE, runs: int = 8, depth: int = 10) -> None:
    os.makedirs(os.path.join(d, "src"), exist_ok=True)
    os.makedirs(os.path.join(d, "test"), exist_ok=True)
    shutil.copy(SHARED, os.path.join(d, "src", "MiniInvariant.sol"))
    with open(os.path.join(d, "foundry.toml"), "w") as fh:
        fh.write(TOML.format(runs=runs, depth=depth))
    with open(os.path.join(d, "test", "Suite.t.sol"), "w") as fh:
        fh.write(suite)


def vacuity(d: str, *args: str, **kw):
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO
    env["PATH"] = os.path.dirname(FORGE) + os.pathsep + env.get("PATH", "")
    return subprocess.run([sys.executable, "-m", "vacuity", "--root", d, *args],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, **kw)


def probe_left(d: str) -> bool:
    return os.path.exists(os.path.join(d, "test", "__vacuity__"))


@unittest.skipUnless(HAVE_FORGE, "forge not installed")
class IntegrationTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="vacuity-it-")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_basic_run_and_cleanup(self):
        make_project(self.d)
        r = vacuity(self.d, "--format", "json")
        self.assertEqual(r.returncode, 1, r.stderr)
        rep = json.loads(r.stdout)
        verdicts = {i["name"]: i["verdict"] for c in rep["contracts"] for i in c["invariants"]}
        self.assertEqual(verdicts, {"invariant_live()": "live", "invariant_frozen()": "frozen"})
        self.assertFalse(probe_left(self.d), "generated probe left behind")

    def test_user_out_and_cache_untouched(self):
        make_project(self.d)
        subprocess.run([FORGE, "build"], cwd=self.d, check=True, capture_output=True)
        out_dir = os.path.join(self.d, "out")
        cache_file = os.path.join(self.d, "cache", "solidity-files-cache.json")

        def snapshot():
            # contents and modification times of every file in out/ plus the build cache
            files = {}
            paths = [os.path.join(r, n) for r, _, ns in os.walk(out_dir) for n in ns] + [cache_file]
            for p in paths:
                with open(p, "rb") as fh:
                    files[p] = (hashlib.sha256(fh.read()).hexdigest(), os.path.getmtime(p))
            return files

        before = snapshot()
        time.sleep(1.1)
        r = vacuity(self.d)
        self.assertIn(r.returncode, (0, 1), r.stderr)
        self.assertEqual(snapshot(), before, "vacuity modified the user's out/ or cache file")

    def test_keep_probe_and_no_probe(self):
        make_project(self.d)
        vacuity(self.d, "--keep-probe")
        self.assertTrue(probe_left(self.d))
        shutil.rmtree(os.path.join(self.d, "test", "__vacuity__"))
        r = vacuity(self.d, "--no-probe", "--format", "json")
        self.assertEqual(r.returncode, 0, r.stderr)
        rep = json.loads(r.stdout)
        self.assertEqual(rep["mode"], "metrics")
        self.assertFalse(probe_left(self.d))

    def test_leftover_probe_from_crashed_run_is_replaced(self):
        make_project(self.d)
        os.makedirs(os.path.join(self.d, "test", "__vacuity__"))
        # garbage under both the old single-file name and the current per-contract names
        for fn in ("VacuityProbes.t.sol", "VacuityProbe_0.t.sol", "VacuityProbeBase.sol"):
            with open(os.path.join(self.d, "test", "__vacuity__", fn), "w") as fh:
                fh.write("this is not solidity")
        r = vacuity(self.d, "--format", "json")
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertFalse(probe_left(self.d))

    def test_compile_error_reported_and_cleaned(self):
        make_project(self.d, suite=SUITE.replace("targetContract(address(c));", "targetContract(address(c))"))
        r = vacuity(self.d)
        self.assertEqual(r.returncode, 2)
        self.assertIn("forge build failed", r.stderr)
        self.assertFalse(probe_left(self.d))

    def test_no_invariants(self):
        make_project(self.d, suite="// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
                                   "contract T { function test_x() public pure {} }\n")
        r = vacuity(self.d, "--format", "json")
        self.assertEqual(r.returncode, 0, r.stderr)
        rep = json.loads(r.stdout)
        self.assertEqual(rep["contracts"], [])
        self.assertTrue(any("no concrete test contracts" in n for n in rep["notes"]))
        r = vacuity(self.d, "--match-contract", "Nope")
        self.assertEqual(r.returncode, 2)

    def test_solc_change_does_not_reuse_stale_artifacts(self):
        # regression: artifacts of a previous compiler version used to be read as current
        want = {"invariant_live()": "live", "invariant_frozen()": "frozen"}

        def verdicts():
            r = vacuity(self.d, "--format", "json")
            rep = json.loads(r.stdout)
            return {i["name"]: i["verdict"] for c in rep["contracts"] for i in c["invariants"]}, rep

        make_project(self.d)
        toml = os.path.join(self.d, "foundry.toml")
        # 1) pinned solc_version changes between runs
        for v in ("0.8.13", "0.8.28", "0.8.19"):
            with open(toml) as fh:
                cfg = fh.read()
            with open(toml, "w") as fh:
                fh.write(re.sub(r'solc_version = "[0-9.]+"', f'solc_version = "{v}"', cfg))
            got, rep = verdicts()
            self.assertEqual(got, want, f"solc {v}: {rep}")
        # 2) solc auto-detected from the pragma; only the pragma changes
        with open(toml) as fh:
            cfg = fh.read()
        with open(toml, "w") as fh:
            fh.write(re.sub(r'solc_version = "[0-9.]+"\n', "", cfg))
        suite_path = os.path.join(self.d, "test", "Suite.t.sol")
        for v in ("0.8.13", "0.8.28"):
            with open(suite_path) as fh:
                src = fh.read()
            with open(suite_path, "w") as fh:
                fh.write(re.sub(r"pragma solidity [^;]+;", f"pragma solidity ={v};", src))
            got, rep = verdicts()
            self.assertEqual(got, want, f"pragma {v}: {rep}")

    def test_ignore_strict_json_out(self):
        make_project(self.d)
        out = os.path.join(self.d, "report.json")
        r = vacuity(self.d, "--ignore", "Suite.invariant_frozen", "--json-out", out)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        with open(out) as fh:
            rep = json.load(fh)
        self.assertEqual(rep["summary"]["errors"], 0)
        # glob on the contract name suppresses everything in it
        r = vacuity(self.d, "--ignore", "Sui*", "--format", "json")
        self.assertEqual(json.loads(r.stdout)["summary"], {"errors": 0, "warnings": 0})
        # a pattern that matches nothing changes nothing
        r = vacuity(self.d, "--ignore", "Other.invariant_frozen", "--format", "json")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(json.loads(r.stdout)["summary"]["errors"], 1)

    def test_strict_fails_on_warnings(self):
        # a handler whose only function always reverts: a warning, not an error
        suite = SUITE.replace("targetContract(address(c));", "targetContract(address(n)); targetContract(address(c));")
        suite = suite.replace('contract Suite is MiniInvariant {', '''contract Reverter { uint256 internal x; function f() external { x = 1; revert("no"); } }
contract Suite is MiniInvariant {''').replace("n = new MiniNoop();", "n = new MiniNoop(); r = new Reverter(); targetContract(address(r));")
        suite = suite.replace("MiniNoop internal n;", "MiniNoop internal n; Reverter internal r;")
        suite = suite.replace("    function invariant_frozen() public view { require(n.value() == 7, \"y\"); }\n", "")
        make_project(self.d, suite=suite)
        r = vacuity(self.d, "--format", "json")
        rep = json.loads(r.stdout)
        self.assertEqual(rep["summary"]["errors"], 0, r.stdout)
        self.assertGreater(rep["summary"]["warnings"], 0, r.stdout)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(vacuity(self.d, "--strict").returncode, 1)

    def test_from_json(self):
        make_project(self.d)
        env = dict(os.environ)
        env["FOUNDRY_INVARIANT_SHOW_METRICS"] = "true"
        p = subprocess.run([FORGE, "test", "--json"], cwd=self.d, capture_output=True, text=True, env=env)
        path = os.path.join(self.d, "forge.json")
        with open(path, "w") as fh:
            fh.write(p.stdout)
        r = vacuity(self.d, "--from-json", path, "--format", "json")
        self.assertEqual(r.returncode, 0, r.stderr)
        rep = json.loads(r.stdout)
        self.assertEqual(rep["mode"], "from-json")
        (suite,) = rep["contracts"]
        self.assertEqual(suite["contract"], "test/Suite.t.sol:Suite")
        self.assertGreater(suite["campaign"]["calls"], 0)
        self.assertEqual({i["verdict"] for i in suite["invariants"]}, {"not-probed"})
        # garbage input is a clean usage error, not a traceback
        with open(path, "w") as fh:
            fh.write("not json")
        r = vacuity(self.d, "--from-json", path)
        self.assertEqual(r.returncode, 2)
        self.assertNotIn("Traceback", r.stderr)

    def test_sigint_cleans_up(self):
        make_project(self.d, runs=4000, depth=500)  # long campaign
        env = dict(os.environ, PYTHONPATH=REPO)
        env["PATH"] = os.path.dirname(FORGE) + os.pathsep + env.get("PATH", "")
        p = subprocess.Popen([sys.executable, "-m", "vacuity", "--root", self.d],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        deadline = time.time() + 120
        while not probe_left(self.d) and time.time() < deadline:
            time.sleep(0.2)
        self.assertTrue(probe_left(self.d), "probe file never appeared")
        time.sleep(2)
        p.send_signal(signal.SIGINT)
        p.wait(timeout=120)
        self.assertNotEqual(p.returncode, 0)
        self.assertFalse(probe_left(self.d), "probe file left behind after SIGINT")


if __name__ == "__main__":
    unittest.main()
