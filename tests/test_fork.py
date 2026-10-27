"""Fork-mode tests against a local anvil node (skipped when forge or anvil is missing).

The suite forks a local chain where MiniNoop was deployed by a transaction, so the
frozen invariant's input lives in forked state, not in anything setUp created.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from test_integration import FORGE, HAVE_FORGE, make_project, probe_left, vacuity  # noqa: E402

BIN = os.path.dirname(FORGE)
ANVIL = os.path.join(BIN, "anvil")
CAST = os.path.join(BIN, "cast")
HAVE_ANVIL = os.path.isfile(ANVIL) and os.path.isfile(CAST)
KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"  # anvil account 0

SUITE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "../src/MiniInvariant.sol";

interface ForkVm {
    function createSelectFork(string calldata url, uint256 blockNumber) external returns (uint256);
    function createSelectFork(string calldata url) external returns (uint256);
    function envString(string calldata name) external view returns (string memory);
    function envAddress(string calldata name) external view returns (address);
}

contract ForkSuite is MiniInvariant {
    ForkVm internal constant fvm = ForkVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    MiniCounter internal c;
    MiniNoop internal n;
    uint256 internal forkBlock;

    function setUp() public {
        __FORK__
        c = new MiniCounter();  // Forge only fuzzes fork contracts via targetInterfaces
        n = MiniNoop(fvm.envAddress("FORK_NOOP"));
        targetContract(address(c));
    }
    function invariant_live() public view { require(c.count() < type(uint128).max, "x"); }
    function invariant_frozen() public view { require(n.value() == 7, "y"); }
    function invariant_forkBlock() public view { require(forkBlock == 0 || forkBlock > 0, "z"); }
}
"""

PINNED = 'fvm.createSelectFork(fvm.envString("FORK_URL"), 2);'
LATEST = 'fvm.createSelectFork(fvm.envString("FORK_URL")); forkBlock = block.number;'


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def creation_code(project: str, name: str) -> str:
    with open(os.path.join(project, "out", "MiniInvariant.sol", f"{name}.json")) as fh:
        return json.load(fh)["bytecode"]["object"]


@unittest.skipUnless(HAVE_FORGE and HAVE_ANVIL, "forge/anvil not installed")
class ForkTest(unittest.TestCase):
    def start_chain(self, block_time: int | None):
        port = free_port()
        args = [ANVIL, "--port", str(port), "--silent"]
        if block_time:
            args += ["--block-time", str(block_time)]
        self.anvil = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.url = f"http://127.0.0.1:{port}"
        for _ in range(100):
            if subprocess.run([CAST, "block-number", "--rpc-url", self.url], capture_output=True).returncode == 0:
                break
            time.sleep(0.1)
        else:
            self.fail("anvil did not start")

    def deploy(self, project: str) -> dict:
        subprocess.run([FORGE, "build"], cwd=project, check=True, capture_output=True)
        addrs = {}
        for name in ("MiniCounter", "MiniNoop"):
            r = subprocess.run([CAST, "send", "--rpc-url", self.url, "--private-key", KEY, "--json",
                                "--create", creation_code(project, name)],
                               capture_output=True, text=True, check=True)
            addrs[name] = json.loads(r.stdout)["contractAddress"]
        return addrs

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="vacuity-fork-")
        self.anvil = None

    def tearDown(self):
        if self.anvil:
            self.anvil.kill()
            self.anvil.wait()
        shutil.rmtree(self.d, ignore_errors=True)

    def miner(self):
        while not self.stop_mining.is_set():
            subprocess.run([CAST, "rpc", "--rpc-url", self.url, "evm_mine"], capture_output=True)
            time.sleep(0.05)

    def run_suite(self, fork_line: str, moving: bool):
        self.start_chain(None)
        make_project(self.d, suite=SUITE.replace("__FORK__", fork_line))
        addrs = self.deploy(self.d)
        shutil.rmtree(os.path.join(self.d, "out"))
        os.environ.update(FORK_URL=self.url, FORK_NOOP=addrs["MiniNoop"])
        self.stop_mining = threading.Event()
        t = threading.Thread(target=self.miner, daemon=True)
        if moving:
            t.start()
        try:
            r = vacuity(self.d, "--format", "json")
        finally:
            self.stop_mining.set()
            if moving:
                t.join()
            for k in ("FORK_URL", "FORK_NOOP"):
                os.environ.pop(k, None)
        self.assertFalse(probe_left(self.d))
        rep = json.loads(r.stdout)
        return r.returncode, {i["name"]: i["verdict"] for c in rep["contracts"] for i in c["invariants"]}, r

    def test_fork_only_contract_without_artifact_is_never_an_error(self):
        # Compile a contract in a separate project, deploy it, and read it from a suite that
        # only knows its interface: the probe can see it never changed but cannot
        # write-check it, so it must not report an error.
        self.start_chain(None)
        other = os.path.join(self.d, "other")
        os.makedirs(os.path.join(other, "src"))
        with open(os.path.join(other, "foundry.toml"), "w") as fh:
            fh.write('[profile.default]\nsrc = "src"\nlibs = []\nsolc_version = "0.8.28"\noffline = true\n')
        with open(os.path.join(other, "src", "Foreign.sol"), "w") as fh:
            fh.write("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
                     "contract Foreign { uint256 public value = 7; function set(uint256 v) external { value = v; } }\n")
        subprocess.run([FORGE, "build"], cwd=other, check=True, capture_output=True)
        with open(os.path.join(other, "out", "Foreign.sol", "Foreign.json")) as fh:
            code = json.load(fh)["bytecode"]["object"]
        r = subprocess.run([CAST, "send", "--rpc-url", self.url, "--private-key", KEY, "--json", "--create", code],
                           capture_output=True, text=True, check=True)
        foreign = json.loads(r.stdout)["contractAddress"]
        proj = os.path.join(self.d, "proj")
        suite = SUITE.replace("__FORK__", PINNED.replace(", 2)", ", 1)"))
        suite = suite.replace("MiniNoop internal n;", "IForeign internal n;")
        suite = suite.replace('n = MiniNoop(fvm.envAddress("FORK_NOOP"));', 'n = IForeign(fvm.envAddress("FORK_NOOP"));')
        suite = suite.replace("contract ForkSuite", "interface IForeign { function value() external view returns (uint256); }\ncontract ForkSuite")
        make_project(proj, suite=suite)
        os.environ.update(FORK_URL=self.url, FORK_NOOP=foreign)
        try:
            r = vacuity(proj, "--format", "json")
        finally:
            for k in ("FORK_URL", "FORK_NOOP"):
                os.environ.pop(k, None)
        rep = json.loads(r.stdout)
        verdicts = {i["name"]: i["verdict"] for c in rep["contracts"] for i in c["invariants"]}
        self.assertIn(verdicts["invariant_frozen()"], ("frozen-guarded", "frozen-untracked"), r.stdout)
        self.assertEqual(verdicts["invariant_live()"], "live", r.stdout)
        errors = [f for c in rep["contracts"] for f in c["findings"] if f["severity"] == "error"]
        self.assertEqual([f["subject"] for f in errors], ["invariant_forkBlock()"], r.stdout)

    def test_pinned_fork(self):
        code, verdicts, r = self.run_suite(PINNED, False)
        self.assertEqual(verdicts, {"invariant_live()": "live", "invariant_frozen()": "frozen",
                                    "invariant_forkBlock()": "frozen"}, r.stdout)
        self.assertEqual(code, 1)

    def test_latest_fork_moving_chain_is_inconclusive(self):
        # blocks are mined while vacuity runs, so its two forge runs fork different heads.
        # invariant_frozen's input is the same at every block, so it is still provably frozen;
        # invariant_forkBlock's input (the stored block number) differs, so it is inconclusive.
        code, verdicts, r = self.run_suite(LATEST, True)
        self.assertEqual(verdicts["invariant_live()"], "live", r.stdout)
        self.assertEqual(verdicts["invariant_frozen()"], "frozen", r.stdout)
        self.assertEqual(verdicts["invariant_forkBlock()"], "inconclusive", r.stdout)
        self.assertIn("different in the probe's two runs", r.stdout)
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
