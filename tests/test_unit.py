"""Unit tests for the Python side. Run with: python3 -m unittest discover -s tests"""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from vacuity import analysis, artifacts, cheatcodes, cli, forge  # noqa: E402
from vacuity.analysis import Campaign, Thresholds  # noqa: E402
from vacuity.keccak import checksum, keccak256, selector  # noqa: E402
from vacuity.probe_gen import ProbeTarget, generate  # noqa: E402
from vacuity.writes import WriteGraph  # noqa: E402

DATA = os.path.join(HERE, "data")


def load(name):
    with open(os.path.join(DATA, name), encoding="utf-8") as fh:
        return json.load(fh)


class KeccakTest(unittest.TestCase):
    def test_vectors(self):
        self.assertEqual(keccak256(b"").hex(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(selector("transfer(address,uint256)"), "a9059cbb")
        self.assertEqual(selector("load(address,bytes32)"), "667f9d70")
        self.assertEqual(keccak256(b"abc").hex(), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")

    def test_multiblock_consistency(self):
        # rate boundary: 135, 136, 137 bytes must all hash without error and differ
        hs = {keccak256(b"x" * n).hex() for n in (135, 136, 137, 272, 273)}
        self.assertEqual(len(hs), 5)

    def test_checksum_eip55_vectors(self):
        for a in ["0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
                  "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"]:
            self.assertEqual(checksum(a.lower()), a)


class CheatcodeTest(unittest.TestCase):
    def test_classification(self):
        self.assertEqual(cheatcodes.classify(selector("assertEq(uint256,uint256)")),
                         ("assertEq(uint256,uint256)", True))
        sig, safe = cheatcodes.classify(selector("getNonce(address)"))
        self.assertEqual(sig, "getNonce(address)")
        self.assertFalse(safe)
        self.assertTrue(cheatcodes.classify(selector("load(address,bytes32)"))[1])
        self.assertTrue(cheatcodes.classify(selector("label(address,string)"))[1])
        self.assertFalse(cheatcodes.classify(selector("unixTime()"))[1])
        self.assertFalse(cheatcodes.classify(selector("readFile(string)"))[1])

    def test_unknown_selector_is_untracked(self):
        self.assertEqual(cheatcodes.classify("deadbeef"), (None, False))
        self.assertEqual(cheatcodes.untracked(["deadbeef"]), ["unknown cheatcode 0xdeadbeef"])
        self.assertEqual(cheatcodes.untracked([selector("toString(uint256)")]), [])


class ForgeJsonTest(unittest.TestCase):
    def test_parse_test_json_tolerates_noise(self):
        payload = {"a": {"test_results": {}}}
        self.assertEqual(forge.parse_test_json(json.dumps(payload)), payload)
        noisy = "Compiling...\nwarning: x\n" + json.dumps(payload) + "\n"
        self.assertEqual(forge.parse_test_json(noisy), payload)
        with self.assertRaises(forge.ForgeError):
            forge.parse_test_json("")
        with self.assertRaises(forge.ForgeError):
            forge.parse_test_json("Error: compilation failed\n[1,2,3]")

    def test_parse_version(self):
        self.assertEqual(forge.parse_version("forge Version: 1.5.1-stable"), (1, 5, 1))
        self.assertEqual(forge.parse_version("forge 0.2.0 (abc 2024-01-01)"), (0, 2, 0))
        with self.assertRaises(forge.ForgeError):
            forge.parse_version("garbage")


class CampaignShapesTest(unittest.TestCase):
    """Real `forge test --json` output from three Forge versions."""

    def _suite(self, data, name):
        for k, v in data.items():
            if k.endswith(":" + name):
                return v
        raise KeyError(name)

    def test_per_invariant_model(self):
        for v in ("v1.0.0", "v1.5.1"):
            data = load(f"forge_{v}_metrics.json")
            camps, setup = analysis.campaigns(self._suite(data, "V04_UntouchedSlot"))
            self.assertIsNone(setup)
            self.assertEqual(len(camps), 2, v)
            names = sorted(n for c in camps for n, _, _ in c.invariants)
            self.assertEqual(names, ["invariant_neverPaused()", "invariant_solvent()"])
            self.assertTrue(all(c.calls > 0 and c.metrics for c in camps), v)

    def test_shared_campaign_model(self):
        data = load("forge_v1.8.6_metrics.json")
        camps, _ = analysis.campaigns(self._suite(data, "V04_UntouchedSlot"))
        self.assertEqual(len(camps), 1)
        self.assertEqual(sorted(n for n, _, _ in camps[0].invariants),
                         ["invariant_neverPaused()", "invariant_solvent()"])

    def test_single_invariant_failure_reasons(self):
        # 1.5.1 reports the reason at top level, 1.8.6 only in invariant_failures
        for v in ("v1.5.1", "v1.8.6"):
            data = load(f"forge_{v}_single_failure.json")
            suite = next(iter(data.values()))
            camps, _ = analysis.campaigns(suite)
            self.assertEqual(camps[0].invariants, [("invariant_count()", "Failure", "too many")], v)

    def test_discards_are_inside_calls(self):
        for v in ("v1.5.1", "v1.8.6"):
            data = load(f"forge_{v}_metrics.json")
            camps, _ = analysis.campaigns(self._suite(data, "W04_HighDiscard"))
            m = next(iter(camps[0].metrics.values()))
            self.assertGreater(m["discards"], 0)
            self.assertEqual(m["calls"] - m["discards"], camps[0].calls, v)

    def test_malformed_suites(self):
        for suite in ({}, {"test_results": None}, {"test_results": {"x": None}},
                      {"test_results": {"invariant_x()": {"kind": "weird"}}},
                      {"test_results": {"invariant_x()": {"kind": {"Invariant": {}}, "status": "Success"}}}):
            camps, _ = analysis.campaigns(suite)
            for c in camps:
                self.assertIsInstance(c.calls, int)


class MetricFindingsTest(unittest.TestCase):
    def camp(self, metrics, calls=100, reverts=0):
        return Campaign([("invariant_a()", "Success", "")], metrics, 10, calls, reverts)

    def codes(self, camp, th=Thresholds()):
        return sorted(f.code for f in analysis.metric_findings("c", "C", camp, th, []))

    def test_dead_and_high_revert(self):
        self.assertEqual(self.codes(self.camp({"p:H.f": {"calls": 10, "reverts": 10, "discards": 0}})),
                         ["dead-selector"])
        self.assertEqual(self.codes(self.camp({"p:H.f": {"calls": 10, "reverts": 9, "discards": 0}})),
                         ["high-revert-selector"])
        self.assertEqual(self.codes(self.camp({"p:H.f": {"calls": 10, "reverts": 8, "discards": 0}})), [])

    def test_discards_excluded_from_revert_rate(self):
        # 10 calls, 8 discarded, 2 executed, 2 reverted -> dead (100% of executed), plus high discard
        m = {"p:H.f": {"calls": 10, "reverts": 2, "discards": 8}}
        self.assertEqual(self.codes(self.camp(m)), ["dead-selector", "high-discard"])
        # all discarded: never executed
        m = {"p:H.f": {"calls": 10, "reverts": 0, "discards": 10}}
        fs = analysis.metric_findings("c", "C", self.camp(m), Thresholds(), [])
        self.assertEqual([f.code for f in fs], ["high-discard"])
        self.assertIn("never executed", fs[0].message)

    def test_campaign_level(self):
        self.assertIn("all-calls-reverted", self.codes(self.camp({}, calls=50, reverts=50)))
        self.assertIn("high-revert-campaign", self.codes(self.camp({}, calls=100, reverts=80)))
        self.assertIn("no-calls", self.codes(self.camp({}, calls=0, reverts=0)))

    def test_ignore_patterns(self):
        fs = analysis.metric_findings("c", "C", self.camp({"p:H.f": {"calls": 10, "reverts": 10, "discards": 0}}),
                                      Thresholds(), ["H.f"])
        self.assertEqual(fs, [])

    def test_aggregate_sums(self):
        a = self.camp({"p:H.f": {"calls": 5, "reverts": 1, "discards": 0}}, calls=5, reverts=1)
        b = self.camp({"p:H.f": {"calls": 7, "reverts": 2, "discards": 1}}, calls=6, reverts=2)
        agg = analysis.aggregate([a, b])
        self.assertEqual(agg.metrics["p:H.f"], {"calls": 12, "reverts": 3, "discards": 1})
        self.assertEqual((agg.calls, agg.reverts), (11, 3))

    def test_entry_points(self):
        c = self.camp({"t/H.sol:H.ok": {"calls": 5, "reverts": 1, "discards": 0},
                       "t/H.sol:H.dead": {"calls": 5, "reverts": 5, "discards": 0},
                       "t/H.sol:H.disc": {"calls": 5, "reverts": 0, "discards": 5}})
        self.assertEqual(analysis.entry_points(c), [("H", "ok")])
        self.assertEqual(analysis.entry_points(None, c), [("H", "ok")])


class ProbeInfoTest(unittest.TestCase):
    def test_parse_and_garbage(self):
        logs = ["VPINFO|1|1", "VPINV|0|1|1|5|1",
                "VPSLOT|0|0xAa|0x" + "00" * 31 + "02|0x" + "00" * 32 + "|0xBb",
                "VPBAL|0|0xCc", "VPCODE|0|0xDd", "VPCHEAT|0|0x7a0c5a6d" + "0" * 56,
                "VPACCT|0xaa|0x6080", "VPINNER|0xAA", "VPEND",
                "garbage", "VPSLOT|9|bad", "VPINV|x|y", "", None, 42]
        info = analysis.parse_info(logs)
        self.assertTrue(info.trace_supported and info.complete)
        p = info.per[0]
        self.assertEqual(p["env"], 5)
        self.assertTrue(p["captured"])
        self.assertEqual(p["slots"][0][3], "0xBb")
        self.assertEqual(p["bals"], ["0xCc"])
        self.assertEqual(p["cheats"], ["7a0c5a6d"])
        self.assertEqual(info.inner, "0xaa")

    def test_incomplete_info(self):
        info = analysis.parse_info(["VPINFO|1|0", "VPINV|0|1|0|0"])
        self.assertFalse(info.complete)
        self.assertFalse(info.trace_supported)
        self.assertTrue(info.per[0]["captured"])  # older format without the field


class GlobAndFilterTest(unittest.TestCase):
    def test_globs(self):
        m = artifacts.path_matches
        self.assertTrue(m("test/detection/a/B.t.sol", "test/detection/*"))
        self.assertFalse(m("test/reference/X.t.sol", "test/detection/*"))
        self.assertTrue(m("lib/x/y.sol", "lib/**"))
        self.assertTrue(m("test/a.t.sol", "{test/a.t.sol,test/b.t.sol}"))
        self.assertTrue(m("test/my dir/X.t.sol", "test/my dir/*"))
        self.assertTrue(m("test/x1.t.sol", "test/x[0-9].t.sol"))
        self.assertFalse(m("test/xa.t.sol", "test/x[0-9].t.sol"))

    def _art(self, name, source, invs=("invariant_a",), creation="6080", ctor_inputs=0):
        abi = [{"type": "function", "name": n, "inputs": []} for n in invs]
        if ctor_inputs:
            abi.append({"type": "constructor", "inputs": [{"type": "uint256"}] * ctor_inputs})
        return artifacts.Artifact(name=name, source=source, abi=abi, creation=creation, runtime="6080")

    def test_select_targets(self):
        arts = [self._art("A", "test/A.t.sol"), self._art("B", "test/detection/B.t.sol"),
                self._art("Abstract", "test/Base.sol", creation=""), self._art("C", "src/C.sol"),
                self._art("D", "test/D.t.sol", ctor_inputs=1), self._art("E", "test/E.t.sol", invs=("test_x",)),
                self._art("F", "test/F.t.sol", invs=("statefulFuzz_x", "invariant_slow"))]
        prof = artifacts.Filters(no_match_path="test/detection/*", no_match_test="slow")
        t, invs, notes = artifacts.select_targets(arts, "test", artifacts.Filters(), prof)
        self.assertEqual([a.name for a in t], ["A", "F"])
        self.assertEqual(invs["test/F.t.sol:F"], ["statefulFuzz_x()"])
        self.assertTrue(any("constructor" in n for n in notes))
        t, _, _ = artifacts.select_targets(arts, "test", artifacts.Filters(match_contract="^B$"), None)
        self.assertEqual([a.name for a in t], ["B"])


class ArtifactLoadTest(unittest.TestCase):
    @staticmethod
    def _art(path, version, code):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        meta = {"compiler": {"version": version}, "settings": {"compilationTarget": {"test/A.t.sol": "A"}}}
        with open(path, "w") as fh:
            json.dump({"abi": [], "metadata": meta, "bytecode": {"object": "0x00"},
                       "deployedBytecode": {"object": code}}, fh)

    def test_stale_duplicate_detected_and_newest_used(self):
        with tempfile.TemporaryDirectory() as d:
            # nested path (old compiler) sorts first in a walk; it must not win
            self._art(os.path.join(d, "test", "A.t.sol", "A.json"), "0.8.13+commit.abaa5c0e", "0x13")
            self._art(os.path.join(d, "A.t.sol", "A.json"), "0.8.28+commit.7893614a", "0x28")
            arts, _, dups = artifacts.load_checked(d)
            self.assertEqual(dups, ["test/A.t.sol:A"])
            self.assertEqual(len(arts), 1)
            self.assertEqual(arts[0].runtime, "28")

    def test_same_version_twice_is_not_a_duplicate(self):
        with tempfile.TemporaryDirectory() as d:
            self._art(os.path.join(d, "A.t.sol", "A.json"), "0.8.28+commit.7893614a", "0x28")
            self._art(os.path.join(d, "x", "A.t.sol", "A.json"), "0.8.28+commit.7893614a", "0x28")
            _, _, dups = artifacts.load_checked(d)
            self.assertEqual(dups, [])


class CodeIndexTest(unittest.TestCase):
    def test_masks_and_placeholders(self):
        placeholder = "__$" + "ab" * 17 + "$__"
        runtime = "6000" + placeholder + "7f" + "00" * 32 + "56"
        art = artifacts.Artifact("X", "src/X.sol", [], "6080", runtime.lower(),
                                 masks=[(2, 20), (23, 32)])
        idx = artifacts.CodeIndex([art])
        deployed = "6000" + "11" * 20 + "7f" + "22" * 32 + "56"
        self.assertIs(idx.identify("0x" + deployed), art)
        self.assertIsNone(idx.identify("0x" + deployed[:-2] + "57"))
        self.assertIsNone(idx.identify("0xzz"))

    def test_slot_labels_and_mappings(self):
        types = {"t_uint256": {"encoding": "inplace", "numberOfBytes": "32"},
                 "t_mapping": {"encoding": "mapping", "numberOfBytes": "32"},
                 "t_arr": {"encoding": "inplace", "numberOfBytes": "96"}}
        storage = [{"label": "total", "slot": "0", "type": "t_uint256"},
                   {"label": "balanceOf", "slot": "1", "type": "t_mapping"},
                   {"label": "fixed", "slot": "2", "type": "t_arr"}]
        art = artifacts.Artifact("T", "src/T.sol", [], "", "", storage=storage, types=types)
        self.assertEqual(artifacts.slot_label(art, "0x0"), "total")
        self.assertEqual(artifacts.slot_label(art, "0x3"), "fixed (+1 slot)")
        key = 0xABCDEF0000000000000000000000000000000001
        slot = int.from_bytes(keccak256(key.to_bytes(32, "big") + (1).to_bytes(32, "big")), "big")
        self.assertEqual(artifacts.slot_label(art, hex(slot), {key: "Vault"}), "balanceOf[Vault]")
        self.assertEqual(artifacts.slot_label(art, hex(slot)), "(mapping or dynamic array element)")
        self.assertIsNone(artifacts.slot_label(None, "0x0"))


class ProbeGenTest(unittest.TestCase):
    def test_rejects_bad_input(self):
        good = ProbeTarget(0, "T", "test/T.t.sol", True, ["invariant_a()"], ["12345678"])
        self.assertIn("contract VacuityProbe_0__T", generate([good], 1))
        with self.assertRaises(ValueError):
            generate([], 1)
        with self.assertRaises(ValueError):
            generate([ProbeTarget(0, "T;evil", "test/T.t.sol", True, ["invariant_a()"], ["12345678"])], 1)
        with self.assertRaises(ValueError):
            generate([ProbeTarget(0, "T", 'test/"x.sol', True, ["invariant_a()"], ["12345678"])], 1)
        with self.assertRaises(ValueError):
            generate([ProbeTarget(0, "T", "test/T.t.sol", True, ["invariant_a()"], ["xyz"])], 1)
        with self.assertRaises(ValueError):
            generate([ProbeTarget(0, "T", "test/T.t.sol", True, [], [])], 1)


def _ast_contract(name, nodes, bases=(), kind="contract"):
    return {"nodeType": "ContractDefinition", "name": name, "contractKind": kind, "abstract": False,
            "baseContracts": [{"baseName": {"name": b}} for b in bases], "nodes": nodes}


def _fn(name, body, mutability="nonpayable", modifiers=()):
    return {"nodeType": "FunctionDefinition", "name": name, "kind": "function", "stateMutability": mutability,
            "modifiers": [{"modifierName": {"name": m}} for m in modifiers],
            "body": {"nodeType": "Block", "statements": body}}


def _var(name):
    return {"nodeType": "VariableDeclaration", "name": name, "stateVariable": True}


def _ident(name):
    return {"nodeType": "Identifier", "name": name, "referencedDeclaration": 1}


def _assign(name):
    return {"nodeType": "ExpressionStatement",
            "expression": {"nodeType": "Assignment", "operator": "=", "leftHandSide": _ident(name),
                           "rightHandSide": {"nodeType": "Literal", "value": "1"}}}


def _if(stmt):
    return {"nodeType": "IfStatement", "condition": _ident("c"), "trueBody": {"nodeType": "Block", "statements": [stmt]}}


def _call_member(base_type, member):
    return {"nodeType": "ExpressionStatement",
            "expression": {"nodeType": "FunctionCall", "arguments": [],
                           "expression": {"nodeType": "MemberAccess", "memberName": member,
                                          "typeDescriptions": {"typeString": "function () external"},
                                          "expression": {"nodeType": "Identifier", "name": "x",
                                                         "typeDescriptions": {"typeString": f"contract {base_type}"}}}}}


def _call_internal(name):
    return {"nodeType": "ExpressionStatement",
            "expression": {"nodeType": "FunctionCall", "arguments": [], "expression": _ident(name)}}


class WriteGraphTest(unittest.TestCase):
    def graph(self):
        handler = _ast_contract("H", [
            _var("flag"), _var("ghost"), _var("ref"),
            _fn("check", [_if(_assign("flag"))]),
            _fn("record", [_assign("ghost")]),
            _fn("viaHelper", [_if(_call_internal("_mark"))]),
            _fn("_mark", [_assign("ghost")], mutability="nonpayable"),
            _fn("callVault", [_call_member("IVault", "deposit")]),
            _fn("setUp", [_assign("ref")]),
        ])
        ivault = _ast_contract("IVault", [{"nodeType": "FunctionDefinition", "name": "deposit", "kind": "function",
                                           "body": None}], kind="interface")
        vault = _ast_contract("Vault", [_var("total"), _fn("deposit", [_assign("total")])], bases=("IVault",))
        return WriteGraph([{"absolutePath": "a.sol", "nodes": [handler, ivault, vault]}])

    def test_conditional_and_unconditional(self):
        sites, complete = self.graph().reachable_writes([("H", "check"), ("H", "record")])
        self.assertTrue(complete)
        got = {(s.contract, s.function, s.variable, s.conditional) for s in sites}
        self.assertIn(("H", "check", "flag", True), got)
        self.assertIn(("H", "record", "ghost", False), got)

    def test_internal_call_inherits_condition(self):
        sites, _ = self.graph().reachable_writes([("H", "viaHelper")])
        self.assertEqual({(s.variable, s.conditional) for s in sites}, {("ghost", True)})

    def test_interface_fans_out_to_implementations(self):
        sites, _ = self.graph().reachable_writes([("H", "callVault")])
        self.assertEqual({(s.contract, s.variable) for s in sites}, {("Vault", "total")})

    def test_no_entry_points_no_writes(self):
        self.assertEqual(self.graph().reachable_writes([])[0], [])

    def test_setup_not_an_entry_point(self):
        from vacuity.writes import is_entry_point
        self.assertFalse(is_entry_point("setUp"))
        self.assertFalse(is_entry_point("invariant_x"))
        self.assertTrue(is_entry_point("deposit"))


class CliTest(unittest.TestCase):
    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            try:
                rc = cli.main(argv)
            except SystemExit as e:
                rc = e.code
        return rc, out.getvalue(), err.getvalue()

    def test_missing_foundry_toml(self):
        with tempfile.TemporaryDirectory() as d:
            rc, _, err = self.run_cli(["--root", d])
            self.assertEqual(rc, 2)
            self.assertIn("no foundry.toml", err)

    def test_bad_forge_path(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "foundry.toml"), "w").close()
            rc, _, err = self.run_cli(["--root", d, "--forge", os.path.join(d, "nope")])
            self.assertEqual(rc, 2)
            self.assertIn("forge binary not found", err)

    def test_old_forge_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "foundry.toml"), "w").close()
            fake = os.path.join(d, "forge")
            with open(fake, "w") as fh:
                fh.write("#!/bin/sh\necho 'forge 0.2.0 (abcdef 2024-01-01T00:00:00)'\n")
            os.chmod(fake, 0o755)
            rc, _, err = self.run_cli(["--root", d, "--forge", fake])
            self.assertEqual(rc, 2)
            self.assertIn("too old", err)

    def test_threshold_validation(self):
        rc, _, _ = self.run_cli(["--selector-revert-threshold", "1.5", "--from-json", "x"])
        self.assertNotEqual(rc, 0)

    def test_unrecognized_args(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "foundry.toml"), "w").close()
            rc, _, err = self.run_cli(["--root", d, "stray"])
            self.assertEqual(rc, 2)
            self.assertIn("after --", err)

    def test_from_json_modes(self):
        path = os.path.join(DATA, "forge_v1.5.1_metrics.json")
        rc, out, _ = self.run_cli(["--from-json", path, "--format", "json"])
        rep = json.loads(out)
        self.assertEqual(rc, 0)  # metrics findings are warnings
        self.assertEqual(rep["mode"], "from-json")
        codes = {f["code"] for c in rep["contracts"] for f in c["findings"]}
        self.assertIn("high-discard", codes)
        rc, _, _ = self.run_cli(["--from-json", path, "--strict"])
        self.assertEqual(rc, 1)
        rc, _, err = self.run_cli(["--from-json", os.path.join(DATA, "missing.json")])
        self.assertEqual(rc, 2)
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write("not json at all")
        try:
            rc, _, err = self.run_cli(["--from-json", fh.name])
            self.assertEqual(rc, 2)
        finally:
            os.unlink(fh.name)

    def test_json_out_file(self):
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "r.json")
            rc, _, _ = self.run_cli(["--from-json", os.path.join(DATA, "forge_v1.8.6_metrics.json"),
                                     "--json-out", target])
            with open(target) as fh:
                rep = json.load(fh)
            self.assertIn("summary", rep)
            self.assertEqual(rep["tool"], "invariant-vacuity")


if __name__ == "__main__":
    unittest.main()


class AbiAndCampaignEnvTest(unittest.TestCase):
    def test_encode_layout(self):
        from vacuity.abi import encode_inputs
        a = "0x" + "11" * 20
        blob = encode_inputs([a], ["0x" + "00" * 31 + "05"], [a], [], [a], 3, "0x" + "ab" * 32)
        words = [int.from_bytes(blob[i:i + 32], "big") for i in range(0, len(blob), 32)]
        self.assertEqual(words[0], 32)  # offset of the tuple
        head = words[1:8]
        self.assertEqual(head[5], 3)  # env
        self.assertEqual(head[6], int("ab" * 32, 16))  # fp
        # first dynamic member starts right after the 7-word head
        self.assertEqual(head[0], 7 * 32)
        self.assertEqual(words[1 + head[0] // 32], 1)  # sa length
        with self.assertRaises(ValueError):
            encode_inputs([a], [], [a], [], [], 0, "0x0")
        with self.assertRaises(ValueError):
            encode_inputs(["0x" + "11" * 21], ["0x0"], [a], [], [], 0, "0x0")

    def test_capture_batches(self):
        def t(i, n):
            return ProbeTarget(i, f"T{i}", "test/T.t.sol", True, [f"invariant_{k}()" for k in range(n)],
                               ["12345678"] * n)
        ts = [t(0, 10), t(1, 10), t(2, 10), t(3, 40), t(4, 1)]
        sizes = [[x.index for x in b] for b in cli._capture_batches(ts)]
        self.assertEqual(sizes, [[0, 1], [2], [3], [4]])  # never splits a probe, never empty
        self.assertEqual(cli._capture_batches([]), [])

    def test_strip_traces(self):
        r = {"a:B": {"test_results": {"t()": {"status": "Success", "traces": [1], "logs": []}}}}
        self.assertEqual(cli._strip_traces(r), {"a:B": {"test_results": {"t()": {"status": "Success", "logs": []}}}})

    def test_build_env_and_batches(self):
        t = ProbeTarget(0, "T", "test/T.t.sol", True, ["invariant_a()", "invariant_b()"], ["11111111", "22222222"])
        logs = ["VPINFO|2|1", "VPINV|0|1|1|0|1|100", "VPSLOT|0|0x" + "aa" * 20 + "|0x00|0x00|0x" + "aa" * 20,
                "VPFP|0|0x" + "cd" * 32, "VPINV|1|1|1|0|0|0", "VPEND"]
        capture = {"test/__vacuity__/VacuityProbe_0.t.sol:VacuityProbe_0__T": {"test_results": {
            "test_vacuityInfo()": {"status": "Success", "decoded_logs": logs}}}}
        env = cli.build_campaign_env([t], capture, {0: "test/__vacuity__/VacuityProbe_0.t.sol"})
        self.assertIn("VACUITY_P0_0", env)
        self.assertNotIn("VACUITY_P0_1", env)  # capture failed: probe reports it inconclusive
        # setUp failure in capture: nothing to run for that probe
        failed = {"test/__vacuity__/VacuityProbe_0.t.sol:VacuityProbe_0__T": {"test_results": {
            "setUp()": {"status": "Failure", "reason": "VACUITY:SETUP_FAILED: x"}}}}
        self.assertEqual(cli.build_campaign_env([t], failed, {0: "test/__vacuity__/VacuityProbe_0.t.sol"}), {})
        big = {f"VACUITY_P{i}_0": "x" * 400_000 for i in range(5)}
        ts = [ProbeTarget(i, "T", "t", True, ["invariant_a()"], ["11111111"]) for i in range(5)]
        batches = cli._batches(ts, big)
        self.assertGreater(len(batches), 1)
        self.assertEqual(sum(len(b) for b in batches), 5)
        for b in batches:
            self.assertLessEqual(sum(len(big[f"VACUITY_P{x.index}_0"]) for x in b), cli.ENV_BUDGET + 400_000)
