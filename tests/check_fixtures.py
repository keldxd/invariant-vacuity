#!/usr/bin/env python3
"""Runs vacuity on a fixture project and compares the JSON report with the
fixture's expected.json. Exits non-zero on any mismatch.

usage: check_fixtures.py <fixture_dir> [--forge PATH] [-- extra vacuity args]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


def run_vacuity(fixture: str, forge: str | None, extra: list[str]) -> tuple[int, dict, str]:
    cmd = [sys.executable, "-m", "vacuity", "--root", fixture, "--format", "json", *extra]
    if forge:
        cmd += ["--forge", forge]
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        report = {}
    return proc.returncode, report, proc.stderr


def check(report: dict, expected: dict) -> list[str]:
    problems: list[str] = []
    contracts = {c["contract"]: c for c in report.get("contracts", [])}
    exp = {k: v for k, v in expected.items() if not k.startswith("_")}
    for key, spec in exp.items():
        c = contracts.get(key)
        if c is None:
            problems.append(f"{key}: missing from report")
            continue
        verdicts = {i["name"]: i for i in c["invariants"]}
        for inv, want in spec.get("verdicts", {}).items():
            got = verdicts.get(inv)
            if got is None:
                problems.append(f"{key} {inv}: missing")
            elif got["verdict"] != want:
                problems.append(f"{key} {inv}: expected {want}, got {got['verdict']} ({got.get('note', '')[:200]})")
        codes = {f["code"] for f in c["findings"]}
        for code in spec.get("findings", []):
            if code not in codes:
                problems.append(f"{key}: expected finding {code}, got {sorted(codes)}")
        frozen = {inv for inv, v in spec.get("verdicts", {}).items() if v == "frozen"}
        for f in c["findings"]:
            if f["severity"] == "error" and f["subject"] not in frozen:
                problems.append(f"{key}: unexpected error on {f['subject']}: {f['message'][:200]}")
        for inv, needles in spec.get("inputs_contain", {}).items():
            inputs = " | ".join((verdicts.get(inv) or {}).get("inputs", []))
            for n in needles:
                if n not in inputs:
                    problems.append(f"{key} {inv}: inputs should mention {n!r}, got: {inputs[:300]}")
        if os.environ.get("FOUNDRY_PROFILE", "default") == "default":
            for inv, want_calls in spec.get("probe_calls_default", {}).items():
                got_calls = None
                for f in c["findings"]:
                    if f["subject"] == inv:
                        got_calls = f.get("details", {}).get("probe_calls")
                if got_calls != want_calls:
                    problems.append(f"{key} {inv}: expected {want_calls} probe calls (inline config), got {got_calls}")
        for inv, needles in spec.get("guarded_contain", {}).items():
            writes = []
            for f in c["findings"]:
                if f["subject"] == inv:
                    writes += f.get("details", {}).get("reachable_writes", [])
            joined = " | ".join(writes)
            for n in needles:
                if n not in joined:
                    problems.append(f"{key} {inv}: reachable writes should mention {n!r}, got: {joined[:300]}")
    for key in contracts:
        if key not in exp:
            problems.append(f"{key}: in report but not in expected.json")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("fixture")
    ap.add_argument("--forge", default=None)
    ap.add_argument("extra", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    extra = a.extra[1:] if a.extra[:1] == ["--"] else a.extra
    fixture = os.path.abspath(a.fixture)
    with open(os.path.join(fixture, "expected.json"), encoding="utf-8") as fh:
        expected = json.load(fh)
    t0 = time.time()
    rc, report, stderr = run_vacuity(fixture, a.forge, extra)
    dt = time.time() - t0
    if not report:
        print(f"FAIL: vacuity produced no JSON (exit {rc})\n{stderr[-3000:]}")
        return 1
    problems = check(report, expected)
    want_rc = 1 if any(
        v == "frozen" for k, s in expected.items() if not k.startswith("_") for v in s.get("verdicts", {}).values()
    ) else 0
    if rc != want_rc:
        problems.append(f"exit code {rc}, expected {want_rc}")
    n = sum(len(s.get("verdicts", {})) for k, s in expected.items() if not k.startswith("_"))
    if problems:
        print(f"FAIL ({len(problems)} problems, {n} invariants, {dt:.0f}s, forge {report.get('forge_version')})")
        for p in problems:
            print("  -", p)
        return 1
    print(f"PASS: {n} invariants matched expectations ({dt:.0f}s, forge {report.get('forge_version')}, "
          f"{report['summary']['errors']} errors, {report['summary']['warnings']} warnings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
