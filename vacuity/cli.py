"""Command line entry point: `vacuity`."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import sys
from typing import List, Optional

from . import __version__
from . import artifacts as art_mod
from . import forge as forge_mod
from .abi import encode_inputs
from .analysis import (ContractReport, Finding, InvariantReport, Thresholds, campaigns, find_suite, judge,
                       metric_findings, parse_info, to_dict)
from .forge import ForgeError
from .probe_gen import DEFAULT_RECORD_GAS, DEFAULT_TRACE_GAS, INFO_TEST, PROBE_PREFIX, ProbeTarget, generate_files, probe_file
from .report import render
from .writes import WriteGraph

GEN_DIR = "__vacuity__"
GEN_PREFIXES = ("VacuityProbe_", "VacuityProbeBase", "VacuityProbes")  # current and older layouts

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_TOOL = 2


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vacuity",
        description="Find Foundry invariant tests that pass for the wrong reason.",
        epilog="Arguments after `--` are passed to `forge test` (for example: -- --fork-url $RPC).",
    )
    p.add_argument("--version", action="version", version=f"invariant-vacuity {__version__}")
    p.add_argument("--root", default=".", help="Foundry project root (default: current directory)")
    p.add_argument("--forge", default=None, help="path to the forge binary (default: forge on PATH)")
    p.add_argument("--match-contract", default=None, help="only test contracts whose name matches this regex")
    p.add_argument("--match-path", default=None, help="only test files matching this glob, e.g. 'test/invariant/*'")
    p.add_argument("--no-probe", action="store_true", help="skip the frozen-input probe, run metrics checks only")
    p.add_argument("--from-json", default=None, metavar="FILE",
                   help="metrics checks only, from an existing `forge test --json` output file (no forge run)")
    p.add_argument("--strict", action="store_true", help="exit 1 on warnings as well as errors")
    p.add_argument("--format", choices=["text", "json"], default="text", help="stdout format")
    p.add_argument("--json-out", default=None, metavar="FILE", help="also write the JSON report to FILE")
    p.add_argument("--ignore", action="append", default=[], metavar="PATTERN",
                   help="suppress findings for Contract, Contract.invariant_x or Handler.selector (glob, repeatable)")
    p.add_argument("--selector-revert-threshold", type=float, default=0.9,
                   help="warn when a selector's revert rate is at or above this (default 0.9)")
    p.add_argument("--campaign-revert-threshold", type=float, default=0.75,
                   help="warn when a campaign's overall revert rate is at or above this (default 0.75)")
    p.add_argument("--discard-threshold", type=float, default=0.5,
                   help="warn when a selector's discard rate is at or above this (default 0.5)")
    p.add_argument("--timeout", type=float, default=None, help="seconds before forge commands are aborted")
    p.add_argument("--record-gas", type=int, default=DEFAULT_RECORD_GAS,
                   help=f"max gas of one invariant call the probe will record (default {DEFAULT_RECORD_GAS:,}); "
                        "higher values let heavier invariants be analyzed but use more memory")
    p.add_argument("--trace-gas", type=int, default=DEFAULT_TRACE_GAS,
                   help=f"max gas of one invariant call the probe will opcode-trace (default {DEFAULT_TRACE_GAS:,}); "
                        "Forge uses about 400 bytes of memory per traced gas")
    p.add_argument("--keep-probe", action="store_true", help="keep the generated probe file for debugging")
    p.add_argument("--verbose", action="store_true", help="list every input of frozen invariants")
    p.add_argument("forge_args", nargs=argparse.REMAINDER, help=argparse.SUPPRESS)
    return p


def _thresholds(a) -> Thresholds:
    for name in ("selector_revert_threshold", "campaign_revert_threshold", "discard_threshold"):
        v = getattr(a, name)
        if not 0 < v <= 1:
            raise SystemExit(f"vacuity: --{name.replace('_', '-')} must be in (0, 1], got {v}")
    return Thresholds(a.selector_revert_threshold, a.campaign_revert_threshold, a.discard_threshold)


def _exit_code(reports: List[ContractReport], strict: bool) -> int:
    sev = {f.severity for r in reports for f in r.findings}
    if "error" in sev or (strict and "warning" in sev):
        return EXIT_FINDINGS
    return EXIT_OK


def _emit(reports: List[ContractReport], args, header: str, notes: List[str], meta: dict) -> None:
    payload = {
        "tool": "invariant-vacuity",
        "version": __version__,
        **meta,
        "notes": notes,
        "contracts": to_dict(reports),
        "summary": {
            "errors": sum(1 for r in reports for f in r.findings if f.severity == "error"),
            "warnings": sum(1 for r in reports for f in r.findings if f.severity == "warning"),
        },
    }
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
    if args.format == "json":
        print(json.dumps(payload, indent=2))
    else:
        print(render(reports, header, notes, args.verbose))


def _from_json(args, th: Thresholds) -> int:
    try:
        with open(args.from_json, encoding="utf-8") as fh:
            results = forge_mod.parse_test_json(fh.read())
    except OSError as e:
        print(f"vacuity: cannot read {args.from_json}: {e}", file=sys.stderr)
        return EXIT_TOOL
    except ForgeError as e:
        print(f"vacuity: {args.from_json}: {e}", file=sys.stderr)
        return EXIT_TOOL
    reports: List[ContractReport] = []
    rx = re.compile(args.match_contract) if args.match_contract else None
    for key in sorted(results):
        suite = results[key]
        if not isinstance(suite, dict):
            continue
        camps, setup_failure = campaigns(suite)
        if not camps:
            continue
        short = key.rsplit(":", 1)[-1]
        if rx and not rx.search(short):
            continue
        if short.startswith(PROBE_PREFIX):
            continue
        rep = ContractReport(contract=key)
        if setup_failure:
            rep.findings.append(Finding("warning", "setup-failed", key, "setUp()", f"setUp() failed: {setup_failure}"))
        for camp in camps:
            for name, status, reason in camp.invariants:
                rep.invariants.append(InvariantReport(name=name, verdict="failing" if status == "Failure" else "not-probed"))
            rep.findings.extend(metric_findings(key, short, camp, th, args.ignore))
        c0 = camps[0]
        rep.campaign = {"runs": c0.runs, "calls": c0.calls, "reverts": c0.reverts}
        reports.append(rep)
    notes = ["metrics-only mode (--from-json): the frozen-input probe did not run"]
    if not reports:
        notes.append("no invariant campaigns found in the JSON")
    _emit(reports, args, f"invariant-vacuity {__version__} (from {args.from_json})", notes, {"mode": "from-json"})
    return _exit_code(reports, args.strict)


class _Cleanup:
    def __init__(self):
        self.paths: List[str] = []
        self.dirs: List[str] = []

    def run(self):
        for p in self.paths:
            try:
                os.remove(p)
            except OSError:
                pass
        for d in self.dirs:
            try:
                os.rmdir(d)  # only if empty
            except OSError:
                pass
        self.paths, self.dirs = [], []


def main(argv: Optional[List[str]] = None) -> int:
    args = _parser().parse_args(argv)
    th = _thresholds(args)
    passthrough = list(args.forge_args or [])
    if passthrough and passthrough[0] == "--":
        passthrough = passthrough[1:]
    elif passthrough:
        print(f"vacuity: unrecognized arguments: {' '.join(passthrough)} (put forge arguments after --)",
              file=sys.stderr)
        return EXIT_TOOL

    if args.from_json:
        return _from_json(args, th)

    root = os.path.abspath(args.root)
    if not os.path.isfile(os.path.join(root, "foundry.toml")):
        print(f"vacuity: no foundry.toml in {root}", file=sys.stderr)
        return EXIT_TOOL

    cleanup = _Cleanup()

    def _on_signal(signum, _frame):
        cleanup.run()
        raise SystemExit(128 + signum)

    old_int = signal.signal(signal.SIGINT, _on_signal)
    old_term = signal.signal(signal.SIGTERM, _on_signal)
    try:
        return _run(args, th, root, passthrough, cleanup)
    except ForgeError as e:
        print(f"vacuity: {e}", file=sys.stderr)
        return EXIT_TOOL
    finally:
        if not args.keep_probe:
            cleanup.run()
        signal.signal(signal.SIGINT, old_int)
        signal.signal(signal.SIGTERM, old_term)


def _wipe_build(out_dir: str, cache_file: str, key_file: str) -> None:
    shutil.rmtree(out_dir, ignore_errors=True)
    # some Forge versions treat --cache-path as a directory, others as a file
    if os.path.isdir(cache_file):
        shutil.rmtree(cache_file, ignore_errors=True)
    elif os.path.exists(cache_file):
        os.remove(cache_file)
    if os.path.exists(key_file):
        os.remove(key_file)


def _run(args, th: Thresholds, root: str, passthrough: List[str], cleanup: _Cleanup) -> int:
    env = dict(os.environ)
    forge = forge_mod.find_forge(args.forge)
    ver, ver_text = forge_mod.version(forge, root, env)
    cfg = forge_mod.config(forge, root, env)

    test_dir = str(cfg.get("test") or "test")
    cache_dir = str(cfg.get("cache_path") or "cache")
    work = cache_dir if os.path.isabs(cache_dir) else os.path.join(root, cache_dir)
    work = os.path.join(work, "vacuity")
    out_dir = os.path.join(work, "out")
    cache_file = os.path.join(work, "solidity-files-cache.json")
    persist = os.path.join(work, "invariant-failures")
    shutil.rmtree(persist, ignore_errors=True)
    os.makedirs(work, exist_ok=True)

    abs_test = test_dir if os.path.isabs(test_dir) else os.path.join(root, test_dir)
    gen_dir = os.path.join(abs_test, GEN_DIR)
    if os.path.isdir(gen_dir):
        for fn in os.listdir(gen_dir):  # leftovers from an interrupted run
            if fn.startswith(GEN_PREFIXES) and fn.endswith(".sol"):
                os.remove(os.path.join(gen_dir, fn))

    extra_output = [x for x in (cfg.get("extra_output") or []) if isinstance(x, str)]
    if "storageLayout" not in extra_output:
        extra_output.append("storageLayout")
    env.update({
        "FOUNDRY_INVARIANT_SHOW_METRICS": "true",
        "FOUNDRY_INVARIANT_SHRINK_RUN_LIMIT": "0",
        "FOUNDRY_INVARIANT_FAILURE_PERSIST_DIR": persist,
        "FOUNDRY_EXTRA_OUTPUT": json.dumps(extra_output),
        "FOUNDRY_AST": "true",
        # Forge 1.8 turns this on by default. It rewrites `new X()` in test files, so code
        # the probe deploys stops matching the build artifacts. It is a compile-time cache
        # optimization only; turning it off in the isolated build changes no test behavior.
        "FOUNDRY_DYNAMIC_TEST_LINKING": "false",
    })
    inv_cfg = cfg.get("invariant") or {}
    if inv_cfg.get("corpus_dir"):
        corpus = os.path.join(work, "corpus")
        shutil.rmtree(corpus, ignore_errors=True)
        env["FOUNDRY_INVARIANT_CORPUS_DIR"] = corpus

    iso = ["--out", out_dir, "--cache-path", cache_file]
    # The isolated build is reused between runs only while the Forge version and the
    # resolved config stay the same; otherwise artifacts from another compiler or profile
    # could be read as if they belonged to this build.
    key_file = os.path.join(work, "build-key")
    key = hashlib.sha256(json.dumps([ver_text, cfg, extra_output], sort_keys=True, default=str).encode()).hexdigest()
    old_key = None
    try:
        with open(key_file, encoding="utf-8") as fh:
            old_key = fh.read().strip()
    except OSError:
        pass
    fresh = old_key != key
    if fresh:
        _wipe_build(out_dir, cache_file, key_file)
    forge_mod.build(forge, root, env, iso, args.timeout)
    arts, asts, dups = art_mod.load_checked(out_dir)
    if dups and not fresh:
        # stale artifacts despite an unchanged key (for example a pragma edit that changed
        # the auto-detected solc): rebuild from scratch once
        _wipe_build(out_dir, cache_file, key_file)
        forge_mod.build(forge, root, env, iso, args.timeout)
        arts, asts, dups = art_mod.load_checked(out_dir)
    with open(key_file, "w", encoding="utf-8") as fh:
        fh.write(key)
    rel_test = os.path.relpath(abs_test, root).replace(os.sep, "/")
    cli_filters = art_mod.Filters(match_contract=args.match_contract, match_path=args.match_path)
    profile_filters = art_mod.Filters(**{k: (cfg.get(k) or None) for k in (
        "match_contract", "no_match_contract", "match_path", "no_match_path", "match_test", "no_match_test")})
    selected, inv_of, notes = art_mod.select_targets(arts, rel_test, cli_filters, profile_filters,
                                                     skip_dirs=[f"{rel_test}/{GEN_DIR}"])
    for d in dups:
        notes.append(f"{d} is compiled with more than one solc version in this build; using the newest version's artifact")
    header = f"invariant-vacuity {__version__} | {ver_text}"
    meta = {"forge_version": ".".join(map(str, ver)), "mode": "full" if not args.no_probe else "metrics"}
    if not selected:
        notes.append(f"no concrete test contracts with invariants found under {rel_test}/")
        _emit([], args, header, notes, meta)
        return EXIT_TOOL if (args.match_contract or args.match_path) else EXIT_OK

    targets: List[ProbeTarget] = []
    for i, a in enumerate(selected):
        sigs = inv_of[f"{a.source}:{a.name}"]
        method_ids = _method_ids(a)
        c_cfg, i_cfg = art_mod.inline_config(asts.get(a.source), a.name, sigs)
        targets.append(ProbeTarget(
            index=i, contract=a.name, source=a.source, has_setup=a.has_function("setUp"),
            invariants=sigs, selectors=[method_ids[s] for s in sigs],
            contract_config=c_cfg, invariant_config=i_cfg,
        ))

    probe = not args.no_probe
    if probe:
        initial_balance = _int(cfg.get("initial_balance"), 0xffffffffffffffffffffffff)
        try:
            files = generate_files(targets, initial_balance, args.record_gas, args.trace_gas)
        except ValueError as e:
            raise ForgeError(f"cannot generate probe: {e}")
        os.makedirs(gen_dir, exist_ok=True)
        if not os.listdir(gen_dir):
            cleanup.dirs.append(gen_dir)
        for fn, code in files:
            path = os.path.join(gen_dir, fn)
            cleanup.paths.append(path)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(code)

    never = "^VACUITY_NEVER_MATCHES_ANYTHING$"
    # Targets were already filtered with the user's profile filters above. Neutralize
    # those filters in forge so they cannot exclude the generated probe file or its tests.
    neutral = ["--no-match-contract", never, "--no-match-test", never,
               "--match-path", "**", "--no-match-path", "__vacuity_never_matches__/**"]
    rel_gen = os.path.relpath(gen_dir, root).replace(os.sep, "/")
    probe_rel = {t.index: f"{rel_gen}/{probe_file(t)}" for t in targets}
    user_rx = "|".join(sorted({re.escape(t.contract) for t in targets}))
    capture: dict = {}
    campaign_env: dict = {}
    if probe:
        # Phase 1: capture each invariant's inputs. It needs -vvv (Forge only enables the
        # opcode tracer at that verbosity), and then Forge keeps every call trace in memory
        # and in its JSON, including the recorded opcode traces (several MB per invariant).
        # Small batches keep both Forge's and our memory bounded.
        for batch in _capture_batches(targets):
            probe_rx = "|".join(re.escape(t.probe_name) for t in batch)
            p1 = ["test", "--json", "-vvv", *iso, "--match-contract", f"^({probe_rx})$",
                  "--match-test", f"^{INFO_TEST}", *neutral, *passthrough]
            capture.update(_forge_test(forge, p1, root, env, args.timeout, gen_dir))
        campaign_env = build_campaign_env(targets, capture, probe_rel)

    # Phase 2: the user's own invariants plus the probe campaigns (input lists via env).
    batches = _batches(targets, campaign_env) if probe else [[]]
    results: dict = {}
    for n, batch in enumerate(batches):
        names = ([user_rx] if n == 0 else []) + [re.escape(t.probe_name) for t in batch]
        if not names:
            continue
        p2 = ["test", "--json", *iso, "--match-contract", f"^({'|'.join(names)})$",
              "--match-test", "^(invariant|statefulFuzz)", *neutral, *passthrough]
        benv = dict(env)
        if batch:
            benv["VACUITY_MODE"] = "campaign"
            for t in batch:
                for k in range(len(t.invariants)):
                    key = f"VACUITY_P{t.index}_{k}"
                    if key in campaign_env:
                        benv[key] = campaign_env[key]
        results.update(_forge_test(forge, p2, root, benv, args.timeout, gen_dir))

    graph = WriteGraph(asts.values()) if asts else None
    reports = []
    for t, a in zip(targets, selected):
        user_suite = find_suite(results, t.source, t.contract)
        probe_suite = find_suite(results, probe_rel[t.index], t.probe_name) if probe else None
        info_suite = find_suite(capture, probe_rel[t.index], t.probe_name) if probe else None
        reports.append(judge(t, a, arts, user_suite, probe_suite, th, args.ignore, probe, graph, info_suite))
    if not probe:
        notes.append("--no-probe: frozen-input probe skipped, metrics checks only")
    _emit(reports, args, header, notes, meta)
    return _exit_code(reports, args.strict)


ENV_BUDGET = 1_000_000  # bytes of VACUITY_* environment per forge invocation
CAPTURE_INVARIANTS = 24  # invariants per capture run (whole probes; a bigger probe runs alone)


def _capture_batches(targets: List[ProbeTarget]) -> List[List[ProbeTarget]]:
    batches: List[List[ProbeTarget]] = []
    count = 0
    for t in targets:
        if not batches or count + len(t.invariants) > CAPTURE_INVARIANTS:
            batches.append([])
            count = 0
        batches[-1].append(t)
        count += len(t.invariants)
    return batches


def _strip_traces(results: dict) -> dict:
    """Drops call traces (never used, often most of the output) as soon as JSON is parsed."""
    for suite in results.values():
        if isinstance(suite, dict):
            for t in (suite.get("test_results") or {}).values():
                if isinstance(t, dict):
                    t.pop("traces", None)
    return results


def build_campaign_env(targets: List[ProbeTarget], capture: dict, probe_rel: dict) -> dict:
    """VACUITY_P<i>_<k> = abi-encoded input lists for every invariant captured in phase 1."""
    out = {}
    for t in targets:
        suite = find_suite(capture, probe_rel[t.index], t.probe_name)
        if suite is None:
            continue
        _, setup_failure = campaigns(suite)
        if setup_failure:
            continue  # reported from the capture results; nothing to run
        info_r = (suite.get("test_results") or {}).get(f"{INFO_TEST}()") or {}
        info = parse_info(info_r.get("decoded_logs") or [])
        if not info.complete:
            continue
        for k in range(len(t.invariants)):
            per = info.per.get(k)
            if not per or not per.get("captured") or not per.get("fp"):
                continue
            blob = encode_inputs(
                [x[0] for x in per["slots"]], [x[1] for x in per["slots"]], [x[3] for x in per["slots"]],
                per["bals"], per["codes"], per["env"], per["fp"])
            out[f"VACUITY_P{t.index}_{k}"] = "0x" + blob.hex()
    return out


def _batches(targets: List[ProbeTarget], env: dict) -> List[List[ProbeTarget]]:
    batches: List[List[ProbeTarget]] = [[]]
    size = 0
    for t in targets:
        tsize = sum(len(env.get(f"VACUITY_P{t.index}_{k}", "")) + 32 for k in range(len(t.invariants)))
        if batches[-1] and size + tsize > ENV_BUDGET:
            batches.append([])
            size = 0
        batches[-1].append(t)
        size += tsize
    return batches


def _forge_test(forge: str, argv: List[str], root: str, env: dict, timeout, gen_dir: str) -> dict:
    rc, out, err = forge_mod.run(forge, argv, root, env, timeout=timeout)
    try:
        return _strip_traces(forge_mod.parse_test_json(out))
    except ForgeError:
        if "No tests found" in (out + err) or "No tests match" in (out + err):
            return {}
        msg = forge_mod.tail(err or out)
        if rc in (137, -9):
            msg = (f"forge was killed (exit {rc}), most likely out of memory.\n" + msg).strip()
        elif not msg:
            msg = f"forge exited with code {rc} and printed nothing"
        if GEN_DIR in msg:
            msg += (f"\n\nThe generated probe failed to compile. This is a bug in invariant-vacuity; "
                    f"rerun with --keep-probe and report the files in {os.path.relpath(gen_dir, root)}.")
        raise ForgeError(f"forge test did not produce results:\n{msg}")


def _method_ids(a) -> dict:
    from .keccak import selector
    out = {}
    for f in a.functions():
        if f.get("inputs"):
            continue
        sig = f"{f.get('name')}()"
        out[sig] = selector(sig)
    return out


def _int(v, default: int) -> int:
    if v is None:
        return default
    try:
        if isinstance(v, int):
            return v
        s = str(v)
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except ValueError:
        return default


if __name__ == "__main__":
    sys.exit(main())
