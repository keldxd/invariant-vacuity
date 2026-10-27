"""Turns forge JSON results into findings.

Severity policy: errors are proofs, warnings are smells.
  error   - the probe verified that none of an invariant's inputs changed during
            the campaign, and every input it read was tracked.
  warning - something that usually indicates a weak or broken campaign but is
            not proof (high revert rates, dead selectors, untracked inputs,
            inconclusive probe).
  info    - context (e.g. the invariant already fails in your run).
"""

from __future__ import annotations

import fnmatch
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple

from . import cheatcodes
from .keccak import checksum
from .writes import CHEAT_PREFIX, ENV_CHEATS, WILDCARD, WriteGraph, is_entry_point
from .artifacts import Artifact, CodeIndex, slot_label
from .probe_gen import (ENV_TRACKED, ENV_UNTRACKED, INFO_TEST, LIVE_MARKER, PROBE_INVARIANT_PREFIX,
                        SETUP_MARKER, UNSUPPORTED_MARKER, ProbeTarget)


@dataclass
class Thresholds:
    selector_revert: float = 0.9
    campaign_revert: float = 0.75
    discard: float = 0.5


@dataclass
class Finding:
    severity: str
    code: str
    contract: str
    subject: str
    message: str
    details: dict = field(default_factory=dict)


@dataclass
class InvariantReport:
    name: str
    verdict: str  # live | frozen | frozen-untracked | inconclusive | failing | not-probed
    inputs: List[str] = field(default_factory=list)
    note: str = ""


@dataclass
class ContractReport:
    contract: str  # path:Name
    invariants: List[InvariantReport] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    campaign: dict = field(default_factory=dict)


@dataclass
class Campaign:
    invariants: List[Tuple[str, str, str]]  # (name with (), status, reason)
    metrics: Dict[str, dict]
    runs: int
    calls: int
    reverts: int


def _with_parens(name: str) -> str:
    return name if name.endswith(")") else f"{name}()"


def campaigns(suite: dict) -> Tuple[List[Campaign], Optional[str]]:
    """Extracts invariant campaigns from one suite. Supports both the
    one-campaign-per-invariant model (forge <= 1.7) and the shared-campaign
    model with invariant_predicate_results (forge >= 1.8)."""
    out: List[Campaign] = []
    setup_failure = None
    results = suite.get("test_results") or {}
    for test_name, r in results.items():
        if not isinstance(r, dict):
            continue
        if test_name.startswith("setUp(") and r.get("status") == "Failure":
            setup_failure = r.get("reason") or "setUp() failed"
            continue
        kind = r.get("kind") or {}
        inv = kind.get("Invariant") if isinstance(kind, dict) else None
        if not isinstance(inv, dict):
            continue
        # forge >= 1.8 may report failure reasons only in invariant_failures
        # (single-invariant contracts have no invariant_predicate_results).
        fail_reason: Dict[str, str] = {}
        first_fail = ""
        for f in r.get("invariant_failures") or []:
            if not isinstance(f, dict):
                continue
            reason = f.get("reason") or ""
            if f.get("name"):
                fail_reason.setdefault(_with_parens(str(f["name"])), reason)
            first_fail = first_fail or reason
        preds = r.get("invariant_predicate_results")
        if isinstance(preds, list) and preds:
            invs = []
            for p in preds:
                if not isinstance(p, dict):
                    continue
                pname = _with_parens(str(p.get("name", "?")))
                invs.append((pname, p.get("status", "?"), p.get("reason") or fail_reason.get(pname, "")))
        else:
            tname = _with_parens(test_name)
            reason = r.get("reason") or fail_reason.get(tname) or first_fail or ""
            invs = [(tname, r.get("status", "?"), reason)]
        out.append(Campaign(
            invariants=invs,
            metrics=inv.get("metrics") or {},
            runs=int(inv.get("runs") or 0),
            calls=int(inv.get("calls") or 0),
            reverts=int(inv.get("reverts") or 0),
        ))
    return out, setup_failure


def aggregate(camps: List[Campaign]) -> Campaign:
    """Sums several campaigns of one test contract. Forge <= 1.7 runs one campaign
    per invariant with identical targets, so per-selector totals are what matter."""
    if len(camps) == 1:
        return camps[0]
    metrics: Dict[str, dict] = {}
    for c in camps:
        for k, m in (c.metrics or {}).items():
            acc = metrics.setdefault(k, {"calls": 0, "reverts": 0, "discards": 0})
            for f in ("calls", "reverts", "discards"):
                acc[f] += int((m or {}).get(f, 0))
    invs = [i for c in camps for i in c.invariants]
    return Campaign(invariants=invs, metrics=metrics, runs=sum(c.runs for c in camps),
                    calls=sum(c.calls for c in camps), reverts=sum(c.reverts for c in camps))


def find_suite(results: dict, source: str, name: str) -> Optional[dict]:
    key = f"{source}:{name}"
    if key in results:
        return results[key]
    for k, v in results.items():
        if k.endswith(f":{name}") and k.replace("\\", "/").endswith(f"{source}:{name}"):
            return v
    return None


def _short(selector_key: str) -> str:
    return selector_key.rsplit(":", 1)[-1]


def _ignored(patterns: List[str], *subjects: str) -> bool:
    return any(fnmatch.fnmatch(s, p) for p in patterns for s in subjects)


def metric_findings(contract: str, short: str, camp: Campaign, th: Thresholds, ignore: List[str]) -> List[Finding]:
    out: List[Finding] = []
    names = ", ".join(n for n, _, _ in camp.invariants)
    passing = any(s == "Success" for _, s, _ in camp.invariants)
    if passing and camp.calls == 0:
        out.append(Finding("warning", "no-calls", contract, names,
                           "the campaign made 0 calls, so the invariant was only checked against the setUp state"))
    if camp.calls > 0 and not camp.metrics:
        out.append(Finding("warning", "metrics-missing", contract, names,
                           "forge reported no per-selector metrics for this campaign"))
    if camp.calls > 0 and camp.reverts == camp.calls:
        out.append(Finding("warning", "all-calls-reverted", contract, names,
                           f"every one of {camp.calls} calls reverted, so no handler ever changed state",
                           {"calls": camp.calls}))
    elif camp.calls > 0 and camp.reverts / camp.calls >= th.campaign_revert:
        pct = round(100 * camp.reverts / camp.calls)
        out.append(Finding("warning", "high-revert-campaign", contract, names,
                           f"{pct}% of {camp.calls} calls reverted (threshold {round(100 * th.campaign_revert)}%)",
                           {"calls": camp.calls, "reverts": camp.reverts}))
    for key in sorted(camp.metrics):
        m = camp.metrics[key] or {}
        # Forge's per-selector "calls" includes discarded calls (vm.assume rejections).
        c, rv, d = int(m.get("calls", 0)), int(m.get("reverts", 0)), int(m.get("discards", 0))
        executed = max(c - d, 0)
        sel = _short(key)
        if _ignored(ignore, sel, f"{short}.{sel}"):
            continue
        if executed > 0 and rv >= executed:
            out.append(Finding("warning", "dead-selector", contract, sel,
                               f"{sel} reverted in all {executed} executed calls (never succeeded)",
                               {"calls": c, "executed": executed, "reverts": rv, "discards": d}))
        elif executed > 0 and rv / executed >= th.selector_revert:
            out.append(Finding("warning", "high-revert-selector", contract, sel,
                               f"{sel} reverted in {round(100 * rv / executed)}% of {executed} executed calls",
                               {"calls": c, "executed": executed, "reverts": rv, "discards": d}))
        if c > 0 and d > 0 and d / c >= th.discard:
            extra = " and was never executed" if executed == 0 else ""
            out.append(Finding("warning", "high-discard", contract, sel,
                               f"{sel}: {d} of {c} calls were discarded by vm.assume ({round(100 * d / c)}%){extra}",
                               {"calls": c, "executed": executed, "discards": d}))
    return out


# ---------------------------------------------------------------- probe parsing

@dataclass
class ProbeInfo:
    trace_supported: bool = False
    complete: bool = False
    inner: str = ""
    per: Dict[int, dict] = field(default_factory=dict)
    accounts: Dict[str, str] = field(default_factory=dict)  # lowercase addr -> code hex


def parse_info(logs: List[str]) -> ProbeInfo:
    info = ProbeInfo()
    for line in logs or []:
        if not isinstance(line, str) or not line.startswith("VP"):
            continue
        parts = line.split("|")
        tag = parts[0]
        try:
            if tag == "VPINFO":
                info.trace_supported = parts[2] == "1"
            elif tag == "VPINV":
                i = int(parts[1])
                info.per[i] = {"baseline_ok": parts[2] == "1", "trace_ok": parts[3] == "1", "env": int(parts[4]),
                               "captured": (parts[5] == "1") if len(parts) > 5 else True,
                               "gas": int(parts[6]) if len(parts) > 6 else None,
                               "slots": [], "bals": [], "codes": [], "cheats": []}
            elif tag == "VPSLOT":
                code = parts[5] if len(parts) > 5 else parts[2]
                info.per[int(parts[1])]["slots"].append((parts[2], parts[3], parts[4], code))
            elif tag == "VPBAL":
                info.per[int(parts[1])]["bals"].append(parts[2])
            elif tag == "VPCODE":
                info.per[int(parts[1])]["codes"].append(parts[2])
            elif tag == "VPFP":
                info.per[int(parts[1])]["fp"] = parts[2]
            elif tag == "VPCHEAT":
                info.per[int(parts[1])]["cheats"].append(parts[2][2:10])
            elif tag == "VPACCT":
                info.accounts[parts[1].lower()] = parts[2]
            elif tag == "VPINNER":
                info.inner = parts[1].lower()
            elif tag == "VPEND":
                info.complete = True
        except (IndexError, ValueError, KeyError):
            continue
    return info


def probe_statuses(suite: Optional[dict], info_suite: Optional[dict] = None
                   ) -> Tuple[Dict[int, Tuple[str, str]], Dict[int, Campaign], Optional[str], List[str]]:
    """Returns ({idx: (state, reason)}, {idx: campaign}, setup_failure, info_logs).

    `suite` holds the probe campaigns; `info_suite` the capture phase (info test).
    Both may be the same suite."""
    info_suite = info_suite if info_suite is not None else suite
    setup_failure = None
    if info_suite is not None:
        _, setup_failure = campaigns(info_suite)
    camps: List[Campaign] = []
    if suite is not None:
        camps, campaign_setup = campaigns(suite)
        setup_failure = setup_failure or campaign_setup
    states: Dict[int, Tuple[str, str]] = {}
    by_idx: Dict[int, Campaign] = {}
    for camp in camps:
        for name, status, reason in camp.invariants:
            base = name[:-2] if name.endswith("()") else name
            if not base.startswith(PROBE_INVARIANT_PREFIX):
                continue
            try:
                idx = int(base[len(PROBE_INVARIANT_PREFIX):])
            except ValueError:
                continue
            if status == "Success":
                states[idx] = ("frozen", "")
            elif status == "Failure" and LIVE_MARKER in (reason or ""):
                states[idx] = ("live", "")
            else:
                states[idx] = ("inconclusive", reason or f"probe status {status}")
            by_idx[idx] = camp
    logs: List[str] = []
    info_r = ((info_suite or {}).get("test_results") or {}).get(f"{INFO_TEST}()")
    if isinstance(info_r, dict):
        logs = info_r.get("decoded_logs") or []
    return states, by_idx, setup_failure, logs


# ---------------------------------------------------------------- naming

class Namer:
    def __init__(self, arts: List[Artifact], info: ProbeInfo, user_contract: str,
                 user_art: Optional[Artifact] = None):
        self.index = CodeIndex(arts)
        self.info = info
        self.user_contract = user_contract
        self.user_art = user_art
        self.extra_keys: List[str] = []
        self._cache: Dict[str, Tuple[str, Optional[Artifact]]] = {}

    def account(self, addr: str) -> Tuple[str, Optional[Artifact]]:
        a = addr.lower()
        if a in self._cache:
            return self._cache[a]
        art = None
        if a == self.info.inner:
            label = f"{self.user_contract} (your test contract)"
            # The probe deployed this address itself with `new <test contract>()`, so it is
            # an instance of the test contract even when its bytecode differs from the
            # artifact (Forge 1.8 preprocesses test files and can compile `new X()` there
            # differently from the same code inside the probe).
            art = self.user_art
            if art is None:
                code = self.info.accounts.get(a)
                art = self.index.identify(code) if code else None
        else:
            code = self.info.accounts.get(a)
            art = self.index.identify(code) if code else None
            pretty = checksum(addr) if len(addr) == 42 else addr
            label = f"{art.name}@{pretty[:8]}" if art else pretty
        self._cache[a] = (label, art)
        return label, art

    def _keys(self) -> Dict[int, str]:
        if not hasattr(self, "_key_cache"):
            keys: Dict[int, str] = {}
            for a in list(self.info.accounts) + ([self.info.inner] if self.info.inner else []):
                try:
                    keys[int(a, 16)] = self.account(a)[0]
                except ValueError:
                    continue
            for extra in self.extra_keys:
                try:
                    keys.setdefault(int(extra, 16), extra)
                except ValueError:
                    continue
            for n in range(8):
                keys.setdefault(n, str(n))
            self._key_cache = keys
        return self._key_cache

    def variables(self, code_addr: str, slot_hex: str) -> Tuple[Optional[Artifact], Optional[List[str]]]:
        """(artifact whose code read the slot, state variable names) or names None if unknown."""
        _, art = self.account(code_addr)
        if art is None:
            return None, None
        label = slot_label(art, slot_hex, self._keys())
        if not label or label.startswith("("):
            return art, None
        names = []
        for part in label.split(", "):
            part = part.split(" (+")[0]
            names.append(part.split("[")[0])
        return art, names

    def slot(self, addr: str, slot_hex: str, code_addr: Optional[str] = None) -> str:
        label, _ = self.account(addr)
        code_label, art = self.account(code_addr or addr)
        var = slot_label(art, slot_hex, self._keys())
        if code_addr and code_addr.lower() != addr.lower():
            label = f"{label} (via {code_label})"
        s = int(slot_hex, 16)
        slot_txt = f"slot {s}" if s < 2 ** 32 else f"slot {slot_hex[:12]}..."
        return f"{label}: {var} ({slot_txt})" if var else f"{label}: {slot_txt}"


# ---------------------------------------------------------------- verdicts

def judge(
    target: ProbeTarget, art: Artifact, arts: List[Artifact], user_suite: Optional[dict], probe_suite: Optional[dict],
    th: Thresholds, ignore: List[str], probe_enabled: bool, graph: Optional[WriteGraph] = None,
    info_suite: Optional[dict] = None,
) -> ContractReport:
    contract = f"{target.source}:{target.contract}"
    rep = ContractReport(contract=contract)

    # user campaign(s)
    user_status: Dict[str, Tuple[str, str]] = {}
    user_camp_of: Dict[str, Campaign] = {}
    user_camps: List[Campaign] = []
    user_setup_failed = False
    if user_suite is not None:
        camps, setup_failure = campaigns(user_suite)
        user_camps = camps
        user_setup_failed = bool(setup_failure)
        if setup_failure:
            rep.findings.append(Finding("warning", "setup-failed", contract, "setUp()",
                                        f"setUp() failed in your test run: {setup_failure}"))
        for camp in camps:
            for name, status, reason in camp.invariants:
                user_status[name] = (status, reason)
                user_camp_of[name] = camp
        live_camps = [c for c in camps if not _ignored(
            ignore, target.contract, *[f"{target.contract}.{n[:-2]}" for n, _, _ in c.invariants])]
        if live_camps:
            agg = aggregate(live_camps)
            rep.findings.extend(metric_findings(contract, target.contract, agg, th, ignore))
        if camps:
            agg_all = aggregate(camps)
            rep.campaign = {"campaigns": len(camps), "runs": max(c.runs for c in camps), "calls": agg_all.calls,
                            "reverts": agg_all.reverts,
                            "model": "shared" if any(len(c.invariants) > 1 for c in camps) else "per-invariant"}

    # probe
    states: Dict[int, Tuple[str, str]] = {}
    probe_camps: Dict[int, Campaign] = {}
    probe_setup = None
    info = ProbeInfo()
    if probe_enabled and (probe_suite is not None or info_suite is not None):
        states, probe_camps, probe_setup, logs = probe_statuses(probe_suite, info_suite)
        info = parse_info(logs)
    namer = Namer(arts, info, target.contract, art)

    for idx, inv in enumerate(target.invariants):
        subject = f"{target.contract}.{inv[:-2]}"
        ignored = _ignored(ignore, target.contract, subject)
        ustatus = user_status.get(inv)
        r = InvariantReport(name=inv, verdict="not-probed")
        rep.invariants.append(r)
        if ustatus and ustatus[0] == "Failure":
            r.verdict = "failing"
            r.note = "fails in your test run, so vacuity is not the issue"
            if not ignored:
                rep.findings.append(Finding("info", "invariant-failing", contract, inv,
                                            f"{inv} fails in your run: {(ustatus[1] or '')[:200]}"))
            continue
        if not probe_enabled:
            continue
        if probe_suite is None and not probe_setup:
            r.verdict = "inconclusive"
            r.note = "probe results missing from forge output"
            if not ignored:
                rep.findings.append(Finding("warning", "probe-missing", contract, inv, r.note))
            continue
        if probe_setup:
            r.verdict = "inconclusive"
            if UNSUPPORTED_MARKER in probe_setup:
                r.note = f"probe not supported here: {probe_setup}"
            elif SETUP_MARKER in probe_setup and user_setup_failed:
                r.note = "setUp() reverts in your own test run too, so there was nothing to probe"
            elif SETUP_MARKER in probe_setup:
                r.note = ("your setUp() passes in your run but reverted inside the probe wrapper "
                          "(see README: setUp assumptions)")
            else:
                r.note = f"probe setUp failed: {probe_setup[:300]}"
            if not ignored:
                rep.findings.append(Finding("warning", "probe-inconclusive", contract, inv, r.note))
            continue
        state, reason = states.get(idx, ("inconclusive", "probe result missing"))
        if state == "live":
            r.verdict = "live"
            continue
        if state == "inconclusive":
            r.verdict = "inconclusive"
            if "VACUITY:NONDETERMINISTIC" in reason:
                r.note = ("the state right after setUp was different in the probe's two runs (for example a "
                          "fork of the latest block, or setUp using randomness), so the probe cannot compare "
                          "inputs reliably")
            elif "VACUITY:CAPTURE_FAILED" in reason:
                r.note = ("the probe could not record this invariant's inputs: one call of it needs more gas "
                          "than the recording limit (--record-gas, default 5,000,000)")
            else:
                r.note = f"probe campaign ended without a verdict: {reason[:300]}"
            if not ignored:
                rep.findings.append(Finding("warning", "probe-inconclusive", contract, inv, r.note))
            continue

        # frozen: decide whether every input was tracked
        per = info.per.get(idx)
        camp = probe_camps.get(idx)
        calls = camp.calls if camp else 0
        problems: List[str] = []
        if per is None or not info.complete:
            problems.append("the probe's input details were not reported, so tracking could not be confirmed")
            per = per or {"slots": [], "bals": [], "codes": [], "cheats": [], "env": 0,
                          "baseline_ok": True, "trace_ok": False}
        if not per["baseline_ok"]:
            r.verdict = "inconclusive"
            r.note = "the invariant reverted when the probe called it at the setUp state"
            if not ignored:
                rep.findings.append(Finding("warning", "probe-inconclusive", contract, inv, r.note))
            continue
        if not per["trace_ok"]:
            gas = per.get("gas")
            why = (f"one call of it uses about {gas:,} gas, more than --trace-gas" if gas and gas > 0 else
                   "no tracer, or the invariant needs more gas than --trace-gas")
            problems.append(f"the opcode trace was unavailable ({why}), so balance, environment and "
                            "cheatcode reads were not tracked")
        env = per["env"]
        for bit, label in ENV_UNTRACKED.items():
            if env & bit:
                problems.append(f"it reads {label}, which the probe does not track")
        problems.extend(f"it calls {name}, whose result the probe does not track"
                        for name in cheatcodes.untracked(per["cheats"]))

        inner = info.inner
        namer.extra_keys = [v for _, _, v, _ in per["slots"] if 2 ** 16 < int(v, 16) < 2 ** 160]
        slots = sorted(per["slots"], key=lambda x: x[0].lower() == inner)  # protocol state first
        inputs = [namer.slot(a, s, c) for a, s, _, c in slots]
        inputs += [f"ETH balance of {namer.account(a)[0]}" for a in per["bals"]]
        inputs += [label for bit, label in ENV_TRACKED.items() if env & bit]
        r.inputs = inputs

        mismatch = _compare_targets(user_camp_of.get(inv), camp)
        if mismatch:
            problems.append(mismatch)

        n_inputs = len(inputs)
        plural = "s" if n_inputs != 1 else ""
        details = {"inputs": inputs, "probe_calls": calls, "codes": len(per["codes"])}
        if problems:
            if n_inputs == 0:
                tracked = "it reads no tracked storage, balance or environment value"
            else:
                tracked = f"none of its {n_inputs} tracked input{plural} changed during {calls} probe calls"
            r.verdict = "frozen-untracked"
            r.note = f"{tracked}, but this is not confirmed: " + "; ".join(problems)
            if not ignored:
                rep.findings.append(Finding("warning", "frozen-untracked", contract, inv, r.note,
                                            {**details, "untracked": problems}))
        else:
            if n_inputs == 0:
                summary = (f"reads no storage, balance or environment value, so its result cannot change "
                           f"({calls} probe calls)")
            else:
                summary = f"none of its {n_inputs} input{plural} changed during {calls} probe calls"
            guarded, unanalyzed = classify_frozen(per, namer, graph, entry_points(
                aggregate([c for c in user_camps]) if user_camps else None, camp))
            if guarded or unanalyzed:
                r.verdict = "frozen-guarded"
                parts = []
                if guarded:
                    shown = guarded[:4]
                    more = f"; and {len(guarded) - 4} more" if len(guarded) > 4 else ""
                    parts.append("code that ran during the campaign can write them (" + "; ".join(shown) + more
                                 + "), yet they never changed. Either those writes hit another instance or "
                                 "mapping key, sit behind a condition that was never true (expected for a "
                                 "violation flag on a correct implementation), or always wrote the same value")
                if unanalyzed:
                    parts.append("not every input could be analyzed: " + "; ".join(unanalyzed[:3]))
                r.note = summary + ". " + " ".join(p[0].upper() + p[1:] + "." for p in parts)
                if not ignored:
                    rep.findings.append(Finding("warning", "frozen-guarded", contract, inv, r.note,
                                                {**details, "reachable_writes": guarded, "unanalyzed": unanalyzed}))
                continue
            r.verdict = "frozen"
            r.note = (summary if n_inputs == 0 else
                      summary + ", and no code that ran during the campaign writes any of them")
            if not ignored:
                rep.findings.append(Finding("error", "frozen", contract, inv, r.note, details))
    return rep


def entry_points(*camps: Optional[Campaign]) -> List[Tuple[str, str]]:
    """Target functions that completed successfully at least once in a campaign."""
    for camp in camps:
        if camp is None or not camp.metrics:
            continue
        out = []
        for key, m in camp.metrics.items():
            c, rv, d = int((m or {}).get("calls", 0)), int((m or {}).get("reverts", 0)), int((m or {}).get("discards", 0))
            if c - d - rv <= 0:
                continue
            short = key.rsplit(":", 1)[-1]
            if "." not in short:
                continue
            contract, fn = short.split(".", 1)
            if is_entry_point(fn):
                out.append((contract, fn))
        return out
    return []


def classify_frozen(per: dict, namer: "Namer", graph: Optional[WriteGraph], entries: List[Tuple[str, str]]
                    ) -> Tuple[List[str], List[str]]:
    """Returns (reachable writes to the inputs, unanalyzed inputs).

    Both empty means no code that completed successfully during the campaign
    writes any of the invariant's input variables, on any instance or key:
    the inputs could not have changed. Writes are matched by contract type and
    variable name only, so a reachable write may target another instance, another
    mapping key, sit in a branch that never ran, or always write the same value.
    Any of those keeps the result a warning rather than an error."""
    if graph is None:
        return [], ["write-path analysis was unavailable (no AST in build output)"]
    sites, complete = graph.reachable_writes(entries)
    stores = [x for x in sites if x.variable == CHEAT_PREFIX + "store"]
    writes: List[str] = []
    unanalyzed: List[str] = []

    def fmt(site) -> str:
        var = site.variable.replace(CHEAT_PREFIX, "vm.")
        how = "conditionally" if site.conditional else "unconditionally"
        if var == WILDCARD:
            var = "storage via assembly sstore"
        return f"{site.contract}.{site.function} writes {var} ({how})"

    for acct, slot, _val, code in per["slots"]:
        art, names = namer.variables(code, slot)
        if art is None:
            unanalyzed.append(f"{namer.slot(acct, slot, code)} (contract not identified from build artifacts)")
            continue
        hits = [x for x in sites if x.contract == art.name and not x.variable.startswith(CHEAT_PREFIX) and
                (names is None or x.variable in names or x.variable == WILDCARD)]
        hits += stores
        writes.extend(fmt(x) for x in hits)
    for a in per["bals"]:
        unanalyzed.append(f"ETH balance of {namer.account(a)[0]} (balance writes are not analyzed)")
    env = per["env"]
    for name, bit in ENV_CHEATS.items():
        if env & bit:
            writes.extend(fmt(x) for x in sites if x.variable == CHEAT_PREFIX + name)
    if not complete:
        unanalyzed.append("code reached from the handlers makes calls the analysis cannot follow")
    return sorted(set(writes)), unanalyzed


def _compare_targets(user: Optional[Campaign], probe: Optional[Campaign]) -> Optional[str]:
    """Sanity check that the probe fuzzed the same targets as the user's campaign."""
    if user is None or probe is None or not user.metrics or not probe.metrics:
        return None
    u = {k: int((v or {}).get("calls", 0)) for k, v in user.metrics.items()}
    p = {k: int((v or {}).get("calls", 0)) for k, v in probe.metrics.items()}
    missing = [k for k, c in u.items() if c >= 20 and p.get(k, 0) == 0]
    extra = [k for k, c in p.items() if c >= 20 and u.get(k, 0) == 0]
    if missing or extra:
        parts = []
        if missing:
            parts.append("probe never called " + ", ".join(_short(k) for k in sorted(missing)[:5]))
        if extra:
            parts.append("probe called " + ", ".join(_short(k) for k in sorted(extra)[:5]) + " which your run did not")
        return "probe campaign targets differ from your campaign (" + "; ".join(parts) + ")"
    if user.calls > 0 and probe.calls < user.calls // 2:
        return f"probe campaign made {probe.calls} calls vs {user.calls} in your run"
    return None


def to_dict(reports: List[ContractReport]) -> List[dict]:
    return [asdict(r) for r in reports]
