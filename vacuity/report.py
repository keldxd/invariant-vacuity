"""Human readable output."""

from __future__ import annotations

from typing import List

from .analysis import ContractReport

_MARK = {
    "live": "ok      ",
    "frozen": "FROZEN  ",
    "frozen-untracked": "frozen? ",
    "frozen-guarded": "guarded ",
    "inconclusive": "unknown ",
    "failing": "failing ",
    "not-probed": "-       ",
}


def render(reports: List[ContractReport], header: str, notes: List[str], verbose: bool) -> str:
    lines = [header, ""]
    for n in notes:
        lines.append(f"note: {n}")
    if notes:
        lines.append("")
    for rep in reports:
        lines.append(rep.contract)
        if rep.campaign:
            c = rep.campaign
            if c.get("campaigns", 1) > 1:
                lines.append(f"  campaigns: {c['campaigns']} (one per invariant), up to {c.get('runs', 0)} runs each, "
                             f"{c.get('calls', 0)} calls and {c.get('reverts', 0)} reverts in total")
            else:
                lines.append(f"  campaign: {c.get('runs', 0)} runs, {c.get('calls', 0)} calls, "
                             f"{c.get('reverts', 0)} reverts")
        for inv in rep.invariants:
            lines.append(f"  {_MARK.get(inv.verdict, inv.verdict):8} {inv.name}")
            if inv.verdict in ("frozen", "frozen-untracked", "frozen-guarded", "inconclusive") and inv.note:
                lines.append(f"           {inv.note}")
            if inv.verdict in ("frozen", "frozen-untracked", "frozen-guarded") and inv.inputs:
                shown = inv.inputs if verbose else inv.inputs[:8]
                lines.append("           inputs that never changed:")
                lines.extend(f"             - {x}" for x in shown)
                if len(inv.inputs) > len(shown):
                    lines.append(f"             ... and {len(inv.inputs) - len(shown)} more (use --verbose)")
        metric = [f for f in rep.findings if f.code not in ("frozen", "frozen-untracked", "frozen-guarded",
                                                             "probe-inconclusive")]
        for f in metric:
            lines.append(f"  {f.severity}: {f.message}")
        lines.append("")
    errors = sum(1 for r in reports for f in r.findings if f.severity == "error")
    warnings = sum(1 for r in reports for f in r.findings if f.severity == "warning")
    lines.append(f"summary: {errors} error{'s' if errors != 1 else ''}, "
                 f"{warnings} warning{'s' if warnings != 1 else ''}")
    return "\n".join(lines)
