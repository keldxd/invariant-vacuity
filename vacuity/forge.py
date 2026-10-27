"""Thin wrapper around the forge binary."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from typing import Dict, List, Optional, Sequence, Tuple

# 1.0.x panics ("missing CALL account accesses") when state diff recording is started and
# stopped inside a nested call, which the probe relies on. Fixed in 1.1.0.
MIN_VERSION = (1, 1, 0)


class ForgeError(Exception):
    """forge could not be run or its output could not be understood."""


def find_forge(explicit: Optional[str] = None) -> str:
    if explicit:
        if os.path.isfile(explicit) and os.access(explicit, os.X_OK):
            return os.path.abspath(explicit)
        found = shutil.which(explicit)
        if found:
            return found
        raise ForgeError(f"forge binary not found at {explicit!r}")
    found = shutil.which("forge")
    if not found:
        home = os.path.expanduser("~/.foundry/bin/forge")
        if os.path.isfile(home):
            return home
        raise ForgeError("forge not found on PATH. Install Foundry or pass --forge /path/to/forge")
    return found


def run(forge: str, args: Sequence[str], root: str, env: Dict[str, str],
        timeout: Optional[float] = None) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            [forge, *args], cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise ForgeError(f"forge {' '.join(args[:2])} timed out after {timeout}s") from e
    except OSError as e:
        raise ForgeError(f"could not run forge: {e}") from e
    return proc.returncode, proc.stdout, proc.stderr


def parse_version(text: str) -> Tuple[int, int, int]:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text)
    if not m:
        raise ForgeError(f"could not parse forge version from: {text.strip()[:200]!r}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def version(forge: str, root: str, env: Dict[str, str]) -> Tuple[Tuple[int, int, int], str]:
    rc, out, err = run(forge, ["--version"], root, env, timeout=60)
    if rc != 0:
        raise ForgeError(f"forge --version failed: {err.strip()[-500:]}")
    first = out.strip().splitlines()[0] if out.strip() else ""
    v = parse_version(first)
    if v < MIN_VERSION:
        raise ForgeError(
            f"forge {'.'.join(map(str, v))} is too old; invariant-vacuity needs forge >= "
            f"{'.'.join(map(str, MIN_VERSION))}. Run `foundryup`."
        )
    return v, first


def config(forge: str, root: str, env: Dict[str, str]) -> dict:
    rc, out, err = run(forge, ["config", "--json"], root, env, timeout=120)
    if rc != 0:
        raise ForgeError(f"forge config --json failed:\n{_tail(err)}")
    try:
        cfg = json.loads(out)
    except json.JSONDecodeError:
        # tolerate warnings printed around the JSON object
        start, end = out.find("{"), out.rfind("}")
        try:
            cfg = json.loads(out[start:end + 1]) if start != -1 and end > start else None
        except json.JSONDecodeError:
            cfg = None
        if cfg is None:
            raise ForgeError(f"forge config --json returned invalid JSON:\n{_tail(out)}")
    if not isinstance(cfg, dict):
        raise ForgeError("forge config --json did not return an object")
    return cfg


def parse_test_json(stdout: str) -> dict:
    """Parses `forge test --json` output.

    Forge prints one JSON object on stdout. Defensively, if anything else got
    mixed in, take the last line that parses as a JSON object.
    """
    text = stdout.strip()
    if not text:
        raise ForgeError("forge test produced no JSON output")
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    for line in reversed(text.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict):
                return data
    raise ForgeError("could not find a JSON object in forge test output")


def _tail(text: str, lines: int = 40) -> str:
    rows = [r for r in text.strip().splitlines() if r.strip()]
    return "\n".join(rows[-lines:])


def tail(text: str, lines: int = 40) -> str:
    return _tail(text, lines)


def build(forge: str, root: str, env: Dict[str, str], extra: List[str], timeout: Optional[float]) -> None:
    rc, out, err = run(forge, ["build", *extra], root, env, timeout=timeout)
    if rc != 0:
        raise ForgeError(f"forge build failed:\n{_tail(err or out)}")
