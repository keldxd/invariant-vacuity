"""Classifies cheatcode selectors seen in an invariant's opcode trace.

The probe tracks vm.load, vm.getBlockTimestamp, vm.getBlockNumber and
vm.getChainId itself. Every other cheatcode the invariant called is reported
back by selector. A cheatcode is "safe" if its result cannot change because of
handler activity during the campaign (assertions, string helpers, labels,
signing, ...). Anything else, including selectors we cannot name, is treated as
an untracked input: the probe cannot see whether it changed, so a frozen result
is downgraded to a warning instead of an error.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Dict, List, Optional, Tuple

from .keccak import selector

_SAFE_PREFIXES = ("assert", "parse", "serialize", "expect", "keyExists", "env")

_SAFE_NAMES = {
    "assume", "assumeNoRevert", "bound", "breakpoint", "skip", "sleep",
    "label", "getLabel", "addr", "computeCreateAddress", "computeCreate2Address",
    "ensNamehash", "eip712HashStruct", "eip712HashType", "eip712HashTypedData",
    "toString", "toBase64", "toBase64URL", "toLowercase", "toUppercase", "trim",
    "replace", "split", "indexOf", "contains", "sort",
    "sign", "signCompact", "signP256", "signEd25519", "publicKeyP256", "publicKeyEd25519",
    "createWallet", "createEd25519Key", "deriveKey", "rememberKey", "rememberKeys",
    "ecAddAffine", "ecAddProjective", "ecAffineToProjective", "ecMulAffine",
    "ecMulProjective", "ecProjectiveToAffine", "verifyEd25519", "fromRlp", "toRlp",
    "resolveEnv", "getCode", "getDeployedCode", "getArtifactPathByCode",
    "getArtifactPathByDeployedCode", "projectRoot", "currentFilePath",
    "getFoundryVersion", "foundryVersionAtLeast", "foundryVersionCmp", "getEvmVersion",
    "getChain", "rpcUrl", "rpcUrls", "rpcUrlStructs",
    "pauseGasMetering", "resumeGasMetering", "resetGasMetering", "pauseTracing", "resumeTracing",
    "prank", "startPrank", "stopPrank", "stopExpectSafeMemory",
    "startSnapshotGas", "stopSnapshotGas", "snapshotGasLastCall", "snapshotGasLastFrame",
    "snapshotValue", "cool", "coolSlot", "warmSlot",
}

# Read by the probe itself, listed so they can be named in reports.
_TRACKED_NAMES = {"load", "getBlockTimestamp", "getBlockNumber", "getChainId"}


def is_safe_name(name: str) -> bool:
    if name in _SAFE_NAMES:
        return True
    return any(name.startswith(p) for p in _SAFE_PREFIXES)


@lru_cache(maxsize=1)
def _table() -> Dict[str, str]:
    path = os.path.join(os.path.dirname(__file__), "vm_signatures.txt")
    table: Dict[str, str] = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            table[selector(line)] = line
    return table


def classify(sel_hex: str) -> Tuple[Optional[str], bool]:
    """Returns (signature or None, safe)."""
    sel = sel_hex.lower().replace("0x", "")[:8]
    sig = _table().get(sel)
    if sig is None:
        return None, False
    name = sig.split("(")[0]
    if name in _TRACKED_NAMES:
        return sig, True
    return sig, is_safe_name(name)


def untracked(selectors: List[str]) -> List[str]:
    """Human readable names of the untracked cheatcodes among `selectors`."""
    out = []
    for s in selectors:
        sig, safe = classify(s)
        if not safe:
            out.append(f"vm.{sig}" if sig else f"unknown cheatcode 0x{s.lower().replace('0x', '')[:8]}")
    return out
