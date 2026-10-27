"""Minimal ABI encoder for the probe's input blobs.

Encodes `abi.encode(VpInputs)` where
  struct VpInputs { address[] sa; bytes32[] ss; address[] sc; address[] bals; address[] codes;
                    uint256 env; bytes32 fp; }
"""

from __future__ import annotations

from typing import List


def _word(n: int) -> bytes:
    if n < 0 or n >= 1 << 256:
        raise ValueError("value out of uint256 range")
    return n.to_bytes(32, "big")


def _addr(a: str) -> int:
    v = int(a, 16)
    if v >= 1 << 160:
        raise ValueError(f"not an address: {a}")
    return v


def _array(values: List[int]) -> bytes:
    return _word(len(values)) + b"".join(_word(v) for v in values)


def encode_inputs(sa: List[str], ss: List[str], sc: List[str], bals: List[str], codes: List[str],
                  env: int, fp: str) -> bytes:
    if not (len(sa) == len(ss) == len(sc)):
        raise ValueError("slot arrays must have equal length")
    dynamic = [
        _array([_addr(a) for a in sa]),
        _array([int(s, 16) for s in ss]),
        _array([_addr(a) for a in sc]),
        _array([_addr(a) for a in bals]),
        _array([_addr(a) for a in codes]),
    ]
    head_size = 32 * 7  # 5 offsets + env + fp
    heads = []
    offset = head_size
    for d in dynamic:
        heads.append(_word(offset))
        offset += len(d)
    heads.append(_word(env))
    heads.append(_word(int(fp, 16)))
    tuple_enc = b"".join(heads) + b"".join(dynamic)
    # a single dynamic tuple argument is preceded by its offset
    return _word(32) + tuple_enc
