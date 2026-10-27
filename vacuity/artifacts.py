"""Reads Forge build artifacts: finds invariant test contracts, and maps
runtime code and storage slots back to names for the report."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from .keccak import keccak256

INVARIANT_PREFIXES = ("invariant", "statefulFuzz")
_PLACEHOLDER = re.compile(r"__\$[0-9a-fA-F]{34}\$__")


@dataclass
class Artifact:
    name: str
    source: str  # project relative, forward slashes
    abi: list
    creation: str  # hex without 0x
    runtime: str  # hex without 0x
    masks: List[Tuple[int, int]] = field(default_factory=list)  # (byte start, length) in runtime
    storage: list = field(default_factory=list)  # storageLayout.storage
    types: dict = field(default_factory=dict)  # storageLayout.types

    @property
    def concrete(self) -> bool:
        return bool(self.creation)

    def functions(self) -> List[dict]:
        return [x for x in self.abi if isinstance(x, dict) and x.get("type") == "function"]

    def invariant_functions(self) -> List[str]:
        out = []
        for f in self.functions():
            name = f.get("name", "")
            if name.startswith(INVARIANT_PREFIXES) and not f.get("inputs"):
                out.append(f"{name}()")
        return sorted(set(out))

    def has_function(self, sig_name: str) -> bool:
        return any(f.get("name") == sig_name and not f.get("inputs") for f in self.functions())

    def constructor_inputs(self) -> int:
        for x in self.abi:
            if isinstance(x, dict) and x.get("type") == "constructor":
                return len(x.get("inputs") or [])
        return 0


def _doc_text(node: dict) -> str:
    doc = node.get("documentation")
    if isinstance(doc, dict):
        return doc.get("text") or ""
    return doc if isinstance(doc, str) else ""


def inline_config(ast: Optional[dict], contract: str, invariants: List[str]) -> Tuple[List[str], List[List[str]]]:
    """forge-config lines on the contract and on each invariant (by name), from the AST.

    Only invariant-related keys are copied (fuzz/invariant settings), since the
    probe only runs invariant campaigns."""
    def lines(text: str) -> List[str]:
        out = []
        for raw in text.splitlines():
            raw = raw.strip().lstrip("*/ ").strip()
            if raw.startswith("forge-config:") and ".invariant." in raw:
                out.append(raw)
        return out

    if not isinstance(ast, dict):
        return [], [[] for _ in invariants]
    for node in ast.get("nodes") or []:
        if node.get("nodeType") == "ContractDefinition" and node.get("name") == contract:
            per = {}
            for f in node.get("nodes") or []:
                if f.get("nodeType") == "FunctionDefinition":
                    per[f.get("name")] = lines(_doc_text(f))
            return lines(_doc_text(node)), [per.get(i.split("(")[0], []) for i in invariants]
    return [], [[] for _ in invariants]


def _norm(path: str) -> str:
    p = path.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def _hex(obj) -> str:
    if isinstance(obj, dict):
        obj = obj.get("object", "")
    if not isinstance(obj, str):
        return ""
    h = obj[2:] if obj.startswith("0x") else obj
    return h.lower()


def _metadata(data: dict) -> Optional[dict]:
    meta = data.get("metadata")
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except json.JSONDecodeError:
            meta = None
    if not isinstance(meta, dict):
        raw = data.get("rawMetadata")
        if isinstance(raw, str):
            try:
                meta = json.loads(raw)
            except json.JSONDecodeError:
                meta = None
    return meta if isinstance(meta, dict) else None


def _compilation_target(data: dict) -> Optional[Tuple[str, str]]:
    meta = _metadata(data)
    if meta is None:
        return None
    target = (meta.get("settings") or {}).get("compilationTarget") or {}
    if len(target) != 1:
        return None
    (src, name), = target.items()
    return _norm(src), name


def _compiler_version(data: dict) -> Tuple[int, ...]:
    meta = _metadata(data) or {}
    v = str((meta.get("compiler") or {}).get("version") or "")
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", v)
    return tuple(int(x) for x in m.groups()) if m else ()


def _masks(deployed: dict) -> List[Tuple[int, int]]:
    out: List[Tuple[int, int]] = []
    if not isinstance(deployed, dict):
        return out
    for refs in (deployed.get("immutableReferences") or {}).values():
        for r in refs or []:
            out.append((int(r["start"]), int(r["length"])))
    for libs in (deployed.get("linkReferences") or {}).values():
        for refs in (libs or {}).values():
            for r in refs or []:
                out.append((int(r["start"]), int(r["length"])))
    return out


def load(out_dir: str) -> List[Artifact]:
    return load_with_asts(out_dir)[0]


def load_with_asts(out_dir: str) -> Tuple[List[Artifact], Dict[str, dict]]:
    """Artifacts plus one source-unit AST per source path (when the build emitted ASTs)."""
    arts, asts, _ = load_checked(out_dir)
    return arts, asts


def load_checked(out_dir: str) -> Tuple[List[Artifact], Dict[str, dict], List[str]]:
    """Like load_with_asts, and also returns the contracts that have artifacts from more
    than one compiler version. Forge leaves an old version's artifact next to the new one
    (under a nested path) when a file is rebuilt with a different solc, so duplicates
    usually mean a stale build directory. When they remain after a clean build (a project
    that really compiles one file with two compilers), the newest compiler's artifact is
    used, deterministically."""
    found: Dict[Tuple[str, str], List[Tuple[Tuple[int, ...], str, dict]]] = {}
    for dirpath, dirnames, filenames in os.walk(out_dir):
        dirnames[:] = sorted(d for d in dirnames if d != "build-info")
        for fn in sorted(filenames):
            if not fn.endswith(".json"):
                continue
            path = os.path.join(dirpath, fn)
            try:
                with open(path, encoding="utf-8") as fh:
                    data = json.load(fh)
            except (OSError, json.JSONDecodeError, UnicodeDecodeError):
                continue
            if not isinstance(data, dict) or "abi" not in data:
                continue
            target = _compilation_target(data)
            if target is None:
                continue
            found.setdefault(target, []).append((_compiler_version(data), path, data))

    asts: Dict[str, dict] = {}
    arts: Dict[Tuple[str, str], Artifact] = {}
    duplicates: List[str] = []
    for (src, name), cands in sorted(found.items()):
        if len({c[0] for c in cands}) > 1:
            duplicates.append(f"{src}:{name}")
        # newest compiler first; path breaks ties so the choice never depends on walk order
        cands.sort(key=lambda c: (tuple(-x for x in c[0]), c[1]))
        data = cands[0][2]
        ast = data.get("ast")
        if isinstance(ast, dict) and src not in asts:
            asts[src] = ast
        layout = data.get("storageLayout") or {}
        deployed = data.get("deployedBytecode") or {}
        arts[(src, name)] = Artifact(
            name=name,
            source=src,
            abi=data.get("abi") or [],
            creation=_hex(data.get("bytecode")),
            runtime=_hex(deployed),
            masks=_masks(deployed),
            storage=layout.get("storage") or [],
            types=layout.get("types") or {},
        )
    return sorted(arts.values(), key=lambda a: (a.source, a.name)), asts, duplicates


def is_under(source: str, directory: str) -> bool:
    d = _norm(directory).rstrip("/")
    if d in ("", "."):
        return True
    return source == d or source.startswith(d + "/")


def glob_regex(pattern: str) -> "re.Pattern[str]":
    """Glob to regex with globset-like semantics: ** and * match any characters
    (including /), ? one character, {a,b} alternation, [...] classes."""
    pattern = _norm(pattern)
    out = []
    i = 0
    depth = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            while i + 1 < len(pattern) and pattern[i + 1] == "*":
                i += 1
            out.append(".*")
        elif c == "?":
            out.append(".")
        elif c == "{":
            depth += 1
            out.append("(?:")
        elif c == "}" and depth:
            depth -= 1
            out.append(")")
        elif c == "," and depth:
            out.append("|")
        elif c == "[":
            j = pattern.find("]", i + 1)
            if j == -1:
                out.append(re.escape(c))
            else:
                body = pattern[i + 1:j]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = j
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("^(?:\\./)?" + "".join(out) + "$")


def path_matches(source: str, pattern: str) -> bool:
    return bool(glob_regex(pattern).match(_norm(source)))


@dataclass
class Filters:
    """Test filters from the CLI and from the user's foundry.toml profile."""
    match_contract: Optional[str] = None
    no_match_contract: Optional[str] = None
    match_path: Optional[str] = None
    no_match_path: Optional[str] = None
    match_test: Optional[str] = None
    no_match_test: Optional[str] = None

    def test_ok(self, fn_name: str) -> bool:
        if self.match_test and not re.search(self.match_test, fn_name):
            return False
        if self.no_match_test and re.search(self.no_match_test, fn_name):
            return False
        return True


def select_targets(
    arts: Iterable[Artifact], test_dir: str, cli: Filters, profile: Optional[Filters] = None,
    skip_dirs: Iterable[str] = (),
) -> Tuple[List[Artifact], Dict[str, List[str]], List[str]]:
    """Concrete contracts under the test dir with at least one invariant that the
    user's own `forge test` would run.

    Returns (targets, invariants per target key, notes).
    """
    profile = profile or Filters()
    skip = [_norm(s).rstrip("/") for s in skip_dirs]
    targets: List[Artifact] = []
    invariants: Dict[str, List[str]] = {}
    notes: List[str] = []
    for a in arts:
        if not is_under(a.source, test_dir):
            continue
        if any(is_under(a.source, s) for s in skip):
            continue
        invs = a.invariant_functions()
        if not invs:
            continue
        excluded = False
        for f in (cli, profile):
            if f.match_contract and not re.search(f.match_contract, a.name):
                excluded = True
            if f.no_match_contract and re.search(f.no_match_contract, a.name):
                excluded = True
            if f.match_path and not path_matches(a.source, f.match_path):
                excluded = True
            if f.no_match_path and path_matches(a.source, f.no_match_path):
                excluded = True
        if excluded:
            continue
        invs = [i for i in invs if cli.test_ok(i[:-2]) and profile.test_ok(i[:-2])]
        if not invs:
            continue
        if not a.concrete:
            continue  # abstract base contracts are probed through their concrete children
        if a.constructor_inputs():
            notes.append(f"skipped {a.source}:{a.name}: constructor takes arguments")
            continue
        targets.append(a)
        invariants[f"{a.source}:{a.name}"] = invs
    return targets, invariants, notes


# ---------------------------------------------------------------- code naming

def _apply_masks(code: bytes, masks: List[Tuple[int, int]]) -> bytes:
    if not masks:
        return code
    b = bytearray(code)
    for start, length in masks:
        if start + length <= len(b):
            b[start:start + length] = b"\x00" * length
    return bytes(b)


class CodeIndex:
    """Matches deployed runtime code against artifacts, ignoring immutable and
    library-link positions (which differ per deployment)."""

    def __init__(self, arts: Iterable[Artifact]):
        self._by_len: Dict[int, List[Tuple[bytes, Artifact]]] = {}
        for a in arts:
            if not a.runtime:
                continue
            # Unlinked library placeholders (__$<34 hex>$__, 20 bytes) are covered by
            # linkReferences masks, so their content does not matter.
            hexcode = _PLACEHOLDER.sub("0" * 40, a.runtime)
            try:
                code = bytes.fromhex(hexcode)
            except ValueError:
                continue
            self._by_len.setdefault(len(code), []).append((_apply_masks(code, a.masks), a))

    def identify(self, code_hex: str) -> Optional[Artifact]:
        h = code_hex[2:] if code_hex.startswith("0x") else code_hex
        try:
            code = bytes.fromhex(h)
        except ValueError:
            return None
        for masked, art in self._by_len.get(len(code), []):
            if _apply_masks(code, art.masks) == masked:
                return art
        return None


def _k(word: bytes) -> int:
    return int.from_bytes(keccak256(word), "big")


def _mapping_label(art: Artifact, slot: int, keys: Dict[int, str]) -> Optional[str]:
    """Resolves keccak(key . base) slots of mappings, one or two levels deep,
    trying the known addresses (and small integers) as keys."""
    bases = []
    for v in art.storage:
        t = art.types.get(v.get("type", ""), {})
        if t.get("encoding") == "mapping":
            try:
                bases.append((int(v.get("slot", "0")), v.get("label", "?")))
            except (TypeError, ValueError):
                continue
    if not bases:
        return None
    pad = lambda x: x.to_bytes(32, "big")  # noqa: E731
    for base, label in bases:
        for k1, n1 in keys.items():
            s1 = _k(pad(k1) + pad(base))
            if s1 == slot:
                return f"{label}[{n1}]"
            for k2, n2 in keys.items():
                if _k(pad(k2) + pad(s1)) == slot:
                    return f"{label}[{n1}][{n2}]"
    return None


def slot_label(art: Optional[Artifact], slot_hex: str, keys: Optional[Dict[int, str]] = None) -> Optional[str]:
    """Best effort name for a storage slot using the storage layout."""
    if art is None or not art.storage:
        return None
    try:
        slot = int(slot_hex, 16)
    except ValueError:
        return None
    hits = []
    for v in art.storage:
        try:
            base = int(v.get("slot", "0"))
        except (TypeError, ValueError):
            continue
        t = art.types.get(v.get("type", ""), {})
        try:
            size = int(t.get("numberOfBytes", "32"))
        except (TypeError, ValueError):
            size = 32
        span = max(1, (size + 31) // 32)
        if base <= slot < base + span:
            label = v.get("label", "?")
            if span > 1:
                label += f" (+{slot - base} slot)" if slot != base else ""
            hits.append(label)
    if hits:
        return ", ".join(hits)
    if slot > 2 ** 64:
        if keys:
            m = _mapping_label(art, slot, keys)
            if m:
                return m
        return "(mapping or dynamic array element)"
    return None
