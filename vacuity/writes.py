"""Static write-path analysis over the Solidity AST.

Used to tell two kinds of frozen invariant apart:

  frozen          nothing that ran during the campaign could have changed the
                  invariant's inputs: the only writers do not exist, never ran
                  successfully, or ran unconditionally and wrote the same value.
  frozen-guarded  a write to one of the inputs exists behind a condition on a
                  code path that did run (for example `if (bad) violated = true;`
                  in a handler). The condition was simply never true. That is
                  the expected outcome for violation flags on a correct
                  implementation, and also what a hard-to-reach branch looks like.

Resolution is name based (contracts, functions, state variables) because AST
node ids are only consistent within one compilation job. Every approximation
errs towards "guarded" (a warning), never towards "frozen" (an error):
unresolvable calls through interfaces fan out to all implementations, local
variables that shadow state variables count as writes, and if the search hits
its size limit the result is treated as guarded.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple

_SUCCESS_EXITS = {"Return", "Break", "Continue"}
WILDCARD = "*"  # assembly sstore: may write any slot of the executing contract
CHEAT_PREFIX = "@cheat:"
_VM_TYPES = {"Vm", "VmSafe"}
# cheatcodes that change block/tx environment values (bit values match probe_gen.ENV_TRACKED)
ENV_CHEATS = {"warp": 1, "roll": 2, "chainId": 4, "coinbase": 8, "txGasPrice": 32}
_SKIP_FUNCTIONS = {"setUp", "afterInvariant"}
_SKIP_PREFIXES = ("invariant", "test", "statefulFuzz")
MAX_STATES = 50_000


@dataclass(frozen=True)
class WriteSite:
    contract: str  # contract whose code performs the write
    function: str
    variable: str
    conditional: bool  # true if some branch could skip it on a successful call


def _walk(node, fn):
    if isinstance(node, dict):
        fn(node)
        for v in node.values():
            if isinstance(v, (dict, list)):
                _walk(v, fn)
    elif isinstance(node, list):
        for v in node:
            _walk(v, fn)


def _root_identifier(expr) -> Optional[str]:
    """Name of the state-variable-like root of an lvalue: x, x[i], x.y, x[i].y ..."""
    while isinstance(expr, dict):
        t = expr.get("nodeType")
        if t == "Identifier":
            return expr.get("name")
        if t == "IndexAccess":
            expr = expr.get("baseExpression")
        elif t == "MemberAccess":
            expr = expr.get("expression")
        elif t == "IndexRangeAccess":
            expr = expr.get("baseExpression")
        elif t == "TupleExpression":
            return None
        else:
            return None
    return None


def _tuple_roots(expr) -> List[str]:
    if isinstance(expr, dict) and expr.get("nodeType") == "TupleExpression":
        out = []
        for c in expr.get("components") or []:
            out.extend(_tuple_roots(c))
        return out
    r = _root_identifier(expr)
    return [r] if r else []


def _contract_of_type(type_string: str) -> Optional[str]:
    # "contract Vault", "contract super Base", "type(library SafeERC20)", "type(contract X)" ...
    if not type_string:
        return None
    ts = type_string
    if ts.startswith("contract super "):
        return None
    if ts.startswith("contract "):
        return ts[len("contract "):].split()[0]
    for prefix in ("type(library ", "type(contract "):
        if ts.startswith(prefix):
            return ts[len(prefix):].rstrip(")").split()[0]
    return None


def _encoded_target(arg) -> Tuple[Optional[str], Optional[str], bool]:
    """For addr.call(abi.encode...(...)): returns (contract or None, function name, resolved)."""
    if not isinstance(arg, dict) or arg.get("nodeType") != "FunctionCall":
        return None, None, False
    expr = arg.get("expression") or {}
    fname = expr.get("memberName") if expr.get("nodeType") == "MemberAccess" else None
    args = arg.get("arguments") or []
    if not args:
        return None, None, False
    first = args[0]
    if fname == "encodeWithSignature" and first.get("nodeType") == "Literal":
        value = first.get("value") or ""
        return None, value.split("(")[0] or None, bool(value)
    if fname == "encodeCall" and first.get("nodeType") == "MemberAccess":
        btype = ((first.get("expression") or {}).get("typeDescriptions") or {}).get("typeString") or ""
        return _contract_of_type(btype), first.get("memberName"), True
    if fname == "encodeWithSelector" and first.get("nodeType") == "MemberAccess" \
            and first.get("memberName") == "selector":
        inner = first.get("expression") or {}
        if inner.get("nodeType") == "MemberAccess":
            btype = ((inner.get("expression") or {}).get("typeDescriptions") or {}).get("typeString") or ""
            return _contract_of_type(btype), inner.get("memberName"), True
    return None, None, False


def _has_success_exit(node) -> bool:
    found = []

    def f(n):
        if n.get("nodeType") in _SUCCESS_EXITS:
            found.append(True)
    _walk(node, f)
    return bool(found)


class _FunctionFacts:
    __slots__ = ("writes", "calls", "opaque")

    def __init__(self):
        self.writes: List[Tuple[str, bool]] = []  # (variable name, conditional)
        self.calls: List[Tuple[Optional[str], str, bool]] = []  # (contract or None=internal, name, conditional)
        self.opaque = False  # contains a call the analysis cannot follow


class WriteGraph:
    def __init__(self, source_units: Iterable[dict]):
        self.contracts: Dict[str, List[dict]] = {}
        self._facts: Dict[Tuple[int, str], _FunctionFacts] = {}
        self._hier: Dict[str, List[dict]] = {}
        self._impls: Dict[str, List[str]] = {}
        seen_units = set()
        for su in source_units:
            if not isinstance(su, dict):
                continue
            key = su.get("absolutePath") or id(su)
            if key in seen_units:
                continue
            seen_units.add(key)
            for node in su.get("nodes") or []:
                if isinstance(node, dict) and node.get("nodeType") == "ContractDefinition":
                    self.contracts.setdefault(node.get("name", ""), []).append(node)

    # ------------------------------------------------------------ hierarchy

    @staticmethod
    def _base_names(c: dict) -> List[str]:
        out = []
        for b in c.get("baseContracts") or []:
            bn = b.get("baseName") or {}
            name = bn.get("name") or bn.get("namePath")
            if name:
                out.append(name.split(".")[-1])
        return out

    def hierarchy(self, name: str) -> List[dict]:
        if name in self._hier:
            return self._hier[name]
        out: List[dict] = []
        seen: Set[int] = set()
        stack = [name]
        while stack:
            n = stack.pop()
            for c in self.contracts.get(n, []):
                if id(c) in seen:
                    continue
                seen.add(id(c))
                out.append(c)
                stack.extend(self._base_names(c))
        self._hier[name] = out
        return out

    def state_vars(self, name: str) -> Set[str]:
        out = set()
        for c in self.hierarchy(name):
            for n in c.get("nodes") or []:
                if n.get("nodeType") == "VariableDeclaration" and n.get("stateVariable"):
                    out.add(n.get("name"))
        return out

    def implementations(self, name: str) -> List[str]:
        """Concrete contracts whose hierarchy includes `name` (for interface calls)."""
        if name in self._impls:
            return self._impls[name]
        out = []
        for cname, nodes in self.contracts.items():
            if any(n.get("contractKind") == "contract" and not n.get("abstract") for n in nodes):
                if any(c.get("name") == name for c in self.hierarchy(cname)):
                    out.append(cname)
        self._impls[name] = out
        return out

    def callables(self, contract: str, name: str) -> List[Tuple[dict, dict]]:
        out = []
        for c in self.hierarchy(contract):
            for n in c.get("nodes") or []:
                t = n.get("nodeType")
                if t in ("FunctionDefinition", "ModifierDefinition") and n.get("name") == name:
                    out.append((c, n))
        return out

    # ------------------------------------------------------------ per function facts

    def facts(self, node: dict, contract: str) -> _FunctionFacts:
        key = (id(node), contract)
        if key in self._facts:
            return self._facts[key]
        f = _FunctionFacts()
        self._facts[key] = f
        svars = self.state_vars(contract)
        for m in node.get("modifiers") or []:
            mn = (m.get("modifierName") or {})
            name = mn.get("name") or mn.get("namePath")
            if name:
                f.calls.append((None, name.split(".")[-1], False))
        body = node.get("body")
        if body:
            self._visit(body, False, f, svars)
        return f

    def _write(self, f: _FunctionFacts, names: Iterable[str], cond: bool, svars: Set[str]):
        for n in names:
            if n in svars:
                f.writes.append((n, cond))

    def _visit(self, n, cond: bool, f: _FunctionFacts, svars: Set[str]):
        if isinstance(n, list):
            for x in n:
                self._visit(x, cond, f, svars)
            return
        if not isinstance(n, dict):
            return
        t = n.get("nodeType")
        if t in ("Block", "UncheckedBlock"):
            c = cond
            for s in n.get("statements") or []:
                self._visit(s, c, f, svars)
                if s.get("nodeType") in ("IfStatement", "ForStatement", "WhileStatement", "DoWhileStatement",
                                         "TryStatement") and _has_success_exit(s):
                    c = True  # a successful call may have returned before the rest of this block
            return
        if t == "IfStatement":
            self._visit(n.get("condition"), cond, f, svars)
            self._visit(n.get("trueBody"), True, f, svars)
            self._visit(n.get("falseBody"), True, f, svars)
            return
        if t == "Conditional":
            self._visit(n.get("condition"), cond, f, svars)
            self._visit(n.get("trueExpression"), True, f, svars)
            self._visit(n.get("falseExpression"), True, f, svars)
            return
        if t in ("ForStatement", "WhileStatement", "DoWhileStatement"):
            self._visit(n.get("initializationExpression"), cond, f, svars)
            self._visit(n.get("condition"), cond, f, svars)
            self._visit(n.get("loopExpression"), True, f, svars)
            self._visit(n.get("body"), True, f, svars)
            return
        if t == "TryStatement":
            self._visit(n.get("externalCall"), cond, f, svars)
            for cl in n.get("clauses") or []:
                self._visit(cl.get("block"), True, f, svars)
            return
        if t == "BinaryOperation" and n.get("operator") in ("&&", "||"):
            self._visit(n.get("leftExpression"), cond, f, svars)
            self._visit(n.get("rightExpression"), True, f, svars)
            return
        if t == "Assignment":
            self._write(f, _tuple_roots(n.get("leftHandSide")), cond, svars)
            self._visit(n.get("leftHandSide"), cond, f, svars)
            self._visit(n.get("rightHandSide"), cond, f, svars)
            return
        if t == "UnaryOperation" and n.get("operator") in ("++", "--", "delete"):
            self._write(f, _tuple_roots(n.get("subExpression")), cond, svars)
            self._visit(n.get("subExpression"), cond, f, svars)
            return
        if t == "VariableDeclarationStatement":
            for d in n.get("declarations") or []:
                if isinstance(d, dict) and d.get("storageLocation") == "storage":
                    # storage pointer alias: writes through it are invisible to name matching
                    roots = []
                    _walk(n.get("initialValue"), lambda x: roots.append(x.get("name"))
                          if x.get("nodeType") == "Identifier" else None)
                    self._write(f, roots, cond, svars)
            self._visit(n.get("initialValue"), cond, f, svars)
            return
        if t == "InlineAssembly":
            sstores = []
            _walk(n.get("AST"), lambda x: sstores.append(True)
                  if x.get("nodeType") == "YulFunctionCall"
                  and (x.get("functionName") or {}).get("name") == "sstore" else None)
            if sstores:
                f.writes.append((WILDCARD, cond))
            names = []
            _walk(n.get("AST"), lambda x: names.append(x.get("name", "").split(".")[0])
                  if x.get("nodeType") == "YulIdentifier" else None)
            for ref in n.get("externalReferences") or []:
                # older solc: list of {name: {declaration, ...}} or {declaration, src, ...}
                if isinstance(ref, dict):
                    for k in ref:
                        names.append(str(k).split(".")[0])
            self._write(f, names, cond, svars)
            return
        if t == "FunctionCall":
            expr = n.get("expression") or {}
            et = expr.get("nodeType")
            if et == "Identifier":
                ref = expr.get("referencedDeclaration")
                if not (isinstance(ref, int) and ref < 0):  # negative ids are builtins (require, keccak256, ...)
                    f.calls.append((None, expr.get("name", ""), cond))
            elif et == "MemberAccess" and expr.get("memberName") in ("call", "delegatecall", "staticcall") \
                    and (((expr.get("expression") or {}).get("typeDescriptions") or {}).get("typeString") or "") \
                    .startswith("address"):
                target, name, ok = _encoded_target((n.get("arguments") or [None])[0])
                if ok and name:
                    f.calls.append((target or "*", name, cond))
                elif expr.get("memberName") != "staticcall":
                    f.opaque = True
            elif et == "FunctionCallOptions":
                # x.f{value: v}(...) or addr.call{value: v}(...)
                inner = expr.get("expression") or {}
                if inner.get("nodeType") == "MemberAccess":
                    btype = ((inner.get("expression") or {}).get("typeDescriptions") or {}).get("typeString") or ""
                    target = _contract_of_type(btype)
                    if target:
                        f.calls.append((target, inner.get("memberName", ""), cond))
                    elif inner.get("memberName") in ("call", "delegatecall"):
                        tgt, name, ok = _encoded_target((n.get("arguments") or [None])[0])
                        if ok and name:
                            f.calls.append((tgt or "*", name, cond))
                        elif (n.get("arguments") or [{}])[0].get("nodeType") != "Literal":
                            f.opaque = True
            elif et == "MemberAccess":
                member = expr.get("memberName", "")
                base = expr.get("expression") or {}
                ftype = (expr.get("typeDescriptions") or {}).get("typeString") or ""
                root = _root_identifier(base)
                if member in ("push", "pop") or (root in svars and ftype.startswith("function")
                                                  and " view" not in ftype and " pure" not in ftype):
                    # array push/pop, or a library function bound to a state variable (using-for)
                    if root:
                        self._write(f, [root], cond, svars)
                btype = (base.get("typeDescriptions") or {}).get("typeString") or ""
                if base.get("nodeType") == "Identifier" and base.get("name") == "super":
                    f.calls.append((None, member, cond))
                else:
                    target = _contract_of_type(btype)
                    if target:
                        f.calls.append((target, member, cond))
            self._visit(expr, cond, f, svars)
            self._visit(n.get("arguments"), cond, f, svars)
            return
        for k, v in n.items():
            if isinstance(v, (dict, list)) and k not in ("typeDescriptions", "documentation"):
                self._visit(v, cond, f, svars)

    # ------------------------------------------------------------ reachability

    def _defining(self, name: str) -> List[str]:
        out = []
        for cname, nodes in self.contracts.items():
            for c in nodes:
                if any(n.get("nodeType") in ("FunctionDefinition", "ModifierDefinition") and n.get("name") == name
                       and (n.get("body") or n.get("nodeType") == "ModifierDefinition")
                       for n in c.get("nodes") or []):
                    out.append(cname)
                    break
        return out

    def reachable_writes(self, starts: Iterable[Tuple[str, str]]) -> Tuple[List[WriteSite], bool]:
        """Write sites reachable from (contract, function) entry points.

        A site is `conditional` if some branch on the path to it (or around it)
        could be skipped on a successful call. Returns (sites, complete); complete
        is False if a reached function makes a call the analysis cannot follow or
        the search hit its size limit."""
        sites: Set[WriteSite] = set()
        q = deque((c, fn, False) for c, fn in starts)
        visited: Set[Tuple[str, str, bool]] = set()
        complete = True
        while q:
            if len(visited) > MAX_STATES:
                complete = False
                break
            contract, fn, cond = q.popleft()
            key = (contract, fn, cond)
            if key in visited:
                continue
            visited.add(key)
            if contract in _VM_TYPES:
                sites.add(WriteSite(contract, fn, CHEAT_PREFIX + fn, cond))
                continue
            if contract == "*":
                for impl in self._defining(fn):
                    q.append((impl, fn, cond))
                continue
            nodes = [(o, n) for o, n in self.callables(contract, fn)
                     if n.get("body") or n.get("nodeType") == "ModifierDefinition"]
            if not nodes:
                # interface / abstract / unknown type, or a library function bound with using-for
                impls = [i for i in self.implementations(contract) if i != contract
                         and any(n.get("body") for _, n in self.callables(i, fn))]
                for impl in impls:
                    q.append((impl, fn, cond))
                if not impls:
                    q.append(("*", fn, cond))
                continue
            for owner, node in nodes:
                if node.get("nodeType") == "FunctionDefinition" and node.get("kind") == "constructor":
                    continue
                facts = self.facts(node, contract)
                if facts.opaque:
                    complete = False
                for var, c in facts.writes:
                    sites.add(WriteSite(contract, fn, var, cond or c))
                for target, name, c in facts.calls:
                    q.append((target or contract, name, cond or c))
        return sorted(sites, key=lambda s: (s.contract, s.function, s.variable, s.conditional)), complete


def is_entry_point(name: str) -> bool:
    return name not in _SKIP_FUNCTIONS and not name.startswith(_SKIP_PREFIXES)
