"""Generates the Solidity probe file.

For every user test contract that has invariants we emit a wrapper contract that:

1. deploys the user's test contract and runs its setUp() (no edits to user code),
2. forwards Forge's targeting getters (targetContracts, targetSelectors, ...)
   so the probe campaign fuzzes exactly the same targets,
3. records what each invariant reads at the post-setUp state:
     - storage slots (Forge state diff recording),
     - ETH balances read via BALANCE/SELFBALANCE, code read via EXTCODE*,
       block/tx environment values, slots read via vm.load, and any other
       cheatcode calls (Forge debug trace recording),
4. defines one inverted "probe" invariant per user invariant. A probe reverts
   with VACUITY:LIVE as soon as any recorded input differs from its post-setUp
   value. A probe still passing at the end of the campaign means none of the
   invariant's inputs changed during the campaign.

The generated code avoids syntax newer than solc 0.8.0 and does not import
forge-std, so it compiles against whatever the user's project pins.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Tuple

from .keccak import selector

LIVE_MARKER = "VACUITY:LIVE"
UNSUPPORTED_MARKER = "VACUITY:UNSUPPORTED"
SETUP_MARKER = "VACUITY:SETUP_FAILED"
PROBE_PREFIX = "VacuityProbe_"
INFO_TEST = "test_vacuityInfo"
PROBE_INVARIANT_PREFIX = "invariant_vacuityProbe_"

# Environment bits reported by the probe (must match the Solidity below).
ENV_TRACKED = {
    1: "block.timestamp",
    2: "block.number",
    4: "block.chainid",
    8: "block.coinbase",
    16: "block.gaslimit",
    32: "tx.gasprice",
    64: "tx.origin",
}
ENV_UNTRACKED = {
    128: "block.basefee",
    256: "block.prevrandao",
    512: "blockhash()",
    1024: "blobhash()",
    2048: "block.blobbasefee",
}

SEL_LOAD = selector("load(address,bytes32)")
SEL_TS = selector("getBlockTimestamp()")
SEL_NUM = selector("getBlockNumber()")
SEL_CHAIN = selector("getChainId()")
SEL_STOP_TRACE = selector("stopAndReturnDebugTraceRecording()")

_IDENT = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")


@dataclass
class ProbeTarget:
    index: int
    contract: str  # user test contract name
    source: str  # project-relative source path, e.g. test/Foo.t.sol
    has_setup: bool
    invariants: List[str] = field(default_factory=list)  # e.g. "invariant_total()"
    selectors: List[str] = field(default_factory=list)  # 8 hex chars, same order
    contract_config: List[str] = field(default_factory=list)  # inline "forge-config:" lines
    invariant_config: List[List[str]] = field(default_factory=list)  # per invariant, same order

    @property
    def probe_name(self) -> str:
        return f"{PROBE_PREFIX}{self.index}__{self.contract}"


BASE = r"""
interface VmVacuity__ {
    struct ChainInfo { uint256 forkId; uint256 chainId; }
    struct StorageAccess {
        address account; bytes32 slot; bool isWrite; bytes32 previousValue; bytes32 newValue; bool reverted;
    }
    // Prefix of Forge's AccountAccess. Newer Forge versions append fields at the end;
    // decoding a prefix is unaffected. The layout is verified at runtime by
    // _vpCalibrate() before any result is trusted. Forge's DebugStep[] (opcode trace)
    // is parsed word by word from the return-data buffer instead (see _vpParseTrace).
    struct AccountAccess {
        ChainInfo chainInfo; uint8 kind; address account; address accessor; bool initialized;
        uint256 oldBalance; uint256 newBalance; bytes deployedCode; uint256 value; bytes data; bool reverted;
        StorageAccess[] storageAccesses;
    }
    function startStateDiffRecording() external;
    function stopAndReturnStateDiff() external returns (AccountAccess[] memory accesses);
    function load(address target, bytes32 slot) external view returns (bytes32 data);
    function deal(address account, uint256 newBalance) external;
    function makePersistent(address account) external;
    function toString(address value) external pure returns (string memory);
    function toString(bytes32 value) external pure returns (string memory);
    function toString(uint256 value) external pure returns (string memory);
    function toString(bytes calldata value) external pure returns (string memory);
    function envOr(string calldata name, bytes calldata defaultValue) external view returns (bytes memory);
    function envOr(string calldata name, string calldata defaultValue) external view returns (string memory);
}

contract VacuityCalibLib__ {
    function readSlot5() external view returns (uint256 r) { assembly { r := sload(5) } }
    function selfBal() external view returns (uint256) { return address(this).balance; }
}

contract VacuityCalib__ {
    constructor() {
        assembly {
            sstore(7, 0xa7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7)
            sstore(3, 0xb3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3)
            sstore(5, 0xc5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5)
        }
    }
    function readTwo(address other) external view returns (uint256 r) {
        assembly { r := xor(sload(7), sload(3)) }
        r = r ^ other.balance;
    }
    function viaDelegate(address lib) external returns (bool ok) {
        (ok, ) = lib.delegatecall(abi.encodeWithSignature("readSlot5()"));
    }
    function bump() external { assembly { sstore(9, add(sload(9), 1)) } }
    function traceMe(address lib, address other) external returns (uint256 r) {
        r = other.balance + block.timestamp;
        (, bytes memory b) = lib.delegatecall(abi.encodeWithSignature("selfBal()"));
        r += b.length;
        r += uint256(VmVacuity__(address(uint160(uint256(keccak256("hevm cheat code"))))).load(address(this), bytes32(uint256(7))));
    }
}

abstract contract VacuityProbeBase__ {
    VmVacuity__ internal constant vpVm = VmVacuity__(address(uint160(uint256(keccak256("hevm cheat code")))));
    address internal constant VP_CONSOLE = 0x000000000000000000636F6e736F6c652e6c6f67;
    bytes4 internal constant VP_TAG = 0x7661636b;
    bytes4 internal constant VP_TAG_TRACE = 0x76616374;
    bytes4 internal constant SEL_LOAD = 0x__SEL_LOAD__;
    bytes4 internal constant SEL_TS = 0x__SEL_TS__;
    bytes4 internal constant SEL_NUM = 0x__SEL_NUM__;
    bytes4 internal constant SEL_CHAIN = 0x__SEL_CHAIN__;
    bytes4 internal constant SEL_STOP_TRACE = 0x__SEL_STOP__;
    uint256 internal constant VP_CAP = 512;
    // Gas caps bound how much Forge has to record (its memory use grows with the
    // number of steps recorded, independently of EVM gas accounting).
    // Measured: Forge needs roughly 400 bytes per gas of traced execution and ~36 bytes
    // per gas of state-diff recording for call-heavy code, per concurrently running suite.
    uint256 internal constant VP_RECORD_GAS = __RECORD_GAS__;
    uint256 internal constant VP_TRACE_CALL_GAS = __TRACE_GAS__;

    struct VpSlot { address acct; bytes32 slot; bytes32 val; address code; }
    struct VpBal { address acct; uint256 val; }
    struct VpCode { address acct; bytes32 hash; }
    // calls: accounts called directly; delegates: delegate-call targets; owners: storage owners seen in
    // delegate frames; balanceReads: accounts read with BALANCE. Used for the fallback balance set.
    struct VpRec {
        bool ok; uint256 gas; address[] sa; bytes32[] ss; address[] sc; address[] code;
        address[] calls; address[] delegates; address[] owners; address[] balanceReads;
    }
    struct VpTrace { bool complete; address[] bal; address[] code; address[] la; bytes32[] ls; uint256 env; bytes4[] cheats; }

    address internal vpInner;
    address internal vpCalib;
    address internal vpCalibLib;
    bool internal vpTraceSupported;
    uint256 internal vpTs;
    uint256 internal vpNum;
    uint256 internal vpChain;
    address internal vpCoinbase;
    uint256 internal vpGasLimit;
    uint256 internal vpGasPrice;
    address internal vpOrigin;
    uint256 internal vpCount;
    mapping(uint256 => VpSlot[]) internal vpSlots;
    mapping(uint256 => VpBal[]) internal vpBals;
    mapping(uint256 => VpCode[]) internal vpCodes;
    mapping(uint256 => uint256) internal vpEnv;
    mapping(uint256 => bytes4[]) internal vpCheats;
    mapping(uint256 => bool) internal vpBaselineOk;
    mapping(uint256 => bool) internal vpTraceOk;
    mapping(uint256 => bool) internal vpCaptureFailed;
    mapping(uint256 => uint256) internal vpGas;
    mapping(uint256 => bool) internal vpNondeterministic;
    uint256 internal vpProbeIndex;

    function _vpDeploy() internal virtual returns (address);
    function _vpHasSetUp() internal pure virtual returns (bool);
    function _vpSel(uint256 i) internal pure virtual returns (bytes4);

    // ------------------------------------------------------------------ setup

    function _vpInit(uint256 probeIndex, uint256 count, uint256 initialBalance) internal {
        vpProbeIndex = probeIndex;
        vpCount = count;
        // No vm.prank here: Forge calls setUp() without a prank, and a pending prank
        // would make a vm.startPrank inside the user's setUp() revert.
        address inner = _vpDeploy();
        vpInner = inner;
        vpVm.deal(inner, initialBalance);
        vpVm.makePersistent(inner);
        if (_vpHasSetUp()) {
            (bool ok, bytes memory ret) = inner.call(abi.encodeWithSignature("setUp()"));
            if (!ok) {
                revert(string(abi.encodePacked(
                    "VACUITY:SETUP_FAILED: user setUp() reverted in the probe wrapper. raw revert data: ",
                    vpVm.toString(ret)
                )));
            }
        }
        vpTs = block.timestamp;
        vpNum = block.number;
        vpChain = block.chainid;
        vpCoinbase = block.coinbase;
        vpGasLimit = block.gaslimit;
        vpGasPrice = tx.gasprice;
        vpOrigin = tx.origin;
        // Two phases, one compile. "capture" (default): record each invariant's inputs and
        // report them through test_vacuityInfo. "campaign": load the recorded input lists from
        // environment variables, so this setUp stays small and failing traces stay small.
        bool campaign = keccak256(bytes(vpVm.envOr("VACUITY_MODE", string("capture")))) == keccak256(bytes("campaign"));
        if (!campaign) _vpCalibrate();
        for (uint256 i = 0; i < count; i++) {
            if (campaign) _vpLoad(i);
            else _vpCapture(i);
        }
    }

    struct VpInputs { address[] sa; bytes32[] ss; address[] sc; address[] bals; address[] codes; uint256 env; bytes32 fp; }

    function _vpEnvName(uint256 i) internal view returns (string memory) {
        return string(abi.encodePacked("VACUITY_P", vpVm.toString(vpProbeIndex), "_", vpVm.toString(i)));
    }

    /// Campaign mode: the input lists recorded in the capture phase. Baseline values are
    /// read again here; the fingerprint check guarantees they match the capture phase.
    function _vpLoad(uint256 i) internal {
        bytes memory blob = vpVm.envOr(_vpEnvName(i), bytes(""));
        if (blob.length == 0) {
            vpCaptureFailed[i] = true;
            return;
        }
        VpInputs memory x = abi.decode(blob, (VpInputs));
        vpBaselineOk[i] = true;
        for (uint256 k = 0; k < x.sa.length; k++) {
            vpSlots[i].push(VpSlot(x.sa[k], x.ss[k], vpVm.load(x.sa[k], x.ss[k]), x.sc[k]));
        }
        for (uint256 k = 0; k < x.bals.length; k++) vpBals[i].push(VpBal(x.bals[k], x.bals[k].balance));
        for (uint256 k = 0; k < x.codes.length; k++) vpCodes[i].push(VpCode(x.codes[k], x.codes[k].codehash));
        vpEnv[i] = x.env;
        if (_vpFingerprint(i) != x.fp) vpNondeterministic[i] = true;
    }

    /// Hash of everything the probe compares against, taken right after setUp.
    function _vpFingerprint(uint256 i) internal view returns (bytes32 h) {
        h = keccak256(abi.encode(vpInner, vpEnv[i]));
        VpSlot[] storage s = vpSlots[i];
        for (uint256 k = 0; k < s.length; k++) h = keccak256(abi.encode(h, s[k].acct, s[k].slot, s[k].val));
        VpBal[] storage b = vpBals[i];
        for (uint256 k = 0; k < b.length; k++) h = keccak256(abi.encode(h, b[k].acct, b[k].val));
        VpCode[] storage c = vpCodes[i];
        for (uint256 k = 0; k < c.length; k++) h = keccak256(abi.encode(h, c[k].acct, c[k].hash));
    }

    function _vpCalibrate() internal {
        VacuityCalib__ cal = new VacuityCalib__();
        VacuityCalibLib__ lib = new VacuityCalibLib__();
        vpCalib = address(cal);
        vpCalibLib = address(lib);
        address other = address(uint160(0xCa11b4a7E));
        vpVm.deal(other, 12345);
        vpVm.deal(address(cal), 777);

        vpVm.startStateDiffRecording();
        cal.readTwo(other);
        cal.viaDelegate(address(lib));
        cal.bump();
        VmVacuity__.AccountAccess[] memory a = vpVm.stopAndReturnStateDiff();
        uint256 flags = 0;
        for (uint256 i = 0; i < a.length; i++) {
            if (a[i].kind == 7 && a[i].account == other) flags |= 1;
            if (a[i].kind == 1 && a[i].account == address(lib)) flags |= 2;
            flags |= _vpCalibStorage(a[i].storageAccesses, address(cal));
        }
        if (flags & 12 != 12) revert("VACUITY:UNSUPPORTED: state diff storage reads did not decode as expected on this Forge version");
        if (flags & 1 == 0) revert("VACUITY:UNSUPPORTED: state diff balance access did not decode as expected on this Forge version");
        if (flags & 18 != 18) revert("VACUITY:UNSUPPORTED: state diff delegatecall accounting did not decode as expected on this Forge version");
        if (flags & 32 == 0) revert("VACUITY:UNSUPPORTED: state diff storage writes did not decode as expected on this Forge version");

        // Debug trace recording needs a tracer (forge -vvv). Without it, or if the
        // layout does not decode as expected, fall back to imprecise mode.
        (bool started, ) = address(vpVm).call(abi.encodeWithSignature("startDebugTraceRecording()"));
        if (!started) return;
        cal.traceMe(address(lib), other);
        if (!_vpStopTrace()) return;
        VpTrace memory t = _vpParseTrace();
        vpTraceSupported = _vpCalibTrace(t, address(cal), other);
    }

    function _vpCalibStorage(VmVacuity__.StorageAccess[] memory s, address cal) internal pure returns (uint256 flags) {
        for (uint256 k = 0; k < s.length; k++) {
            if (s[k].account != cal) continue;
            uint256 slot = uint256(s[k].slot);
            bytes32 prev = s[k].previousValue;
            bool w = s[k].isWrite;
            if (slot == 7 && !w && prev == 0xa7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7
                && s[k].newValue == prev) flags |= 4;
            if (slot == 3 && !w && prev == 0xb3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3) flags |= 8;
            if (slot == 5 && !w && prev == 0xc5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5) flags |= 16;
            if (slot == 9 && w && prev == bytes32(0) && s[k].newValue == bytes32(uint256(1))) flags |= 32;
        }
    }

    function _vpCalibTrace(VpTrace memory t, address cal, address other) internal pure returns (bool) {
        if (!t.complete || t.env & 1 == 0) return false;
        bool sawOther;
        bool sawSelf;
        bool sawLoad;
        for (uint256 k = 0; k < t.bal.length; k++) {
            if (t.bal[k] == other) sawOther = true; // BALANCE with the queried address
            if (t.bal[k] == cal) sawSelf = true; // SELFBALANCE in a delegate frame, context = cal
        }
        for (uint256 k = 0; k < t.la.length; k++) {
            if (t.la[k] == cal && t.ls[k] == bytes32(uint256(7))) sawLoad = true;
        }
        return sawOther && sawSelf && sawLoad;
    }

    function _vpCapture(uint256 i) internal {
        (bool recorded, VpRec memory r) = _vpRunStateDiff(i);
        if (!recorded) {
            vpCaptureFailed[i] = true; // e.g. ran out of gas; the probe reports this invariant as inconclusive
            return;
        }
        vpBaselineOk[i] = r.ok;
        vpGas[i] = r.gas;
        VpTrace memory t;
        bool traced = false;
        if (vpTraceSupported) (traced, t) = _vpRunTrace(i);
        vpTraceOk[i] = traced && t.complete;

        // storage: state diff reads plus vm.load slots, deduplicated in memory
        for (uint256 k = 0; k < r.sa.length; k++) {
            vpSlots[i].push(VpSlot(r.sa[k], r.ss[k], vpVm.load(r.sa[k], r.ss[k]), r.sc[k]));
        }
        if (traced) {
            for (uint256 k = 0; k < t.la.length; k++) {
                if (_vpHasSlot(r.sa, r.ss, t.la[k], t.ls[k])) continue;
                vpSlots[i].push(VpSlot(t.la[k], t.ls[k], vpVm.load(t.la[k], t.ls[k]), t.la[k]));
            }
            vpEnv[i] = t.env;
            for (uint256 k = 0; k < t.cheats.length; k++) vpCheats[i].push(t.cheats[k]);
        }
        // balances: precise from the trace; conservative static set otherwise (computed here,
        // outside the gas-capped recording frame, because scanning bytecode is expensive)
        address[] memory bals = vpTraceOk[i] ? t.bal : _vpUnion(traced ? t.bal : new address[](0), _vpStaticBalances(r));
        for (uint256 k = 0; k < bals.length; k++) vpBals[i].push(VpBal(bals[k], bals[k].balance));
        address[] memory codes = _vpUnion(r.code, traced ? t.code : new address[](0));
        for (uint256 k = 0; k < codes.length; k++) vpCodes[i].push(VpCode(codes[k], codes[k].codehash));
    }

    function _vpMin(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function _vpHasSlot(address[] memory sa, bytes32[] memory ss, address a, bytes32 sl) internal pure returns (bool) {
        for (uint256 q = 0; q < sa.length; q++) if (sa[q] == a && ss[q] == sl) return true;
        return false;
    }

    function _vpUnion(address[] memory a, address[] memory b) internal pure returns (address[] memory out) {
        out = new address[](a.length + b.length);
        uint256 n = 0;
        for (uint256 k = 0; k < a.length; k++) n = _vpAddUnique(out, n, a[k]);
        for (uint256 k = 0; k < b.length; k++) n = _vpAddUnique(out, n, b[k]);
        assembly { mstore(out, n) }
    }

    function _vpRunStateDiff(uint256 i) internal returns (bool, VpRec memory r) {
        // Cap the frame's gas so this outer frame can always continue if it runs out.
        (bool ok, bytes memory data) =
            address(this).call{gas: gasleft() * 3 / 4}(abi.encodeWithSignature("vacuityRecord(uint256)", i));
        if (ok || data.length < 4) return (false, r);
        bytes4 tag;
        assembly { tag := mload(add(data, 32)) }
        if (tag != VP_TAG) return (false, r);
        r = abi.decode(_vpStrip(data), (VpRec));
        // Ran out of gas under the recording cap: too heavy to record.
        if (!r.ok && r.gas >= VP_RECORD_GAS * 63 / 64) return (false, r);
        return (true, r);
    }

    function _vpRunTrace(uint256 i) internal returns (bool, VpTrace memory t) {
        (bool ok, bytes memory data) =
            address(this).call{gas: gasleft() * 3 / 4}(abi.encodeWithSignature("vacuityTrace(uint256)", i));
        if (ok || data.length < 4) return (false, t);
        bytes4 tag;
        assembly { tag := mload(add(data, 32)) }
        if (tag != VP_TAG_TRACE) return (false, t);
        t = abi.decode(_vpStrip(data), (VpTrace));
        return (true, t);
    }

    function _vpStrip(bytes memory data) internal pure returns (bytes memory payload) {
        payload = new bytes(data.length - 4);
        for (uint256 k = 0; k < payload.length; k++) payload[k] = data[k + 4];
    }

    /// Runs one invariant under state diff recording and always reverts, so any
    /// state the invariant writes is rolled back. Results travel in the revert data.
    function vacuityRecord(uint256 i) external {
        require(msg.sender == address(this), "VACUITY: internal");
        vpVm.startStateDiffRecording();
        uint256 g0 = gasleft();
        // Capped so a heavy invariant cannot make Forge record an unbounded state diff.
        (bool callOk, ) = vpInner.call{gas: _vpMin(gasleft() / 2, VP_RECORD_GAS)}(abi.encodeWithSelector(_vpSel(i)));
        uint256 used = g0 - gasleft();
        VmVacuity__.AccountAccess[] memory a = vpVm.stopAndReturnStateDiff();
        VpRec memory r;
        r.ok = callOk;
        r.gas = used;
        _vpCollectSlots(a, r);
        _vpCollectAccounts(a, r);
        bytes memory out = abi.encodePacked(VP_TAG, abi.encode(r));
        assembly { revert(add(out, 32), mload(out)) }
    }

    /// Same idea with an opcode trace: which balances, code, environment values,
    /// vm.load slots and other cheatcodes the invariant actually used.
    function vacuityTrace(uint256 i) external {
        require(msg.sender == address(this), "VACUITY: internal");
        (bool started, ) = address(vpVm).call(abi.encodeWithSignature("startDebugTraceRecording()"));
        require(started, "VACUITY: no tracer");
        // Capped so a heavy invariant cannot make Forge record millions of steps.
        (bool callOk, ) = vpInner.call{gas: _vpMin(gasleft() / 2, VP_TRACE_CALL_GAS)}(abi.encodeWithSelector(_vpSel(i)));
        require(_vpStopTrace(), "VACUITY: stop trace failed");
        VpTrace memory t = _vpParseTrace();
        // It completed when recorded with full gas but not under the cap: the trace is partial.
        if (!callOk && vpBaselineOk[i]) t.complete = false;
        bytes memory out = abi.encodePacked(VP_TAG_TRACE, abi.encode(t));
        assembly { revert(add(out, 32), mload(out)) }
    }

    /// Stops debug trace recording, leaving the encoded DebugStep[] in the
    /// return-data buffer (nothing is copied to memory).
    function _vpStopTrace() internal returns (bool ok) {
        bytes4 sel = SEL_STOP_TRACE;
        address vm_ = address(vpVm);
        assembly {
            mstore(0, sel)
            ok := call(gas(), vm_, 0, 0, 4, 0, 0)
        }
    }

    function _vpRd(uint256 pos) internal pure returns (uint256 v) {
        assembly {
            returndatacopy(0, pos, 32)
            v := mload(0)
        }
    }

    /// Parses Forge's DebugStep[] word by word from the return-data buffer left by
    /// _vpStopTrace(). Copying the whole trace into memory would cost quadratic
    /// memory gas on long traces. No external call may happen while parsing, since
    /// that would overwrite the buffer; an out-of-bounds read reverts the frame,
    /// which the caller treats as "trace unavailable".
    /// DebugStep layout: stack, memoryInput, opcode, depth, isOutOfGas, contractAddr.
    function _vpParseTrace() internal view returns (VpTrace memory t) {
        t.bal = new address[](VP_CAP);
        t.code = new address[](VP_CAP);
        t.la = new address[](VP_CAP);
        t.ls = new bytes32[](VP_CAP);
        t.cheats = new bytes4[](64);
        t.complete = true;
        uint256[4] memory n; // bal, code, loads, cheats
        uint256 size;
        assembly { size := returndatasize() }
        if (size < 64) {
            t.complete = false;
        } else {
            uint256 base = _vpRd(0);
            uint256 count = _vpRd(base);
            uint256 head = base + 32;
            for (uint256 k = 0; k < count; k++) {
                uint256 tup = head + _vpRd(head + 32 * k);
                address ctx = address(uint160(_vpRd(tup + 160)));
                if (ctx == address(this)) continue;
                _vpStep(uint8(_vpRd(tup + 64)), tup, ctx, t, n);
            }
        }
        uint256 nb = n[0];
        uint256 nc = n[1];
        uint256 nl = n[2];
        uint256 nh = n[3];
        address[] memory bal = t.bal;
        address[] memory code = t.code;
        address[] memory la = t.la;
        bytes32[] memory ls = t.ls;
        bytes4[] memory ch = t.cheats;
        assembly { mstore(bal, nb) mstore(code, nc) mstore(la, nl) mstore(ls, nl) mstore(ch, nh) }
    }

    function _vpStack(uint256 tup) internal pure returns (uint256 len, uint256 s0, uint256 s1) {
        uint256 off = tup + _vpRd(tup);
        len = _vpRd(off);
        if (len > 0) s0 = _vpRd(off + 32);
        if (len > 1) s1 = _vpRd(off + 64);
    }

    function _vpStep(uint8 op, uint256 tup, address ctx, VpTrace memory t, uint256[4] memory n) internal view {
        if (op == 0x47) {
            _vpAddAddr(t, t.bal, n, 0, ctx);
        } else if (op == 0x31 || op == 0x3b || op == 0x3c || op == 0x3f) {
            (uint256 len, uint256 s0, ) = _vpStack(tup);
            if (len > 0) {
                if (op == 0x31) _vpAddAddr(t, t.bal, n, 0, address(uint160(s0)));
                else _vpAddAddr(t, t.code, n, 1, address(uint160(s0)));
            }
        } else if (op == 0x42) { t.env |= 1; }
        else if (op == 0x43) { t.env |= 2; }
        else if (op == 0x46) { t.env |= 4; }
        else if (op == 0x41) { t.env |= 8; }
        else if (op == 0x45) { t.env |= 16; }
        else if (op == 0x3a) { t.env |= 32; }
        else if (op == 0x32) { t.env |= 64; }
        else if (op == 0x48) { t.env |= 128; }
        else if (op == 0x44) { t.env |= 256; }
        else if (op == 0x40) { t.env |= 512; }
        else if (op == 0x49) { t.env |= 1024; }
        else if (op == 0x4a) { t.env |= 2048; }
        else if (op == 0xf1 || op == 0xf2 || op == 0xf4 || op == 0xfa) {
            (uint256 len, , uint256 s1) = _vpStack(tup);
            if (len > 1 && address(uint160(s1)) == address(vpVm)) _vpCheat(tup, t, n);
        }
    }

    function _vpCheat(uint256 tup, VpTrace memory t, uint256[4] memory n) internal pure {
        uint256 off = tup + _vpRd(tup + 32);
        uint256 len = _vpRd(off);
        if (len < 4) { _vpAddCheat(t, n, bytes4(0)); return; }
        bytes4 sel = bytes4(bytes32(_vpRd(off + 32)));
        if (sel == SEL_LOAD && len >= 68) {
            address a = address(uint160(_vpRd(off + 36)));
            bytes32 sl = bytes32(_vpRd(off + 68));
            for (uint256 q = 0; q < n[2]; q++) if (t.la[q] == a && t.ls[q] == sl) return;
            if (n[2] >= VP_CAP) { t.complete = false; return; }
            t.la[n[2]] = a;
            t.ls[n[2]] = sl;
            n[2]++;
        } else if (sel == SEL_TS) { t.env |= 1; }
        else if (sel == SEL_NUM) { t.env |= 2; }
        else if (sel == SEL_CHAIN) { t.env |= 4; }
        else { _vpAddCheat(t, n, sel); }
    }

    function _vpAddCheat(VpTrace memory t, uint256[4] memory n, bytes4 sel) internal pure {
        for (uint256 q = 0; q < n[3]; q++) if (t.cheats[q] == sel) return;
        if (n[3] >= t.cheats.length) { t.complete = false; return; }
        t.cheats[n[3]] = sel;
        n[3]++;
    }

    function _vpAddAddr(VpTrace memory t, address[] memory arr, uint256[4] memory n, uint256 which, address a) internal view {
        if (_vpIgnored(a)) return;
        uint256 c = n[which];
        for (uint256 q = 0; q < c; q++) if (arr[q] == a) return;
        if (c >= arr.length) { t.complete = false; return; }
        arr[c] = a;
        n[which] = c + 1;
    }

    function _vpCollectSlots(VmVacuity__.AccountAccess[] memory a, VpRec memory r) internal view {
        uint256 total = 0;
        for (uint256 k = 0; k < a.length; k++) total += a[k].storageAccesses.length;
        r.sa = new address[](total);
        r.ss = new bytes32[](total);
        r.sc = new address[](total);
        uint256 n = 0;
        for (uint256 k = 0; k < a.length; k++) {
            // For a DelegateCall entry, the executing code (whose storage layout applies)
            // is the delegate target, while the storage belongs to the caller.
            n = _vpCollectFrom(a[k].storageAccesses, a[k].account, r, n);
        }
        address[] memory sa = r.sa;
        bytes32[] memory ss = r.ss;
        address[] memory sc = r.sc;
        assembly { mstore(sa, n) mstore(ss, n) mstore(sc, n) }
    }

    function _vpCollectFrom(VmVacuity__.StorageAccess[] memory s, address code, VpRec memory r, uint256 n)
        internal view returns (uint256)
    {
        for (uint256 j = 0; j < s.length; j++) {
            if (s[j].isWrite || _vpIgnored(s[j].account)) continue;
            bool dup = false;
            for (uint256 q = 0; q < n; q++) {
                if (r.sa[q] == s[j].account && r.ss[q] == s[j].slot) { dup = true; break; }
            }
            if (dup) continue;
            r.sa[n] = s[j].account;
            r.ss[n] = s[j].slot;
            r.sc[n] = code;
            n++;
        }
        return n;
    }

    function _vpCollectAccounts(VmVacuity__.AccountAccess[] memory a, VpRec memory r) internal view {
        // Forge reports the accessor of a DelegateCall as the preserved msg.sender, not the
        // storage owner, so delegate frames are summarized by their storage owners instead.
        address[] memory code = new address[](a.length);
        address[] memory calls = new address[](a.length);
        address[] memory dels = new address[](a.length);
        address[] memory bals = new address[](a.length);
        uint256 total = 0;
        for (uint256 k = 0; k < a.length; k++) {
            if (a[k].kind == 1 || a[k].kind == 2) total += a[k].storageAccesses.length;
        }
        address[] memory owners = new address[](total);
        uint256[5] memory n; // code, calls, dels, bals, owners
        for (uint256 k = 0; k < a.length; k++) {
            uint8 kind = a[k].kind;
            address acct = a[k].account;
            if (_vpIgnored(acct)) continue;
            if (kind == 0 || kind == 3) {
                n[0] = _vpAddUnique(code, n[0], acct);
                n[1] = _vpAddUnique(calls, n[1], acct);
            } else if (kind == 1 || kind == 2) {
                n[0] = _vpAddUnique(code, n[0], acct);
                n[2] = _vpAddUnique(dels, n[2], acct);
                n[4] = _vpAddStorageOwners(a[k].storageAccesses, owners, n[4]);
            } else if (kind == 7) {
                n[3] = _vpAddUnique(bals, n[3], acct);
            } else if (kind >= 8 && kind <= 10) {
                n[0] = _vpAddUnique(code, n[0], acct);
            }
        }
        uint256 n0 = n[0];
        uint256 n1 = n[1];
        uint256 n2 = n[2];
        uint256 n3 = n[3];
        uint256 n4 = n[4];
        assembly { mstore(code, n0) mstore(calls, n1) mstore(dels, n2) mstore(bals, n3) mstore(owners, n4) }
        r.code = code;
        r.calls = calls;
        r.delegates = dels;
        r.balanceReads = bals;
        r.owners = owners;
    }

    /// Conservative balance set used only when the opcode trace is unavailable:
    /// BALANCE reads, called accounts whose code contains SELFBALANCE, and if any
    /// delegate target contains SELFBALANCE, every called account and storage owner.
    function _vpStaticBalances(VpRec memory r) internal view returns (address[] memory out) {
        out = new address[](r.balanceReads.length + r.calls.length + r.owners.length);
        uint256 n = 0;
        for (uint256 k = 0; k < r.balanceReads.length; k++) n = _vpAddUnique(out, n, r.balanceReads[k]);
        bool delegated = false;
        for (uint256 k = 0; k < r.delegates.length; k++) {
            if (_vpHasSelfBalance(r.delegates[k])) { delegated = true; break; }
        }
        for (uint256 k = 0; k < r.calls.length; k++) {
            if (delegated || _vpHasSelfBalance(r.calls[k])) n = _vpAddUnique(out, n, r.calls[k]);
        }
        if (delegated) {
            for (uint256 k = 0; k < r.owners.length; k++) n = _vpAddUnique(out, n, r.owners[k]);
        }
        assembly { mstore(out, n) }
    }

    function _vpAddStorageOwners(VmVacuity__.StorageAccess[] memory s, address[] memory owners, uint256 n)
        internal view returns (uint256)
    {
        for (uint256 j = 0; j < s.length && n < owners.length; j++) {
            if (!_vpIgnored(s[j].account)) n = _vpAddUnique(owners, n, s[j].account);
        }
        return n;
    }

    function _vpIgnored(address a) internal view returns (bool) {
        return a == address(0) || a == address(vpVm) || a == VP_CONSOLE || a == address(this);
    }

    function _vpAddUnique(address[] memory arr, uint256 n, address a) internal pure returns (uint256) {
        for (uint256 i = 0; i < n; i++) if (arr[i] == a) return n;
        arr[n] = a;
        return n + 1;
    }

    /// True if the account's code contains a SELFBALANCE opcode (PUSH data skipped).
    /// Over-approximates, which can only make an invariant look live, never frozen.
    function _vpHasSelfBalance(address a) internal view returns (bool) {
        bytes memory c = a.code;
        uint256 i = 0;
        while (i < c.length) {
            uint8 op = uint8(c[i]);
            if (op == 0x47) return true;
            if (op >= 0x60 && op <= 0x7f) i += uint256(op) - 0x5f;
            i++;
        }
        return false;
    }

    // ------------------------------------------------------------------ checks

    function _vpCheck(uint256 i) internal view {
        if (vpCaptureFailed[i]) revert("VACUITY:CAPTURE_FAILED: could not record this invariant's inputs (out of gas?)");
        if (vpNondeterministic[i]) revert("VACUITY:NONDETERMINISTIC: the state after setUp differs between runs");
        VpSlot[] storage s = vpSlots[i];
        for (uint256 k = 0; k < s.length; k++) {
            if (vpVm.load(s[k].acct, s[k].slot) != s[k].val) revert("VACUITY:LIVE");
        }
        VpBal[] storage b = vpBals[i];
        for (uint256 k = 0; k < b.length; k++) {
            if (b[k].acct.balance != b[k].val) revert("VACUITY:LIVE");
        }
        VpCode[] storage c = vpCodes[i];
        for (uint256 k = 0; k < c.length; k++) {
            if (c[k].acct.codehash != c[k].hash) revert("VACUITY:LIVE");
        }
        uint256 env = vpEnv[i];
        if (env != 0) _vpCheckEnv(env);
    }

    function _vpCheckEnv(uint256 env) internal view {
        if (env & 1 != 0 && block.timestamp != vpTs) revert("VACUITY:LIVE");
        if (env & 2 != 0 && block.number != vpNum) revert("VACUITY:LIVE");
        if (env & 4 != 0 && block.chainid != vpChain) revert("VACUITY:LIVE");
        if (env & 8 != 0 && block.coinbase != vpCoinbase) revert("VACUITY:LIVE");
        if (env & 16 != 0 && block.gaslimit != vpGasLimit) revert("VACUITY:LIVE");
        if (env & 32 != 0 && tx.gasprice != vpGasPrice) revert("VACUITY:LIVE");
        if (env & 64 != 0 && tx.origin != vpOrigin) revert("VACUITY:LIVE");
    }

    // ------------------------------------------------------------------ report

    function test_vacuityInfo() public view {
        _vpLog(string(abi.encodePacked("VPINFO|", vpVm.toString(vpCount), "|", vpTraceSupported ? "1" : "0")));
        address[] memory seen = new address[](256);
        uint256 ns = 0;
        for (uint256 i = 0; i < vpCount; i++) {
            ns = _vpLogInvariant(i, seen, ns);
        }
        for (uint256 k = 0; k < ns; k++) {
            _vpLog(string(abi.encodePacked("VPACCT|", vpVm.toString(seen[k]), "|", vpVm.toString(seen[k].code))));
        }
        _vpLog(string(abi.encodePacked("VPINNER|", vpVm.toString(vpInner))));
        _vpLog("VPEND");
    }

    function _vpLogInvariant(uint256 i, address[] memory seen, uint256 ns) internal view returns (uint256) {
        string memory idx = vpVm.toString(i);
        _vpLog(string(abi.encodePacked(
            "VPINV|", idx, "|", vpBaselineOk[i] ? "1" : "0", "|", vpTraceOk[i] ? "1" : "0", "|",
            vpVm.toString(vpEnv[i]), "|", vpCaptureFailed[i] ? "0" : "1", "|", vpVm.toString(vpGas[i])
        )));
        if (!vpCaptureFailed[i]) _vpLog(string(abi.encodePacked("VPFP|", idx, "|", vpVm.toString(_vpFingerprint(i)))));
        VpSlot[] storage s = vpSlots[i];
        for (uint256 k = 0; k < s.length; k++) {
            _vpLog(string(abi.encodePacked(
                "VPSLOT|", idx, "|", vpVm.toString(s[k].acct), "|", vpVm.toString(s[k].slot), "|", vpVm.toString(s[k].val),
                "|", vpVm.toString(s[k].code)
            )));
            if (ns < seen.length) ns = _vpAddUnique(seen, ns, s[k].acct);
            if (ns < seen.length) ns = _vpAddUnique(seen, ns, s[k].code);
        }
        VpBal[] storage b = vpBals[i];
        for (uint256 k = 0; k < b.length; k++) {
            _vpLog(string(abi.encodePacked("VPBAL|", idx, "|", vpVm.toString(b[k].acct))));
            if (ns < seen.length) ns = _vpAddUnique(seen, ns, b[k].acct);
        }
        VpCode[] storage c = vpCodes[i];
        for (uint256 k = 0; k < c.length; k++) {
            _vpLog(string(abi.encodePacked("VPCODE|", idx, "|", vpVm.toString(c[k].acct))));
        }
        bytes4[] storage h = vpCheats[i];
        for (uint256 k = 0; k < h.length; k++) {
            _vpLog(string(abi.encodePacked("VPCHEAT|", idx, "|", vpVm.toString(bytes32(h[k])))));
        }
        return ns;
    }

    function _vpLog(string memory s) internal view {
        (bool ok, ) = VP_CONSOLE.staticcall(abi.encodeWithSignature("log(string)", s));
        ok;
    }

    // --------------------------------------------------- Forge target forwarding

    function _vpFwd() internal view {
        (bool ok, bytes memory d) = vpInner.staticcall(msg.data);
        if (!ok || d.length < 64) d = abi.encode(new uint256[](0));
        assembly { return(add(d, 32), mload(d)) }
    }

    function excludeContracts() public view returns (address[] memory r) {
        (bool ok, bytes memory d) = vpInner.staticcall(abi.encodeWithSignature("excludeContracts()"));
        address[] memory prev;
        if (ok && d.length >= 64) prev = abi.decode(d, (address[]));
        r = new address[](prev.length + 3);
        uint256 n = 0;
        for (uint256 i = 0; i < prev.length; i++) r[n++] = prev[i];
        r[n++] = vpInner;
        if (vpCalib != address(0)) r[n++] = vpCalib; // only deployed in capture mode
        if (vpCalibLib != address(0)) r[n++] = vpCalibLib;
        assembly { mstore(r, n) }
    }
}
"""

FORWARDERS = r"""
    struct FuzzSelector { address addr; bytes4[] selectors; }
    struct FuzzArtifactSelector { string artifact; bytes4[] selectors; }
    struct FuzzInterface { address addr; string[] artifacts; }
    function targetContracts() public view returns (address[] memory r) { r = new address[](0); _vpFwd(); }
    function targetSenders() public view returns (address[] memory r) { r = new address[](0); _vpFwd(); }
    function excludeSenders() public view returns (address[] memory r) { r = new address[](0); _vpFwd(); }
    function targetArtifacts() public view returns (string[] memory r) { r = new string[](0); _vpFwd(); }
    function excludeArtifacts() public view returns (string[] memory r) { r = new string[](0); _vpFwd(); }
    function targetSelectors() public view returns (FuzzSelector[] memory r) { r = new FuzzSelector[](0); _vpFwd(); }
    function excludeSelectors() public view returns (FuzzSelector[] memory r) { r = new FuzzSelector[](0); _vpFwd(); }
    function targetArtifactSelectors() public view returns (FuzzArtifactSelector[] memory r) { r = new FuzzArtifactSelector[](0); _vpFwd(); }
    function targetInterfaces() public view returns (FuzzInterface[] memory r) { r = new FuzzInterface[](0); _vpFwd(); }
"""


_CONFIG = re.compile(r"^forge-config:\s*[A-Za-z0-9_.\-]+\s*=\s*[A-Za-z0-9_.\-\"' \[\],]+$")


def _natspec(line: str) -> str:
    line = line.strip()
    if not _CONFIG.match(line):
        raise ValueError(f"unexpected inline config line: {line!r}")
    return line


def _sol_string(s: str) -> str:
    if any(ch in s for ch in '"\\\n\r'):
        raise ValueError(f"unsupported character in path: {s!r}")
    return f'"{s}"'


DEFAULT_RECORD_GAS = 5_000_000
DEFAULT_TRACE_GAS = 300_000


BASE_FILE = "VacuityProbeBase.sol"
HEADER = [
    "// SPDX-License-Identifier: MIT",
    "// Generated by invariant-vacuity. Temporary file, safe to delete.",
    "pragma solidity >=0.8.0 <0.9.0;",
    "",
]


def probe_file(t: "ProbeTarget") -> str:
    return f"VacuityProbe_{t.index}.t.sol"


def generate_files(targets: List[ProbeTarget], initial_balance: int,
                   record_gas: int = DEFAULT_RECORD_GAS, trace_gas: int = DEFAULT_TRACE_GAS) -> List[Tuple[str, str]]:
    """The probe as separate files: one shared base, one file per test contract.

    One file per probe matters for memory: Forge embeds the AST of a contract's whole
    source file in its artifact and loads every artifact, so N probes in one file cost
    O(N^2) memory."""
    if not targets:
        raise ValueError("no targets to probe")
    if not (100_000 <= record_gas <= 10 ** 12 and 10_000 <= trace_gas <= 10 ** 12):
        raise ValueError("record_gas / trace_gas out of range")
    base = (
        BASE.replace("__SEL_LOAD__", SEL_LOAD)
        .replace("__SEL_TS__", SEL_TS)
        .replace("__SEL_NUM__", SEL_NUM)
        .replace("__SEL_CHAIN__", SEL_CHAIN)
        .replace("__SEL_STOP__", SEL_STOP_TRACE)
        .replace("__RECORD_GAS__", str(int(record_gas)))
        .replace("__TRACE_GAS__", str(int(trace_gas)))
    )
    files = [(BASE_FILE, "\n".join(HEADER + [base]))]
    for t in targets:
        files.append((probe_file(t), "\n".join(HEADER + [
            f'import {{VacuityProbeBase__}} from "./{BASE_FILE}";',
            _probe_import(t),
            _probe_contract(t, initial_balance),
        ])))
    return files


def generate(targets: List[ProbeTarget], initial_balance: int,
             record_gas: int = DEFAULT_RECORD_GAS, trace_gas: int = DEFAULT_TRACE_GAS) -> str:
    """Everything in one source string (for tests that compile with plain solc)."""
    files = generate_files(targets, initial_balance, record_gas, trace_gas)
    parts = list(HEADER)
    parts += [_probe_import(t) for t in targets]
    parts.append(files[0][1].split("\n", len(HEADER))[len(HEADER)])
    parts += [_probe_contract(t, initial_balance) for t in targets]
    return "\n".join(parts)


def _probe_import(t: ProbeTarget) -> str:
    if not _IDENT.match(t.contract):
        raise ValueError(f"unexpected contract name {t.contract!r}")
    return f"import {{{t.contract} as VacuityUser_{t.index}__}} from {_sol_string(t.source)};"


def _probe_contract(t: ProbeTarget, initial_balance: int) -> str:
    if len(t.invariants) != len(t.selectors) or not t.invariants:
        raise ValueError(f"bad invariant list for {t.contract}")
    for sel in t.selectors:
        if not re.fullmatch(r"[0-9a-f]{8}", sel):
            raise ValueError(f"bad selector {sel!r}")
    sel_lines = "\n".join(
        f"        if (i == {k}) return 0x{sel};" for k, sel in enumerate(t.selectors)
    )
    probe_lines = []
    for k in range(len(t.invariants)):
        for line in (t.invariant_config[k] if k < len(t.invariant_config) else []):
            probe_lines.append(f"    /// {_natspec(line)}")
        probe_lines.append(f"    function {PROBE_INVARIANT_PREFIX}{k}() public view {{ _vpCheck({k}); }}")
    probes = "\n".join(probe_lines)
    contract_doc = "".join(f"/// {_natspec(line)}\n" for line in t.contract_config)
    comment = "\n".join(f"    // probe {k}: {name}" for k, name in enumerate(t.invariants))
    return f"""
{contract_doc}contract {t.probe_name} is VacuityProbeBase__ {{
{comment}
    function setUp() public {{ _vpInit({t.index}, {len(t.invariants)}, {initial_balance}); }}
    function _vpDeploy() internal override returns (address) {{ return address(new VacuityUser_{t.index}__()); }}
    function _vpHasSetUp() internal pure override returns (bool) {{ return {"true" if t.has_setup else "false"}; }}
    function _vpSel(uint256 i) internal pure override returns (bytes4) {{
{sel_lines}
        revert("VACUITY: bad index");
    }}
{probes}
{FORWARDERS}
}}
"""
