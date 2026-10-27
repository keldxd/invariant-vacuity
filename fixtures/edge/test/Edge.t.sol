// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "../src/MiniInvariant.sol";

/// setUp always reverts: Forge cannot run the suite, and neither can the probe.
contract E_SetupReverts is MiniInvariant {
    MiniCounter internal c;
    function setUp() public { c = new MiniCounter(); revert("broken setUp"); }
    function invariant_x() public view { require(c.count() < type(uint128).max, "x"); }
}

/// The invariant fails at the very first check.
contract E_FailsAtStart is MiniInvariant {
    MiniCounter internal c;
    function setUp() public { c = new MiniCounter(); targetContract(address(c)); }
    function invariant_broken() public view { require(c.count() > 1000, "starts broken"); }
}

/// One invariant whose capture is too large to record (out of gas in the
/// recording frame) next to a normal one. Only the heavy one may be inconclusive.
/// forge-config: default.invariant.runs = 1
/// forge-config: default.invariant.depth = 2
contract E_HeavyCapture is MiniInvariant {
    MiniCounter internal c;
    function setUp() public { c = new MiniCounter(); targetContract(address(c)); }
    function invariant_heavy() public view {
        uint256 s = 0;
        for (uint256 i = 0; i < 60000; i++) s += c.count();
        require(s < type(uint256).max, "x");
    }
    function invariant_light() public view { require(c.count() < type(uint128).max, "x"); }
}

/// excludeSender is forwarded: the only sender allowed to succeed is excluded.
contract E_ExcludeSender is MiniInvariant {
    Gated internal g;
    function setUp() public {
        g = new Gated(address(0xBEEF));
        targetContract(address(g));
        excludeSender(address(0xBEEF));
    }
    function invariant_gated() public view { require(g.count() < type(uint128).max, "x"); }
}

contract Gated {
    address internal allowed;
    uint256 public count;
    constructor(address a) { allowed = a; }
    function inc() external { require(msg.sender != allowed, "excluded sender got through"); count += 1; }
}

/// A test contract without invariants is ignored.
contract E_UnitOnly {
    function test_nothing() public pure {}
}

/// About 1.25M gas of pure computation per invariant call: recordable, but over the
/// opcode-trace cap, so the trace is partial. The live one must stay live; the
/// frozen one must be downgraded to a warning (untracked), never an error.
/// forge-config: default.invariant.runs = 1
/// forge-config: default.invariant.depth = 3
contract E_HeavyCompute is MiniInvariant {
    MiniCounter internal c;
    MiniNoop internal n;
    function setUp() public {
        c = new MiniCounter();
        n = new MiniNoop();
        targetContract(address(c));
    }
    function _burn() internal pure returns (uint256 s) {
        for (uint256 i = 0; i < 5000; i++) s += i;
    }
    function invariant_computeLive() public view { require(_burn() > 0 && c.count() < type(uint128).max, "x"); }
    function invariant_computeFrozen() public view { require(_burn() > 0 && n.value() == 7, "x"); }
}

contract Stamp {
    uint256 public value;
    constructor(uint256 v) { value = v; }
}

/// setUp stores the wall-clock time, so the state after setUp differs between the
/// probe's capture and campaign runs. Must be inconclusive, never frozen or live.
contract E_Nondeterministic is MiniInvariant {
    Stamp internal s;
    MiniCounter internal c;
    function setUp() public {
        s = new Stamp(vm.unixTime());
        c = new MiniCounter();
        targetContract(address(c));
    }
    function invariant_stamp() public view { require(s.value() > 0, "x"); }
}
