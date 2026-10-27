// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../src/Compat.sol";

/// No forge-std: default targeting (every contract deployed in setUp).
contract CompatLive {
    Counter internal c;
    function setUp() public { c = new Counter(); }
    function invariant_live() public view { require(c.count() < type(uint128).max, "overflow"); }
}

/// forge-config: default.invariant.runs = 9
contract CompatFrozen {
    Frozen internal f;
    function setUp() public { f = new Frozen(); }
    function invariant_frozen() public view { require(f.value() == 7, "changed"); }
}
