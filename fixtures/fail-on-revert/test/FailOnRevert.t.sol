// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "../src/MiniInvariant.sol";

contract SometimesReverts {
    uint256 public count;
    function poke(uint256 x) external { require(x % 2 == 0, "odd"); count += 1; }
}

contract FR_Live is MiniInvariant {
    MiniCounter internal c;
    function setUp() public { c = new MiniCounter(); targetContract(address(c)); }
    function invariant_live() public view { require(c.count() < type(uint128).max, "x"); }
}

contract FR_Frozen is MiniInvariant {
    MiniNoop internal n;
    function setUp() public { n = new MiniNoop(); targetContract(address(n)); }
    function invariant_frozen() public view { require(n.value() == 7, "x"); }
}

contract FR_Reverting is MiniInvariant {
    SometimesReverts internal s;
    function setUp() public { s = new SometimesReverts(); targetContract(address(s)); }
    function invariant_count() public view { require(s.count() < type(uint128).max, "x"); }
}
