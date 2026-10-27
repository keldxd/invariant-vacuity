// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@proto/MiniInvariant.sol";

/// Custom src/test/out/cache dirs, a remapping, and spaces in the path.
contract WeirdLayout is MiniInvariant {
    MiniCounter internal c;
    MiniNoop internal n;
    function setUp() public {
        c = new MiniCounter();
        n = new MiniNoop();
        targetContract(address(c));
        targetContract(address(n));
    }
    function invariant_live() public view { require(c.count() < type(uint128).max, "x"); }
    function invariant_frozen() public view { require(n.value() == 7, "y"); }
}
