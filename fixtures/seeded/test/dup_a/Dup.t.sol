// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// Same contract name as test/dup_b/Dup.t.sol. This one is live.
contract D_Dup is Test {
    Counter internal c;
    function setUp() public {
        c = new Counter(address(0));
        targetContract(address(c));
    }
    function invariant_countBounded() public view {
        assertLe(c.count(), type(uint128).max);
    }
}
