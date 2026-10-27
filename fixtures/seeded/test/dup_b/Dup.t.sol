// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// Same contract name as test/dup_a/Dup.t.sol. This one is vacuous.
contract D_Dup is Test {
    Counter internal c;
    Token internal t;
    function setUp() public {
        c = new Counter(address(0));
        t = new Token();
        targetContract(address(t));
    }
    function invariant_countBounded() public view {
        assertLe(c.count(), type(uint128).max);
    }
}
