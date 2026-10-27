// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// Seeded bug: invariants that cannot fail whatever the protocol does.
contract V07_Trivial is Test {
    Counter internal c;
    function setUp() public {
        c = new Counter(address(0));
        targetContract(address(c));
    }
    function invariant_deployed() public view {
        assertTrue(address(c) != address(0));
    }
    function invariant_arithmetic() public pure {
        assertEq(uint256(1) + 1, 2);
    }
}
