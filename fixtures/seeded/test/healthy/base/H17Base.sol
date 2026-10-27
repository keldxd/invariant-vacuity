// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../../src/Protocol.sol";

/// Abstract base defining the invariant; probed through its concrete child.
abstract contract H17Base is Test {
    Counter internal c;
    function invariant_countBounded() public view {
        assertLe(c.count(), type(uint128).max);
    }
}
