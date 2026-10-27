// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// No setUp(): the target is deployed by a state variable initializer.
contract H09_NoSetUp is Test {
    Counter internal c = new Counter(address(0));
    function invariant_countBounded() public view {
        assertLe(c.count(), type(uint128).max);
    }
}
