// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// setUp ends with an active startPrank. Must not break the probe.
contract H11_LeakedPrank is Test {
    Counter internal c;
    function setUp() public {
        c = new Counter(address(0));
        targetContract(address(c));
        vm.startPrank(address(uint160(uint256(keccak256("h11-prankster")))));
    }
    function invariant_countBounded() public view {
        assertLe(c.count(), type(uint128).max);
    }
}
