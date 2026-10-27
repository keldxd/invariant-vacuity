// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// Seeded bug: only alice may increment, but the suite targets bob as sender.
contract V10_WrongSender is Test {
    Counter internal c;
    function setUp() public {
        c = new Counter(makeAddr("alice"));
        targetContract(address(c));
        targetSender(makeAddr("bob"));
        bytes4[] memory sels = new bytes4[](1);
        sels[0] = Counter.incIfAllowed.selector;
        targetSelector(FuzzSelector({addr: address(c), selectors: sels}));
    }
    function invariant_countBounded() public view {
        assertLe(c.count(), type(uint128).max);
    }
}
