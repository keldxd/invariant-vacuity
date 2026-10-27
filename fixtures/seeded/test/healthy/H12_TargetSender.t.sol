// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// Only alice may increment and the suite targets alice. This is live only if
/// the probe forwards targetSenders() correctly (random senders always revert).
contract H12_TargetSender is Test {
    Counter internal c;
    function setUp() public {
        address alice = makeAddr("alice");
        c = new Counter(alice);
        targetContract(address(c));
        targetSender(alice);
        bytes4[] memory sels = new bytes4[](1);
        sels[0] = Counter.incIfAllowed.selector;
        targetSelector(FuzzSelector({addr: address(c), selectors: sels}));
    }
    function invariant_countBounded() public view {
        assertLe(c.count(), type(uint128).max);
    }
}
