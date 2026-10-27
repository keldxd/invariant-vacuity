// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// Reads block.basefee, which the probe does not track. Warning, not error.
contract W02Handler is Test {
    function setFee(uint256 f) external { vm.fee(bound(f, 0, 1000 gwei)); }
}

contract W02_Basefee is Test {
    W02Handler internal h;
    function setUp() public {
        h = new W02Handler();
        targetContract(address(h));
    }
    function invariant_feeBounded() public view {
        assertLe(block.basefee, type(uint128).max);
    }
}
