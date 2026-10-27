// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// No storage changes at all, but the handler warps time and the invariant
/// depends on block.timestamp. Must be reported live.
contract H03Handler is Test {
    function warp(uint256 dt) external {
        vm.warp(block.timestamp + bound(dt, 1, 2 days));
    }
}

contract H03_TimeWarp is Test {
    Vesting internal vest;
    H03Handler internal h;
    function setUp() public {
        vest = new Vesting(1_000e18, 30 days);
        h = new H03Handler();
        targetContract(address(h));
    }
    function invariant_vestedLeTotal() public view {
        assertLe(vest.vested(), vest.total());
    }
}
