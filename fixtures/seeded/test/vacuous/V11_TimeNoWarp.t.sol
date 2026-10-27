// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// Seeded bug: the invariant depends on block.timestamp, but no handler ever
/// warps time, so vested() never changes.
contract V11Handler {
    event Noop();
    function noop() external { emit Noop(); }
}

contract V11_TimeNoWarp is Test {
    Vesting internal vest;
    V11Handler internal h;
    function setUp() public {
        vest = new Vesting(1_000e18, 30 days);
        h = new V11Handler();
        targetContract(address(h));
    }
    function invariant_vestedLeTotal() public view {
        assertLe(vest.vested(), vest.total());
    }
}
