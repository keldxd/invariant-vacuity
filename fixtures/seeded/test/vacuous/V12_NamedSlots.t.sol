// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// Seeded bug plus a naming check: a contract with an immutable and an external
/// library. The invariant reads frozenFlag, which no handler writes.
contract V12Handler {
    FeeVault internal fv;
    constructor(FeeVault f) { fv = f; }
    function charge(uint256 a) external { fv.charge(a % 1e30); }
}

contract V12_NamedSlots is Test {
    FeeVault internal fv;
    V12Handler internal h;
    function setUp() public {
        fv = new FeeVault(30);
        h = new V12Handler(fv);
        targetContract(address(h));
    }
    function invariant_flagNeverSet() public view {
        assertFalse(fv.frozenFlag());
    }
    function invariant_collectedBounded() public view {
        assertLe(fv.collected(), type(uint256).max);
    }
}
