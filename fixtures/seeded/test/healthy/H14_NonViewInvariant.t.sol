// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// A non-view invariant that writes its own storage. The probe must roll the
/// write back when it records the invariant's inputs.
contract H14Handler {
    Counter internal c;
    constructor(Counter c_) { c = c_; }
    function inc() external { c.inc(); }
}

contract H14_NonViewInvariant is Test {
    Counter internal c;
    H14Handler internal h;
    uint256 public checks;
    function setUp() public {
        c = new Counter(address(0));
        h = new H14Handler(c);
        targetContract(address(h));
    }
    function invariant_countBounded() public {
        checks += 1;
        assertLe(c.count(), type(uint128).max);
    }
}
