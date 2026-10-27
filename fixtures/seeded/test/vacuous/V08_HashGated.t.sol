// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// Seeded bug: the only state change is gated behind a ~1 in 2^20 hash
/// condition, so the campaign never reaches it.
contract V08Handler {
    Counter internal c;
    constructor(Counter c_) { c = c_; }
    function poke(uint256 x) external {
        if (uint256(keccak256(abi.encode(x, "salt"))) < 2 ** 236) c.inc();
    }
}

contract V08_HashGated is Test {
    Counter internal c;
    V08Handler internal h;
    function setUp() public {
        c = new Counter(address(0));
        h = new V08Handler(c);
        targetContract(address(h));
    }
    function invariant_countBounded() public view {
        assertLe(c.count(), type(uint128).max);
    }
}
