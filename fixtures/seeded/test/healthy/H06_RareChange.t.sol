// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// State changes on roughly 1 call in 64. Must still be reported live.
contract H06Handler {
    Counter internal c;
    constructor(Counter c_) { c = c_; }
    function poke(uint256 x) external {
        if (uint256(keccak256(abi.encode(x))) % 64 == 13) c.inc();
    }
}

contract H06_RareChange is Test {
    Counter internal c;
    H06Handler internal h;
    function setUp() public {
        c = new Counter(address(0));
        h = new H06Handler(c);
        targetContract(address(h));
    }
    function invariant_countBounded() public view {
        assertLe(c.count(), type(uint128).max);
    }
}
