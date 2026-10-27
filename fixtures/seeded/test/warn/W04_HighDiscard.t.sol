// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// vm.assume rejects most inputs, so most calls are discarded.
contract W04Handler is Test {
    Counter internal c;
    constructor(Counter c_) { c = c_; }
    function poke(uint256 x) external {
        vm.assume(x % 4 == 0);
        c.inc();
    }
}

contract W04_HighDiscard is Test {
    Counter internal c;
    W04Handler internal h;
    function setUp() public {
        c = new Counter(address(0));
        h = new W04Handler(c);
        targetContract(address(h));
    }
    function invariant_countBounded() public view {
        assertLe(c.count(), type(uint128).max);
    }
}
