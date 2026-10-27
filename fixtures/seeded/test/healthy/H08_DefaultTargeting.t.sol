// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// No targetContract: Forge fuzzes every contract deployed in setUp except
/// excluded ones. The probe must reproduce that (and exclude its own helpers).
contract H08_DefaultTargeting is Test {
    Counter internal c;
    Token internal t;
    function setUp() public {
        c = new Counter(address(0));
        t = new Token();
        excludeContract(address(t));
    }
    function invariant_countBounded() public view {
        assertLe(c.count(), type(uint128).max);
    }
}
