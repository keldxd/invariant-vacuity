// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "./base/H17Base.sol";

contract H17_Inherited is H17Base {
    function setUp() public {
        c = new Counter(address(0));
        targetContract(address(c));
    }
}
