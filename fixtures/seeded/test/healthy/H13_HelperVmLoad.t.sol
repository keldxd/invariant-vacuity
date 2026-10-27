// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// The vm.load happens inside a separate helper contract, not the test.
contract H13Reader is Test {
    function countOf(address counter) external view returns (uint256) {
        return uint256(vm.load(counter, bytes32(uint256(0))));
    }
}

contract H13Handler {
    Counter internal c;
    constructor(Counter c_) { c = c_; }
    function inc() external { c.inc(); }
}

contract H13_HelperVmLoad is Test {
    Counter internal c;
    H13Reader internal reader;
    H13Handler internal h;
    function setUp() public {
        c = new Counter(address(0));
        reader = new H13Reader();
        h = new H13Handler(c);
        targetContract(address(h));
    }
    function invariant_countBounded() public view {
        assertLe(reader.countOf(address(c)), type(uint128).max);
    }
}
