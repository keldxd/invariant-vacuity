// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// Reads protocol state only through vm.load. The probe must track the loaded
/// slot (no SLOAD happens) and report this live.
contract H02Handler {
    Counter internal c;
    constructor(Counter c_) { c = c_; }
    function inc() external { c.inc(); }
}

contract H02_VmLoad is Test {
    Counter internal c;
    H02Handler internal h;
    function setUp() public {
        c = new Counter(address(0));
        h = new H02Handler(c);
        targetContract(address(h));
    }
    function invariant_countViaVmLoad() public view {
        uint256 count = uint256(vm.load(address(c), bytes32(uint256(0))));
        assertLe(count, type(uint128).max);
    }
}
