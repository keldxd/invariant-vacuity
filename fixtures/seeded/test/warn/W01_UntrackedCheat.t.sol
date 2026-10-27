// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// The invariant's only input is vm.getNonce, which the probe cannot track.
/// Expected: a warning (frozen-untracked), never an error.
contract W01Handler {
    function spawn() external { new Counter(address(0)); }
}

contract W01_UntrackedCheat is Test {
    W01Handler internal h;
    function setUp() public {
        h = new W01Handler();
        targetContract(address(h));
    }
    function invariant_nonceBounded() public view {
        assertLe(vm.getNonce(address(h)), type(uint64).max);
    }
}
