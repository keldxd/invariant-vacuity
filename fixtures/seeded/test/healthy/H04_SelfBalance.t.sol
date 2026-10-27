// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// The invariant's only changing input is an ETH balance read with SELFBALANCE
/// inside EthVault.totalAssets(). Must be reported live.
contract H04Handler is Test {
    EthVault internal ev;
    constructor(EthVault e) { ev = e; }
    function deposit(uint256 a) external {
        a = bound(a, 1, 100 ether);
        vm.deal(address(this), a);
        ev.deposit{value: a}();
    }
    receive() external payable {}
}

contract H04_SelfBalance is Test {
    EthVault internal ev;
    H04Handler internal h;
    function setUp() public {
        ev = new EthVault();
        h = new H04Handler(ev);
        targetContract(address(h));
    }
    function invariant_assetsBounded() public view {
        assertLe(ev.totalAssets(), type(uint256).max);
    }
}
