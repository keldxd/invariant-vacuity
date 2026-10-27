// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// setUp spends ETH from the test contract's own balance, which Forge funds.
contract H10Handler is Test {
    EthVault internal ev;
    constructor(EthVault e) { ev = e; }
    function deposit(uint256 a) external {
        a = bound(a, 1, 10 ether);
        vm.deal(address(this), a);
        ev.deposit{value: a}();
    }
}

contract H10_SetupNeedsEth is Test {
    EthVault internal ev;
    H10Handler internal h;
    function setUp() public {
        ev = new EthVault();
        ev.deposit{value: 5 ether}();
        h = new H10Handler(ev);
        targetContract(address(h));
    }
    function invariant_depositsBacked() public view {
        assertGe(address(ev).balance, ev.deposits(address(h)));
    }
}
