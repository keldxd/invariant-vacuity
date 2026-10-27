// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// The invariant reads address(ev).balance with the BALANCE opcode. Must be live.
contract H05Handler is Test {
    EthVault internal ev;
    constructor(EthVault e) { ev = e; }
    function deposit(uint256 a) external {
        a = bound(a, 1, 100 ether);
        vm.deal(address(this), a);
        ev.deposit{value: a}();
    }
}

contract H05_BalanceOpcode is Test {
    EthVault internal ev;
    H05Handler internal h;
    function setUp() public {
        ev = new EthVault();
        h = new H05Handler(ev);
        targetContract(address(h));
    }
    function invariant_balanceBounded() public view {
        assertLe(address(ev).balance, type(uint256).max);
    }
}
