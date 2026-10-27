// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// Mixed contract: one live invariant and one that checks state no handler can
/// reach (only the owner can pause, and the handler is not the owner).
contract V04Handler is Test {
    Vault internal v;
    Token internal t;
    constructor(Vault v_, Token t_) { v = v_; t = t_; }
    function deposit(uint256 a) external {
        a = bound(a, 1, 1e24);
        t.mint(address(this), a);
        t.approve(address(v), a);
        v.deposit(a);
    }
    function withdraw(uint256 a) external {
        a = bound(a, 0, v.shares(address(this)));
        v.withdraw(a);
    }
}

contract V04_UntouchedSlot is Test {
    Token internal t;
    Vault internal v;
    V04Handler internal h;
    function setUp() public {
        t = new Token();
        v = new Vault(t);
        h = new V04Handler(v, t);
        targetContract(address(h));
    }
    function invariant_neverPaused() public view {
        assertFalse(v.paused());
    }
    function invariant_solvent() public view {
        assertGe(t.balanceOf(address(v)), v.totalShares());
    }
}
