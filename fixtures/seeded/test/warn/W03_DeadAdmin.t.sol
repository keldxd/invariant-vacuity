// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// Targets the vault directly. deposit works (via a pre-funded sender), but the
/// owner-only setters always revert. Invariant is live; metrics should warn.
contract W03Handler is Test {
    Vault internal v;
    Token internal t;
    constructor(Vault v_, Token t_) { v = v_; t = t_; }
    function deposit(uint256 a) external {
        a = bound(a, 1, 1e24);
        t.mint(address(this), a);
        t.approve(address(v), a);
        v.deposit(a);
    }
    function adminPause() external { v.setPaused(true); }
}

contract W03_DeadAdmin is Test {
    Token internal t;
    Vault internal v;
    W03Handler internal h;
    function setUp() public {
        t = new Token();
        v = new Vault(t);
        h = new W03Handler(v, t);
        targetContract(address(h));
    }
    function invariant_solvent() public view {
        assertGe(t.balanceOf(address(v)), v.totalShares());
    }
}
