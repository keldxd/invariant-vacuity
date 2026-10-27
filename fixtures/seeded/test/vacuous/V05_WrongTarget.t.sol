// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// Seeded bug: two vaults are deployed, the handler drives vault A, the
/// invariant checks vault B.
contract V05Handler is Test {
    Vault internal v;
    Token internal t;
    constructor(Vault v_, Token t_) { v = v_; t = t_; }
    function deposit(uint256 a) external {
        a = bound(a, 1, 1e24);
        t.mint(address(this), a);
        t.approve(address(v), a);
        v.deposit(a);
    }
}

contract V05_WrongTarget is Test {
    Token internal t;
    Vault internal vaultA;
    Vault internal vaultB;
    V05Handler internal h;
    function setUp() public {
        t = new Token();
        vaultA = new Vault(t);
        vaultB = new Vault(t);
        h = new V05Handler(vaultA, t);
        targetContract(address(h));
    }
    function invariant_vaultBSolvent() public view {
        assertGe(t.balanceOf(address(vaultB)), vaultB.totalShares());
    }
}
