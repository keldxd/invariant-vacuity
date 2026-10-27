// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// Seeded bug: setUp sets the cap to 0, and the handler bounds deposits to the
/// remaining cap, so every deposit is 0. Calls succeed, writes happen, but no
/// value ever changes.
contract V02Handler is Test {
    Vault internal v;
    Token internal t;
    uint256 public ghostDeposited;
    constructor(Vault v_, Token t_) { v = v_; t = t_; }
    function deposit(uint256 a) external {
        a = bound(a, 0, v.cap() - v.totalShares());
        t.mint(address(this), a);
        t.approve(address(v), a);
        v.deposit(a);
        ghostDeposited += a;
    }
}

contract V02_BoundToZero is Test {
    Token internal t;
    Vault internal v;
    V02Handler internal h;
    function setUp() public {
        t = new Token();
        v = new Vault(t);
        v.setCap(0);
        h = new V02Handler(v, t);
        targetContract(address(h));
    }
    function invariant_sharesMatchGhost() public view {
        assertEq(v.totalShares(), h.ghostDeposited());
    }
}
