// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// Seeded bug: the handler moves real funds but never updates its ghost
/// variables, and the invariant only compares the ghosts.
contract V03Handler is Test {
    Vault internal v;
    Token internal t;
    uint256 public ghostDeposited;
    uint256 public ghostWithdrawn;
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

contract V03_GhostNeverUpdated is Test {
    Token internal t;
    Vault internal v;
    V03Handler internal h;
    function setUp() public {
        t = new Token();
        v = new Vault(t);
        h = new V03Handler(v, t);
        targetContract(address(h));
    }
    function invariant_withdrawnLeDeposited() public view {
        assertLe(h.ghostWithdrawn(), h.ghostDeposited());
    }
}
