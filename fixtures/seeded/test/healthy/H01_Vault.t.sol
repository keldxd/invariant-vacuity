// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// A correct ghost-variable suite. Both invariants must be reported live.
contract H01Handler is Test {
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
        ghostDeposited += a;
    }
    function withdraw(uint256 a) external {
        a = bound(a, 0, v.shares(address(this)));
        v.withdraw(a);
        ghostWithdrawn += a;
    }
}

contract H01_Vault is Test {
    Token internal t;
    Vault internal v;
    H01Handler internal h;
    function setUp() public {
        t = new Token();
        v = new Vault(t);
        h = new H01Handler(v, t);
        targetContract(address(h));
    }
    function invariant_solvent() public view {
        assertGe(t.balanceOf(address(v)), v.totalShares());
    }
    function invariant_ghostAccounting() public view {
        assertEq(v.totalShares(), h.ghostDeposited() - h.ghostWithdrawn());
    }
}
