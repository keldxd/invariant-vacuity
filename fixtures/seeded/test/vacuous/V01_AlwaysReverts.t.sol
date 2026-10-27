// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// Seeded bug: the handler forgets to mint and approve, so every deposit reverts.
contract V01Handler is Test {
    Vault internal v;
    uint256 public ghostDeposited;
    constructor(Vault v_) { v = v_; }
    function deposit(uint256 a) external {
        a = bound(a, 1, 1e24);
        v.deposit(a);
        ghostDeposited += a;
    }
}

contract V01_AlwaysReverts is Test {
    Token internal t;
    Vault internal v;
    V01Handler internal h;
    function setUp() public {
        t = new Token();
        v = new Vault(t);
        h = new V01Handler(v);
        targetContract(address(h));
    }
    function invariant_sharesMatchGhost() public view {
        assertEq(v.totalShares(), h.ghostDeposited());
    }
}
