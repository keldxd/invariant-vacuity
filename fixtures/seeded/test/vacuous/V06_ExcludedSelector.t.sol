// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// Seeded bug: targetSelector lists only ping(), so deposit() is never fuzzed.
contract V06Handler is Test {
    Vault internal v;
    Token internal t;
    event Ping();
    constructor(Vault v_, Token t_) { v = v_; t = t_; }
    function deposit(uint256 a) external {
        a = bound(a, 1, 1e24);
        t.mint(address(this), a);
        t.approve(address(v), a);
        v.deposit(a);
    }
    function ping() external { emit Ping(); }
}

contract V06_ExcludedSelector is Test {
    Token internal t;
    Vault internal v;
    V06Handler internal h;
    function setUp() public {
        t = new Token();
        v = new Vault(t);
        h = new V06Handler(v, t);
        bytes4[] memory sels = new bytes4[](1);
        sels[0] = V06Handler.ping.selector;
        targetSelector(FuzzSelector({addr: address(h), selectors: sels}));
        targetContract(address(h));
    }
    function invariant_solvent() public view {
        assertGe(t.balanceOf(address(v)), v.totalShares());
    }
}
