// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// The invariant reads 300 balances. Exercises capture size and probe cost.
contract H16Handler is Test {
    Token internal t;
    address[] internal actors;
    constructor(Token t_, address[] memory a) { t = t_; actors = a; }
    function mint(uint256 who, uint256 a) external {
        t.mint(actors[who % actors.length], bound(a, 1, 1e24));
    }
}

contract H16_LargeReadSet is Test {
    Token internal t;
    H16Handler internal h;
    address[] internal actors;
    function setUp() public {
        t = new Token();
        for (uint256 i = 0; i < 300; i++) actors.push(address(uint160(0x10000 + i)));
        h = new H16Handler(t, actors);
        targetContract(address(h));
    }
    function invariant_sumMatchesSupply() public view {
        uint256 sum = 0;
        for (uint256 i = 0; i < actors.length; i++) sum += t.balanceOf(actors[i]);
        assertEq(sum, t.totalSupply());
    }
}
