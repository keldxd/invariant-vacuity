// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Counter {
    uint256 public count;
    function inc() external { count += 1; }
}

contract Frozen {
    uint256 public value = 7;
    event Noop();
    function noop() external { emit Noop(); }
}
