// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Minimal stand-in for forge-std's StdInvariant: exposes the targeting getters
/// Forge calls, without forge-std. Lets fixtures run on any solc 0.8.x and proves
/// the probe forwards getters regardless of who implements them.
interface MiniVm {
    function warp(uint256) external;
    function deal(address, uint256) external;
    function unixTime() external view returns (uint256);
}

abstract contract MiniInvariant {
    MiniVm internal constant vm = MiniVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    struct FuzzSelector { address addr; bytes4[] selectors; }
    address[] internal _targets;
    address[] internal _senders;
    address[] internal _excludedSenders;
    FuzzSelector[] internal _selectors;

    function targetContract(address a) internal { _targets.push(a); }
    function targetSender(address a) internal { _senders.push(a); }
    function excludeSender(address a) internal { _excludedSenders.push(a); }
    function targetSelector(FuzzSelector memory s) internal { _selectors.push(s); }

    function targetContracts() public view returns (address[] memory) { return _targets; }
    function targetSenders() public view returns (address[] memory) { return _senders; }
    function excludeSenders() public view returns (address[] memory) { return _excludedSenders; }
    function targetSelectors() public view returns (FuzzSelector[] memory) { return _selectors; }
}

contract MiniCounter {
    uint256 public count;
    function inc() external { count += 1; }
}

contract MiniNoop {
    uint256 public value = 7;
    event Noop();
    function noop() external { emit Noop(); }
}
