// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@proto/MiniInvariant.sol";

/// Excluded by no_match_path in foundry.toml: must not appear in the report.
contract SkippedSuite is MiniInvariant {
    MiniNoop internal n;
    function setUp() public { n = new MiniNoop(); targetContract(address(n)); }
    function invariant_skipped() public view { require(n.value() == 7, "z"); }
}
