// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// Seeded bug: the handler calls the implementation directly instead of the
/// proxy, so the proxy's storage (which the invariant reads) never changes.
contract V09Handler {
    CounterImpl internal target;
    constructor(CounterImpl t) { target = t; }
    function inc() external { target.inc(); }
}

contract V09_ProxyBypass is Test {
    CounterImpl internal impl;
    Proxy internal proxy;
    V09Handler internal h;
    function setUp() public {
        impl = new CounterImpl();
        proxy = new Proxy(address(impl));
        h = new V09Handler(impl); // bug: should be CounterImpl(address(proxy))
        targetContract(address(h));
    }
    function invariant_proxyCountBounded() public view {
        assertLe(CounterImpl(address(proxy)).get(), type(uint128).max);
    }
}
