// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import "forge-std/Test.sol";
import "../../src/Protocol.sol";

/// Same as V09 but the handler goes through the proxy. Must be live.
contract H07Handler {
    CounterImpl internal target;
    constructor(CounterImpl t) { target = t; }
    function inc() external { target.inc(); }
}

contract H07_ProxyCorrect is Test {
    CounterImpl internal impl;
    Proxy internal proxy;
    H07Handler internal h;
    function setUp() public {
        impl = new CounterImpl();
        proxy = new Proxy(address(impl));
        h = new H07Handler(CounterImpl(address(proxy)));
        targetContract(address(h));
    }
    function invariant_proxyCountBounded() public view {
        assertLe(CounterImpl(address(proxy)).get(), type(uint128).max);
    }
}
