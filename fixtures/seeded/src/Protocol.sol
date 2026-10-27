// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// Small contracts used by the seeded fixtures. Deliberately simple: the point
/// is to exercise the test suites around them, not the contracts themselves.

contract Token {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract Vault {
    Token public immutable asset;
    address public owner;
    bool public paused;
    uint256 public cap = type(uint256).max;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    constructor(Token asset_) {
        asset = asset_;
        owner = msg.sender;
    }

    function deposit(uint256 amount) external {
        require(!paused, "paused");
        require(totalShares + amount <= cap, "cap");
        asset.transferFrom(msg.sender, address(this), amount);
        shares[msg.sender] += amount;
        totalShares += amount;
    }

    function withdraw(uint256 amount) external {
        shares[msg.sender] -= amount;
        totalShares -= amount;
        asset.transfer(msg.sender, amount);
    }

    function setPaused(bool p) external {
        require(msg.sender == owner, "owner");
        paused = p;
    }

    function setCap(uint256 c) external {
        require(msg.sender == owner, "owner");
        cap = c;
    }
}

contract EthVault {
    mapping(address => uint256) public deposits;

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        deposits[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send");
    }

    function totalAssets() external view returns (uint256) {
        return address(this).balance;
    }
}

contract Vesting {
    uint256 public immutable start;
    uint256 public immutable duration;
    uint256 public total;

    constructor(uint256 total_, uint256 duration_) {
        start = block.timestamp;
        duration = duration_;
        total = total_;
    }

    function vested() public view returns (uint256) {
        uint256 elapsed = block.timestamp - start;
        if (elapsed >= duration) return total;
        return total * elapsed / duration;
    }
}

contract Counter {
    uint256 public count;
    address public allowed;

    constructor(address allowed_) {
        allowed = allowed_;
    }

    function inc() external {
        count += 1;
    }

    function incIfAllowed() external {
        require(msg.sender == allowed, "not allowed");
        count += 1;
    }
}

contract CounterImpl {
    uint256 public count;

    function inc() external {
        count += 1;
    }

    function get() external view returns (uint256) {
        return count;
    }
}

contract Proxy {
    bytes32 internal constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    constructor(address impl) {
        assembly { sstore(IMPL_SLOT, impl) }
    }

    fallback() external payable {
        assembly {
            let impl := sload(IMPL_SLOT)
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok case 0 { revert(0, returndatasize()) } default { return(0, returndatasize()) }
        }
    }
}

library FeeMath {
    function fee(uint256 amount, uint256 bps) external pure returns (uint256) {
        return amount * bps / 10_000;
    }
}

/// Uses an immutable and an external library so code matching must mask both.
contract FeeVault {
    uint256 public immutable bps;
    bool public frozenFlag;
    uint256 public collected;

    constructor(uint256 bps_) {
        bps = bps_;
    }

    function charge(uint256 amount) external {
        collected += FeeMath.fee(amount, bps);
    }
}
