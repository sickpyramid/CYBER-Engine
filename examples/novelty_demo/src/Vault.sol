// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal mock token for the isolated fuzz.
contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;
    function mint(address to, uint256 a) external { balanceOf[to] += a; totalSupply += a; }
    function approve(address s, uint256 a) external returns (bool) { allowance[msg.sender][s] = a; return true; }
    function transfer(address to, uint256 a) external returns (bool) { _move(msg.sender, to, a); return true; }
    function transferFrom(address f, address to, uint256 a) external returns (bool) {
        if (allowance[f][msg.sender] != type(uint256).max) allowance[f][msg.sender] -= a;
        _move(f, to, a); return true;
    }
    function _move(address f, address to, uint256 a) internal { balanceOf[f] -= a; balanceOf[to] += a; }
}

/// A share vault. Looks reasonable. Has a hidden flaw the author did not anticipate —
/// we do NOT tell the fuzzer what it is. The fuzzer must discover it from the invariant.
contract InflatableVault {
    MockERC20 public asset;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    constructor(MockERC20 a) { asset = a; }
    function totalAssets() public view returns (uint256) { return asset.balanceOf(address(this)); }

    function deposit(uint256 amt) external returns (uint256 s) {
        uint256 ta = totalAssets();
        s = totalShares == 0 ? amt : (amt * totalShares) / ta;   // rounds DOWN
        asset.transferFrom(msg.sender, address(this), amt);
        shares[msg.sender] += s;
        totalShares += s;
    }

    function withdraw(uint256 s) external returns (uint256 amt) {
        amt = (s * totalAssets()) / totalShares;
        shares[msg.sender] -= s;
        totalShares -= s;
        asset.transfer(msg.sender, amt);
    }
}
