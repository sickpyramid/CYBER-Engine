// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";
import "../src/Vault.sol";

/// The fuzzer calls these in random sequences with random args. It is told NOTHING about
/// any attack — only these actions exist. It must discover a sequence that breaks the invariant.
contract Handler is Test {
    MockERC20 public asset;
    InflatableVault public vault;
    address constant VICTIM = address(0xBEEF);
    bool public victimDilutedToZero;   // ghost: set if an honest, non-trivial deposit yields 0 shares

    constructor(MockERC20 a, InflatableVault v) { asset = a; vault = v; }

    // attacker-controlled small deposit
    function attackerDeposit(uint256 amt) public {
        amt = bound(amt, 1, 1_000);
        asset.mint(address(this), amt);
        asset.approve(address(vault), type(uint256).max);
        vault.deposit(amt);
    }

    // direct transfer into the vault (NOT a deposit) — an ordinary, allowed action
    function donate(uint256 amt) public {
        amt = bound(amt, 1, 1e24);
        asset.mint(address(this), amt);
        asset.transfer(address(vault), amt);
    }

    // an honest user deposits a NON-TRIVIAL amount and should receive shares
    function victimDeposit(uint256 amt) public {
        amt = bound(amt, 1e6, 1e24);
        asset.mint(VICTIM, amt);
        vm.startPrank(VICTIM);
        asset.approve(address(vault), type(uint256).max);
        uint256 got = vault.deposit(amt);
        vm.stopPrank();
        if (got == 0) victimDilutedToZero = true;   // an honest depositor just lost everything
    }
}

contract InflationInvariant is StdInvariant, Test {
    MockERC20 asset;
    InflatableVault vault;
    Handler handler;

    function setUp() public {
        asset = new MockERC20();
        vault = new InflatableVault(asset);
        handler = new Handler(asset, vault);
        targetContract(address(handler));
    }

    /// The only property we assert: an honest, non-trivial depositor is never diluted to 0 shares.
    /// We do NOT describe the inflation attack anywhere. If the fuzzer finds a call sequence that
    /// breaks this, it discovered a NOVEL exploit path on its own.
    function invariant_honestDepositorNeverDilutedToZero() public view {
        assertFalse(handler.victimDilutedToZero(), "NOVEL BUG: honest depositor diluted to 0 shares");
    }
}
