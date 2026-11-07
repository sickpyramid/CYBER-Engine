"""Novelty engine — find UNKNOWN / hidden vulnerabilities via invariant fuzzing.

Pattern-matching the attack history only catches contracts whose authors didn't. A good
contract is immune to every known class. To find NEW bugs you don't look for known attacks
— you state what the contract ASSUMES is always true (its invariants) and let a fuzzer
search millions of call sequences for a state that BREAKS one. A broken invariant is a
novel vulnerability, discovered empirically, not from a library.

This builds a Foundry stateful-invariant harness for a target:
  - fork the chain, point a Handler at the deployed contract (fuzzes its mutators)
  - assert invariants the AGENT extracted from THIS contract's specific logic
  - `forge test` searches call-sequences; a failing invariant = a candidate novel bug

The agent's job (via SKILL): read the contract, write its SPECIFIC invariants + which
functions the Handler should fuzz. This module scaffolds the harness and gives candidate
invariants per archetype to start from.
"""
from __future__ import annotations

# Candidate invariants per archetype — starting points; the agent adds contract-specific ones.
CANDIDATE_INVARIANTS = {
    "vault": [
        "totalAssets() >= 0 && (totalSupply()==0 || convertToAssets(totalSupply()) <= totalAssets()+1)  // no value created from shares",
        "sum of user shares == totalSupply()  // no phantom shares",
        "pricePerShare never decreases except on a real loss  // monotonic pps",
    ],
    "lending": [
        "sum(collateralValue) * price >= sum(debt)  // protocol stays solvent",
        "no position can be left healthy==false after its own successful borrow",
        "totalDebt == sum(position.debt)  // debt accounting conserved",
    ],
    "amm": [
        "reserve0 * reserve1 >= kLast after any non-mint/burn op  // constant product holds",
        "no sequence returns more output tokens than a fair swap at the invariant price",
    ],
    "stablecoin": [
        "mintable/minted supply <= backing/reserve value  // fully backed",
        "redeem(x) returns <= x worth of reserve  // no redemption arbitrage",
    ],
    "token": [
        "sum(balanceOf(all holders)) == totalSupply()  // supply conservation",
        "no address can increase its balance without a transfer/mint it is entitled to",
    ],
}


def candidate_invariants(archetypes) -> list[str]:
    out = []
    for a in (archetypes or []):
        out += CANDIDATE_INVARIANTS.get(a, [])
    if not out:
        out = CANDIDATE_INVARIANTS["token"]
    return out


def scaffold(address: str, fork_alias: str, block: int | None,
             target_iface: str, handler_actions: str, invariants: str,
             contract_name: str = "Target") -> str:
    """Build a Foundry stateful-invariant test. The agent fills target_iface (the functions
    to call), handler_actions (bounded fuzz calls), and invariants (invariant_* assertions)."""
    fork = (f'vm.createSelectFork("{fork_alias}", {block});' if block
            else f'vm.createSelectFork("{fork_alias}");')
    return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";

// --- the deployed target's surface the handler will fuzz (AGENT: fill the functions) ---
interface I{contract_name} {{
{target_iface}
}}

/// Handler: the fuzzer calls these in random sequences with random args, exploring state.
contract Handler is Test {{
    I{contract_name} public target;
    constructor(I{contract_name} t) {{ target = t; }}
{handler_actions}
}}

/// Invariants: properties that must ALWAYS hold. A failing one is a candidate NOVEL bug.
contract InvariantTest is StdInvariant, Test {{
    I{contract_name} target;
    Handler handler;

    function setUp() public {{
        {fork}
        target = I{contract_name}({address});
        handler = new Handler(target);
        targetContract(address(handler));
    }}

{invariants}
}}
"""


EXAMPLE = '''# Example the agent fills in (ERC4626 vault share-inflation invariant):
target_iface = "    function totalAssets() external view returns (uint256);\\n    function totalSupply() external view returns (uint256);\\n    function deposit(uint256,address) external returns (uint256);"
handler_actions = """    function deposit(uint256 a) public {
        a = bound(a, 1, 1e24);
        deal(/* asset */ address(0), address(this), a);
        try target.deposit(a, address(this)) {} catch {}
    }"""
invariants = """    function invariant_noValueFromShares() public view {
        uint256 ts = target.totalSupply();
        if (ts == 0) return;
        // shares must never be redeemable for more than the assets backing them
        assertLe(ts, target.totalAssets() + 1, "shares exceed assets -> inflation bug");
    }"""
'''
