"""Exhaustive attack-hypothesis enumeration — the intelligence core.

Instead of one hypothesis, enumerate the FULL space for a target and hand it to the A/B
harness to test every one on the fork:
  1. single-contract vuln classes (from the mechanism model)
  2. MATHEMATICAL invariant violations (rounding, precision, decimals, first-depositor,
     donation, fee-on-transfer, overflow boundaries, zero-value edges)
  3. MULTI-STAGE / cross-contract (from the system value-flow map: manipulate A -> trigger B)
  4. COMBINATIONS (flashloan x {oracle, reentrancy, first-depositor, donation}, ...)

Each hypothesis is concrete + testable: {id, family, vuln_class, invariant, attack_stages,
needs_flashloan, priority}. The A/B harness synthesizes a PoC per hypothesis and proves it.
"""
from __future__ import annotations
import itertools

# --- economic invariants per archetype: what the protocol ASSUMES is always true ---
ARCHETYPE_INVARIANTS = {
    "amm": [
        ("constant_product", "x * y >= k across every state transition",
         ["donate tokens directly to the pair (no swap fee)", "call skim/sync to realize the imbalance",
          "swap against the mispriced reserves"]),
        ("lp_share_value", "LP shares redeem for their pro-rata reserves",
         ["mint LP in an empty/near-empty pool", "donate to inflate reserves per share",
          "later LPs' deposits round to fewer shares; redeem to capture their value"]),
    ],
    "vault": [
        ("first_depositor", "shares * pricePerShare == assets; first deposit can't be front-run",
         ["deposit 1 wei as first depositor -> 1 share", "donate assets directly to the vault",
          "victim deposits, rounds down to 0 shares", "redeem your 1 share for everything"]),
        ("rounding_direction", "deposit rounds shares DOWN, withdraw rounds assets DOWN (never in user favor)",
         ["find an amount where share<->asset conversion rounds in your favor", "loop deposit/withdraw to accrete the rounding dust"]),
        ("donation_pps", "pricePerShare can't be moved without a real deposit",
         ["donate assets directly (transfer, not deposit) to inflate totalAssets", "redeem shares against the inflated pps"]),
    ],
    "lending": [
        ("solvency", "collateralValue * price >= debt * mat at all times",
         ["open a position at the mat boundary", "nudge price/NHI feed to lower the required mat",
          "borrow beyond true solvency", "let it go bad-debt"]),
        ("liquidation_rounding", "liquidation seizes <= collateral and leaves the position healthy",
         ["trigger a self-liquidation where seize rounding over-credits the liquidator"]),
        ("interest_accrual", "accrued interest monotonic, no free borrow across a block",
         ["borrow and repay within one block to dodge accrual", "exploit accrual rounding to repay less"]),
    ],
    "stablecoin": [
        ("backing", "mintable supply <= reserve/backing value",
         ["inflate reserveValueUsd (donation/feed) within the mint call", "mint stable beyond true backing", "redeem/sell"]),
    ],
    "bridge": [
        ("message_auth", "only a validly-proven source message mints/releases",
         ["forge or replay a deposit proof / message", "release funds with no real lock"]),
    ],
}

# --- generic MATH hypotheses that apply to almost any value-handling contract ---
MATH_HYPOTHESES = [
    ("decimals_mismatch", "all token amounts are normalized to a common scale",
     ["use a token with non-18 decimals (6/8) where the code assumes 18",
      "the scale error mis-sizes a mint/price/share by 10^(18-d)"]),
    ("fee_on_transfer", "balanceOf(this) rises by exactly the amount sent",
     ["use a fee-on-transfer / rebasing token", "contract credits the pre-fee amount it never received",
      "withdraw the uncredited difference"]),
    ("precision_loss", "mulDiv order never drops value the user is owed",
     ["find a divide-before-multiply or truncating division path", "amplify the dropped remainder in a loop"]),
    ("zero_value_edge", "empty-state (totalSupply==0, empty pool) is handled safely",
     ["be the first actor so a denominator is 0 or 1", "exploit the uninitialized-state branch"]),
    ("overflow_boundary", "unchecked arithmetic stays within bounds",
     ["drive an unchecked block to its wrap boundary with a crafted amount"]),
]

FLASHLOAN_COMBINABLE = {"price_oracle_manip", "first_depositor", "donation_pps", "constant_product",
                        "backing", "solvency", "liquidation_rounding"}


def enumerate_hypotheses(mech: dict, system_flows: list | None = None, max_hyp: int = 40) -> list[dict]:
    H, seen = [], set()
    arche = set(mech.get("archetypes") or [])

    def add(family, vuln_class, invariant, stages, needs_fl, prio):
        key = (vuln_class, invariant)
        if key in seen:
            return
        seen.add(key)
        H.append({"id": f"h{len(H)+1}", "family": family, "vuln_class": vuln_class,
                  "invariant": invariant, "attack_stages": stages,
                  "needs_flashloan": needs_fl, "priority": round(prio, 2)})

    # 1) single-contract hypotheses the mechanism layer already found
    for h in mech.get("hypotheses", []):
        add("single", h["vuln_class"], h.get("evidence", ""), h.get("attack_path", []),
            h.get("vuln_class") in FLASHLOAN_COMBINABLE, h.get("confidence", 0.5))

    # 2) mathematical invariant violations keyed to archetype
    for a in arche:
        for inv, desc, stages in ARCHETYPE_INVARIANTS.get(a, []):
            add("math", inv, desc, stages, inv in FLASHLOAN_COMBINABLE, 0.55)

    # 3) generic math hypotheses (apply broadly)
    for inv, desc, stages in MATH_HYPOTHESES:
        add("math", inv, desc, stages, False, 0.4)

    # 4) multi-stage / cross-contract from the system value-flow map
    for f in (system_flows or []):
        g, producer, consumers = f.get("getter"), f.get("producer"), f.get("consumers", [])
        add("cross_contract", "price_oracle_manip",
            f"{producer}.{g}() feeds value in {consumers} — manipulate upstream, trigger downstream",
            [f"move {producer}.{g}() (donation / feed / balance)",
             f"trigger the value-consuming path in {consumers}",
             "extract the mispriced mint/redeem/liquidation"], True, 0.7)

    # 5) combinations: flashloan x each combinable single/math hypothesis
    base = [h for h in H if h["vuln_class"] in FLASHLOAN_COMBINABLE]
    for h in list(base):
        add("combo", h["vuln_class"], "flashloan-funded: " + h["invariant"],
            ["flashloan bootstrap capital"] + h["attack_stages"] + ["repay flashloan, keep profit"],
            True, h["priority"] + 0.1)

    H.sort(key=lambda x: x["priority"], reverse=True)
    return H[:max_hyp]
