# The Deep Reasoning Protocol — how to find bugs a bot cannot

> A bot greps one contract for known-bad patterns. Those bugs are already found.
> The money is in exploits where **every line is correct in isolation** and the drain
> comes from composing correct parts through another mechanism on the chain.
> This document is the discipline that finds those. It is meant to be *reasoned through*
> on every target, line by line — not pattern-matched.

The single mental shift: **stop asking "is this code correct?" Start asking "what must be
true for this to be safe, and what on-chain could make it false?"** Almost every real drain
is an **invariant** broken by composition, not a typo.

---

## 0. The core model: a protocol is a set of INVARIANTS defended by ASSUMPTIONS

Every protocol silently promises a few invariants. The exploit is always the violation of one.
Write them down first, explicitly, for the target:

- **Value conservation**: tokens out ≤ tokens in + yield earned. Nobody mints value from nothing.
- **Solvency / backing**: Σ(user claims) ≤ assets actually held, per asset.
- **Price sanity**: every price used for minting/borrowing/liquidation reflects a fair, non-
  manipulable market at the moment it is consumed.
- **Access**: only the intended actor moves funds or changes power; power changes are observable.
- **Accounting atomicity**: balances/debt/shares are written before the value they gate moves.
- **Uniqueness**: each nullifier/nonce/requestId/deposit is consumed exactly once.

Each invariant rests on **assumptions** ("this token is a plain ERC20", "this price is fair",
"this caller is honest", "this external contract won't re-enter", "this proof binds this value").
**An assumption with nothing enforcing it on-chain is the attack surface.** The whole hunt is:
list the assumptions, find the one the code trusts but does not enforce, and build the mechanism
that violates it.

---

## 1. Read EVERYTHING, and interrogate every token

Danial's rule: every line, every word, every connection. Concretely, for the target source:

- **Every external call** (`.call`, `.transfer`, `.swap`, `delegatecall`, a call to any address
  you don't control the code of) → ask the Call Questions (§2).
- **Every value read from outside the contract** (a price, a balance, a share rate, an oracle, a
  reserve, another contract's getter) → ask the Value Questions (§3).
- **Every privileged actor** (owner/admin/guard/keeper/relayer/upgrader) → ask the Power Questions (§4).
- **Every assumption in a comment or a variable name** ("fair", "trusted", "safe", "verified",
  "fee-on-transfer", "whitelisted") → find what enforces it on-chain. If nothing does, flag it.
- **Every arithmetic step** that converts between units (shares↔assets, token↔USD, 6↔18 dec) →
  ask where rounding goes and whether the inputs are attacker-influenced.

---

## 2. The CALL questions (for every external call the contract makes)

A function correct by itself becomes an exploit when it calls OUT to something an attacker shapes.

1. **Who is on the other end?** A fixed trusted address, or an address/param the caller chooses?
2. **Can the attacker make the callee run their code?** (a token they listed, a router path through
   their pair, a hook token (ERC777/ERC677), a user-supplied callback target). If yes → **reentrancy
   and return-value manipulation are live.**
3. **Is state written before or after this call?** Value moved before the debt/balance/supply update
   = classic reentrancy. (CEI.)
4. **Is the result trusted?** (`amountOut`, a returned price, a balance delta). Can the attacker move
   the number this call returns within the same tx? (balance-delta around attacker code; a swap
   through a pool they skewed with a flash loan).
5. **What re-entrancy guard scope covers this?** Guarded on *this* path but not on a sibling path that
   touches the same state = cross-function reentrancy.

## 3. The VALUE questions (for every price / balance / rate consumed)

Most lending/AMM drains are here.

1. **Where does this number originate?** An AMM spot (`getReserves`, `get_virtual_price`), a share
   rate (`totalAssets/totalSupply`, `pricePerShare`), a keeper push, a Chainlink feed, a fixed const?
2. **Can it move within ONE transaction?** If it's an AMM spot or a donatable share rate → **yes, with
   a flash loan.** That is the whole flash-loan+oracle class. TWAP/multi-source/deviation-bound closes it.
3. **Can it move across transactions cheaply?** A keeper-pushed price with a loose bound can be *walked*
   across windows (Poppie pattern). A thin-market asset can be pumped (Mango).
4. **What bounds it on-chain?** Deviation cap, staleness, min/max clamp, virtual shares. Is the bound
   **tighter than the asset's real volatility × the LTV it unlocks?** If not, it's a drain, just slower.
5. **Is value conservation enforced at a fair price?** Can a buy→sell / deposit→withdraw round-trip in
   one tx return more than it put in when pool state is moved? (Harvest.)

## 4. The POWER questions (for every privileged actor and setter)

1. **Resolve the gate to the real on-chain address.** Walk admin()/owner()/canUpgrade hop by hop to
   the terminal. (Use `compose`.)
2. **Classify it: EOA / multisig (threshold) / timelock (delay).** And read its **nonce** — a hot
   automated key (high nonce, server env var) is far more exposed than a cold wallet.
3. **What can each key touch?** Separate fund-critical powers (swap verifier, upgrade, set oracle,
   set price, sweep) from ops powers (pause, approve a real deposit). **A hot key on a fund-critical
   power = server breach drains. A hot key firewalled to ops = breach griefs only.**
4. **Is there a timelock on fund-critical changes?** No timelock = instant & silent, no exit window.
5. **Is one key reused across tiers?** (an ops key that is also a multisig signer).

## 5. The CROSS-PROTOCOL questions (the out-of-scope leap)

This is where humans still beat bots, and where to spend the most imagination. The target can be
correct and still be broken by **another contract's correct behavior**.

1. **What does the rest of the chain let an attacker borrow, flash, mint, or own for free in one tx?**
   (flash loans of any size, flash-mintable tokens, your own deployed token/pair, LP you can donate).
2. **Does the target read or route through anything an attacker can pre-position?** (an AMM pair, a
   4626 vault used as collateral, an oracle, a token with transfer hooks). Pre-position it, then act.
3. **Can the attacker *become* a dependency?** List their own token, register their own market,
   deploy the pair the path routes through, supply the callback target. (Penpie, SZK-2 self-pair.)
4. **Tx-ordering / MEV:** can the attacker sandwich the target's own action, back-run an oracle
   update, or JIT a position around it? Does the protocol rely on a private mempool to be safe?
5. **Composition of two "safe" steps:** step A (correct) changes state that step B (correct) depends
   on. Freeze-then-upgrade, donate-then-deposit, borrow-then-manipulate-then-liquidate.

---

## 6. The loop: hypothesize → A/B the whole space → PROVE on a fork

1. From §§2–5, enumerate **every** candidate hypothesis (the engine's `hypotheses` tier). Do not test
   one guess — test the space: single-contract, math, cross-contract, cross-protocol, multi-stage.
2. For each, state the **invariant it would violate** and the **cheapest experiment** to test it.
3. **Prove it on a mainnet fork** at a real block (`prover`). A hypothesis is a claim; a PoC that
   drains the real contract on a fork is the only proof. If you cannot write the PoC without
   fabricating state, say so — a fake finding is worse than none.
4. For NOVEL bugs (no known pattern), **fuzz the invariants** (`invariants` tier): assert value
   conservation / solvency / no-free-round-trip as a stateful Foundry invariant and let the fuzzer
   find the sequence. This is how you find bugs that are, by definition, not in any pattern list.

---

## 7. Honesty discipline (so the system is trusted, not just loud)

- A candidate from a heuristic is a **lead, not a finding.** Verify each by hand or PoC.
- Distinguish **code bug** (payable) from **trust/centralization risk** (usually informational) from
  **bounded MEV** (usually not payable). Say which, plainly.
- A 2-of-3 multisig admin is a real mitigation; "admin can rug" on a multisig is usually informational.
- Report what you proved, with the fork output. Never dress a trust assumption as a drain.

The engine already mechanizes parts of this: `compose` (§4 trust graph + §4 infra heat),
`heuristics` (the known classes from `audited_exploits.md`), `trust_delegation` (§0 unenforced
assumptions), `hypotheses` (§6 the space), `invariants` (§6 novel-bug fuzzing), `prover` (§6 proof).
This document is the glue that tells you how to *reason* with them — the part that is not grep.
