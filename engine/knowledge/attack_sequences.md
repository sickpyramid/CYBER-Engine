# Attack Sequences: A Playbook of Reproducible DeFi Exploit Mechanisms

Purpose: feed an automated vulnerability engine the *exact, step-by-step attack sequences* behind
real smart-contract exploits — the reproducible mechanism (setup -> trigger -> extraction), not the
bug name. The engine's job is to reason about **multi-step, cross-mechanism** attacks: each function is
correct in isolation but composable into a drain. This file is biased toward that composition reasoning.

Conventions:
- `approx` = figure varies across post-mortems; the *mechanism* is load-bearing, not the number.
- `unconfirmed` = could not verify a specific claim from public sources; do not treat as fact.
- "Invariant a fuzzer should assert" = a property that MUST hold across any single transaction (or any
  sequence) and whose violation *is* the exploit. Write these as differential/post-state checks.
- Addresses/figures are illustrative where not quoted; sequences are generalized to the *class*.
- All source URLs below were returned by live web search during authoring. Where I could not confirm a
  specific primary post-mortem, the example is still attributed to secondary analyses and marked.

Glossary of recurring primitives the engine must model:
- **Flash loan**: atomically borrow up to pool liquidity, must repay + fee in the same tx. Gives any
  actor temporary capital = TVL of the largest lending/AMM pool. Removes the "attacker is poor" assumption.
- **Spot price**: `reserveB / reserveA` read live from an AMM at call time. Moveable within one tx.
- **`pricePerShare` / `get_virtual_price` / `totalAssets()/totalSupply()`**: a ratio oracle whose
  numerator can be inflated by a bare token transfer (donation) into the vault/pool.
- **Checks-Effects-Interactions (CEI)**: effects (state writes) must precede interactions (external
  calls). Violations enable reentrancy.
- **Read-only reentrancy**: a `view` function returns a *mid-transaction* (inconsistent) value while an
  external callback is on the stack; a third protocol reads it and acts on a lie.

---

## 1. Flash-loan + spot-oracle manipulation (lending drain)

**Mechanism in one line:** Borrow huge, shove an AMM's spot price, make a lending market read that spot
price as collateral value, borrow out more than you deposited, unwind.

**Sequence (setup -> trigger -> extraction):**
1. **Setup.** Attacker deploys an exploit contract. Identify a lending market `L` that prices collateral
   token `C` (or debt token) from a single DEX pool `P`'s spot reserves (`getReserves()` / `price0()` /
   a `slot0` read) with no TWAP and no cross-check.
2. **Capital.** Flash-loan a large amount of asset `X` from Aave/dYdX/Uniswap (`flashLoan` / `flashSwap`).
3. **Deposit at honest price.** Deposit a modest amount of `C` into `L` as collateral (state: `L` records
   collateral balance; health computed later against the manipulated price).
4. **Trigger — move the oracle.** Swap a large chunk of `X` into `P` to skew `reserveC/reserveX`
   (state: `P.reserves` now off-market; `P.spotPrice(C)` inflated). Because `L`'s oracle *is* `P.spot`,
   `C` is now valued far above market **inside this same tx**.
5. **Extraction — borrow against the lie.** Call `L.borrow(Y)` for the maximum the inflated collateral
   value permits, pulling out other assets `Y` (state: `L` believes position is healthy; it is not at
   true price). Alternatively mint/redeem a derivative priced off `P`.
6. **Unwind.** Swap back on `P` to recover most of `X` (reserves restored minus fees/slippage), repay the
   flash loan + fee. Keep the difference. Collateral `C` left behind is worth far less than `Y` extracted;
   the hole becomes protocol bad debt.

**Invariant violated:** "Collateral value used for a borrow decision must equal a manipulation-resistant
market value." The protocol assumed `P.spot` ≈ fair value; it is only fair *between* transactions.

**Preconditions to look for in source/on-chain:**
- Oracle = `IUniswapV2Pair.getReserves()` / `pair.price0CumulativeLast` read once (not TWAP) / Uniswap v3
  `slot0.sqrtPriceX96` (instantaneous) / a `getAmountOut` quote, used inside borrow/liquidation math.
- Single-source price, no Chainlink/median cross-check, no `require(abs(spot - twap) < band)`.
- The priced pool's 2% depth is small relative to `L`'s borrowable reserves (manipulation cost << payout).
- Any function path: `deposit -> (user-controlled swap) -> borrow` reachable in one tx.

**Invariant a fuzzer should assert:**
- For every tx: `collateralValue(account)` computed by the protocol must not differ from a
  TWAP/independent reference by more than X% (e.g. 1–2%); flag if a borrow succeeds while
  `|protocolPrice - referenceTWAP| / referenceTWAP > band`.
- Stronger: in a forked sim, `borrowUSD_out <= depositUSD_in` must hold at a *time-averaged* price after
  any single-tx sequence that includes a swap on the price source.

**Real example — bZx, 2nd attack, Feb 2020, approx $630k (approx 2,378 ETH):** attacker flash-loaned
7,500 ETH, used part to buy sUSD on Kyber/Uniswap to inflate its price >2x, and bZx's Fulcrum read that
inflated sUSD price, letting them borrow ~6,796 ETH against sUSD originally worth ~3,518 ETH.
- https://www.theblock.co/post/56207/bzx-attacked-again-645k-in-eth-estimated-to-be-lost
- https://quantstamp.com/blog/10-quick-and-dirty-facts-about-the-bzx-hacks
- https://cosimo.gitbook.io/ethereum-security/smart-contract-weaknesses/price-oracle-manipulation/bzx-second-hack

(See also Harvest Finance Oct 2020 in `audited_exploits.md` — same class via Curve Y-pool spot reserves.)

---

## 2. ERC4626 / vault first-depositor & donation share-inflation

**Mechanism in one line:** Be the first depositor into an empty vault/market, mint 1 wei of shares, then
*donate* underlying directly to the vault so 1 share = a huge amount; later depositors' deposits round
down to 0 shares and their value accrues to you (or you borrow against an inflated exchange rate).

**Sequence (setup -> trigger -> extraction):**
1. **Setup.** Find a vault/market `V` with `totalSupply == 0` (brand-new ERC4626 vault, or a freshly
   listed Compound-v2-fork cToken market with no reserves). Exchange rate when empty is a fixed
   `initialExchangeRate` or `totalAssets/totalSupply` with a rounding path.
2. **Mint dust.** Deposit the minimum (e.g. `mint(1)` → receive 1 share / 1 wei of cTokens).
   State: `totalSupply = 1`, `totalAssets = 1`.
3. **Trigger — donation.** Transfer a large amount `D` of the underlying *directly* to `V` via raw ERC20
   `transfer` (not `deposit`). State: `totalAssets = 1 + D`, `totalSupply = 1` → one share now worth
   `1 + D`. The exchange rate / `pricePerShare` is inflated by donation, bypassing share accounting.
4. **Extraction A (share theft via rounding).** A victim deposits `A < pricePerShare`. Shares minted =
   `A * totalSupply / totalAssets` rounds **down to 0**; their underlying is absorbed into `totalAssets`,
   accruing to the attacker's single share. Attacker redeems 1 share for `1 + D + A`.
5. **Extraction B (lending-fork variant — Sonne/Hundred style).** On a cToken fork, the inflated exchange
   rate makes `redeemUnderlying`/`borrow` math truncate: mint tiny collateral, donate to spike
   `exchangeRate`, borrow another asset against the inflated collateral valuation, then `redeem` to
   recover the donation and keep the borrowed asset. Repeat across markets.

**Invariant violated:** "Share price is a function only of accounted deposits." A bare token transfer that
is not routed through `deposit()` must not change the price per share, and `shares(depositor)` must never
round to zero for a non-trivial deposit.

**Preconditions to look for in source/on-chain:**
- `convertToShares` / `mint` uses `assets * totalSupply / totalAssets` with floor division and **no virtual
  shares / no decimals offset** (OpenZeppelin ERC4626 `_decimalsOffset` == 0) and no dead-shares mint.
- `totalAssets()` reads `asset.balanceOf(address(this))` (so a raw transfer inflates it) rather than an
  internal accounted `_totalAssets` counter.
- A market can be created and used while `totalSupply == 0` (no minimum-liquidity / no protocol seed).
- cToken fork: `exchangeRateStored = (cash + borrows - reserves) / totalSupply`, `cash` = `balanceOf(this)`.

**Invariant a fuzzer should assert:**
- `convertToShares(convertToAssets(s)) == s` for all `s` up to rounding of 1 wei, AND a deposit of any
  `assets > 0` must mint `shares > 0`.
- Donation independence: `price_per_share` after `asset.transfer(V, D)` (not via deposit) must be
  unchanged. Assert `pricePerShare_before == pricePerShare_after_raw_transfer`.
- No state where `totalSupply` is tiny (1) while `totalAssets` is large and attacker-controlled.

**Real example — Sonne Finance, May 14, 2024, approx $20M (Optimism):** a newly added, empty VELO cToken
market was attacked with the "known donation attack" on Compound-v2 forks — mint minimal collateral,
donate underlying to inflate the exchange rate, borrow against inflated collateral, redeem to recover the
donation. Rounding/truncation in `redeemUnderlying` enabled it. (Same class as Hundred Finance, Apr 2023.)
- https://medium.com/@SonneFinance/post-mortem-sonne-finance-exploit-12f3daa82b06
- https://www.certik.com/blog/sonne-finance-incident-analysis
- https://blog.verichains.io/p/compound-v2-forked-vulnerability

---

## 3. Read-only reentrancy (Curve/Balancer LP price mid-call)

**Mechanism in one line:** Enter a Curve/Balancer pool's `remove_liquidity`, which sends you ETH via a
callback *before* it finishes updating internal accounting; from inside that callback call a **third**
protocol whose oracle reads the pool's `get_virtual_price()` / LP price — it returns a corrupted
mid-transaction value — and borrow/mint against the lie.

**Sequence (setup -> trigger -> extraction):**
1. **Setup.** Protocol `T` prices an LP token (or derives collateral value) by reading the pool `P`'s
   `get_virtual_price()` or `balances()` directly. `P` is a Curve/Balancer pool whose
   `remove_liquidity` makes a native-ETH transfer (a `.call`/raw send → reentrancy point) **before**
   it finishes writing its state. `P` itself has a nonReentrant guard, but it is a *write* guard; `T`'s
   read path does not share that lock.
2. **Capital.** Flash-loan; add liquidity to `P` to obtain LP tokens. State: normal.
3. **Trigger — reenter mid-remove.** Call `P.remove_liquidity(...)`. During the ETH payout callback to the
   attacker contract, `P` has already paid out assets / adjusted part of its balances but `get_virtual_price()`
   is now computed over an **inconsistent** `(balances, total_supply)` pair — it is temporarily wrong.
4. **Extraction — read the lie.** From inside the callback (the `receive()`/fallback), call `T` (e.g.
   `T.borrow()`, `T.deposit()`, `T.liquidate()`). `T` reads `P.get_virtual_price()` = corrupted value,
   over- or under-values collateral, and lets the attacker borrow more than solvency allows or mint cheap.
5. **Unwind.** Callback returns, `remove_liquidity` finishes, state becomes consistent again; the damage
   in `T` is already booked. Repay flash loan, keep proceeds.

**Invariant violated:** "A `view` price is only valid when the pool it reads is in a consistent state."
The oracle read happened while the pool was mid-mutation; no lock protected the *read*.

**Preconditions to look for in source/on-chain:**
- `T` calls `ICurvePool.get_virtual_price()` / `pool.balances(i)` / Balancer `getPoolTokens` **without**
  invoking the pool's reentrancy-check helper (Curve: calling `remove_liquidity(0)` as a lock probe;
  Balancer: `VaultReentrancyLib.ensureNotInVaultContext`).
- The pool contains a native-ETH or ERC777/hook token leg (gives the callback).
- `T`'s oracle path is reachable from a `receive()`/token hook (i.e., can be called mid-callback).

**Invariant a fuzzer should assert:**
- Any external `view` oracle used for a value decision must return the *same* number whether called
  normally or while a `remove_liquidity`/token-callback frame is on the stack. Differential assert:
  `price_normal == price_during_reentrancy`.
- No state-changing action in `T` (borrow/mint/liquidate) may execute while a known pool's write-lock is
  held; simulate entering via the pool callback and assert `T` reverts or reads a guarded price.

**Real example — Conic Finance, Jul 21, 2023, approx $3.2M (1,724 ETH):** the newly deployed
`CurveLPOracleV2` read Curve pool data while the pool was mid-update; the attacker flash-loaned ~20,000
stETH and used read-only reentrancy on the ETH Omnipool to feed Conic incorrect values and make repeated
recursive `withdraw` calls. (Also: Sentiment, Apr 2023, approx $1M on Arbitrum — Balancer read-only
reentrancy on an LP collateral price; Sentiment's own fix adopted Balancer's reentrancy-guard guidance.)
- https://www.certik.com/blog/conic-finance-incident-analysis
- https://www.halborn.com/blog/post/explained-the-conic-finance-hack-july-2023
- https://blog.solidityscan.com/sentiment-hack-analysis-reentrancy-attack-8d1b2b6a1691
- https://hackmd.io/@sentimentxyz/SJCySo1z2 (Sentiment post-mortem)

---

## 4. Cross-function & cross-contract reentrancy

**Mechanism in one line:** An external call (token transfer, ETH send, ERC777/ERC721 hook) hands control
back to the attacker *before* the first function finished updating state; the attacker reenters a
**different** function (cross-function) or a **different contract that shares the stale state**
(cross-contract) and acts on balances that have not yet been decremented.

**Sequence (setup -> trigger -> extraction):**
1. **Setup.** Find function `f()` in contract `A` that performs an external call (`token.transfer`,
   `msg.sender.call`, or a callback-bearing token) **before** writing the effect (balance decrement /
   health update). Identify a sibling function `g()` (same contract) or contract `B` that reads the same
   state `A` is about to change. Classic cToken-fork: `borrow`/`redeem`/`exitMarket` update account
   liquidity after transferring out.
2. **Enter.** Call `A.f()` with the attacker contract as recipient. `A` sends tokens/ETH out (interaction)
   but has **not** yet decremented the attacker's collateral or marked the debt.
3. **Trigger — reenter in the stale window.** In the attacker's `receive()`/`tokensReceived`/`onERC721Received`,
   call `A.g()` or `B.h()`. Because `A`'s effect hasn't been written, `g`/`h` sees inflated collateral /
   un-decremented balance and permits a second borrow/withdraw against the same collateral.
4. **Extraction.** Repeat the reenter to borrow/withdraw multiple times against collateral that is only
   debited once, or `exitMarket` (dropping collateral accounting) and then borrow in the same frame.
5. **Return.** Outer call completes and writes its (now-too-late) single decrement. Net: assets out >>
   collateral in.

**Invariant violated:** CEI / single-use-of-collateral. "Every unit of collateral backs at most one
borrow; account health must be re-checked and state written before any value leaves the contract."

**Preconditions to look for in source/on-chain:**
- An external call (ETH `.call`, `safeTransfer` of a hook token, NFT safe-mint) that **precedes** the
  state write / `accountLiquidity` update in the same function. Grep for `.call{value:}` or token transfer
  lines above the balance/`checkpoint`/`exitMarket` updates.
- `nonReentrant` applied per-function but **not shared** across `f` and `g` (cross-function gap), or
  contract `B` reading `A`'s balances with no global lock (cross-contract gap).
- Support for ERC777/ERC1363/ERC721-safeTransfer collateral (built-in callbacks).

**Invariant a fuzzer should assert:**
- Reentrancy differential: for every externally-reachable state-mutating function, simulate a malicious
  recipient that reenters *every other* public function; assert global invariants still hold
  (`sum(debt) <= sum(collateralValue)`, `sum(user balances) == totalSupply`). Flag any reenter path that
  increases attacker net worth.
- "No value leaves before state settles": assert that at the point of any external transfer, the account's
  post-conditions (decremented balance, updated health) are already written.

**Real example — Rari Capital (Fuse) / Fei Protocol, Apr 30, 2022, approx $80M:** a reentrancy in the
Fuse (Compound-fork) `borrow` path violated checks-effects-interactions; the attacker re-entered via
`exitMarket()` (per PeckShield) using a flash loan and the cEther callback, borrowing against collateral
whose accounting had not yet been updated. A patch shipped Apr 1, 2022 was incomplete.
- https://www.certik.com/blog/revisiting-fei-protocol-incident
- https://www.theblock.co/post/144511/hackers-steal-80-million-from-rari-capitals-lending-pools

(Archetype: The DAO, 2016 — recursive `splitDAO`/withdraw before balance zeroing. Cross-contract variant:
dForce/Lendf.me, see Family 9.)

---

## 5. Price-per-share / rebasing / fee-on-transfer accounting mismatches

**Mechanism in one line:** The contract assumes `amount sent == amount received` (or that balances don't
change without its own calls); a fee-on-transfer/rebasing/deflationary token breaks that, letting the
attacker make the protocol's *stored* balance diverge from its *real* balance and then arbitrage the gap.

**Sequence (setup -> trigger -> extraction) — Balancer/STA fee-on-transfer archetype:**
1. **Setup.** Pool/vault `V` holds token `T` that charges a transfer fee (e.g. burns 1% on every
   `transfer`). `V` records `T` balances from the *amount argument*, or caches balances that drift from
   reality, and exposes a `gulp()`/`sync()` that resets the cached balance to the real `balanceOf`.
2. **Capital.** Flash-loan.
3. **Trigger — drain the real balance while the cache lags.** Repeatedly swap/join/exit `T` through `V`.
   Each transfer burns 1% of the real `T`, so `V`'s *actual* `T.balanceOf(V)` falls toward ~0 while other
   assets stay. (State: real `T` balance → near 0.)
4. **Resync the lie.** Call `V.gulp(T)` / `sync()` so `V` now books its stored `T` reserve = the real
   near-zero balance. Because the invariant `k = reserve_T * reserve_other` treats `T` as ultra-scarce,
   `T` is now priced astronomically high relative to the other tokens.
5. **Extraction.** Swap a tiny amount of `T` (which you still hold / minted cheaply) for the pool's other
   valuable tokens (WETH, LINK, SNX, WBTC) at the corrupted price. Repay flash loan; keep the other tokens.

**Rebasing/pricePerShare variants:**
- **Positive rebase donation:** inflate `pricePerShare` by raw-transferring underlying (see Families 1/2;
  Cream yUSD in `audited_exploits.md`).
- **Fee-on-transfer deposit accounting:** `deposit(amount)` credits `amount` shares but the vault only
  received `amount*(1-fee)`; attacker is over-credited; withdraw drains the shortfall from others.
- **Negative rebase / stETH:** code that stores a token *amount* rather than *shares* mis-accounts after a
  rebase; withdrawals compute against stale amounts.

**Invariant violated:** "Credited amount == actually received amount" and "stored reserves == real
balances at the moment they are used for pricing."

**Preconditions to look for in source/on-chain:**
- Accounting uses the `amount` parameter instead of measuring `balanceAfter - balanceBefore`.
- A `sync()`/`gulp()`/`skim()` that trusts `balanceOf(this)` combined with support for non-standard tokens.
- Token list/allowlist includes fee-on-transfer, rebasing, or low-decimal tokens; no `require(received ==
  amount)`.
- Share math denominated in token *amounts* rather than *shares* for a rebasing collateral.

**Invariant a fuzzer should assert:**
- On any deposit/transfer-in: assert `creditedAmount == token.balanceOf(V)_after - token.balanceOf(V)_before`.
- After any user-driven sequence, `pool.price(T)` must not be movable by causing `T.balanceOf(V)` to change
  without a corresponding accounted event. Assert invariant `k`/share-price stability under adversarial
  transfer-fee tokens (fuzz with a mock FoT/rebasing token).

**Real example — Balancer / STA (Statera), Jun 28–29, 2020, approx $450k–$500k:** STA charged a 1%
transfer fee; the pool didn't account for it. The attacker flash-loaned, repeatedly swapped STA through
the pool to burn the real STA balance toward zero, called `gulp()` to update stored reserves to the real
near-zero value — spiking STA's implied price — then swapped STA for WETH/WBTC/SNX/LINK.
- https://www.theblock.co/news/defi/2020-06-29-balancer-pools-drained-of-more-than-450000-due-to-an-exploit-connected-to-deflationary-tokens-69785
- https://slowmist.medium.com/detailed-analysis-of-balancer-hack-de8bd86020de

---

## 6. Governance flash-loan capture

**Mechanism in one line:** Governance weight = token balance / LP stake measured at call time; flash-loan
enough of the token in one tx to reach quorum, submit+pass+execute a malicious proposal that transfers
protocol funds to yourself, all atomically — then repay.

**Sequence (setup -> trigger -> extraction):**
1. **Setup.** Governance `G` computes voting power from a *current* balance or a stake that can be acquired
   and voted in the same block, and offers an **emergency/instant-execution** path (or the proposal
   timelock can be satisfied with a pre-seeded proposal). Identify the drainable treasury/minter.
2. **Pre-seed (if needed).** In an earlier block, submit an innocuous-looking proposal, or deposit a
   seed stake, to satisfy any "proposal must exist / proposer must hold X" precheck. (Beanstalk: attacker
   pre-submitted BIP-18/BIP-19.)
3. **Capital.** Flash-loan the governance token (or the assets to mint LP/stake that counts as votes).
4. **Trigger — acquire quorum atomically.** Convert the flash-loaned capital into voting weight
   (deposit/stake/mint governance LP). State: attacker now controls > quorum of `Stalk`/votes **this
   block**, with no snapshot/flash-loan guard.
5. **Extraction — vote + execute malicious proposal.** Call the emergency-commit/execute function; the
   malicious proposal (a `delegatecall` to attacker code, or a transfer of the treasury/`init` call)
   executes, sending protocol funds to the attacker.
6. **Unwind.** Redeem the stake back to tokens, repay the flash loan + fee, keep the drained treasury.

**Invariant violated:** "Voting power must reflect durable, at-risk ownership." Measuring votes at
execution time (not a past snapshot) lets borrowed capital decide governance.

**Preconditions to look for in source/on-chain:**
- Voting power read from `balanceOf` / `getVotes()` at `propose`/`execute` time, **not** a past-block
  snapshot (`getPastVotes(blockNumber)` / ERC20Votes checkpoints) or a staking lock with a cooldown.
- An emergency/fast-track execution with reduced or zero timelock, or a timelock short enough to combine
  with pre-seeding.
- Proposals can contain arbitrary calldata (`delegatecall`, token transfers, minter grants) — i.e.
  governance can move funds directly.
- No "flash-loan-resistant" check (no requirement that voting stake was held before the proposal's
  snapshot block).

**Invariant a fuzzer should assert:**
- Voting weight for a proposal must be sourced from a block strictly *before* the proposal was created;
  assert `votingPower(voter, proposal) == getPastVotes(voter, proposal.snapshotBlock)` and that
  `snapshotBlock < proposal.creationBlock`.
- No single transaction may both acquire >quorum voting power and execute a fund-moving proposal. Simulate
  flash-loan → stake → vote → execute in one tx and assert it reverts or has zero effect.

**Real example — Beanstalk, Apr 17, 2022, approx $182M (attacker kept approx $76–80M):** attacker used an
Aave flash loan to acquire a supermajority of `Stalk` voting power in one transaction and pass a malicious
BIP via the emergency governance path; Beanstalk had no flash-loan-resistant measure to determine the % of
Stalk voting in favor, so the proposal (which transferred protocol assets) executed.
- https://rekt.news/beanstalk-rekt
- https://www.certik.com/skynet-report/revisiting-beanstalk-farms-exploit

---

## 7. Keeper / off-chain oracle / price-pusher manipulation or key compromise

**Mechanism in one line:** The protocol trusts an off-chain actor to push the truth on-chain — a Chainlink
node, a bespoke price pusher, a keeper bot, or a privileged signer. Break the *source* (feed glitch, stale
price, mempool front-run of the update) or the *key* (compromise the signer), and the protocol faithfully
executes on a false truth.

**Sub-mechanism A — stale / glitched push-oracle + front-run (Synthetix sKRW archetype):**
1. **Setup.** An on-chain price `p` is updated periodically by an off-chain pusher; trades settle at the
   last-pushed `p` until the next update. The feed aggregates a small set of sources.
2. **Trigger — bad source or lag.** One source glitches (sKRW reported ~1000x high) and the aggregator
   fails to reject the outlier, OR the next correct update sits in the mempool.
3. **Extraction.** An arbitrage/bot trades at the wrong on-chain `p` before it corrects (mint sKRW, convert
   to sETH), or front-runs the pending update (buy before an up-tick lands in the same block).
4. **Result.** Massive synthetic/collateral mis-mint; protocol left insolvent until reversed.

**Sub-mechanism B — signer/validator key compromise (Ronin archetype):**
1. **Setup.** A bridge/oracle requires `m`-of-`n` signatures to authorize withdrawals/price updates.
2. **Trigger — compromise.** Attacker obtains `m` keys (phishing, infra breach, a "gas-free RPC" backdoor
   that signs on behalf of a validator).
3. **Extraction.** Forge `m` valid signatures over withdrawal messages; call the bridge's `withdraw`/
   `submitSignatures` to drain the locked assets to attacker addresses.
4. **Detection lag.** With no on-chain monitoring, the drain goes unnoticed for days.

**Invariant violated:** "The trusted off-chain input is correct, fresh, and authorized." Protocols rarely
bound *how wrong* or *how stale* the input can be, nor the blast radius of one compromised signer.

**Preconditions to look for in source/on-chain:**
- Price used with no `require(block.timestamp - updatedAt < maxAge)` (staleness) and no `require(price >
  minAnswer && price < maxAnswer)` (bounds) — Chainlink `latestRoundData` consumed naively.
- Settlement at the last-pushed price with no per-block/per-update deviation cap (front-runnable).
- Multisig/threshold where `m` is small, keys are operationally concentrated (same org/infra), or a node
  can sign without independent validation.
- No circuit breaker / no divergence check against a second independent feed.

**Invariant a fuzzer should assert:**
- Staleness + bounds: assert every consumed price satisfies `updatedAt` freshness and sits within a sane
  band vs a reference; a trade/liquidation must revert otherwise.
- Deviation cap: assert `|newPrice - lastPrice| / lastPrice <= maxJump`; flag settlement that profits from
  a single-update jump (front-run surface).
- Authorization blast radius (static/property, not pure fuzz): assert no single key/role can authorize a
  withdrawal exceeding a bounded limit without a second independent factor/timelock.

**Real examples:**
- **Synthetix sKRW, Jun 2019:** a commercial FX API intermittently reported KRW ~1000x too high and the
  oracle averaged the skewed remaining feeds; an arbitrage bot converted into sKRW then sETH, inflating
  balances massively (profits later reversed for a bounty). Synthetix separately documented a bot
  front-running oracle price updates from the mempool.
  - https://blog.synthetix.io/response-to-oracle-incident/
  - https://blog.synthetix.io/frontrunning-synthetix-a-history/
- **Ronin bridge, Mar 23, 2022, approx $625M:** attacker controlled 5 of 9 validator signatures (4 Sky
  Mavis validators + the Axie DAO validator reached via a gas-free RPC backdoor) and forged two
  withdrawals draining 173,600 ETH + 25.5M USDC; undetected for ~6 days.
  - https://halborn.com/explained-the-ronin-hack-march-2022/
  - https://securityaffairs.com/129609/cyber-crime/625m-axie-infinity-ronin-hack.html

---

## 8. Liquidation / bad-debt / self-liquidation logic abuse

**Mechanism in one line:** Push *your own* position into an insolvent-looking state (via oracle move or a
balance-reducing action with no health check), then exploit the liquidation *reward* math — the liquidation
discount / close-factor pays the liquidator (you) more than the position is actually worth, so
self-liquidating extracts protocol value.

**Sequence (setup -> trigger -> extraction) — self-liquidation via unchecked balance reduction (Euler
`donateToReserves` archetype):**
1. **Setup.** Protocol `L` has (a) a dynamic liquidation discount that grows with how underwater a position
   is, and (b) a state-mutating function that *reduces a user's equity/collateral without a post-call
   solvency check* (`donateToReserves`, a mis-ordered transfer, or an oracle the user can move).
2. **Leverage up.** Flash-loan; mint large leveraged collateral+debt via repeated borrow/mint (e.g. eDAI
   collateral and dDAI debt), building a big balanced position.
3. **Trigger — become insolvent on purpose.** Call the unchecked function (`donateToReserves(largeAmount)`)
   to burn your own collateral token, leaving large debt — **no health check runs**, so the protocol lets
   you create a deeply underwater account on demand. (Alternatively: move the collateral oracle down.)
4. **Extraction — liquidate yourself.** With a second controlled account, call `L.liquidate(badAccount)`.
   Because the position is deeply underwater, the dynamic discount is huge: the liquidator seizes the full
   collateral (eDAI) balance while assuming only a *fraction* of the debt (dDAI). Net equity flows to the
   liquidator account.
5. **Unwind.** Withdraw the seized collateral, repay flash loan, keep the gap. Protocol eats the residual
   bad debt.

**Thin-collateral self-borrow variant (Mango archetype):** open a large perp long on a thin token on
account A, pump the token's spot (the oracle), your unrealized PnL counts as collateral, borrow out all
other assets on account A against the inflated collateral, walk away leaving bad debt (see Family 1 for the
oracle move; the *extraction* is the borrow-against-inflated-equity, not a repayment).

**Invariant violated:** "A liquidation must never pay the liquidator more than the collateral it consumes,
and no user action may reduce account health without an immediate solvency re-check." The discount should
be bounded so self-liquidation is never net-positive.

**Preconditions to look for in source/on-chain:**
- Any balance/equity-reducing function (`donate`, `transfer`, `redeem`, `exitMarket`) that does **not**
  call the module's standard `checkLiquidity(account)` before returning, while other such functions do.
- Liquidation discount that scales with insolvency depth with no cap, or close-factor that lets a liquidator
  take collateral disproportionate to debt repaid.
- Attacker can be both the insolvent account and the liquidator (no same-actor restriction), and can reach
  deep insolvency in one tx.
- Collateral value derived from a price the position holder can move (links to Families 1, 5).

**Invariant a fuzzer should assert:**
- Health monotonicity: after *any* user-callable function returns, `isHealthy(account)` must hold for every
  account whose state it touched (or the function reverts). Flag any path that leaves `account` unhealthy
  without reverting.
- Liquidation non-profitability for the borrower: assert `collateralSeizedValue <= debtRepaidValue *
  (1 + maxDiscount)` and that a borrower's net worth cannot increase by self-liquidating (simulate
  A creates bad position, B liquidates, assert `netWorth(A)+netWorth(B)` is non-increasing minus fees).

**Real examples:**
- **Euler Finance, Mar 13, 2023, approx $187–200M:** `donateToReserves()` had no debt/liquidity check, so a
  user could donate a large eToken balance and leave large debt; the dynamic liquidation discount made
  self-liquidation profitable (liquidator takes full eDAI, part of dDAI).
  - https://www.zellic.io/blog/euler-finance-exploit-analysis
  - https://medium.com/@omniscia.io/euler-finance-incident-post-mortem-1ce077c28454
- **Mango Markets, Oct 11, 2022, approx $110–116M (Solana):** inflated MNGO-PERP unrealized PnL counted as
  collateral after pumping thin MNGO spot; attacker borrowed ~$144M of other assets against it, leaving the
  protocol insolvent (the oracle "worked as designed"; the fault was thin-liquidity collateral).
  - https://cointelegraph.com/news/how-low-liquidity-led-to-mango-markets-losing-over-116-million
  - https://ackee.xyz/blog/2022-solana-hacks-explained-mango-markets/

---

## 9. Cross-protocol composition (use protocol A's correct behavior to break protocol B)

**Mechanism in one line:** Nobody's code is "buggy" in isolation — the attacker chains protocol A's
*legitimate* feature (a transfer hook, a flash-swap callback, a 4626 vault used as collateral, a router
callback) into a reentrancy/mispricing in protocol B. The composition is the bug.

**Canonical compositions the engine must enumerate:**

**(a) Transfer-hook token (ERC777/ERC1363/ERC721-safeTransfer) + a lending market without CEI
(dForce/Lendf.me archetype):**
1. **Setup.** Lending market `B` (a Compound-v1-style fork) lists a hook token `A` (imBTC = ERC777) as
   collateral and lacks a reentrancy guard / violates CEI in `supply`/`withdraw`.
2. **Enter.** `supply(A, amount)`; `B` calls `A.transferFrom`, which triggers A's `tokensReceived`/
   `tokensToSend` hook back into the attacker **before** `B` finishes updating the attacker's balance.
3. **Reenter.** In the hook, call `B.withdraw(A)` (or supply again) against the not-yet-updated balance,
   double-counting collateral.
4. **Extraction.** Repeat to withdraw more than deposited; drain `B`.

**(b) ERC4626 vault share used as collateral in a lending market (Cream yUSD archetype):**
- Protocol A = a yield vault whose `pricePerShare` can be donation-inflated. Protocol B prices A's share as
  collateral. Attacker inflates A's share price (raw transfer into the vault), borrows against the inflated
  collateral in B (see Families 2/5 and `audited_exploits.md` §4).

**(c) Flash-swap / router callback as the reentrancy/capital source:**
- Uniswap/Balancer flash-swap hands tokens then calls `uniswapV2Call`/`receiveFlashLoan` on the attacker
  *before* requiring repayment. Inside that callback the attacker performs the privileged action on B
  (deposit/borrow/vote/settle) while B assumes the caller is solvent or the market is quiet.

**(d) A 4626 vault / LP whose `convertToAssets` reads a manipulable pool, used by B for valuation** — same
as Family 3 but the composition is "B trusts A's view function."

**Invariant violated:** "External primitives behave within the assumptions I made about them." B assumed A
transfers atomically / prices honestly / never calls back; A's legitimate feature breaks that assumption.

**Preconditions to look for in source/on-chain:**
- B integrates any token/vault/pool with a callback or a manipulable `view` and performs a state decision
  (mint/borrow/liquidate/settle) that trusts A's instantaneous behavior.
- Allowlist admits ERC777/hook tokens, fee-on-transfer tokens, rebasing tokens, or vault shares.
- B's privileged entrypoints are reachable from within A's callback (no global reentrancy lock spanning the
  cross-protocol call).

**Invariant a fuzzer should assert:**
- Model every integrated external contract as **adversarial**: a mock token with a reentrant hook, a mock
  vault with a donation-inflatable price, a mock pool returning adversarial `view` values. Assert B's global
  invariants (`solvency`, `sum(shares)==totalSupply`, `collateral>=debt`) hold under all of them.
- Cross-protocol reentrancy: simulate B being re-entered from A's callback on every integration point;
  assert no net value extraction.

**Real example — dForce / Lendf.me, Apr 19, 2020, approx $25M:** Lendf.me (a modified Compound v1 with no
reentrancy guard, violating CEI) listed imBTC (ERC777). The ERC777 `tokensToSend`/`tokensReceived` callback
let the attacker reenter `supply`/`withdraw` and repeatedly inflate collateral before balances updated,
draining ~99.95% of funds. The same imBTC hook was used against a Uniswap v1 pool the same day.
- https://quantstamp.com/blog/how-the-dforce-hacker-used-reentrancy-to-steal-25-million
- https://medium.com/dforcenet/a-summary-of-the-attack-on-lendf-me-on-april-19-2020-e2f1c5d96640

---

## 10. Proxy / upgrade / init front-running & uninitialized-implementation

**Mechanism in one line:** Upgradeable contracts separate logic (implementation) from storage (proxy).
If an implementation is left *uninitialized*, or an `initialize()` can be called by anyone (front-run), an
attacker seizes owner/admin and either drains via the proxy or `selfdestruct`s the implementation (UUPS) to
brick the system.

**Sequence (setup -> trigger -> extraction):**

**(a) Front-run initialization (deploy-then-initialize gap):**
1. **Setup.** A proxy/clone is deployed in tx1 and `initialize(owner=...)` is intended in tx2 (or a factory
   deploys then initializes in separate calls). `initialize` has no access control, only an `initializer`
   guard that is currently unset.
2. **Trigger.** Attacker watches the mempool, calls `initialize(owner=attacker)` before the legit tx lands
   (or on a freshly-deployed-but-uninitialized clone).
3. **Extraction.** Now `owner`/`admin`, the attacker calls privileged functions (upgrade, mint, withdraw,
   set fee recipient) and drains.

**(b) Uninitialized UUPS implementation → self-destruct (Wormhole archetype):**
1. **Setup.** A UUPS implementation contract (upgrade logic lives in the implementation) is left
   uninitialized — e.g. a bugfix reverted the original init call. Its `initialize()` is callable directly on
   the *implementation* (not just via the proxy).
2. **Trigger.** Attacker calls `implementation.initialize(...)` setting themselves as the authorized party
   (e.g. their own guardian/signer set).
3. **Extraction.** Attacker calls `upgradeToAndCall()` on the implementation pointing at a malicious contract
   with a `selfdestruct`; the `DELEGATECALL` runs `selfdestruct` in the implementation's context, destroying
   the logic contract and bricking every proxy that delegates to it (or, if storage-aligned, draining).

**(c) Storage-collision / unprotected upgrade:** an admin-only `upgradeTo` reachable by a non-admin, or a new
implementation whose storage layout collides, letting a crafted upgrade reassign `owner`/balances.

**Invariant violated:** "Only the intended deployer governs initialization, and the implementation is inert
on its own." Initialization is a privileged action; leaving it open or on the raw implementation is a
backdoor.

**Preconditions to look for in source/on-chain:**
- `initialize()`/`__Init` with no `onlyFactory`/`onlyDeployer` and a deploy→initialize gap (separate txs),
  especially behind minimal-proxy clones.
- UUPS implementation deployed without `_disableInitializers()` in its constructor (OZ ≥4.3.2 remedy); the
  implementation's `initialize`/`upgradeToAndCall` callable directly.
- `upgradeTo`/`upgradeToAndCall` access control missing or misconfigured; `_authorizeUpgrade` empty.
- OZ `Initializable` version < 4.4.2 patterns / reinitializer misuse.

**Invariant a fuzzer should assert:**
- `initialize` is callable at most once and only by the intended deployer; assert a second call and a
  call-from-stranger both revert, and that the raw implementation cannot be initialized (constructor ran
  `_disableInitializers`).
- No non-admin path reaches `upgradeTo`/`selfdestruct`/`delegatecall`-to-arbitrary; assert the
  implementation cannot be destructed and the proxy admin is immutable to non-admins.

**Real example — Wormhole uninitialized proxy (whitehat, ~Feb 2022, $10M Immunefi bounty):** the core bridge
UUPS implementation was left uninitialized after a bugfix reverted the original init; a whitehat (satya0x)
showed an attacker could `initialize()` the implementation (set their own guardian set), then
`upgradeToAndCall()`/`submitContractUpgrade()` to `DELEGATECALL` a self-destructing contract, destroying the
implementation. Fixed same day.
- https://immunefi.com/blog/bug-fix-reviews/wormhole-uninitialized-proxy-bugfix-review/
- https://portswigger.net/daily-swig/blockchain-bridge-wormhole-pays-record-10m-bug-bounty-reward

(Archetype for self-destruct-via-uninitialized-library: Parity multisig wallet, Nov 2017 — a user called
`initWallet` on the shared library, became owner, and `kill`ed it, freezing ~513k ETH. Primary post-mortem
URL not re-verified here; mark `unconfirmed` if citing a specific link.)

---

## 11. Signature / permit / replay / domain-separator abuse

**Mechanism in one line:** Signed messages (EIP-2612 permit, EIP-712 orders, meta-txs, bridge
attestations) are trusted on-chain; weaknesses — missing nonce, missing `chainId`/domain separator,
unchecked return of `permit`, malleable signatures, or a router that trusts a `from` it doesn't verify —
let an attacker replay, forge, or misroute an approval and move someone else's tokens.

**Sub-mechanism A — `permit` on a non-permit token / fallthrough (Multichain/Anyswap archetype):**
1. **Setup.** A router `R` exposes `swapOutUnderlyingWithPermit(from, token, amount, v,r,s)` that calls
   `IERC20Permit(token).permit(from, R, amount, ...)` then `safeTransferFrom(from, R, amount)`. For a token
   like WETH that **does not implement `permit`**, the call hits WETH's `fallback`/`deposit` and **does not
   revert** — so the missing permit silently "succeeds."
2. **Trigger.** Attacker calls `R.swapOutUnderlyingWithPermit(victim, WETH, victimApproval, junkSig)`.
   `permit` no-ops harmlessly; `R` then executes `safeTransferFrom(victim, R, amount)` — which works because
   the **victim had previously approved `R`** (standard for router UX).
3. **Extraction.** `R` forwards the pulled tokens per attacker-controlled args; any user with a live approval
   to `R` for an affected token is drained. (Fix: V6 contracts removed the need to approve; users told to
   revoke.)

**Sub-mechanism B — replay / missing domain binding:**
1. **Setup.** A signed order/attestation omits a `nonce`, or binds no `chainId`/verifyingContract in its
   EIP-712 domain separator.
2. **Trigger.** Attacker replays the same signature on the same contract again (no nonce), on a *forked
   chain* (no `chainId`), or on another deployment (no `verifyingContract`).
3. **Extraction.** The action (transfer, mint, withdrawal) executes multiple times / cross-chain from one
   signature.

**Sub-mechanism C — malleability / `ecrecover(0)`:** unchecked `ecrecover` returning `address(0)` for a
malformed sig, or accepting both `s` and `curveOrder - s`, lets forged/duplicate sigs pass.

**Invariant violated:** "A signature authorizes exactly one action, on exactly this contract/chain, by
exactly this signer." Replay/forgery/misrouting breaks the one-to-one binding.

**Preconditions to look for in source/on-chain:**
- A call to `token.permit(...)` whose success is **not verified** against the resulting allowance, and the
  router also holds pre-existing user approvals (the dangerous combination).
- EIP-712 domain separator missing `chainId` or `verifyingContract`, or computed once in a constructor and
  never re-derived after a fork.
- No per-signer `nonce` mapping, or nonce not incremented atomically; signatures accepted without
  `usedHash[hash]` tracking.
- `ecrecover` used without `require(signer != address(0))` and without EIP-2 low-`s` enforcement (use
  OZ ECDSA).

**Invariant a fuzzer should assert:**
- Replay resistance: the same signed payload submitted twice must fail the second time (nonce/hash consumed);
  the same payload on a different `chainId`/contract must fail.
- Permit effectiveness: after a `permit`-consuming call, assert `allowance(owner, spender)` actually
  reflects the signed value (catches the silent no-op on non-permit tokens); the transfer must not rely on a
  pre-existing approval that the signature did not authorize.
- `recoveredSigner == expectedOwner && recoveredSigner != address(0)` on every signature path.

**Real example — Multichain / Anyswap router, Jan 18, 2022, approx $1.3–3M:** the router's
`anySwapOutUnderlyingWithPermit` called `permit` on tokens that didn't implement it (e.g. WETH), where the
call fell through without reverting; combined with users' existing router approvals, attackers could pull
approved tokens from any affected user. Multichain's "revoke your approvals" alert ironically advertised the
bug, and attackers drained remaining approvals ~16 hours later.
- https://medium.com/multichainorg/multichain-contract-vulnerability-post-mortem-d37bfab237c8
- https://www.theblock.co/post/130561/cross-chain-protocol-multichain-bug-gets-exploited-for-1-34-million
- https://revoke.cash/exploits/multichain?chainId=1

---

## 12. MEV: sandwich, JIT liquidity, back-running an oracle update

**Mechanism in one line:** The attacker controls transaction *ordering* (as a searcher via the public
mempool/private relays, or as a block proposer/validator) and extracts value by placing trades immediately
before and/or after a victim transaction or a state-changing update.

**Sub-mechanism A — Sandwich:**
1. **Observe.** See a victim swap `V` (buy of token `T` on an AMM) in the mempool with a loose slippage
   tolerance.
2. **Front-run.** Submit a buy of `T` with higher priority (gas/bribe) that lands *before* `V`, pushing `T`'s
   price up. State: pool price of `T` raised.
3. **Victim executes.** `V` fills at the worsened price (up to its slippage limit).
4. **Back-run.** Submit a sell of `T` immediately *after* `V`, realizing the price impact `V` caused. Profit
   = victim's slippage minus fees/gas.
- **Invariant violated:** the victim's realized price should be close to the quote; loose `amountOutMin` lets
  ordering extract the gap.

**Sub-mechanism B — JIT (just-in-time) liquidity (Uniswap v3):**
1. **Observe.** A large swap `V` is pending in a concentrated-liquidity pool.
2. **Front-run (mint).** Mint a very tight liquidity position spanning exactly the swap's price range right
   before `V`.
3. **Capture fees.** `V` executes against your freshly-added liquidity; you earn the bulk of `V`'s swap fee.
4. **Back-run (burn).** Remove the liquidity immediately after, having borne ~zero price risk — crowding out
   passive LPs who provided durable liquidity.
- **Invariant violated:** fee rewards are meant to compensate liquidity at *risk over time*; single-block
  JIT captures fees with no duration risk. (A legitimate-but-extractive MEV strategy, not a contract bug.)

**Sub-mechanism C — Back-running an oracle / state update:**
1. **Observe.** A pending oracle push / rebase / large liquidation / parameter change that will move
   on-chain price or balances.
2. **Back-run.** Place a trade/liquidation in the *same block immediately after* the update to capture the
   now-known price move (buy before a confirmed up-tick propagates to a dependent pool; liquidate the instant
   a price makes a position unhealthy).
- **Invariant violated:** atomic knowledge of an update lets the proposer/searcher trade on information no
  other actor could act on first.

**Proposer-level escalation:** a validator/proposer can *reorder or insert* transactions arbitrarily within
its block (or via a relay bug), turning searcher strategies into guaranteed extraction and even
back-running/unbundling other searchers' bundles.

**Preconditions to look for in source/on-chain:**
- User-facing swaps/zaps with default or user-set `amountOutMin = 0` / `deadline = type(uint).max` (no
  slippage/deadline protection).
- Protocol actions whose profitability depends on *ordering* within a block (liquidations, oracle-dependent
  mints, auctions with no commit-reveal or batch settlement).
- Concentrated-liquidity pools where fee accrual has no minimum-duration / no JIT penalty.
- Any "same-block" dependency between an update and a profitable follow-on action with no TWAP/delay.

**Invariant a fuzzer / simulator should assert:**
- Slippage bound: assert every user swap enforces a non-trivial `amountOutMin` and a `deadline`; flag
  reachable paths that pass `0`.
- Ordering-independence of protocol safety: core invariants (solvency, fair settlement) must hold under
  *adversarial transaction ordering within a block* — simulate front/back-run insertions and assert no
  protocol-level invariant breaks (user MEV loss is a design issue; a *protocol* break is a bug).
- Commit-reveal / batch / TWAP presence for any value that an attacker could act on in the same block it
  changes.

**Real example — rogue validator front-runs MEV sandwich bots, Apr 3, 2023, approx $25M:** within Ethereum
block 16964664, a malicious validator (who had staked 32 ETH 18 days earlier) exploited an
MEV-boost-relay bug to re-bundle/reorder transactions and front-ran 5 sandwich bots across 8 transactions,
taking ~$25M; the validator was slashed for proposer equivocation and relays were patched.
- https://www.certik.com/blog/mev-bot-incident-analysis
- https://halborn.com/blog/post/explained-the-mev-bots-hack-april-2023
- https://blockworks.co/news/validator-frontruns-mev-bots

(JIT liquidity is a documented, widely-measured Uniswap v3 strategy rather than a single named exploit; no
specific incident URL is asserted here.)

---

## THE CROSS-MECHANISM REASONING PROTOCOL

A concrete checklist an analyst (human or LLM) applies to ANY target to find *composition* bugs — where
every function is correct alone but composable into a drain. Work it mechanically; do not reason by vibes.
The core move is: **enumerate every external call, every value read, every trusted assumption, every
privileged actor — and for each, ask "can this move in one transaction, and who/what controls it?"**

### Step 0 — Map the surface (build the graph before reasoning)
- List every **externally-callable function** (public/external), its state writes, and its external calls.
- List every **external contract** the target calls or reads (tokens, oracles, pools, vaults, routers,
  bridges), and whether each can call *back* (hooks, native ETH sends, flash callbacks).
- List every **value the target reads to make a decision** (prices, balances, share rates, total supply,
  voting power, signatures) and its *exact source expression* (e.g. `pair.getReserves()`,
  `vault.pricePerShare()`, `token.balanceOf(this)`, `getVotes()`).
- List every **privileged actor/role** (owner, admin, upgrader, keeper, oracle pusher, signer set,
  liquidator) and what each can do.
- Note the **allowlist**: which token/collateral types are admitted (FoT? rebasing? ERC777/hook? vault
  shares? low-decimal?).

### Step 1 — For every value the contract READS: "where does this come from, and can it move in one tx?"
- **Source class?** Spot AMM reserve / `slot0` (instant, manipulable) · TWAP (bounded) · Chainlink/push
  (stale/compromise risk) · vault `pricePerShare` / `totalAssets()` (donation-inflatable) · internal
  accounted counter (safe-ish).
- **Can one transaction move it?** If flash-loan capital can change this value and then a decision is made on
  it in the same tx → Family 1/5. If a bare `transfer` into a vault/pool changes it → Family 2/5.
- **Is the read consistent?** Could this `view` be read while the underlying is mid-mutation (inside a
  `remove_liquidity`/token callback)? → Family 3. Does the read share a lock with the writer?
- **Staleness/bounds?** Is there `maxAge`, min/max answer, deviation cap, second-feed cross-check? Missing →
  Family 7.
- **Accounting basis?** Does it credit the `amount` argument or measure `balanceAfter - balanceBefore`?
  Does it store token *amounts* or *shares* for a rebasing asset? → Family 5.

### Step 2 — For every EXTERNAL CALL: "who can I hand control to, and what have I not yet written?"
- **Does an external call precede a state write / health check?** (CEI violation.) If yes, list every
  function and every sibling/partner contract reachable from the callback → Family 4/9.
- **Does the callee have a callback?** ERC777/ERC1363/ERC721-safe, native ETH `.call`, flash-swap/flash-loan
  callback, router callback. Each is a reentrancy entrypoint. Does a *global* lock span it, or only
  per-function `nonReentrant`?
- **What invariant is temporarily false during the call?** (Balance not decremented, health not updated,
  reserves mid-change.) Who else reads that exact state? → cross-function/cross-contract/read-only reentrancy.
- **Does the call trust the callee's atomicity/price/return?** Model the callee as adversarial (reentrant
  hook, donation-inflatable price, silent no-op `permit`, malicious upgrade target).

### Step 3 — For every TRUSTED ASSUMPTION: "what enforces this on-chain, in this transaction?"
Write each implicit assumption as a sentence, then find the line that enforces it; if none, it's a lead.
- "amount sent == amount received" → enforced by a balance-delta measure? (else Family 5)
- "share price only changes via deposit/withdraw" → enforced against raw donation? (else Family 2/5)
- "this price is fair" → enforced by TWAP/median/bounds? (else Family 1/7)
- "the caller is solvent after this" → enforced by a post-call `checkLiquidity`? (else Family 4/8)
- "voting power is durably owned" → enforced by a past-block snapshot? (else Family 6)
- "this signature is fresh, single-use, this-chain, this-contract" → enforced by nonce + full EIP-712
  domain? (else Family 11)
- "the implementation is inert and init happens once by us" → enforced by `_disableInitializers` + access
  control? (else Family 10)
- "the token is a vanilla ERC20" → enforced by allowlist excluding FoT/rebasing/hook tokens? (else 5/9)

### Step 4 — For every STATE a function DEPENDS ON: "what other function changes it, and can they interleave?"
- For each state variable read in a safety check, list **every** function that writes it. Can a write be
  triggered *between* this function's read and its action (reentrancy, or a second actor in the same block)?
- Are there two code paths that read the *same* collateral/balance but don't share a reentrancy lock?
  (cross-function reentrancy)
- Is there a cached value (`reserve`, `exchangeRate`, oracle snapshot) that can diverge from the live value,
  plus a `sync()`/`gulp()`/`update()` that an attacker can time? → Family 5.

### Step 5 — For every PRIVILEGED ACTOR: "who can call the thing this calls, and what's the blast radius?"
- For each privileged function, trace the *full* set of addresses/roles that can reach it (including via
  upgrade, delegatecall, factory, or an uninitialized implementation). → Family 10.
- Can voting/keeper/signer power be *acquired atomically* (flash loan → votes; stake → keeper)? → Family 6/7.
- What is the maximum single-actor damage (one key, one role, one proposal)? Is there a timelock, a cap, a
  second independent factor? → Family 7/10.
- Can the actor be both sides of a privileged interaction (self-liquidation, self-deal)? → Family 8.

### Step 6 — Compose: chain the leads into a single-transaction sequence
For each candidate lead, try to build a flash-loan-funded, single-tx (or single-block) sequence:
`flash-loan → move/inflate value X (Step 1) OR hand control to callback (Step 2) → reach a decision function
that trusts an assumption nothing enforces (Step 3) → extract → unwind/repay`.
- Ask: does the attacker end with more value than they started, after repaying? If yes, you have an exploit
  hypothesis — write it as setup → trigger → extraction with the exact calls and the violated invariant.
- Prefer compositions that cross a protocol boundary (A's correct feature breaks B) — these evade
  single-contract audits (Family 9).

### Step 7 — Falsify with invariants (the fuzzer handoff)
Turn each hypothesis into an executable invariant and run it on a mainnet fork:
- **Conservation:** `sum(user balances) == totalSupply`; `protocolAssets >= protocolLiabilities`
  (solvency) after *any* sequence.
- **Value neutrality:** no externally-callable sequence (including flash loans, reentrancy, adversarial
  tokens, adversarial ordering) increases a single actor's net worth at the protocol's expense.
- **Price consistency:** a value used for a decision equals a manipulation-resistant reference within a band,
  and is identical whether read normally or mid-callback.
- **Health monotonicity:** every account the tx touched is healthy on return, or the tx reverts.
- **Authorization:** init/upgrade/withdraw privileged paths are reachable only by intended roles, once,
  within bounds.
Run the fuzzer with **adversarial mocks** for every integrated contract (reentrant hook token,
donation-inflatable vault, silent-no-op permit token, manipulable `view` pool) and with **adversarial
block ordering**. A violated invariant that an attacker can profit from is the proven exploit; attach the
setup→trigger→extraction trace.

### Quick-reference: signal → family map
- Spot reserve / `slot0` in a borrow/liquidation math → **1**
- `totalAssets()==balanceOf(this)`, no virtual shares, usable while `totalSupply==0` → **2**
- `get_virtual_price`/`balances` read with no pool reentrancy probe; ETH/hook leg → **3**
- External call before state write; per-function (not global) locks → **4**
- credits `amount` not balance-delta; `sync()`/`gulp()`; FoT/rebasing allowed → **5**
- votes from current balance, emergency execute, arbitrary proposal calldata → **6**
- oracle with no staleness/bounds/deviation cap; small `m`-of-`n`; price pusher → **7**
- balance-reducing fn without `checkLiquidity`; uncapped liquidation discount; self-liquidation reachable → **8**
- integrates hook token / donation-inflatable vault / flash callback into a trusting decision → **9**
- open/front-runnable `initialize`; UUPS impl without `_disableInitializers`; reachable `upgradeTo` → **10**
- unchecked `permit` return + pre-existing approvals; missing nonce/`chainId`/`verifyingContract` → **11**
- `amountOutMin==0`/no deadline; same-block update→action dependency; ordering-dependent profit → **12**
