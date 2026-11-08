# Bug-Bounty & Disclosure Research — DeFi Vulnerability Knowledge Base

Purpose: feed an automated vulnerability-finding engine with REAL, published bug-bounty
disclosures, hack analyses, and hunter methodology. Everything here is sourced to a URL
that was actually retrieved while compiling this file (see **## Sources**). Figures are
"value/at-risk at time of event" and are often disputed across post-mortems — the
**mechanism** is the load-bearing part, not the number.

Conventions:
- `unconfirmed` = could not verify the specific claim/number/URL from the sources pulled; do not treat as fact.
- Dollar amounts for *bounties* (whitehat payouts) are distinct from *losses* (black-hat drains); each row says which.
- Sibling file `audited_exploits.md` holds deeper mechanism write-ups for several classic oracle/lending drains (Euler, Mango, Cream, Harvest, UwU Lend, Rari/Fuse); cross-referenced below rather than duplicated.

---

## Immunefi Severity Classification

Immunefi's **Vulnerability Severity Classification System (VSCS)** is the de-facto standard
DeFi severity taxonomy; most programs reference it directly. It is **impact-based**: severity
is driven by the *consequence* of the exploit, then adjusted down for the *access* an attacker
needs and the *likelihood* of success. Current reference is **v2.3**; v1 and the "Updated"
scale are retired. The Smart Contract track has four levels (no "None" level is defined for
smart contracts). Impacts requiring privileged access or uncommon user interaction can be
downgraded or rejected.

Source: <https://immunefi.com/immunefi-vulnerability-severity-classification-system-v2-3/> and the severity index <https://immunefi.com/severity-system/>.

### Critical (Smart Contracts) — what qualifies
Verbatim impact list (v2.3 smart-contract track):
- **Manipulation of governance voting result** deviating from the voted outcome.
- **Direct theft of any user funds**, whether at-rest or in-motion, *other than unclaimed yield*.
- **Direct theft of any user NFTs**, whether at-rest or in-motion, *other than unclaimed royalties*.
- **Permanent freezing of funds**.
- **Permanent freezing of NFTs**.
- **Unauthorized minting of NFTs**.
- **Predictable or manipulable RNG** that results in abuse of the principal or NFT.
- **Unintended alteration of what the NFT represents** (e.g. token URI, payload, artistic content).
- **Protocol insolvency**.

Operational gloss: Critical = the protocol or its users end up permanently poorer in a way
the attacker directly causes — a drain, an unrecoverable freeze, unbacked supply (insolvency),
mint-from-nothing, or hijacked governance. This is the tier that pays the headline bounties.

### High (Smart Contracts)
- **Theft of unclaimed yield.**
- **Theft of unclaimed royalties.**
- **Permanent freezing of unclaimed yield.**
- **Permanent freezing of unclaimed royalties.**
- **Temporary freezing of funds.**
- **Temporary freezing of NFTs.**

Gloss: real value loss, but bounded — it hits *yield/royalties* (not principal) or the freeze
is *temporary* (funds recoverable after a delay/upgrade).

### Medium (Smart Contracts)
- **Smart contract unable to operate due to lack of token funds.**
- **Block stuffing.**
- **Griefing** (no profit motive for the attacker, but damage to users or the protocol).
- **Theft of gas.**
- **Unbounded gas consumption.**

### Low (Smart Contracts)
- **Contract fails to deliver promised returns, but doesn't lose value.**

### Engine heuristics derived from VSCS
- A finding is **Critical** if a single actor can end a transaction with more value than they started, *or* can permanently lock principal, *or* can mint supply/votes without authorization. Map any candidate bug to one of the nine Critical impacts; if it maps, prioritize a PoC.
- "Requires owner/privileged key" or "requires victim to do something unusual" downgrades severity — model the *access precondition* explicitly.
- Insolvency (protocol liabilities > assets, even without a direct withdrawal) is Critical on its own — look for accounting paths that create unbacked internal balances.

---

## Published hack analyses & disclosed bugs

Mix of **whitehat bounty disclosures** (patched, no loss) and **black-hat post-mortems**
(funds drained). `B` = bounty payout, `L` = loss/at-risk.

| # | Target / Date | Bug class | Mechanism (how it worked) | Amount | Source |
|---|---|---|---|---|---|
| 1 | **Wormhole** (bridge) — Feb 2022 | Uninitialized UUPS proxy / upgrade | A core-bridge UUPS *implementation* contract was left **uninitialized** after an earlier bugfix reverted the original init. An attacker could call `initialize` on the implementation, take ownership, and `selfdestruct` it — bricking the proxy and permanently freezing bridged funds. Reported by satya0x; validated and patched the same day. | B: **$10M** (record at the time) | Immunefi bugfix review |
| 2 | **Aurora** (NEAR EVM) — Apr 2022 | Integer overflow → unauthorized mint | An integer overflow in the Sputnik-EVM `record_dynamic_cost` path, combined with calls to non-existent contracts succeeding and a precompile "exit to NEAR" quirk, let an attacker **infinitely mint ETH** inside Aurora and withdraw the backing nETH on NEAR. Would have drained the ETH-backing pool. | B: **$6M** (in AURORA); L-averted ~70k ETH | Immunefi / Aurora blog / forum |
| 3 | **ArmorFi** (coverage) — 2020/21 | Logic error / accounting | A flaw let a buyer withdraw **10^18× the coverage they purchased**, which would have drained the underwriting reserve from ~$1 of coverage. Reported by Alexander Schlindwein. | B: **~$1.5M** | Immunefi whitehat spotlight / ArmorFi postmortem |
| 4 | **Belt Finance** (yield) — 2021 | Donation / balance-snapshot manipulation | The strategy valued holdings from a `balanceSnapshot` that could be inflated by **sending tokens directly to the strategy contract**, making the strategy mis-calculate real holdings. One iteration moved ~$10M; repeatable until drained (~$60M BNB at risk). | B: **$1.05M** (incl. $50k match) — "largest Immunefi payout" at the time | Immunefi bugfix review |
| 5 | **88mph** (fixed-rate) — 2021/22 | Unprotected initializer | The NFT contract's `init()` was **missing `onlyOwner` and an `initializer` guard**, so anyone could (re)initialize it and seize control of affected pools (CRV:RENWBTC, CRV:STETH, yaLink). Reported by iosiro's Ashiq Amien. | B: **$42,069** | Immunefi / iosiro postmortem |
| 6 | **Omni Protocol** (NFT lending) — Jul 2022 | Reentrancy (CEI violation) | Two functions performed an external call (NFT/token transfer handing control to the receiver) **before updating internal accounting**, with no reentrancy lock. A malicious receiver re-entered to borrow/withdraw against stale balances. | L: **~$1.4M** | Immunefi hack analysis |
| 7 | **Hundred Finance** (lending, Gnosis) — Mar 2022 | Reentrancy via token hook | Collateral used a **non-standard ERC677-style token with a post-transfer hook**; the redeem/borrow path transferred tokens before updating debt/collateral state, so the hook re-entered before accounting caught up (Compound-fork variant). | L: multi-$M | Immunefi hack analysis (PoC) |
| 8 | **Nomad Bridge** — Aug 2022 | Trusted-root init / replay | A routine upgrade set the **trusted/committed Merkle root to `0x00`**, and the proof check treated the zero root as valid — so *any* message proved true by default. A free-for-all followed: copy the first exploiter's calldata, **swap in your own recipient address**, repeat. | L: **~$190M** | Immunefi hack analysis / CertiK / Halborn |
| 9 | **Beanstalk** (stablecoin) — Apr 2022 | Flash-loan governance | Attacker flash-borrowed ~$1B to acquire a governance supermajority **in one transaction**, then called `emergencyCommit` — which lacked a sufficient execution delay — to pass and execute a malicious BIP that transferred protocol funds, all atomically. | L: **~$181M** | Immunefi hack analysis / Beosin |
| 10 | **Curve (Vyper pools)** — Jul 2023 | Compiler-level broken reentrancy lock | Vyper **0.2.15/0.2.16/0.3.0 mis-compiled the `@nonreentrant` lock**, so the guard didn't actually prevent reentrancy. Several stable pools (alETH/ETH, etc.) were re-entered during `remove_liquidity`. Downstream: Alchemix, JPEG'd, Metronome. | L: **~$70M** (est.; ~$5.4M whitehat-returned) | Halborn / CertiK / Vyper post-mortem |
| 11 | **KyberSwap Elastic** — Nov 2023 | Tick-boundary rounding / double-count | Concentrated-liquidity `computeSwapStep`/tick-crossing math used **slightly different arithmetic in two places**; a flash-loan-engineered swap just under a tick boundary passed a boundary check it should have failed, causing **liquidity to be double-counted** and withdrawn. | L: **~$48M** across 6 chains | REKT / BlockSec / CertiK / Halborn |
| 12 | **Penpie** (Pendle yield) — Sep 2024 | Reentrancy via permissionless registration | `registerPenpiePool` only checked a market existed in Pendle's factory — but **anyone could create a market** via `createNewMarket` around a **malicious SY token**. Registering it, then calling the unguarded `batchHarvestMarketRewards`, let the fake market re-enter and inflate reward accounting. A later audit missed it (scoped to "new contracts only"). | L: **~$27M** (Pendle saved ~$105M more) | REKT / SolidityScan / Cointelegraph |
| 13 | **Astaria** (Code4rena, Jan 2023) | First-depositor share inflation (ERC4626) | Judged **High** (#614). First depositor deposits 1 wei, then **donates assets to inflate `totalAssets`**, so later depositors' share math rounds down to **0 shares** — their deposit is effectively stolen. "min first deposit" alone does not fix it. | B: contest award (undisclosed $) | Code4rena finding #614 |
| 14 | **Notional × Index Coop** (Code4rena, 2022) | ERC4626 rounding direction | A wrapper's rounding **didn't follow ERC4626 expectations**; integrators assuming standard round-down/round-up behavior could be shorted. Judge upgraded to **High** (1 High + 10 Medium in the contest). | B: contest award | Code4rena report |
| 15 | **Cream Finance** — Oct 2021 | Oracle manipulation + vault share inflation | Collateral (yUSD) was priced from the vault's **`pricePerShare`**; attacker flash-borrowed, deposited, then **donated into the underlying Curve pool** to ~2× the share price (shares constant, underlying inflated), valuing their collateral double and borrowing out the lendable liquidity. | L: **~$130M** | Cream official post-mortem (Medium) |

### Additional cross-referenced cases (full mechanism in `audited_exploits.md`)
Primary post-mortem URLs for these were **not re-fetched in this compilation pass** (marked
accordingly); the mechanism write-ups in the sibling file are the internal reference.

- **Euler Finance** — Mar 2023 — `~$197M` — *liquidation/valuation logic*: `donateToReserves` reduced an account's equity with **no post-call health check**; attacker self-donated into insolvency, then self-liquidated into an over-rich liquidation discount. (Euler was multiply-audited.) Contagion hit 11+ protocols — see Cointelegraph coverage.
- **Mango Markets** — Oct 2022 — `~$110–116M` — *oracle manipulation (thin perp collateral)*: pumped MNGO spot across thin venues to inflate perp mark-to-market PnL counted as collateral, then borrowed out everything. Not a code defect — the oracle did what it was coded to do. (Blockworks/Coindesk coverage.)
- **Harvest Finance** — Oct 2020 — `~$24M net` — *AMM spot-reserve share pricing*: vault share value read **instantaneous Curve Y-pool balances**; flash-loan skew → mint cheap → restore → redeem rich.
- **UwU Lend** — Jun 2024 — `~$19–23M` — *oracle manipulation (median of on-chain pools)*: moved Curve-pool inputs to skew the sUSDe median price, borrowing against mis-valued collateral.
- **Rari Capital / Fei (Fuse)** — Apr 2022 — `~$80M` — *Compound-fork read-only/standard reentrancy*: an "April security upgrade" patch was incomplete; `exitMarket`/`borrow` path re-entered.

---

## What top hunters say finds the bugs

Distilled from auditor/hunter interviews and methodology write-ups (samczsun interview;
Cyfrin/Trail of Bits/Dedaub/Sherlock guides; DeFiHackLabs; vendor methodology posts — see Sources).
Treat vendor blogs as perspective, not neutral research.

**Where the real bugs actually hide (recurring themes):**
- **Business logic & economics, not syntax.** Audits reliably catch reentrancy/overflow; the expensive misses are *incentive* and *accounting* flaws — "the code is individually correct but the composition is exploitable." Mango, Harvest, Euler, Belt all fit this. Ask "whose money is this, and does every path that reduces it re-check solvency?"
- **Assumed-trusted components / scope gaps.** Oracles, external vault `pricePerShare`, bridge roots, and "someone else's" price feeds are repeatedly treated as honest. Model the **economic manipulation cost** (how much capital moves the input by X%), not just "is the math right." (UwU Lend, Cream, Mango.)
- **Post-audit code changes & emergent cross-function interactions.** New functions reviewed *in isolation* (Euler's `donateToReserves`, Penpie's permissionless registration) interact catastrophically with *existing* paths. No single reviewer owns the cross-function invariant. Audits scoped to "new contracts only" repeatedly miss this (Penpie).
- **Initialization & upgrade authority.** Unprotected `init()`/`initialize` (88mph, Wormhole, Parity-class), uninitialized proxies, missing `initializer` guards, upgrade without timelock. Grep every `initialize`, every proxy implementation, every `selfdestruct`.
- **External calls before state updates (CEI violations).** Reentrancy still pays — now via **token hooks** (ERC777/ERC677/ERC721 `onReceived`, non-standard SY tokens) and **read-only reentrancy** into price getters. Flag any balance-reducing function whose external call precedes its accounting write or health check. (Omni, Hundred, Penpie, Curve/Vyper.)
- **Rounding & precision at boundaries.** First-depositor share inflation, round-direction mismatches, tick-boundary math where two code paths use different arithmetic. (Astaria, Notional, KyberSwap.)

**What experienced reviewers look at first:**
- `external`/`public` state-mutating functions, `assembly`/low-level calls, and anything touching **access control, value transfer, or price**. Extra scrutiny there because that's where defects cluster.
- **Invariants first**: express "what must always be true" (supply ≤ cap; sum of user balances == protocol assets; every balance-reducing user action leaves the account healthy) and then hunt for a path that breaks one. Many practitioners frame *every* bug as a broken invariant; formal verification / fuzzing is pointed at the handful whose failure is catastrophic.
- **Prior art**: search Solodit / DeFiHackLabs / past contest findings for the same contract pattern or dependency before reading line-by-line — recurring bug classes recur.
- **End-to-end protocol understanding** before line review: whitepaper → spec → code; scope and context before reading a single line.

**Common reviewer blind spots (why audited code still gets drained):**
- Checklist-driven review misses **novel architecture** (cross-chain message ordering → Nomad).
- Single-reviewer coverage — multiple independent reviewers reconcile findings specifically to kill blind spots; the dangerous invariants are the ones no one "owns."
- Pricing a **listed asset's liquidity/manipulation cost** is rarely done — audits verify "collateral math matches spec," not "is the underlying market deep enough that one trader can't move it."
- **Operational / key-management** failure is out of smart-contract scope but is the single largest loss category in recent years (access-control/private-key compromise ≈ most of 2023–24 losses per Hacken) — not a code bug, but the engine should flag privileged single-key control as a finding.

**Practitioner workflow (reproducible, not vibes):**
Scope → understand protocol → enumerate invariants → manual review of value/access/price paths →
fuzz & symbolic-execute path-dependent logic → prove the handful of catastrophic invariants →
write a PoC that *demonstrates* the broken invariant. Contest rank and PoC reproduction (Damn
Vulnerable DeFi, Ethernaut, DeFiHackLabs reproductions) are the standard training path.

---

## Sources

Immunefi — severity system & disclosures:
- [Immunefi VSCS v2.3](https://immunefi.com/immunefi-vulnerability-severity-classification-system-v2-3/)
- [Immunefi severity system index](https://immunefi.com/severity-system/)
- [Severity Classification Systems](https://immunefi.com/severity-classification-systems/)
- [Wormhole Uninitialized Proxy Bugfix Review](https://immunefi.com/blog/bug-fix-reviews/wormhole-uninitialized-proxy-bugfix-review/)
- [Aurora Infinite Spend Bugfix Review — $6M Payout](https://medium.com/immunefi/aurora-infinite-spend-bugfix-review-6m-payout-e635d24273d)
- [Aurora: Mitigates Its Inflation Vulnerability (blog)](https://aurora.dev/blog/aurora-mitigates-its-inflation-vulnerability)
- [Aurora Bug Bounty Program — Reports and Rewards (forum)](https://forum.aurora.dev/t/bug-bounty-program-reports-and-rewards/1257)
- [Hacker Earns Largest-Ever Crypto Bug Bounty via Immunefi (ArmorFi $1.5M)](https://immunefi.com/blog/whitehat-spotlight/hacker-earns-largest-ever-crypto-bug-bounty-via-immunefi/)
- [ArmorFi Bug Bounty Postmortem](https://medium.com/immunefi/armorfi-bug-bounty-postmortem-cf46eb650b38)
- [Belt Finance Logic Error Bugfix Review — Largest Ever Bounty Payout](https://medium.com/immunefi/belt-finance-logic-error-bug-fix-postmortem-39308a158291)
- [88mph Function Initialization Bugfix Review](https://medium.com/immunefi/88mph-function-initialization-bug-fix-postmortem-c3a2282894d3)
- [Hack Analysis: Omni Protocol, July 2022](https://medium.com/immunefi/hack-analysis-omni-protocol-july-2022-2d35091a0109)
- [Hack Analysis: the Hundred Finance Heist, March 2022 (PoC)](https://medium.com/immunefi/a-poc-of-the-hundred-finance-heist-4121f23a098)
- [Hack Analysis: Nomad Bridge, August 2022](https://medium.com/immunefi/hack-analysis-nomad-bridge-august-2022-5aa63d53814a)
- [Hack Analysis: Beanstalk Governance Attack, April 2022](https://immunefi.com/blog/bug-fix-reviews/hack-analysis-beanstalk-governance-attack-april-2022/)
- [The u-up Files with samczsun (interview)](https://medium.com/immunefi/the-u-up-files-with-samczsun-1a9116cf6e74)
- [Immunefi surpasses $100M in payouts (The Block)](https://www.theblock.co/post/301025/web3-immunefi-ethical-hacker-payouts)
- [Wormhole pays record $10M bug bounty (PortSwigger Daily Swig)](https://portswigger.net/daily-swig/blockchain-bridge-wormhole-pays-record-10m-bug-bounty-reward)
- [Aurora pays $6M, saved 70,000 ETH (The Block)](https://www.theblock.co/post/150500/aurora-labs-pays-6-million-reward-to-hacker-that-saved-70000-eth-from-getting-stolen)

Other security firms / post-mortems:
- [Cream Finance official post-mortem (Oct 27 exploit)](https://medium.com/cream-finance/post-mortem-exploit-oct-27-507b12bb6f8e)
- [Curve/Vyper hack explained (Halborn)](https://www.halborn.com/blog/post/explained-the-vyper-bug-hack-july-2023)
- [Vyper incident analysis (CertiK)](https://www.certik.com/blog/vyper-incident-anaylsis)
- [KyberSwap Elastic — REKT](https://rekt.news/kyberswap-rekt)
- [KyberSwap: rounding-error exploitation (BlockSec)](https://blocksec.com/blog/kyberswap-incident-masterful-exploitation-of-rounding-errors-with-exceedingly-subtle-calculations)
- [KyberSwap Elastic analysis (CertiK)](https://www.certik.com/blog/kyberswap-elastic)
- [KyberSwap hack explained (Halborn)](https://www.halborn.com/blog/post/explained-the-kyberswap-hack-november-2023)
- [Penpie — REKT](https://rekt.news/penpie-rekt)
- [Penpie Hack Analysis (SolidityScan)](https://blog.solidityscan.com/penpie-hack-analysis-29034a6f2a61/)
- [2 auditors miss $27M Penpie flaw (Cointelegraph Magazine)](https://cointelegraph.com/magazine/?p=35844)
- [Nomad Bridge Exploit Incident Analysis (CertiK)](https://www.certik.com/blog/nomad-bridge-exploit-incident-analysis)
- [Nomad hack explained (Halborn)](https://halborn.com/explained-the-nomad-hack-august-2022/)
- [Beosin's analysis of the Beanstalk exploit](https://beosin.com/resources/beosins-analysis-of-the-beanstalk-exploit)
- [Euler attack contagion across 11+ protocols (Cointelegraph)](https://cointelegraph.com/news/euler-attack-causes-locked-tokens-losses-in-11-defi-protocols-including-balancer)

Code4rena / contest findings:
- [Code4rena 2023-01 Astaria finding #614 (first-depositor inflation)](https://github.com/code-423n4/2023-01-astaria-findings/issues/614)
- [Code4rena Notional × Index Coop report](https://code4rena.com/reports/2022-06-notional-coop)
- [Mitosis ERC4626 first-depositor inflation finding (Zellic)](https://reports.zellic.io/publications/mitosis/findings/high-protocolsrchubeolvaultsol-protocolsrchubmatrixvaultsol-first-depositor-inflation-attack-via-missing--decimalsoffset-override-in-erc-4626-vault)

Methodology / hunter interviews & guides:
- [Interview with samczsun (ConsenSys Diligence)](https://diligence.consensys.io/blog/2020/01/interview-with-samczsun)
- [How are smart contracts audited? (Dedaub)](https://dedaub.com/blog/how-are-smart-contracts-audited/)
- [Stop doing bad audits (Cyfrin newsletter)](https://newsletter.cyfrin.io/p/stop-doing-bad-audits-23-11-09)
- [How to Become a Smart Contract Auditor (Cyfrin)](https://medium.com/cyfrin/how-to-become-a-smart-contract-auditor-0180ca002e4e)
- [5 steps to becoming a top-level smart contract auditor (Sherlock)](https://sherlock.xyz/post/5-steps-to-becoming-a-top-level-smart-contract-auditor)
- [Inside EthCC[8]: becoming a smart contract auditor (Trail of Bits)](https://blog.trailofbits.com/2025/07/23/inside-ethcc8-becoming-a-smart-contract-auditor/)
- [Smart Contract Bug Hunting: Top 7 Strategies (Chainlink)](https://blog.chain.link/smart-contract-bug-hunting)
- [Lesson 1: Smart Contract Audit Methodology (DeFiHackLabs)](https://defihacklabs.substack.com/p/lesson-1-smart-contract-audit-methodology)
- [2024 Web3 Security Report (Hacken)](https://wp.hacken.io/wp-content/uploads/2024/12/2024-Web3-Security-Report.pdf)
