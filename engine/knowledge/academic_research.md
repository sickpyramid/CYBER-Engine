# Academic Research: Smart-Contract & DeFi Exploits

Knowledge base distilled from real, published academic research (SoKs, conference papers,
tool papers, datasets) for an automated vulnerability-finding engine. Every citation below was
verified via web search against arXiv / DOI / venue records. Where a figure or claim is
version-dependent or not fully confirmed, it is marked `[unconfirmed]`.

Last compiled: 2026-11-08.

---

## Attack taxonomies

Three consolidated taxonomies are used in practice. Engine hunters should tag every finding with
a DASP/SWC class **and** (for economic bugs) a SoK-DeFi root cause, because the DASP/SWC lists are
code-level and largely miss multi-contract economic attacks.

### DASP Top 10 (NCC Group, 2018 — the classic code-level list)
1. **Reentrancy** — external call re-enters victim before state is updated (TheDAO). Cross-function, delegated, and create-based variants exist (Sereum).
2. **Access Control** — missing/incorrect auth on privileged functions, unprotected `init`/owner, `tx.origin` auth, unprotected `SELFDESTRUCT`/`DELEGATECALL` (Parity multisig).
3. **Arithmetic** — integer over/underflow (pre-0.8.0 Solidity or unchecked blocks), rounding/precision loss.
4. **Unchecked Low-Level Calls** — ignored return value of `call`/`send`/`delegatecall`; silent failure leaves inconsistent state.
5. **Denial of Service** — unbounded loops, gas griefing, revert-on-receive blocking withdrawal queues, forced-ether griefing.
6. **Bad Randomness** — on-chain randomness from `block.timestamp`/`blockhash`/`prevrandao` that a miner/searcher can predict or bias.
7. **Front-Running / Transaction-Ordering Dependence (TOD)** — mempool visibility lets adversaries reorder (sandwich, liquidation sniping, MEV).
8. **Time Manipulation** — miner influence over `block.timestamp` affecting logic/randomness.
9. **Short Address / off-ABI encoding** — malformed calldata (largely historical, pre-ABI-hardening).
10. **Unknown Unknowns** — novel logic/composition bugs no checklist anticipates.

### SWC Registry (SmartContractSecurity, CWE-style; ~37 entries, frozen since 2020)
CWE-adapted IDs for Solidity weaknesses, each with description + remediation + test case. Still the
lingua franca for tool output mapping. Notable: SWC-101 (integer over/underflow), SWC-104 (unchecked
call return), SWC-105 (unprotected ether withdrawal), SWC-106 (unprotected SELFDESTRUCT), SWC-107
(reentrancy), SWC-112 (DELEGATECALL to untrusted callee), SWC-114 (TOD), SWC-115 (`tx.origin` auth),
SWC-116 (timestamp dependence), SWC-120 (weak randomness), SWC-128 (DoS via gas limit / block stuffing).
Known to be incomplete; README now points to the SCSVS as the maintained successor.

### SoK-DeFi root causes (Zhou et al., IEEE S&P 2023 — economic/protocol level)
Layered reference frame (network → consensus → smart contract → DeFi protocol → auxiliary/off-chain).
The two most **frequent** incident causes in their 181-incident corpus are under-studied by academia:
- **Price oracle manipulation** — spot-price/AMM reserve manipulation (often flash-loan funded) to misprice collateral/shares.
- **Permissionless (composability) interactions** — abusing one protocol's logic via credit/liquidity from another; "market attacks."
- Plus classic contract bugs (reentrancy, access control, arithmetic), **unsafe/unverified external calls**, **governance attacks**, **flash-loan-enabled** amplification, and **transaction/MEV ordering**.
Key defensive finding: **103 of 181 (56%) incidents were NOT atomic**, leaving a rescue/detection window.

---

## Key papers

### SoKs & surveys
1. **SoK: Decentralized Finance (DeFi) Attacks** — Liyi Zhou, Xihan Xiong, Jens Ernstberger, Stefanos Chaliasos, Zhipeng Wang, Ye Wang, Kaihua Qin, Roger Wattenhofer, Dawn Song, Arthur Gervais. *IEEE S&P 2023* (DOI 10.1109/SP46215.2023.10179435). The anchor taxonomy: 77 papers + 30 audit reports + 181 incidents, ≥\$3.24B lost (2018–2022); identifies oracle manipulation & permissionless composability as the biggest understudied gaps; 56% of attacks non-atomic. https://arxiv.org/abs/2208.13035

2. **SoK: Decentralized Finance (DeFi)** — Sam M. Werner, Daniel Perez, Lewis Gudgeon, Ariah Klages-Mundt, Dominik Harz, William Knottenbelt. *FC 2022* (arXiv 2101.08778). Splits DeFi security into **technical** vs **economic** security; formalizes protocol primitives (AMMs, lending, derivatives) and the financial-risk surface (liquidations, oracle dependence, governance, miner-extractable value). https://arxiv.org/abs/2101.08778

3. **A Survey of DeFi Security: Challenges and Opportunities** — Wenkai Li et al. *J. King Saud Univ. / arXiv 2206.11821* (2022). Layer-by-layer vulnerability survey (blockchain → smart contract → protocol → application) with defense directions. https://arxiv.org/abs/2206.11821

### Flash loans, MEV, oracle & AMM attacks (economic attack classes)
4. **Attacking the DeFi Ecosystem with Flash Loans for Fun and Profit** — Kaihua Qin, Liyi Zhou, Benjamin Livshits, Arthur Gervais. *FC 2021* (DOI 10.1007/978-3-662-64322-8_1; arXiv 2003.03810). First systematic study of flash loans; models attack-parameter search as an optimization over on-chain state; shows the bZx pump-and-arbitrage and oracle-manipulation attacks could be amplified to ~\$829.5k and ~\$1.1M. Core lesson: **atomic, capital-free composition turns logic bugs into immediately profitable exploits.** https://arxiv.org/abs/2003.03810

5. **Flash Boys 2.0: Frontrunning, Transaction Reordering, and Consensus Instability in Decentralized Exchanges** — Philip Daian, Steven Goldfeder, Tyler Kell, Yunqi Li, Xueyuan Zhao, Iddo Bentov, Lorenz Breidenbach, Ari Juels. *IEEE S&P 2020* (arXiv 1904.05234). Defines **Miner/Maximal Extractable Value (MEV)** and **priority gas auctions (PGAs)**; shows ordering-based extraction is a consensus-layer risk. The foundational front-running paper. https://arxiv.org/abs/1904.05234

6. **High-Frequency Trading on Decentralized On-Chain Exchanges** — Liyi Zhou, Kaihua Qin, Christof Ferreira Torres, Duc V. Le, Arthur Gervais. *IEEE S&P 2021* (arXiv 2009.14021). First to **formalize and quantify sandwich attacks** (front-run + back-run around a victim swap on constant-product AMMs); derives optimal adversarial input and models gas-price competition. https://arxiv.org/abs/2009.14021

7. **Quantifying Blockchain Extractable Value: How dark is the forest?** — Kaihua Qin, Liyi Zhou, Arthur Gervais. *IEEE S&P 2022* (arXiv 2101.05511). Measures real BEV from sandwiches, liquidations, and DEX arbitrage: ~\$540.5M over 32 months; introduces an application-agnostic transaction-replay extraction technique. https://arxiv.org/abs/2101.05511

8. **TWAP Oracle Attacks: Easier Done than Said?** — Torgin Mackinga, Tejaswi Nadahalli, Roger Wattenhofer. *IEEE ICBC 2022*. Shows arithmetic-mean TWAP oracles are cheaper to manipulate than assumed; gives single-block and multi-block/MEV manipulation strategies. Directly relevant to oracle-robustness invariants. https://ieeexplore.ieee.org/document/9805499

9. **Demystifying Just-in-Time (JIT) Liquidity Attacks on Uniswap V3** — Xihan Xiong, Zhipeng Wang, William Knottenbelt, Michael Huth. *IACR ePrint 2023/973* (DeFi/CCS workshop). Formalizes the mint→swap→burn JIT sequence; 36,671 attacks / ~7,498 ETH over 20 months; passive LP shares diluted ~85% on average. https://eprint.iacr.org/2023/973

10. **Flash Crash for Cash: Cyber Threats in Decentralized Finance** — Kris Oosthoek. *arXiv 2106.10740* (2021). 20-incident dataset + classification framework separating protocol-level "market attacks" from single-contract bugs; characterizes the flash-loan-funded attack lifecycle as 2020's dominant vector. https://arxiv.org/abs/2106.10740

### Smart-contract analysis tools: symbolic execution & static analysis
11. **Making Smart Contracts Smarter** (Oyente) — Loi Luu, Duc-Hiep Chu, Hrishi Olickel, Prateek Saxena, Aquinas Hobor. *ACM CCS 2016* (DOI 10.1145/2976749.2978309). First EVM symbolic-execution bug finder; formalizes TOD, timestamp dependence, mishandled exceptions, reentrancy; flagged ~8,833/19,336 contracts. https://www.comp.nus.edu.sg/~prateeks/papers/Oyente.pdf

12. **Securify: Practical Security Analysis of Smart Contracts** — Petar Tsankov, Andrei Dan, Dana Drachsler-Cohen, Arthur Gervais, Florian Bünzli, Martin Vechev. *ACM CCS 2018* (DOI 10.1145/3243734.3243780; arXiv 1806.01143). Static analyzer over a dependency-graph semantic facts base; expresses compliance & violation patterns in a DSL to **prove** properties safe/unsafe. https://arxiv.org/abs/1806.01143

13. **ZEUS: Analyzing Safety of Smart Contracts** — Sukrit Kalra, Seep Goel, Mohan Dhawan, Subodh Sharma. *NDSS 2018*. Abstract interpretation + symbolic model checking via constrained Horn clauses; verifies correctness & "fairness" (business-logic) policies; sound (zero FN claim) with low FP. https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_09-1_Kalra_paper.pdf

14. **teEther: Gnawing at Ethereum to Automatically Exploit Smart Contracts** — Johannes Krupp, Christian Rossow. *USENIX Security 2018*. **Automatic exploit generation** from bytecode (backward slicing + symbolic execution + EVM execution); generated working exploits for 815 of 38,757 contracts. Template for an engine that must *prove* a bug, not just flag it. https://www.usenix.org/conference/usenixsecurity18/presentation/krupp

15. **Slither: A Static Analysis Framework for Smart Contracts** — Josselin Feist, Gustavo Grieco, Alex Groce. *WETSEB@ICSE 2019* (arXiv 1908.09878). SlithIR SSA IR enabling dataflow + taint; fast, low-crash detectors; the de-facto first-pass static analyzer and a source of custom detector scripting. https://arxiv.org/abs/1908.09878

16. **Manticore: A User-Friendly Symbolic Execution Framework for Binaries and Smart Contracts** — Mark Mossberg, Felipe Manzano, Eric Hennenfent, Alex Groce, Gustavo Grieco, Josselin Feist, Trent Brunson, Artem Dinaburg. *ASE 2019* (arXiv 1907.03890). Dynamic symbolic execution with fully symbolic transactions (symbolic value + data); scriptable state exploration. https://arxiv.org/abs/1907.03890

17. **Sereum: Protecting Existing Smart Contracts Against Re-Entrancy Attacks** — Michael Rodler, Wenting Li, Ghassan O. Karame, Lucas Davi. *NDSS 2019* (arXiv 1812.05934). Runtime taint-tracking hardened EVM protecting *deployed* contracts; also introduces **cross-function, delegated, and create-based reentrancy** — variants static tools miss. https://arxiv.org/abs/1812.05934

### Fuzzing (closest to the engine's own PoC-proving approach)
18. **ContractFuzzer: Fuzzing Smart Contracts for Vulnerability Detection** — Bo Jiang, Ye Liu, W.K. Chan. *ASE 2018* (DOI 10.1145/3238147.3238177; arXiv 1807.03932). ABI-driven input generation + EVM-instrumented test oracles; found ≥459 vulns across 6,991 contracts (incl. DAO & Parity). https://arxiv.org/abs/1807.03932

19. **Echidna: Effective, Usable, and Fast Fuzzing for Smart Contracts** — Gustavo Grieco, Will Song, Artur Cygan, Josselin Feist, Alex Groce. *ISSTA 2020 (tool demo)*. Property-based (QuickCheck-style) fuzzer: user writes `echidna_*` boolean invariants + assertion checks; coverage-guided. The canonical tool for **invariant fuzzing** — but only as good as the invariants supplied. (ISSTA 2020, DOI 10.1145/3395363.3404366) https://conf.researchr.org/details/issta-2020/issta-2020-tool-demonstration/5/Echidna-Effective-Usable-and-Fast-Fuzzing-for-Smart-Contracts

20. **ItyFuzz: Snapshot-Based Fuzzer for Smart Contract** — Chaofan Shou, Shangyin Tan, Koushik Sen. *ISSTA 2023* (arXiv 2306.17135). Snapshots states + singleton transactions instead of mutating tx sequences; dataflow & comparison **waypoints** prune state space; generates on-chain exploits (incl. reentrancy, price manipulation) on forked mainnet state fast. Most relevant to a fork-based PoC engine. https://arxiv.org/abs/2306.17135

### DeFi-specific detection & empirical tool studies
21. **DeFiRanger: Detecting Price Manipulation Attacks on DeFi Applications** — Siwei Wu, Dabao Wang, Jianliang Wu, et al. (Zhejiang Univ.). *arXiv 2104.15068* (2021); extended in *IEEE TDSC*. Lifts raw tx to a **Cash-Flow Tree** + high-level DeFi actions, then matches price-manipulation patterns; found known + zero-day incidents. Numbers differ between arXiv and journal versions `[version-dependent]`. https://arxiv.org/abs/2104.15068

22. **SmartBugs: A Framework to Analyze Solidity Smart Contracts** — João F. Ferreira, Pedro Cruz, Thomas Durieux, Rui Abreu. *ASE 2020 (tool demo)* (arXiv 2007.04771). Standard harness to run 10+ analyzers uniformly; ships `SB-curated` (annotated vulnerable contracts, DASP-tagged) — a core benchmark dataset. https://arxiv.org/abs/2007.04771

23. **Empirical Review of Automated Analysis Tools on 47,587 Ethereum Smart Contracts** — Thomas Durieux, João F. Ferreira, Rui Abreu, Pedro Cruz. *ICSE 2020* (arXiv 1910.10601). Ran 9 tools over 47k contracts + 69-contract annotated set: only **42%** of annotated vulns caught by *any* tool combined; Mythril best single tool (~27%); ~97% of the full set flagged (huge FP rate). The key evidence that single-tool pipelines miss most real bugs. https://arxiv.org/abs/1910.10601

### Datasets (for retrieval / historical-attack matching)
- **DeFiHackLabs** (SunWeb3Sec, GitHub) — community corpus reproducing 565+ real DeFi hacks as runnable Foundry PoCs on mainnet forks. The best source of *executable* attack templates; cannot cover off-chain/private-key/social-engineering incidents. https://github.com/SunWeb3Sec/DeFiHackLabs
- **SmartBugs `SB-curated`** — 143 annotated vulnerable contracts / 208 tagged vulnerabilities across DASP categories (see #22). https://github.com/smartbugs/smartbugs
- **SWC Registry test cases** — per-weakness minimal vulnerable/fixed contract pairs. https://github.com/SmartContractSecurity/SWC-registry
- **SoK: DeFi Attacks incident corpus** (#1) — 181 curated real-world incidents with root-cause labels. https://github.com/blockchain-unica/defi-attacks `[repo name unconfirmed; dataset released alongside the paper]`

---

## Detection techniques & their blind spots

| Technique | Representative tools/papers | Catches | Misses |
|---|---|---|---|
| **Static analysis / pattern matching** | Slither (#15), Securify (#12), SmartCheck | Known syntactic bug shapes: reentrancy patterns, `tx.origin` auth, unchecked calls, uninitialized storage, shadowing, missing events; fast, whole-contract. | **Cross-contract composition & economic logic.** No notion of token *value*, oracle *price*, or multi-protocol flow. High false positives (Durieux #23: ~97% of contracts flagged). Cannot reason about reachability/feasibility of a path. |
| **Symbolic execution** | Oyente (#11), ZEUS (#13), Manticore (#16), Mythril, teEther (#14) | Deep per-path reasoning on a single contract/bytecode: arithmetic bugs, assert violations, unprotected `SELFDESTRUCT`/`DELEGATECALL`, some reentrancy; can produce concrete exploit inputs (teEther). | **Path explosion** across multi-tx sequences; **external calls to unknown contracts** are over-approximated/stubbed, so cross-contract and oracle-dependent attacks are invisible. Default depth is shallow (Mythril ≈ 2 tx). SMT timeouts drop paths silently. Loops/crypto are hard. |
| **Runtime / dynamic monitoring** | Sereum (#17), DeFiRanger (#21) | Live attack detection using taint/data-flow or cash-flow-tree + price-manipulation patterns; catches cross-function/delegated/create reentrancy and oracle manipulation *as it happens*. | Detection, not prevention of novel logic; pattern-bound (new economic game evades patterns); needs full-node instrumentation / historical tx replay; post-hoc for non-atomic attacks. |
| **Fuzzing — stateless / sequence** | ContractFuzzer (#18), sFuzz | ABI-driven input generation; shallow reachable bugs, exception/assert oracles, bad-randomness/timestamp misuse. | **Multi-transaction economic attacks without the right invariant.** Blind test oracles only know generic bug classes, not protocol-specific solvency/accounting properties. Low coverage on guarded state machines. |
| **Fuzzing — stateful / property (invariant)** | Echidna (#19), Foundry invariant testing, ItyFuzz (#20) | Multi-tx stateful exploration against **user-defined invariants**; coverage/waypoint-guided; ItyFuzz forks mainnet state to hit real deployed dependencies and *generates* exploits. The closest match to proving DeFi economic bugs. | **Only finds violations of invariants you actually wrote.** A missing or too-weak invariant → false sense of safety. Struggles with attacks needing specific external-protocol setup, large search depth, or precise magic constants; cross-chain/bridge logic usually out of harness scope. |
| **Formal verification / bounded model checking** | VerX, Certora Prover, SMTChecker, Halmos | Proves (or BMC-bounds) explicit spec properties: supply conservation, access rules, no-overflow; exhaustive within bound. | Needs a **correct, complete spec**; unmodeled external contracts & real oracle behavior; economic/game-theoretic assumptions outside the model; state-space/solver limits force bounds that miss deep sequences. |

**Cross-cutting lesson for the engine:** code-level tools (static + symbolic) find *contract* bugs; DeFi
losses are dominated by *protocol/economic* attacks (oracle manipulation + permissionless composition,
per SoK #1). The only techniques that reach those are **stateful invariant fuzzing on a mainnet fork**
(Echidna/Foundry/ItyFuzz) and **runtime cash-flow analysis** (DeFiRanger) — and both fail silently
without the right invariants/patterns. Prioritize synthesizing strong economic invariants.

---

## Invariants worth fuzzing

Concrete stateful properties a fork-based invariant fuzzer (Echidna/Foundry/ItyFuzz) should assert.
Drawn from the attack classes in #1, #4, #6, #8, #9, #21. Assert after *every* tx in a random sequence,
with flash-loan-funded actors and adversary-controlled external calls/oracles in the harness.

### Global / any protocol
- **Solvency:** `sum(user_claims) <= protocol_assets` (total redeemable ≤ total held); no path makes aggregate liabilities exceed backing.
- **No value creation from nothing:** total protocol balance of each token changes only by explicit deposits/withdrawals/fees (conservation of funds across a tx).
- **Access control:** only authorized roles mutate privileged state; no reinitialization; owner/admin cannot be silently hijacked; `DELEGATECALL` target cannot be attacker-set.
- **Reentrancy safety:** balances/accounting are consistent before and after any external call; re-entrant call cannot double-spend (cover cross-function & read-only reentrancy).
- **Monotonic share price / no free mint:** shares minted ⇔ assets in; an actor cannot end a tx (or atomic sequence) with more value than they started unless they provided it.

### Lending / borrowing (Compound/Aave-style)
- **No self-liquidation / no profit from own liquidation.**
- **Collateralization:** every account stays `collateralValue * LTV >= borrowValue` after any action; a borrow that breaches this must revert.
- **Oracle-robust health:** a single-block/flash-loan-induced price move cannot make an underwater position appear healthy (fuzz with manipulated spot vs TWAP) — the canonical price-oracle-manipulation invariant.
- **Interest/accounting monotonicity:** total borrows == sum of per-user borrows; indexes never decrease; bad-debt socialization is accounted, not lost.
- **Liquidation bounds:** liquidator reward ≤ configured bonus; cannot seize more collateral than close factor allows.

### AMM / DEX (constant-product & concentrated liquidity)
- **k-invariant:** for x*y=k pools, `k` never decreases except by fee accrual; a swap cannot reduce the invariant (guards rounding/precision drains).
- **No free arbitrage against self:** a swap-in then swap-out in the same tx (no external price change) cannot return more than input minus fees (sandwich/round-trip profitability bound).
- **LP accounting:** `burn(mint(x)) <= x`; JIT mint→swap→burn cannot extract more fees than earned by time-weighted provision; LP share value non-dilutable by atomic add/remove.
- **Price-impact sanity:** reserves and reported price stay consistent; spot price cannot be moved and read within the same tx to misprice a dependent protocol (composability guard).
- **Rounding direction:** every rounding favors the pool, never the user, cumulatively.

### Vault / yield / staking (ERC-4626-style)
- **Share-price monotonicity:** `convertToAssets(convertToShares(x)) <= x`; deposit-then-withdraw in one tx is never profitable (donation/inflation attack guard — assert first-depositor share inflation is bounded).
- **Totals consistency:** `totalAssets >= sum(convertToAssets(balanceOf(u)))`; `totalSupply` of shares matches minted shares.
- **No reward double-claim / no claim exceeding accrued:** cumulative rewards paid ≤ cumulative rewards funded.
- **Withdrawal availability:** a user's redeemable amount is never silently reduced by another user's action (no DoS on withdrawal queue).

### Bridge / cross-chain
- **Mint ⇔ lock conservation:** tokens minted on destination ≤ tokens locked/burned on source; no mint without a verified source event.
- **Message/proof uniqueness:** each cross-chain message (nonce/hash) is processed exactly once — no replay, no double-mint (the dominant bridge-hack class).
- **Signature/quorum integrity:** a withdrawal requires a valid threshold of current-validator-set signatures; validator set cannot be rotated to an attacker-controlled set without authority.
- **Guardian/pause safety:** paused state actually blocks value movement; emergency withdrawal cannot be triggered by non-authorized caller.
- **Fee/amount integrity:** amount credited on destination == amount debited on source minus declared fee; no arithmetic path lets the delta leak value.

---

## Sources

- [SoK: Decentralized Finance (DeFi) Attacks (Zhou et al., IEEE S&P 2023)](https://arxiv.org/abs/2208.13035)
- [SoK: Decentralized Finance (DeFi) (Werner et al., FC 2022)](https://arxiv.org/abs/2101.08778)
- [A Survey of DeFi Security: Challenges and Opportunities (Li et al., 2022)](https://arxiv.org/abs/2206.11821)
- [Attacking the DeFi Ecosystem with Flash Loans for Fun and Profit (Qin et al., FC 2021)](https://arxiv.org/abs/2003.03810)
- [Flash Boys 2.0 (Daian et al., IEEE S&P 2020)](https://arxiv.org/abs/1904.05234)
- [High-Frequency Trading on Decentralized On-Chain Exchanges (Zhou et al., IEEE S&P 2021)](https://arxiv.org/abs/2009.14021)
- [Quantifying Blockchain Extractable Value (Qin et al., IEEE S&P 2022)](https://arxiv.org/abs/2101.05511)
- [TWAP Oracle Attacks: Easier Done than Said? (Mackinga et al., IEEE ICBC 2022)](https://ieeexplore.ieee.org/document/9805499)
- [Demystifying JIT Liquidity Attacks on Uniswap V3 (Xiong et al., ePrint 2023/973)](https://eprint.iacr.org/2023/973)
- [Flash Crash for Cash (Oosthoek, 2021)](https://arxiv.org/abs/2106.10740)
- [Making Smart Contracts Smarter / Oyente (Luu et al., CCS 2016)](https://www.comp.nus.edu.sg/~prateeks/papers/Oyente.pdf)
- [Securify (Tsankov et al., CCS 2018)](https://arxiv.org/abs/1806.01143)
- [ZEUS: Analyzing Safety of Smart Contracts (Kalra et al., NDSS 2018)](https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_09-1_Kalra_paper.pdf)
- [teEther (Krupp & Rossow, USENIX Security 2018)](https://www.usenix.org/conference/usenixsecurity18/presentation/krupp)
- [Slither (Feist et al., WETSEB@ICSE 2019)](https://arxiv.org/abs/1908.09878)
- [Manticore (Mossberg et al., ASE 2019)](https://arxiv.org/abs/1907.03890)
- [Sereum (Rodler et al., NDSS 2019)](https://arxiv.org/abs/1812.05934)
- [ContractFuzzer (Jiang et al., ASE 2018)](https://arxiv.org/abs/1807.03932)
- [Echidna (Grieco et al., ISSTA 2020)](https://conf.researchr.org/details/issta-2020/issta-2020-tool-demonstration/5/Echidna-Effective-Usable-and-Fast-Fuzzing-for-Smart-Contracts)
- [ItyFuzz (Shou et al., ISSTA 2023)](https://arxiv.org/abs/2306.17135)
- [DeFiRanger (Wu et al., 2021 / IEEE TDSC)](https://arxiv.org/abs/2104.15068)
- [SmartBugs (Ferreira et al., ASE 2020)](https://arxiv.org/abs/2007.04771)
- [Empirical Review of Automated Analysis Tools on 47,587 Contracts (Durieux et al., ICSE 2020)](https://arxiv.org/abs/1910.10601)
- [DeFiHackLabs dataset (SunWeb3Sec)](https://github.com/SunWeb3Sec/DeFiHackLabs)
- [SmartBugs curated dataset](https://github.com/smartbugs/smartbugs)
- [SWC Registry (SmartContractSecurity)](https://github.com/SmartContractSecurity/SWC-registry)
- [DASP Top 10 (NCC Group)](https://dasp.co/)
- [OWASP Smart Contract Top 10](https://owasp.org/projects/smart-contract-top-10)
