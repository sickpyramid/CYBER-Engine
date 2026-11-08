// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {LMSRMath} from "../src/LMSRMath.sol";

// external wrapper so fuzz can try/catch the library's reverts (MathOverflow/ZeroShares)
contract Wrap {
    function cost(uint256 qA, uint256 qB, uint256 b) external pure returns (uint256) {
        return LMSRMath.cost(qA, qB, b);
    }
    function buyA(uint256 qA, uint256 qB, uint256 netIn18, uint256 b) external pure returns (uint256) {
        return LMSRMath.deltaSharesForBuy(LMSRMath.Side.A, qA, qB, netIn18, b);
    }
}

contract LMSRRoundTrip is Test {
    Wrap w = new Wrap();
    uint256 constant SCALE = 1e12; // USDC_SCALE (18->6 dec)

    // THE security property: buy side-A with usdcIn6, then immediately sell the shares you got.
    // Must NEVER return more than you paid. A counterexample = the curve can be drained.
    function test_roundTrip_noProfit(uint256 qA, uint256 qB, uint256 b, uint256 usdcIn6) public view {
        qA = bound(qA, 0, 1e24);
        qB = bound(qB, 0, 1e24);
        b  = bound(b, 1e15, 1e24);           // depth; include low-liquidity edge
        usdcIn6 = bound(usdcIn6, 1, 1e12);   // 1e-6 .. 1,000,000 USDC

        uint256 usdcIn18 = usdcIn6 * SCALE;

        // --- curveBuy(A): shares from the inverse-cost, truncated to 6-dec as the contract does ---
        uint256 shares18;
        try w.buyA(qA, qB, usdcIn18, b) returns (uint256 s) { shares18 = s; } catch { return; }
        uint256 shares6 = shares18 / SCALE;
        if (shares6 == 0) return;
        uint256 dq = shares6 * SCALE;        // contract advances qYes by the truncated amount

        // --- curveSell(A) of those exact shares: grossOut = cost(qA+dq,qB) - cost(qA,qB) ---
        uint256 cHi; uint256 cLo;
        try w.cost(qA + dq, qB, b) returns (uint256 c) { cHi = c; } catch { return; }
        try w.cost(qA, qB, b) returns (uint256 c) { cLo = c; } catch { return; }
        assertGe(cHi, cLo, "COST NON-MONOTONIC (bug)");
        uint256 grossOut6 = (cHi - cLo) / SCALE;

        // the attacker must not profit from a pure buy->sell round trip
        assertLe(grossOut6, usdcIn6, "ROUND-TRIP PROFIT: curve drainable");
    }

    // Solvency: cost is convex & increasing -> cost(q) >= cost(0,0) (collateral floor sanity)
    function test_costMonotonic(uint256 qA, uint256 qB, uint256 dq, uint256 b) public view {
        qA = bound(qA, 0, 1e24); qB = bound(qB, 0, 1e24);
        dq = bound(dq, 1, 1e23);  b = bound(b, 1e15, 1e24);
        uint256 c0; uint256 c1;
        try w.cost(qA, qB, b) returns (uint256 c) { c0 = c; } catch { return; }
        try w.cost(qA + dq, qB, b) returns (uint256 c) { c1 = c; } catch { return; }
        assertGe(c1, c0, "cost decreased when adding shares (non-monotonic)");
    }
}
