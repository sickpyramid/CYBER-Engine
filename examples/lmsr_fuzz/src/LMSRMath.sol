// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// VERBATIM copy of WagerPredict's deployed LMSRMath (curve 0xB6F097da…) economic core.
import {SD59x18, sd} from "@prb/math/src/SD59x18.sol";

library LMSRMath {
    enum Side { A, B }
    error MathOverflow();
    error ZeroShares();

    function cost(uint256 qA, uint256 qB, uint256 b) internal pure returns (uint256) {
        SD59x18 bFx = sd(int256(b));
        SD59x18 qAFx = sd(int256(qA));
        SD59x18 qBFx = sd(int256(qB));
        SD59x18 mFx = qAFx >= qBFx ? qAFx : qBFx;

        SD59x18 eA = ((qAFx - mFx) / bFx).exp();
        SD59x18 eB = ((qBFx - mFx) / bFx).exp();
        SD59x18 c = mFx + bFx * (eA + eB).ln();

        int256 raw = c.unwrap();
        return raw < 0 ? 0 : uint256(raw);
    }

    function deltaSharesForBuy(Side side, uint256 qA, uint256 qB, uint256 netIn18, uint256 b)
        internal pure returns (uint256)
    {
        SD59x18 bFx = sd(int256(b));
        SD59x18 qAFx = sd(int256(qA));
        SD59x18 qBFx = sd(int256(qB));
        SD59x18 netFx = sd(int256(netIn18));
        SD59x18 mFx = qAFx >= qBFx ? qAFx : qBFx;

        SD59x18 eA = ((qAFx - mFx) / bFx).exp();
        SD59x18 eB = ((qBFx - mFx) / bFx).exp();
        SD59x18 E = eA + eB;
        SD59x18 eIn = (netFx / bFx).exp();

        SD59x18 inner;
        SD59x18 baseFx;
        if (side == Side.A) { inner = E * eIn - eB; baseFx = qAFx; }
        else { inner = E * eIn - eA; baseFx = qBFx; }
        if (inner.unwrap() <= 0) revert MathOverflow();

        SD59x18 delta = mFx + bFx * inner.ln() - baseFx;
        int256 raw = delta.unwrap();
        if (raw <= 0) revert ZeroShares();
        return uint256(raw);
    }
}
