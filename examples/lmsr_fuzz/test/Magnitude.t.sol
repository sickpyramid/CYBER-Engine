// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "forge-std/Test.sol";
import {LMSRMath} from "../src/LMSRMath.sol";
contract Wrap2 { function cost(uint256 a,uint256 b2,uint256 b) external pure returns(uint256){ return LMSRMath.cost(a,b2,b);} }
contract Magnitude is Test {
    Wrap2 w = new Wrap2();
    uint256 constant SCALE = 1e12; // 6-dec USDC granularity in 18-dec wei
    // Is the non-monotonicity ALWAYS below the 6-dec USDC unit (SCALE)? If so the contract (which
    // works in 6-dec and rounds in its favor) fully absorbs it -> no economic impact.
    function test_nonMonotonicity_below_6dec(uint256 qA,uint256 qB,uint256 dq,uint256 b) public view {
        qA=bound(qA,0,1e24); qB=bound(qB,0,1e24); dq=bound(dq,1,1e23); b=bound(b,1e15,1e24);
        uint256 c0; uint256 c1;
        try w.cost(qA,qB,b) returns(uint256 c){c0=c;}catch{return;}
        try w.cost(qA+dq,qB,b) returns(uint256 c){c1=c;}catch{return;}
        if (c1 >= c0) return; // monotonic, fine
        uint256 drop = c0 - c1; // the artifact magnitude in 18-dec wei
        assertLt(drop, SCALE, "non-monotonicity reaches 6-dec USDC (would matter)");
    }
}
