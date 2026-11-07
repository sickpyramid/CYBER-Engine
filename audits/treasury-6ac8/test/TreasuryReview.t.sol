// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

// UNIT TESTS ONLY. Not executed in this environment.
// These deploy the exact copied Treasury source with local mock dependencies.
// This suite does not claim a mainnet exploit, a live affected token, or profit.
import {Treasury} from "../verified/src/Treasury.sol";
import {IERC20} from "../verified/lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {ISwarmFeed} from "../verified/src/interfaces/ISwarmFeed.sol";

interface Vm {
    function prank(address) external;
    function expectRevert(bytes4) external;
    function warp(uint256) external;
    function etch(address, bytes calldata) external;
}

contract MockToken {
    mapping(address => uint256) public balanceOf;
    Treasury public target;
    bool public callbackBeforeDebit;
    bool public callbackAfterDebit;
    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
    function configure(Treasury t, bool before_, bool after_) external {
        target = t; callbackBeforeDebit = before_; callbackAfterDebit = after_;
    }
    function transfer(address to, uint256 amount) external returns (bool) {
        if (callbackBeforeDebit) target.sync(IERC20(address(this)));
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        if (callbackAfterDebit) target.sync(IERC20(address(this)));
        return true;
    }
    function decimals() external pure returns (uint8) { return 18; }
}
contract MockFeed {
    function isStale() external pure returns (bool) { return false; }
    function latestValue() external view returns (uint256, uint64) { return (1 ether,uint64(block.timestamp)); }
}
contract MockLinkedVault {
    address public parameters;
    address public stablecoin;
    address public gem;
    uint256 public totalBadDebt;
    constructor(address p, address stable_, address gem_) {
        parameters=p; stablecoin=stable_; gem=gem_;
    }
    function setBadDebt(uint256 amount) external { totalBadDebt=amount; }
    function release(Treasury t, address to, uint256 amount) external { t.redeemIMD(to,amount); }
}

contract TreasuryReviewTest {
    Vm constant vm=Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address constant OPERATOR=0xbeFd108085613662356aa26A2466Ad3426DA9C32;
    address constant RECIPIENT=address(0xA11CE);
    address public streamPayee=RECIPIENT;
    uint256 public streamPerDay=50 ether;
    uint256 public oracleBudget=15 ether;

    Treasury t;
    MockLinkedVault v;
    MockToken stable;
    MockToken collateral;
    MockToken spare;

    function setUp() public {
        stable=new MockToken(); collateral=new MockToken(); spare=new MockToken();
        v=new MockLinkedVault(address(this),address(stable),address(collateral));
        t=new Treasury(address(v));
    }
    function test_preDebitCallbackInflatesBookReceiptsWithoutExtraTransfer() public {
        spare.mint(address(t),100 ether);
        t.sync(IERC20(address(spare)));
        spare.configure(t,true,false);
        vm.prank(OPERATOR);
        t.withdraw(IERC20(address(spare)),RECIPIENT,10 ether);
        require(t.totalReceived(IERC20(address(spare)))==110 ether,"expected book inflation");
        require(spare.balanceOf(address(t))==90 ether,"Treasury balance");
        require(spare.balanceOf(RECIPIENT)==10 ether,"only authorized transfer");
    }
    function test_postDebitCallbackDoesNotInflateReceipts() public {
        spare.mint(address(t),100 ether);
        t.sync(IERC20(address(spare)));
        spare.configure(t,false,true);
        vm.prank(OPERATOR);
        t.withdraw(IERC20(address(spare)),RECIPIENT,10 ether);
        require(t.totalReceived(IERC20(address(spare)))==100 ether,"unexpected revenue");
    }
    function test_ordinaryWithdrawalCreditsUnsyncedRevenueOnce() public {
        spare.mint(address(t),100 ether);
        t.sync(IERC20(address(spare)));
        spare.mint(address(t),20 ether);
        vm.prank(OPERATOR);
        t.withdraw(IERC20(address(spare)),RECIPIENT,10 ether);
        t.sync(IERC20(address(spare)));
        require(t.totalReceived(IERC20(address(spare)))==120 ether,"receipt conservation");
    }
    function test_nonOperatorCannotWithdraw() public {
        spare.mint(address(t),100 ether);
        vm.expectRevert(Treasury.Unauthorized.selector);
        t.withdraw(IERC20(address(spare)),RECIPIENT,1 ether);
    }
    function test_nonVaultCannotRedeem() public {
        vm.expectRevert(Treasury.Unauthorized.selector);
        t.redeemIMD(RECIPIENT,1 ether);
    }
    function test_externalCallerCannotEnterUnwrapSelfCall() public {
        vm.expectRevert(Treasury.InvalidRecipient.selector);
        t.unwrapForOracle(IERC20(address(collateral)),1 ether);
    }
    function test_operatorCannotTakeCollateral() public {
        collateral.mint(address(t),100 ether);
        vm.prank(OPERATOR);
        vm.expectRevert(Treasury.ReserveProtected.selector);
        t.withdraw(IERC20(address(collateral)),RECIPIENT,1 ether);
    }
    function test_listedReserveCannotBeWithdrawnByOperator() public {
        MockFeed f=new MockFeed();
        t.setReserveAsset(IERC20(address(spare)),ISwarmFeed(address(f)),10000);
        spare.mint(address(t),100 ether);
        vm.prank(OPERATOR);
        vm.expectRevert(Treasury.ReserveProtected.selector);
        t.withdraw(IERC20(address(spare)),RECIPIENT,1 ether);
    }
    function test_badDebtFloorRestrictsStablecoinWithdrawal() public {
        stable.mint(address(t),100 ether);
        v.setBadDebt(80 ether);
        vm.prank(OPERATOR);
        vm.expectRevert(Treasury.BadDebtFirst.selector);
        t.withdraw(IERC20(address(stable)),RECIPIENT,21 ether);
        vm.prank(OPERATOR);
        t.withdraw(IERC20(address(stable)),RECIPIENT,20 ether);
        require(stable.balanceOf(address(t))==80 ether,"bad debt floor");
    }
    function test_streamRespectsDebtFloorAndDailyCap() public {
        vm.warp(10 days);
        stable.mint(address(t),100 ether);
        v.setBadDebt(80 ether);
        require(t.payStream()==20 ether,"only spare may stream");
        require(t.payStream()==0,"nothing spare");
        v.setBadDebt(0);
        require(t.payStream()==30 ether,"remaining daily allowance");
        require(t.payStream()==0,"daily cap");
        require(stable.balanceOf(RECIPIENT)==50 ether,"recipient total");
    }
}

