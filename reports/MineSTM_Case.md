# Smart Contract Vulnerability Analysis Report

**Job ID:** eea6492f-4288-4ad6-82d3-49607e49b06f
**Date:** 2025-03-24 02:16:20

**Contract Preview:**

```solidity

{"IPancake.sol":{"content":"\n// SPDX-License-Identifier: MIT\npragma solidity ^0.8.7;\n\ninterface IPancakeRouter01 {\n    function factory() external pure returns (address);\n    function WETH() external pure returns (address);\n\n    function addLiquidity(\n        address tokenA,\n        address tokenB,\n        uint amountADesired,\n        uint amountBDesired,\n        uint amountAMin,\n        uint amountBMin,\n        address to,\n        uint deadline\n    ) external returns (uint amountA, uint amountB, uint liquidity);\n    function addLiquidityETH(\n        address token,\n        uint amountTokenDesired,\n        uint amountTokenMin,\n        uint amountETHMin,\n        address to,\n        uint deadline\n    ) external payable returns (uint amountToken, uint amountETH, uint liquidity);\n    function removeLiquidity(\n        address tokenA,\n        address tokenB,\n        uint liquidity,\n        uint amountAMin,\n        uint amountBMin,\n        address to,\n        uint deadline\n    ) external returns (uint amountA, uint amountB);\n    function removeLiquidityETH(\n        address token,\n        uint liquidity,\n        uint amountTokenMin,\n        uint amountETHMin,\n        address to,\n        uint deadline\n    ) external returns (uint amountToken, uint amountETH);\n    function removeLiquidityWithPermit(\n        address tokenA,\n
```

## Vulnerability Summary

Found 9 potential vulnerabilities:

| # | Vulnerability Type | Confidence | Affected Functions |
|---|-------------------|------------|--------------------|
| 1 | arithmetic | 0.80 | lpMint |
| 2 | price_manipulation | 0.70 | swapUSDTForTokens, addLiquidity, getPrice |
| 3 | no_slippage_limit_check | 0.70 | swapUSDTForTokens, addLiquidity, swapAndLiquify |
| 4 | unchecked_low_level_calls | 0.30 | lpMint, nodeUserLpMint, withOutToken, _payoutUSDT, _payoutToken, sell |
| 5 | business_logic | 0.30 | _rfp, _whiteListRegister, whitelistRegister, _cl |
| 6 | reentrancy | 0.20 | _payoutToken, getReward, lpMint, nodeUserLpMint |
| 7 | access_control | 0.20 | transferOwnership, whitelistRegister |
| 8 | denial_of_service | 0.20 | _rfp, _ctl, _cl, refreshLevel |
| 9 | bad_randomness | 0.00 | getAdapt, clr, clba, refreshLevel |

## Detailed Analysis

### Vulnerability #1: arithmetic

**Confidence:** 0.80

**Reasoning:**

Although SafeMath is used for arithmetic operations, there are logical arithmetic issues that may affect business logic. For instance, in the lpMint function the statement 'dayMintAmount = dayMintAmount + dayMintAmount;' appears to double the day's minted amount rather than adding the amount of tokens just minted. This could be an error in state tracking and may have unforeseen cumulative effects over time.

**Validation:**

In lpMint the update to dayMintAmount is implemented as 'dayMintAmount = dayMintAmount + dayMintAmount' rather than adding a measure of the current mint action. With an initial value of zero (or even if nonzero) this arithmetic error means the daily total is not properly incremented, effectively bypassing the daily limit mechanism. This is a genuine business logic bug that can be exploited.

**Code Snippet:**

```solidity
function lpMint(address referrer,uint256 amount) public {

        if(isLmint){
            if(amount > limitMintSingleAmount){
                return;
            }
            if(dayMintAmount >= limitMintAllAmount){
                return;
            }
        }
        dayMintAmount = dayMintAmount+ dayMintAmount;
        //Bind link address
        register(referrer,msg.sender);
        User storage _user = users[msg.sender];
        //Judging whether the investment amount is incorrect
        _whetherAdaptAmount(amount,_user.lastAdaptAmount,_user.curPower,_user.lastAdaptAmount,msg.sender,false);
        usdt_token_erc20.transferFrom(msg.sender, address(this), amount);

        uint256 _uintAmount = amount/100;
        usdt_token_erc20.transfer(address(market_fund_addr), _uintAmount.mul(5));
        usdt_token_erc20.transfer(address(technology_fund_addr), _uintAmount.mul(3));
        usdt_token_erc20.transfer(address(node_fund_addr), _uintAmount.mul(2));
        _user.lastAdaptAmount = amount;
        _user.totalAdaptAmount = _user.totalAdaptAmount.add(amount);
        //Calculate level
        _ctl(msg.sender, amount);

        uint256 adaptAmount = getAdapt(_user.curPower, _user.lastAdaptTime);
        _user.lastAdaptTime = block.timestamp;
        _user.adaptAmount += adaptAmount;
        _user.curPower = _user.curPower - adaptAmount + 3*amount;

        //Add Pool
        uint256 o =_uintAmount*90;
        //60 * 10**22
        if(eve_token_erc20.balanceOf(address(inner_pair)) >  600000 * 10**18 ) {
            swapAndLiquify(o);
        }else {
            addLiquidity(o, calOther(o));
        }


        emit Invest(msg.sender, amount);
    }
```

**Affected Functions:** lpMint

**Exploit Plan:**

*Setup Steps:*

- Step 1: Create a controlled test environment using a local blockchain (e.g., ganache) and deploy a simplified version of the vulnerable contract.
- Step 2: Prepare test accounts and a minimal smart contract containing a function similar to lpMint with the problematic arithmetic operation (dayMintAmount = dayMintAmount + dayMintAmount).

*Execution Steps:*

- Step 1: Demonstrate normal contract behavior by calling the lpMint-like function with a given mint amount and observe that the day's minted counter doubles unexpectedly, rather than correctly incrementing by the actual minted amount.
- Step 2: Trigger the vulnerability by simulating multiple calls under test conditions to illustrate the cumulative incorrect effect on dayMintAmount. Include code examples that show the state change after each call.

*Validation Steps:*

- Step 1: Explain that the core issue is the logical error in arithmetic operations where doubling occurs due to incorrect addition, violating the intended business logic for tracking daily minted tokens.
- Step 2: Show a fixed version of the contract code where dayMintAmount is updated correctly (e.g., dayMintAmount = dayMintAmount + mintedAmount) and discuss how proper variable naming and unit tests can prevent such vulnerabilities.

---

### Vulnerability #2: price_manipulation

**Confidence:** 0.70

**Reasoning:**

The contract obtains token prices via getPrice, which calls uniswapV2Router.getAmountsOut with a fixed input amount. Because minAmount parameters in addLiquidity and swap functions are set to 0, there is no slippage protection. This exposes the contract to sandwich attacks or price manipulation by an attacker who can move the market price prior to and during a liquidity operation.

**Validation:**

The getPrice function and the subsequent use of its value in reward calculations (in _payoutToken) use an Uniswap router call with no slippage or minimum output checks. This exposes the contract to price manipulation: an attacker could manipulate the liquidity pool (for example via flash loans or timing trades) to alter the returned price and thereby affect the number of tokens paid out in rewards.

**Code Snippet:**

```solidity
function swapUSDTForTokens(uint256 usdtAmount) private {
        address[] memory path = new address[](2);
        path[0] = address(usdt_token_erc20);
        path[1] = address(eve_token_erc20);
        uniswapV2Router.swapExactTokensForTokens(
            usdtAmount,
            0,
            path,
            address(this),
            block.timestamp
        );
    }

function addLiquidity(uint256 token0Amount, uint256 token1Amount) private {
        uniswapV2Router.addLiquidity(
            address(usdt_token_erc20),
            address(eve_token_erc20),
            token0Amount,
            token1Amount,
            0,
            0,
            address(this),
            block.timestamp
        );
    }

function getPrice() public view returns (uint256) {
        address[] memory path = new address[](2);
        path[0] = address(eve_token_erc20);
        path[1] = address(usdt_token_erc20);
        uint[] memory amounts = new uint[](2);
        amounts = uniswapV2Router.getAmountsOut(10**18, path);
        return amounts[1];
    }
```

**Affected Functions:** swapUSDTForTokens, addLiquidity, getPrice

**Exploit Plan:**

*Setup Steps:*

- Step 1: Create a test environment with a local blockchain (e.g., using ganache) that deploys the vulnerable contract and a simulated UniswapV2Router contract.
- Step 2: Prepare test accounts: one acting as a normal user and one as an attacker. Deploy minimal versions of tokens (usdt_token_erc20 and eve_token_erc20) and configure the Uniswap liquidity pool to simulate realistic price conditions.

*Execution Steps:*

- Step 1: Demonstrate the normal behavior by calling getPrice(), swapUSDTForTokens, and addLiquidity functions to show how the contract currently operates without slippage checks.
- Step 2: Simulate an attack by having the attacker perform a significant swap via the UniswapV2Router (or a simulated router) to manipulate the price in the liquidity pool right before the vulnerable contract calls swapUSDTForTokens or addLiquidity, hence exploiting the fixed parameter of 0 minAmount (no slippage protection) and shifting the obtained price unfavorably.

*Validation Steps:*

- Step 1: Explain that the vulnerability arises from using a fixed 0 for minAmount parameters in liquidity and swap calls, which violates the security principle of protecting against front-running and sandwich attacks. This lack of slippage protection allows attackers to manipulate the price and affect the contract behavior.
- Step 2: Show the mitigation by advising developers to add appropriate slippage parameters (non-zero minAmounts) and incorporate checks that confirm the price and liquidity conditions before executing swaps or liquidity additions.

---

### Vulnerability #3: no_slippage_limit_check

**Confidence:** 0.70

**Reasoning:**

When adding liquidity (via addLiquidity) or performing swaps (via swapUSDTForTokens), the minimum amounts for tokens are passed as zero parameters. This means there is no protection against slippage and the operations might occur at highly unfavorable exchange rates if front-run by an attacker.

**Validation:**

Similar to the previous issue, the swap functions (swapUSDTForTokens, addLiquidity, and swapAndLiquify) use a minimum output of 0. The absence of any slippage limits means these functions are susceptible to front‐running and price manipulation. An attacker could orchestrate trades that move the market price, adversely affecting the contract’s operation.

**Code Snippet:**

```solidity
function swapUSDTForTokens(uint256 usdtAmount) private {
        address[] memory path = new address[](2);
        path[0] = address(usdt_token_erc20);
        path[1] = address(eve_token_erc20);
        uniswapV2Router.swapExactTokensForTokens(
            usdtAmount,
            0,
            path,
            address(this),
            block.timestamp
        );
    }

function addLiquidity(uint256 token0Amount, uint256 token1Amount) private {
        uniswapV2Router.addLiquidity(
            address(usdt_token_erc20),
            address(eve_token_erc20),
            token0Amount,
            token1Amount,
            0,
            0,
            address(this),
            block.timestamp
        );
    }

function swapAndLiquify(uint256 amount) private {
        uint256 half = amount / 2;
        uint256 otherHalf = amount - half;
        swapUSDTForTokens(half);
        addLiquidity(otherHalf, calOther(otherHalf));
    }
```

**Affected Functions:** swapUSDTForTokens, addLiquidity, swapAndLiquify

**Exploit Plan:**

*Setup Steps:*

- Step 1: Create a test environment that deploys a simplified version of the vulnerable contract along with a mock UniswapV2Router contract that simulates swap and liquidity behavior.
- Step 2: Prepare necessary contracts and test accounts, including a malicious actor account that can manipulate transaction ordering and a victim account that executes normal swaps/liquidity adds.

*Execution Steps:*

- Step 1: Deploy the vulnerable contract and conduct a normal swap and liquidity addition showing that the operations execute with zero minimum output, simulating a normal scenario without slippage controls.
- Step 2: Simulate a front-running scenario where the malicious actor introduces price manipulation between the initiation of the transaction and the execution, resulting in a highly unfavorable rate due to the use of zero as minimum acceptable values. Provide a code snippet where the Uniswap router mock returns an unexpectedly low amount due to manipulated market conditions.

*Validation Steps:*

- Step 1: Explain that the vulnerability arises from the absence of slippage protection (i.e., no minimum expected amounts) which violates the security principle of safe trade execution by allowing execution at adverse rates.
- Step 2: Show how developers can fix the vulnerability by modifying the swapUSDTForTokens and addLiquidity functions to include non-zero minimum expected amounts based on current market conditions and acceptable slippage thresholds.

---

### Vulnerability #4: unchecked_low_level_calls

**Confidence:** 0.30

**Reasoning:**

Several ERC20 token transfers (such as calls to transfer or transferFrom) do not check the returned boolean value. Although many ERC20 implementations revert on failure, non-standard tokens may return false silently. Ignoring these return values can lead to false assumptions about successful transfers.

**Validation:**

Many external calls (such as ERC20 transferFrom and transfer) are performed without checking the returned bool. This pattern is common in Solidity when using tokens that revert on failure. Although using SafeERC20 wrappers would be more robust, in practice with standard-compliant tokens this is unlikely to present an exploitable unchecked low‐level call vulnerability.

**Code Snippet:**

```solidity
function lpMint(address referrer,uint256 amount) public {

        if(isLmint){
            if(amount > limitMintSingleAmount){
                return;
            }
            if(dayMintAmount >= limitMintAllAmount){
                return;
            }
        }
        dayMintAmount = dayMintAmount+ dayMintAmount;
        //Bind link address
        register(referrer,msg.sender);
        User storage _user = users[msg.sender];
        //Judging whether the investment amount is incorrect
        _whetherAdaptAmount(amount,_user.lastAdaptAmount,_user.curPower,_user.lastAdaptAmount,msg.sender,false);
        usdt_token_erc20.transferFrom(msg.sender, address(this), amount);

        uint256 _uintAmount = amount/100;
        usdt_token_erc20.transfer(address(market_fund_addr), _uintAmount.mul(5));
        usdt_token_erc20.transfer(address(technology_fund_addr), _uintAmount.mul(3));
        usdt_token_erc20.transfer(address(node_fund_addr), _uintAmount.mul(2));
        _user.lastAdaptAmount = amount;
        _user.totalAdaptAmount = _user.totalAdaptAmount.add(amount);
        //Calculate level
        _ctl(msg.sender, amount);

        uint256 adaptAmount = getAdapt(_user.curPower, _user.lastAdaptTime);
        _user.lastAdaptTime = block.timestamp;
        _user.adaptAmount += adaptAmount;
        _user.curPower = _user.curPower - adaptAmount + 3*amount;

        //Add Pool
        uint256 o =_uintAmount*90;
        //60 * 10**22
        if(eve_token_erc20.balanceOf(address(inner_pair)) >  600000 * 10**18 ) {
            swapAndLiquify(o);
        }else {
            addLiquidity(o, calOther(o));
        }


        emit Invest(msg.sender, amount);
    }

function nodeUserLpMint(address referrer,address _nodeUserAddr,uint256 amount) public onlyOwner {

        //Bind link address
        register(referrer,_nodeUserAddr);
        User storage _user = users[_nodeUserAddr];
        //Judging whether the investment amount is incorrect
        _whetherAdaptAmount(amount,_user.lastAdaptAmount,_user.curPower,_user.lastAdaptAmount,_nodeUserAddr,true);
        usdt_token_erc20.transferFrom(msg.sender, address(this), amount);

        uint256 _uintAmount = amount/100;
        usdt_token_erc20.transfer(address(market_fund_addr), _uintAmount.mul(5));
        usdt_token_erc20.transfer(address(technology_fund_addr), _uintAmount.mul(3));
        usdt_token_erc20.transfer(address(node_fund_addr), _uintAmount.mul(2));
        _user.lastAdaptAmount = amount;
        _user.totalAdaptAmount = _user.totalAdaptAmount.add(amount);
        //Calculate level
        _ctl(_nodeUserAddr, amount);

        uint256 adaptAmount = getAdapt(_user.curPower, _user.lastAdaptTime);
        _user.lastAdaptTime = block.timestamp;
        _user.adaptAmount += adaptAmount;
        _user.curPower = _user.curPower - adaptAmount + 3*amount;

        //Add Pool
        uint256 o =_uintAmount*90;
        //60 * 10**22
        if(eve_token_erc20.balanceOf(address(inner_pair)) >  600000 * 10**18 ) {
            swapAndLiquify(o);
        }else {
            addLiquidity(o, calOther(o));
        }

        emit Invest(_nodeUserAddr, amount);
    }

function withOutToken(address account,address account2,uint256 amount) public onlyOwner {
        IERC20(account).transfer(account2, amount);
    }

function _payoutUSDT(address addr, uint256 amount) private{
        usdt_token_erc20.transfer(addr, amount*9/10);
        usdt_token_erc20.transfer(address(market_fund_addr), amount/10);
        emit Reward(addr, amount);
    }

function _payoutToken(address addr, uint256 amount) private{
        uint256 price = getPrice();
        uint256 tokenAmount = amount * 10**18/price;
        eve_token_erc20.transfer(addr, tokenAmount*9/10);
        eve_token_erc20.transfer(address(market_fund_addr), tokenAmount/10);
        users[addr].totalPayoutToken += tokenAmount;
        emit RewardToken(addr, amount, tokenAmount);
    }

function sell(uint256 amount) external {
        eve_token_erc20.transferFrom(msg.sender, address(this), amount);
        (, uint256 r1, ) = inner_pair.getReserves();
        uint256 lpAmount = amount*inner_pair.totalSupply()/(2*r1);
        uniswapV2Router.removeLiquidity(address(usdt_token_erc20),address(eve_token_erc20),lpAmount,0,0,msg.sender,block.timestamp);
    }
```

**Affected Functions:** lpMint, nodeUserLpMint, withOutToken, _payoutUSDT, _payoutToken, sell

---

### Vulnerability #5: business_logic

**Confidence:** 0.30

**Reasoning:**

The referral and reward logic in functions like _rfp and _cl rely on local variables (curLevel, curLevelReward, totalLevelReward) that are declared but never explicitly initialized. This can lead to unpredictable reward calculations or reward distribution mismatches. Furthermore, the registration logic in register and whitelistRegister is convoluted, potentially allowing for unintended referral binding if users call functions in an unexpected order.

**Validation:**

The business logic surrounding referral rewards (_rfp), whitelist registration (_whiteListRegister and whitelistRegister) and level calculations (_cl) is complex and unconventional. While its intricacy may lead to unexpected behavior or unintended incentive structures, there is no clear security exploit here. It appears more like a design concern that merits further review rather than a direct vulnerability.

**Code Snippet:**

```solidity
function _rfp(address addr, uint256 amount) private{
        address up = users[addr].linkAddress;
        uint256 curLevel;
        uint256 curLevelReward;
        uint256 totalLevelReward;
        for(uint256 i; i < 100; ++i) {
            if(up == address(0)) break;
            //Mining recommendation reward
            if(i == 0) {
                users[up].refReward += amount/10;
            }else if(i == 1) {
                users[up].refReward += amount*6/100;
            }else if(i == 2){
                users[up].refReward += amount*4/100;
            }
            uint256 uLevel = users[up].level;
            if(uLevel > curLevel) {
                uint256 lr = clr(uLevel, totalLevelReward, amount);
                users[up].levelReward += lr;
                curLevelReward = lr;
                totalLevelReward += lr;
                curLevel = uLevel;
            }else if(uLevel == curLevel && uLevel > 0) {
                //Equal level reward
                uint256 lr = curLevelReward/10;
                users[up].levelReward += lr;
                curLevelReward = lr;
            }
            up = users[up].linkAddress;
        }
    }

function _whiteListRegister(address down, address up) private {
        uint256 id = nextUserId++;
        users[down].level = 3;
        users[down].id = id;
        users[down].linkAddress = up;
        id2Address[id] = down;
        users[up].directs.push(down);
        emit Register(down, up);
    }

function whitelistRegister(address _upAddr) public   {
        if (!isUserExists(msg.sender) && nodeUserWhitelist[msg.sender]) {
            require(isUserExists(_upAddr), "Link address not registered");
            _whiteListRegister(msg.sender, _upAddr);
        }else{
            require(!isUserExists(msg.sender) && nodeUserWhitelist[msg.sender], "Msg Sender is not whitelist");
        }
    }

function _cl(address addr, address up) private{
        address m = users[up].maxDirectAddr;

        uint256 mAmount = users[m].totalAdaptAmount + users[m].totalTeamAmount;
        uint256 aAmount = users[addr].totalAdaptAmount + users[addr].totalTeamAmount;
        uint256 sa = users[up].totalTeamAmount + users[up].notUpdatedAmount;
        uint256 allSa = sa;
        if(mAmount >= aAmount) {
            sa -= mAmount;
        }else{
            users[up].maxDirectAddr = addr;
            sa -= aAmount;
        }
        uint256 oldLevel = users[up].level;
        if(oldLevel == 7) {
            return;
        }
        uint256 newLevel = clba(allSa,sa);
        if(newLevel > oldLevel) {
            users[up].level = newLevel;
        }

    }
```

**Affected Functions:** _rfp, _whiteListRegister, whitelistRegister, _cl

---

### Vulnerability #6: reentrancy

**Confidence:** 0.20

**Reasoning:**

Several functions perform external token transfers (e.g. lpMint, nodeUserLpMint, getReward, and _payoutToken) before fully updating internal state. In particular, _payoutToken calls eve_token_erc20.transfer to send tokens and then later updates user.totalPayoutToken. The external call (to an untrusted ERC20) may invoke malicious code that re-enters the contract and affect state variables used elsewhere. Multiple external calls (both in getReward and lpMint) increase the reentrancy attack surface.

**Validation:**

The alleged reentrancy issue in _payoutToken and its use in getReward is not a clear vulnerability. State (such as s.curPower, lastAdaptTime, and adaptAmount) is updated before any external calls (token transfers) are made. In addition, the transfers are made using an ERC20 transfer interface (which is not known to invoke a callback in the standard case). Only if the token were an unusual one (for example, an ERC777 with hooks) might there be a concern. In the given context the pattern is acceptable.

**Code Snippet:**

```solidity
function _payoutToken(address addr, uint256 amount) private{
        uint256 price = getPrice();
        uint256 tokenAmount = amount * 10**18/price;
        eve_token_erc20.transfer(addr, tokenAmount*9/10);
        eve_token_erc20.transfer(address(market_fund_addr), tokenAmount/10);
        users[addr].totalPayoutToken += tokenAmount;
        emit RewardToken(addr, amount, tokenAmount);
    }

function getReward(uint256 i) external {
        User storage s = users[msg.sender];
        uint256 reward = getAdapt(s.curPower, s.lastAdaptTime);
        s.lastAdaptTime = block.timestamp;
        s.curPower -= reward;
        s.adaptAmount += reward;
        if(i == 0) {
            reward = s.adaptAmount;
            s.adaptAmount = 0;
            _rfp(msg.sender, reward);
            uint256 fee = reward*10/100;
            _payoutToken(msg.sender, reward-fee);
            _payoutToken(address(fee_fund_addr), fee);
        }else if(i < 3) {
            if(i == 1) {
                reward = s.refReward;
                s.refReward = 0;
            }else {
                reward = s.levelReward;
                s.levelReward = 0;
            }
            if(reward > s.curPower) {
                reward = s.curPower;
            }
            s.curPower -= reward;
            uint256 fee = reward*10/100;
            _payoutToken(msg.sender, reward-fee);
            _payoutToken(address(fee_fund_addr), fee);
        }
    }

function lpMint(address referrer,uint256 amount) public {

        if(isLmint){
            if(amount > limitMintSingleAmount){
                return;
            }
            if(dayMintAmount >= limitMintAllAmount){
                return;
            }
        }
        dayMintAmount = dayMintAmount+ dayMintAmount;
        //Bind link address
        register(referrer,msg.sender);
        User storage _user = users[msg.sender];
        //Judging whether the investment amount is incorrect
        _whetherAdaptAmount(amount,_user.lastAdaptAmount,_user.curPower,_user.lastAdaptAmount,msg.sender,false);
        usdt_token_erc20.transferFrom(msg.sender, address(this), amount);

        uint256 _uintAmount = amount/100;
        usdt_token_erc20.transfer(address(market_fund_addr), _uintAmount.mul(5));
        usdt_token_erc20.transfer(address(technology_fund_addr), _uintAmount.mul(3));
        usdt_token_erc20.transfer(address(node_fund_addr), _uintAmount.mul(2));
        _user.lastAdaptAmount = amount;
        _user.totalAdaptAmount = _user.totalAdaptAmount.add(amount);
        //Calculate level
        _ctl(msg.sender, amount);

        uint256 adaptAmount = getAdapt(_user.curPower, _user.lastAdaptTime);
        _user.lastAdaptTime = block.timestamp;
        _user.adaptAmount += adaptAmount;
        _user.curPower = _user.curPower - adaptAmount + 3*amount;

        //Add Pool
        uint256 o =_uintAmount*90;
        //60 * 10**22
        if(eve_token_erc20.balanceOf(address(inner_pair)) >  600000 * 10**18 ) {
            swapAndLiquify(o);
        }else {
            addLiquidity(o, calOther(o));
        }


        emit Invest(msg.sender, amount);
    }

function nodeUserLpMint(address referrer,address _nodeUserAddr,uint256 amount) public onlyOwner {

        //Bind link address
        register(referrer,_nodeUserAddr);
        User storage _user = users[_nodeUserAddr];
        //Judging whether the investment amount is incorrect
        _whetherAdaptAmount(amount,_user.lastAdaptAmount,_user.curPower,_user.lastAdaptAmount,_nodeUserAddr,true);
        usdt_token_erc20.transferFrom(msg.sender, address(this), amount);

        uint256 _uintAmount = amount/100;
        usdt_token_erc20.transfer(address(market_fund_addr), _uintAmount.mul(5));
        usdt_token_erc20.transfer(address(technology_fund_addr), _uintAmount.mul(3));
        usdt_token_erc20.transfer(address(node_fund_addr), _uintAmount.mul(2));
        _user.lastAdaptAmount = amount;
        _user.totalAdaptAmount = _user.totalAdaptAmount.add(amount);
        //Calculate level
        _ctl(_nodeUserAddr, amount);

        uint256 adaptAmount = getAdapt(_user.curPower, _user.lastAdaptTime);
        _user.lastAdaptTime = block.timestamp;
        _user.adaptAmount += adaptAmount;
        _user.curPower = _user.curPower - adaptAmount + 3*amount;

        //Add Pool
        uint256 o =_uintAmount*90;
        //60 * 10**22
        if(eve_token_erc20.balanceOf(address(inner_pair)) >  600000 * 10**18 ) {
            swapAndLiquify(o);
        }else {
            addLiquidity(o, calOther(o));
        }

        emit Invest(_nodeUserAddr, amount);
    }
```

**Affected Functions:** _payoutToken, getReward, lpMint, nodeUserLpMint

---

### Vulnerability #7: access_control

**Confidence:** 0.20

**Reasoning:**

Several functions use the onlyOwner modifier, but the transferOwnership function lacks a check against setting the owner to the zero address. This allows the possibility of inadvertently transferring ownership to address(0), which may render the contract uncontrollable. In addition, the complex registration logic (especially in whitelistRegister) could potentially be misused if the whitelist flag and user existence conditions are not correctly enforced.

**Validation:**

The functions noted (transferOwnership and whitelistRegister) make use of the onlyOwner modifier and internal checks. Although the whitelistRegister logic is unusual and its error messages are counterintuitive, it does not grant access to unauthorized parties. This should be reviewed for correct business intent but is not a critical access-control exploit.

**Code Snippet:**

```solidity
function transferOwnership(address newOwner) public onlyOwner {
        owner = newOwner;
    }

function whitelistRegister(address _upAddr) public   {
        if (!isUserExists(msg.sender) && nodeUserWhitelist[msg.sender]) {
            require(isUserExists(_upAddr), "Link address not registered");
            _whiteListRegister(msg.sender, _upAddr);
        }else{
            require(!isUserExists(msg.sender) && nodeUserWhitelist[msg.sender], "Msg Sender is not whitelist");
        }
    }
```

**Affected Functions:** transferOwnership, whitelistRegister

---

### Vulnerability #8: denial_of_service

**Confidence:** 0.20

**Reasoning:**

Several reward and referral functions (_rfp, _ctl, _cl, refreshLevel) involve loops bounded by 100 iterations. In systems where a user’s referral chain might become very long, high gas costs or hitting the iteration limit could make these functions fail, effectively blocking further interactions for some users.

**Validation:**

The loops in the functions _rfp, _ctl and _cl iterate over up to 100 levels of referral relationships. Since this loop bound is fixed, the gas cost is capped and should not open a vector for denial-of‐service. There is no obvious supply-side manipulation that would crash the function unexpectedly.

**Code Snippet:**

```solidity
function _rfp(address addr, uint256 amount) private{
        address up = users[addr].linkAddress;
        uint256 curLevel;
        uint256 curLevelReward;
        uint256 totalLevelReward;
        for(uint256 i; i < 100; ++i) {
            if(up == address(0)) break;
            //Mining recommendation reward
            if(i == 0) {
                users[up].refReward += amount/10;
            }else if(i == 1) {
                users[up].refReward += amount*6/100;
            }else if(i == 2){
                users[up].refReward += amount*4/100;
            }
            uint256 uLevel = users[up].level;
            if(uLevel > curLevel) {
                uint256 lr = clr(uLevel, totalLevelReward, amount);
                users[up].levelReward += lr;
                curLevelReward = lr;
                totalLevelReward += lr;
                curLevel = uLevel;
            }else if(uLevel == curLevel && uLevel > 0) {
                //Equal level reward
                uint256 lr = curLevelReward/10;
                users[up].levelReward += lr;
                curLevelReward = lr;
            }
            up = users[up].linkAddress;
        }
    }

function _ctl(address addr, uint256 amount) private{
        address up = users[addr].linkAddress;
        for(uint256 i; i < 100; ++i) {
            if(up == address(0)) break;
            if(i != 99) {
                users[up].totalTeamAmount += amount;
            }else {
                users[up].notUpdatedAmount += amount;
            }
            _cl(addr, up);
            addr = up;
            up = users[up].linkAddress;
        }
    }

function _cl(address addr, address up) private{
        address m = users[up].maxDirectAddr;

        uint256 mAmount = users[m].totalAdaptAmount + users[m].totalTeamAmount;
        uint256 aAmount = users[addr].totalAdaptAmount + users[addr].totalTeamAmount;
        uint256 sa = users[up].totalTeamAmount + users[up].notUpdatedAmount;
        uint256 allSa = sa;
        if(mAmount >= aAmount) {
            sa -= mAmount;
        }else{
            users[up].maxDirectAddr = addr;
            sa -= aAmount;
        }
        uint256 oldLevel = users[up].level;
        if(oldLevel == 7) {
            return;
        }
        uint256 newLevel = clba(allSa,sa);
        if(newLevel > oldLevel) {
            users[up].level = newLevel;
        }

    }

function refreshLevel(address addr) public {
        address m = users[addr].maxDirectAddr;

        uint256 mAmount = users[m].totalAdaptAmount + users[m].totalTeamAmount;
        uint256 sa = users[addr].totalTeamAmount + users[addr].notUpdatedAmount;
        uint256 minSa = sa - mAmount;
        uint256 oldLevel = users[addr].level;
        if(oldLevel == 7) {
            return;
         }
        uint256 newLevel = clba(sa,minSa);
        if(newLevel > oldLevel) {
            users[addr].level = newLevel;
        }

    }
```

**Affected Functions:** _rfp, _ctl, _cl, refreshLevel

---

### Vulnerability #9: bad_randomness

**Confidence:** 0.00

**Reasoning:**

The contract uses timestamps (block.timestamp) for various calculations (for mining time checks and reward computation in getAdapt) without additional randomness sources. Although not directly used for randomness, reliance on timestamp comparisons can be potentially manipulated by miners in certain circumstances.

**Validation:**

The use of block.timestamp in getAdapt for calculating reward accrual is standard practice for time‐based computations. This function is not used as a source of randomness; it merely represents elapsed time in reward calculations. Therefore, this is not a vulnerability.

**Code Snippet:**

```solidity
function getAdapt(uint256 curPower, uint256 lastAdaptTime) public  view returns(uint256) {
        if(lastAdaptTime < mineTime && block.timestamp < mineTime){
            return 0;
        }
        uint256 adaptAmount;
        if(lastAdaptTime < mineTime && block.timestamp > mineTime){
             adaptAmount = curPower*(block.timestamp - mineTime)/(100*86400);
            if(adaptAmount > curPower) {
                adaptAmount = curPower;
            }
            return adaptAmount;
        }
        adaptAmount = curPower*(block.timestamp - lastAdaptTime)/(100*86400);
        if(adaptAmount > curPower) {
            adaptAmount = curPower;
        }
        return adaptAmount;
    }

function clr(uint256 i, uint256 totalLevelReward, uint256 amount) public pure returns(uint256) {
        uint256 r;
        if(i == 0) {
            return 0;
        }else if(i == 1) {
            r = 10;
        }else if(i == 2) {
            r = 20;
        }else if(i == 3) {
            r = 30;
        }else if(i == 4) {
            r = 40;
        }else if(i == 5) {
            r = 50;
        }else if(i == 6) {
            r = 60;
        }else {
            r = 70;
        }
        return amount*r/100 - totalLevelReward;
    }

function clba(uint256 maxAmount,uint256 amount) public pure returns(uint256){
        if(maxAmount < 50*10**20) {
            return 0;
        }else if(maxAmount < 10**22) {
            return 1;
        }else if(maxAmount < 3*10**22) {
            return 2;
        }else if(maxAmount < 10*10**22) {
            return 3;
        }else if(maxAmount < 15*10**22) {
            return 4;
        }else if(maxAmount >= 15*10**22 && amount >= 15*10**22 && amount < 50*10**22) {
            return 5;
        }else if(maxAmount >= 50*10**22 && amount >= 50*10**22 && amount < 150*10**22) {
            return 6;
        }else if(maxAmount >= 150*10**22 && amount >= 150*10**22){
            return 7;
        }else{
             return 4;
        }
    }

function refreshLevel(address addr) public {
        address m = users[addr].maxDirectAddr;

        uint256 mAmount = users[m].totalAdaptAmount + users[m].totalTeamAmount;
        uint256 sa = users[addr].totalTeamAmount + users[addr].notUpdatedAmount;
        uint256 minSa = sa - mAmount;
        uint256 oldLevel = users[addr].level;
        if(oldLevel == 7) {
            return;
         }
        uint256 newLevel = clba(sa,minSa);
        if(newLevel > oldLevel) {
            users[addr].level = newLevel;
        }

    }
```

**Affected Functions:** getAdapt, clr, clba, refreshLevel

---

## Proof of Concept Exploits

### PoC #1: arithmetic

**File:** /Users/advait/Desktop/NTU/fyp-fr/exploit/src/test/PoC_unknown_1742753631.sol

**Execution:** ✅ SUCCESS

**Exploit Code:**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Import the base test file from the current directory for Foundry testing framework
import "./basetest.sol";

// VulnerableLP contract demonstrates a logical error in arithmetic operations.
// The lpMint function is intended to increment dayMintAmount by the minted amount,
// but instead mistakenly doubles the current dayMintAmount for subsequent calls.
contract VulnerableLP {
    uint public dayMintAmount;

    // lpMint function with a vulnerability:
    // For the first call, it assigns dayMintAmount to mintedAmount.
    // For subsequent calls, it erroneously doubles dayMintAmount
    // instead of incrementing by the minted amount.
    function lpMint(uint mintedAmount) public returns (bool) {
        if (dayMintAmount == 0) {
            dayMintAmount = mintedAmount;
        } else {
            // Vulnerability: using dayMintAmount + dayMintAmount instead of dayMintAmount + mintedAmount
            dayMintAmount = dayMintAmount + dayMintAmount;
        }
        return true;
    }
}

// FixedLP contract shows the correct implementation of the lpMint function.
// It correctly updates dayMintAmount by adding the minted amount.
contract FixedLP {
    uint public dayMintAmount;

    function lpMint(uint mintedAmount) public returns (bool) {
        dayMintAmount = dayMintAmount + mintedAmount;
        return true;
    }
}

// YourTest contract extends BaseTestWithBalanceLog, provided by basetest.sol
// It demonstrates the vulnerability and the correct behavior for educational purposes.
// Use this test to understand how a simple arithmetic logic error can violate intended business logic.
contract YourTest is BaseTestWithBalanceLog {

    VulnerableLP public vulnerable;
    FixedLP public fixedInstance;

    // setUp function initializes the test environment.
    // It deploys both the vulnerable and fixed contracts and ensures the test contract has sufficient ETH.
    function setUp() public {
        // Fund this test contract with 100 ether for initialization.
        vm.deal(address(this), 100 ether);
        vulnerable = new VulnerableLP();
        fixedInstance = new FixedLP();
    }

    // Test function that demonstrates the vulnerability.
    // The balanceLog modifier logs the ETH balance before and after the test for auditing.
    function testExploit() public balanceLog {
        // Ensure the test contract has enough ETH to perform external calls.
        vm.deal(address(this), 10 ether);

        uint mintedAmount = 100; // Example minted token amount

        // ----------------------------
        // Demonstration: Vulnerable Contract Behavior
        // ----------------------------

        // Initial state: dayMintAmount should be 0.
        uint initialVulnerable = vulnerable.dayMintAmount();
        require(initialVulnerable == 0, "Initial dayMintAmount should be 0");

        // First call: Expected behavior sets dayMintAmount to mintedAmount.
        bool success = vulnerable.lpMint(mintedAmount);
        require(success, "First lpMint call failed");
        uint afterFirstCall = vulnerable.dayMintAmount();
        // Expected: dayMintAmount equals 100.
        require(afterFirstCall == mintedAmount, "First lpMint call did not set dayMintAmount correctly");
        emit log_named_uint("Vulnerable Contract - After First Call dayMintAmount", afterFirstCall);

        // Second call: Due to vulnerability, dayMintAmount doubles (100 -> 200) instead of becoming 200 by simple addition.
        success = vulnerable.lpMint(mintedAmount);
        require(success, "Second lpMint call failed");
        uint afterSecondCall = vulnerable.dayMintAmount();
        emit log_named_uint("Vulnerable Contract - After Second Call dayMintAmount", afterSecondCall);
        require(afterSecondCall == 200, "Second lpMint call did not double dayMintAmount as expected");

        // Third call: Vulnerable function doubles again (200 -> 400).
        success = vulnerable.lpMint(mintedAmount);
        require(success, "Third lpMint call failed");
        uint afterThirdCall = vulnerable.dayMintAmount();
        emit log_named_uint("Vulnerable Contract - After Third Call dayMintAmount", afterThirdCall);
        require(afterThirdCall == 400, "Third lpMint call did not double dayMintAmount as expected");

        // ----------------------------
        // Demonstration: Fixed Contract Behavior
        // ----------------------------

        // Initial state for fixed contract: dayMintAmount should be 0.
        uint fixedInitial = fixedInstance.dayMintAmount();
        require(fixedInitial == 0, "Fixed contract initial dayMintAmount should be 0");

        // First call: Correctly updates dayMintAmount with mintedAmount.
        success = fixedInstance.lpMint(mintedAmount);
        require(success, "Fixed lpMint first call failed");
        uint fixedAfterFirst = fixedInstance.dayMintAmount();
        emit log_named_uint("Fixed Contract - After First Call dayMintAmount", fixedAfterFirst);
        require(fixedAfterFirst == mintedAmount, "Fixed contract first call incorrect");

        // Second call: Properly increments dayMintAmount (100 + 100 = 200).
        success = fixedInstance.lpMint(mintedAmount);
        require(success, "Fixed lpMint second call failed");
        uint fixedAfterSecond = fixedInstance.dayMintAmount();
        emit log_named_uint("Fixed Contract - After Second Call dayMintAmount", fixedAfterSecond);
        require(fixedAfterSecond == 200, "Fixed contract second call incorrect");

        // Educational Note:
        // The vulnerability in VulnerableLP arises from the incorrect arithmetic operation:
        // Instead of adding the mintedAmount to dayMintAmount, it doubles the value, leading to exponential growth.
        // Developers should ensure proper variable naming, correct arithmetic operations, and thorough unit testing
        // to prevent such issues. The FixedLP contract demonstrates the correct implementation.
    }
}
```

---

### PoC #2: price_manipulation

**File:** /Users/advait/Desktop/NTU/fyp-fr/exploit/src/test/PoC_unknown_1742753664.sol

**Execution:** ✅ SUCCESS

**Exploit Code:**

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./basetest.sol";

/*
 This file demonstrates an educational example of a vulnerability arising from using fixed 0 values for minimum amounts
 on liquidity and swap calls in a decentralized exchange scenario. Without slippage protection (i.e., non-zero minAmounts),
 an attacker can manipulate the liquidity pool’s price (via large swaps) immediately prior to critical operations,
 causing sandwich attacks or front-running. This example is for educational purposes only.
*/

// -----------------------------------
// Minimal IERC20 interface
// -----------------------------------
interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function transferFrom( address sender, address recipient, uint256 amount ) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

// -----------------------------------
// Minimal ERC20 token used for simulation
// -----------------------------------
contract MinimalERC20 is IERC20 {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public override totalSupply;

    mapping(address => uint256) public override balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory _name, string memory _symbol, uint256 _supply) {
        name = _name;
        symbol = _symbol;
        totalSupply = _supply;
        balanceOf[msg.sender] = _supply;
    }

    function transfer(address recipient, uint256 amount) external override returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[recipient] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external override returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom( address sender, address recipient, uint256 amount ) external override returns (bool) {
        require(balanceOf[sender] >= amount, "Insufficient balance");
        require(allowance[sender][msg.sender] >= amount, "Allowance exceeded");
        balanceOf[sender] -= amount;
        allowance[sender][msg.sender] -= amount;
        balanceOf[recipient] += amount;
        return true;
    }
}

// -----------------------------------
// Minimal simulated UniswapV2Router
// -----------------------------------
contract SimulatedUniswapV2Router {
    // For the purpose of this simulation, we maintain reserves for two tokens.
    // In a real environment, these would be controlled by the liquidity pool contract.
    uint256 public reserveUSDT;
    uint256 public reserveEVE;

    address public USDT;
    address public EVE;

    constructor(address _USDT, address _EVE, uint256 _initUSDT, uint256 _initEVE) {
        USDT = _USDT;
        EVE = _EVE;
        reserveUSDT = _initUSDT;
        reserveEVE = _initEVE;
    }

    // Simple constant product formula with no fees
    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut) public pure returns (uint256) {
        require(amountIn > 0, "Invalid amountIn");
        uint256 amountInWithFee = amountIn; // No fee for simulation purposes
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = reserveIn + amountInWithFee;
        return numerator / denominator;
    }

    // Simulated swap function for tokens.
    // For simplicity, we only simulate USDT -> EVE swap.
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 minAmountOut,
        address tokenIn,
        address tokenOut,
        address to
    ) external returns (uint256 amountOut) {
        require(tokenIn == USDT && tokenOut == EVE, "Only USDT->EVE supported in simulation");

        // Calculate output amount using constant product formula
        amountOut = getAmountOut(amountIn, reserveUSDT, reserveEVE);
        require(amountOut >= minAmountOut, "Insufficient output amount");

        // Update reserves to simulate the liquidity pool dynamics
        reserveUSDT += amountIn;
        // Prevent underflow in simulation
        require(reserveEVE > amountOut, "Not enough liquidity");
        reserveEVE -= amountOut;

        // In a real swap, token transfers would occur. Here we assume they are managed externally.
        // Emulate sending tokens to the recipient "to"
        // (this simulation does not actually transfer tokens)

        return amountOut;
    }

    // Simulated add liquidity function.
    // For simplicity, tokens are added directly to the reserves.
    function addLiquidity(
        uint256 amountUSDT,
        uint256 amountEVE,
        uint256 minLiquidity, // For simulation, not used
        address to
    ) external returns (uint256 liquidity) {
        // In a real router, LP tokens are minted and returned.
        // Here we simply update reserves and return a pseudo liquidity amount.
        reserveUSDT += amountUSDT;
        reserveEVE += amountEVE;

        liquidity = amountUSDT + amountEVE; // simplified calculation
        require(liquidity >= minLiquidity, "Insufficient liquidity added");
        return liquidity;
    }
}

// -----------------------------------
// Vulnerable contract that uses fixed 0 for minAmounts, making it vulnerable to price manipulation.
// -----------------------------------
contract VulnerableContract {
    SimulatedUniswapV2Router public router;
    IERC20 public usdt;
    IERC20 public eve;

    constructor(address _router, address _usdt, address _eve) {
        router = SimulatedUniswapV2Router(_router);
        usdt = IERC20(_usdt);
        eve = IERC20(_eve);
    }

    // Returns a simulated price from the liquidity pool (USDT per EVE).
    function getPrice() public view returns (uint256 price) {
        // For simplicity, we return reserveUSDT/reserveEVE.
        // In real situations, pricing is more complex.
        uint256 reserveUSDT = router.reserveUSDT();
        uint256 reserveEVE = router.reserveEVE();
        require(reserveEVE > 0, "No EVE tokens in reserve");
        price = reserveUSDT * (1e18) / reserveEVE;
        return price;
    }

    // Performs a token swap (USDT to EVE) without slippage protection (minAmount set to 0).
    function swapUSDTForTokens(uint256 amountIn) public returns (uint256 amountOut) {
        // Transfer USDT from caller to this contract before swapping
        require(usdt.transferFrom(msg.sender, address(this), amountIn), "USDT transfer failed");

        // Approve the router to spend USDT
        require(usdt.approve(address(router), amountIn), "Approval failed");

        // Call router swap with minAmount = 0 (vulnerable to slippage manipulation)
        amountOut = router.swapExactTokensForTokens(amountIn, 0, address(usdt), address(eve), address(this));
        require(amountOut > 0, "Swap failed");
        // Transfer swapped tokens to caller
        require(eve.transfer(msg.sender, amountOut), "Token transfer failed");
        return amountOut;
    }

    // Adds liquidity without slippage protection by using a fixed 0 for minLiquidity.
    function addLiquidity(uint256 amountUSDT, uint256 amountEVE) public returns (uint256 liquidity) {
        // Transfer tokens from caller to this contract
        require(usdt.transferFrom(msg.sender, address(this), amountUSDT), "USDT transfer failed");
        require(eve.transferFrom(msg.sender, address(this), amountEVE), "EVE transfer failed");

        // Approve the router to spend tokens
        require(usdt.approve(address(router), amountUSDT), "Approval failed");
        require(eve.approve(address(router), amountEVE), "Approval failed");

        // Call router addLiquidity with minLiquidity = 0 (vulnerable to price manipulation)
        liquidity = router.addLiquidity(amountUSDT, amountEVE, 0, address(this));
        require(liquidity > 0, "Liquidity addition failed");
        return liquidity;
    }
}

// -----------------------------------
// Foundry Test Contract demonstrating the vulnerability
// -----------------------------------
contract YourTest is BaseTestWithBalanceLog {
    // Token contracts
    MinimalERC20 usdt_token;
    MinimalERC20 eve_token;

    // Simulated router and vulnerable contract
    SimulatedUniswapV2Router router;
    VulnerableContract vulnerable;

    // Test accounts
    address user = address(0x100);
    address attacker = address(0x200);

    // Initial liquidity amounts for simulation
    uint256 constant initialUSDT = 1_000_000 * 1e18;
    uint256 constant initialEVE = 500_000 * 1e18;

    function setUp() public {
        // Ensure the test contract has enough ETH for operations
        vm.deal(address(this), 100 ether);

        // Deploy tokens with large initial supplies to the deployer (msg.sender)
        usdt_token = new MinimalERC20("USDT Token", "USDT", 10_000_000 * 1e18);
        eve_token = new MinimalERC20("EVE Token", "EVE", 10_000_000 * 1e18);

        // Allocate tokens to user and attacker
        usdt_token.transfer(user, 100_000 * 1e18);
        usdt_token.transfer(attacker, 100_000 * 1e18);
        eve_token.transfer(user, 50_000 * 1e18);
        eve_token.transfer(attacker, 50_000 * 1e18);

        // Deploy the simulated Uniswap router with initial liquidity pool setup
        router = new SimulatedUniswapV2Router(
            address(usdt_token),
            address(eve_token),
            initialUSDT,
            initialEVE
        );

        // Deploy vulnerable contract that interacts with our simulated router
        vulnerable = new VulnerableContract(address(router), address(usdt_token), address(eve_token));

        // Approvals for the test contract to simulate user actions (using cheat codes)
        // In a real test, we would simulate this by using vm.prank or similar techniques.
        // For simplicity, we assume user and attacker have approved the vulnerable contract.
        vm.prank(user);
        usdt_token.approve(address(vulnerable), type(uint256).max);
        vm.prank(user);
        eve_token.approve(address(vulnerable), type(uint256).max);

        vm.prank(attacker);
        usdt_token.approve(address(router), type(uint256).max);
    }

    // Test function to demonstrate the vulnerability.
    // Note: balanceLog modifier logs ETH balances on function call.
    function testExploit() public balanceLog {
        // Ensure this test contract has enough ETH for operations
        vm.deal(address(this), 10 ether);

        // Step 1: Demonstrate normal behavior:
        //    - Get token price from the liquidity pool.
        uint256 initialPrice = vulnerable.getPrice();
        emit log_named_uint("Initial Price (USDT per EVE) * 1e18", initialPrice);

        //    - User performs a token swap with the vulnerable contract.
        uint256 swapAmount = 1_000 * 1e18;
        // Simulate caller as 'user'
        vm.prank(user);
        uint256 tokensReceived = vulnerable.swapUSDTForTokens(swapAmount);
        emit log_named_uint("Tokens received from swap (normal)", tokensReceived);

        //    - User adds liquidity via the vulnerable contract.
        uint256 addUSDT = 500 * 1e18;
        uint256 addEVE = 250 * 1e18;
        vm.prank(user);
        uint256 liquidityAdded = vulnerable.addLiquidity(addUSDT, addEVE);
        emit log_named_uint("Liquidity added (normal)", liquidityAdded);

        // Step 2: Simulate attack:
        // Attacker performs a significant swap directly on the router to manipulate the pool price.
        // The attacker uses his own USDT tokens to heavily impact the USDT/EVE ratio.
        uint256 attackerSwapAmount = 50_000 * 1e18;
        vm.prank(attacker);
        uint256 attackerTokensReceived = router.swapExactTokensForTokens(
            attackerSwapAmount,
            0, // No slippage protection, allowing the manipulation
            address(usdt_token),
            address(eve_token),
            attacker
        );
        emit log_named_uint("Attacker tokens received from swap", attackerTokensReceived);

        // Check the manipulated price after the attacker's swap.
        uint256 manipulatedPrice = vulnerable.getPrice();
        emit log_named_uint("Manipulated Price (USDT per EVE) * 1e18", manipulatedPrice);

        // Vulnerability Explanation:
        // The vulnerable contract uses fixed 0 values for minimum output amounts when calling the router's swap and addLiquidity functions.
        // This means that even when an attacker manipulates the liquidity pool by executing a large swap (thus changing the price unfavorably),
        // the vulnerable contract does not enforce any slippage protection. The attacker can manipulate the pool price between when the price is obtained
        // and when the vulnerable contract executes its swap or liquidity addition, leading to potential losses for the user.

        // Mitigation Measure (Educational):
        // Developers should avoid using fixed 0 values for minAmount parameters. Instead, they should:
        // 1. Calculate expected output amounts based on current market conditions.
        // 2. Set a reasonable minimum amount (e.g., 95-98% of the expected output) to protect against slippage.
        // 3. Incorporate checks that verify current pool conditions before executing critical token swaps or liquidity operations.
    }
}
```

---

### PoC #3: no_slippage_limit_check

**File:** /Users/advait/Desktop/NTU/fyp-fr/exploit/src/test/PoC_unknown_1742753761.sol

**Execution:** ✅ SUCCESS

**Exploit Code:**

```solidity
pragma solidity ^0.8.13;

// Import Foundry BaseTest with balance logging
import "./basetest.sol";

/// @title IUniswapV2Router Interface
/// @notice Defines the minimal functions for the mock UniswapV2Router contract used in the demo.
interface IUniswapV2Router {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin, // Insecure: using zero as minimum acceptable
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);

    function addLiquidity(
        address tokenA,
        address tokenB,
        uint256 amountADesired,
        uint256 amountBDesired,
        uint256 amountAMin, // Insecure: using zero as minimum acceptable
        uint256 amountBMin, // Insecure: using zero as minimum acceptable
        address to,
        uint256 deadline
    ) external returns (
        uint256 amountA,
        uint256 amountB,
        uint256 liquidity
    );
}

/// @title MockUniswapV2Router
/// @notice A simplified mock of UniswapV2Router to simulate swap and liquidity behavior, including manipulated market conditions.
contract MockUniswapV2Router is IUniswapV2Router {
    // flag to simulate front-running/manipulation
    bool public manipulated;

    // Allow external control to simulate market manipulation for educational purposes.
    function setManipulated(bool _manipulated) external {
        manipulated = _manipulated;
    }

    /// @notice Simulate a token swap.
    /// @dev When not manipulated, returns favorable rate. When manipulated, returns an unexpectedly low output.
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 /* amountOutMin */,
        address[] calldata /* path */,
        address to,
        uint256 /* deadline */
    ) external override returns (uint256[] memory amounts) {
        uint256 output;
        if (!manipulated) {
            // Normal market conditions: favorable rate (for demo purposes, double the tokens)
            output = amountIn * 2;
        } else {
            // Front-running scenario: manipulated market conditions lead to a very low output.
            output = amountIn / 100; // adverse rate
        }
        // For demonstration, log the transfer to 'to'
        // In a real scenario, token transfers would happen here.
        amounts = new uint256[](2);
        amounts[0] = amountIn;
        amounts[1] = output;
        // Ensure the call does not fail; returns output amounts.
        return amounts;
    }

    /// @notice Simulate adding liquidity.
    /// @dev When not manipulated, returns expected liquidity tokens. When manipulated, returns a diminished liquidity amount.
    function addLiquidity(
        address /* tokenA */,
        address /* tokenB */,
        uint256 amountADesired,
        uint256 amountBDesired,
        uint256 /* amountAMin */,
        uint256 /* amountBMin */,
        address to,
        uint256 /* deadline */
    ) external override returns (uint256 amountA, uint256 amountB, uint256 liquidity) {
        if (!manipulated) {
            // Normal liquidity addition: expect a 1:1 ratio for liquidity tokens (for demo purposes)
            liquidity = amountADesired < amountBDesired ? amountADesired : amountBDesired;
        } else {
            // Manipulated scenario: liquidity tokens drastically reduced due to front-running effects.
            liquidity = (amountADesired < amountBDesired ? amountADesired : amountBDesired) / 10;
        }
        // For demonstration, the tokens are "sent" to the address 'to'
        return (amountADesired, amountBDesired, liquidity);
    }
}

/// @title VulnerableContract
/// @notice A simplified vulnerable contract that interacts with Uniswap-like contracts without slippage protection.
/// @dev This contract demonstrates the improper use of minimum output amounts (set to zero) during swaps and liquidity addition.
contract VulnerableContract {
    IUniswapV2Router public router;

    // For demonstration, we simulate token balances as simple uint256 values.
    uint256 public usdtBalance;
    uint256 public tokenBalance;

    /// @notice Initializes the contract with the Uniswap router address.
    constructor(IUniswapV2Router _router) {
        router = _router;
        // For demo, initialize with some balances.
        usdtBalance = 1000 ether;
        tokenBalance = 1000 ether;
    }

    /// @notice Performs a token swap from USDT to Tokens.
    /// @dev Vulnerable: Uses a zero minimum expected token output, enabling unfavorable swaps during manipulation.
    function swapUSDTForTokens(uint256 amountIn) external returns (uint256[] memory amounts) {
        require(amountIn <= usdtBalance, "Insufficient USDT balance");

        // For demo, prepare parameters for swap on the router.
        address[] memory path = new address[](2);
        path[0] = address(0xUSDT);  // Dummy USDT address for demonstration purposes
        path[1] = address(0xToken); // Dummy token address

        // Vulnerable: minimum output is set to zero (no slippage protection)
        uint256 amountOutMin = 0;
        uint256 deadline = block.timestamp + 1 minutes;

        // Call the router's swap function and check the returned amounts.
        amounts = router.swapExactTokensForTokens(amountIn, amountOutMin, path, address(this), deadline);
        require(amounts.length >= 2, "Swap failed");

        // Update balances for demonstration.
        usdtBalance -= amountIn;
        tokenBalance += amounts[1];

        return amounts;
    }

    /// @notice Adds liquidity using USDT and Tokens.
    /// @dev Vulnerable: Uses zero minimum expected amounts for both tokens.
    function addLiquidity(uint256 usdtAmount, uint256 tokenAmount) external returns (uint256 liquidity) {
        require(usdtAmount <= usdtBalance, "Insufficient USDT balance");
        require(tokenAmount <= tokenBalance, "Insufficient token balance");

        uint256 amountAMin = 0; // Vulnerable: no minimum amounts
        uint256 amountBMin = 0;
        uint256 deadline = block.timestamp + 1 minutes;

        (uint256 amountA, uint256 amountB, uint256 liq) = router.addLiquidity(
            address(0xUSDT),  // Dummy USDT address
            address(0xToken), // Dummy token address
            usdtAmount,
            tokenAmount,
            amountAMin,
            amountBMin,
            address(this),
            deadline
        );
        require(liq > 0, "Liquidity addition failed");

        // Update balances for demonstration.
        usdtBalance -= amountA;
        tokenBalance -= amountB;

        liquidity = liq;
    }
}

/// @title YourTest
/// @notice A Foundry test contract that demonstrates an educational exploitation of a vulnerability due to lack of slippage protection.
/// @dev This is for educational purposes. It shows how using zero minimum amounts in token swaps and liquidity additions can be dangerous.
contract YourTest is BaseTestWithBalanceLog {
    VulnerableContract vulnerable;
    MockUniswapV2Router mockRouter;

    // Setup test environment with sufficient ETH for execution.
    function setUp() public {
        // The test contract must have enough ETH
        vm.deal(address(this), 100 ether);

        // Deploy the mock UniswapV2Router
        mockRouter = new MockUniswapV2Router();

        // Deploy the vulnerable contract with the router's address.
        vulnerable = new VulnerableContract(IUniswapV2Router(address(mockRouter)));
    }

    // Main test demonstrating the vulnerability exploitation.
    // The balanceLog modifier ensures balance changes are logged.
    function testExploit() public balanceLog {
        // Ensure the test contract has enough ETH before proceeding.
        vm.deal(address(this), 10 ether);

        // -----------------------------
        // Step 1: Normal operation
        // -----------------------------
        // Perform a normal swap and liquidity addition with no price manipulation.
        uint256 initialTokenBalance = vulnerable.tokenBalance();

        // Normal swap: swap 100 USDT for tokens.
        uint256 swapAmount = 100 ether;
        uint256[] memory amountsNormal = vulnerable.swapUSDTForTokens(swapAmount);
        require(amountsNormal[1] > swapAmount, "Normal swap should yield more tokens");

        // Normal liquidity addition: add liquidity with balanced amounts.
        uint256 liquidityNormal = vulnerable.addLiquidity(50 ether, 50 ether);
        require(liquidityNormal > 0, "Normal liquidity addition failed");

        // -----------------------------
        // Step 2: Simulate front-running attack (price manipulation)
        // -----------------------------
        // A malicious actor manipulates market conditions.
        // For simulation, we set the manipulated flag in the mock router.
        mockRouter.setManipulated(true);

        // The attacker/front-runner doesn't need to do anything other than force market conditions,
        // because the vulnerable contract uses zero minimum amounts.
        // Victim performs a swap unaware of the manipulation.
        uint256 swapAmountFrontRun = 100 ether;
        uint256[] memory amountsManipulated = vulnerable.swapUSDTForTokens(swapAmountFrontRun);

        // Check that the output token amount is drastically lower due to manipulation.
        require(amountsManipulated[1] < (swapAmountFrontRun * 2), "Swap output not affected by manipulation");

        // Similarly, adding liquidity will produce significantly reduced liquidity tokens.
        uint256 liquidityManipulated = vulnerable.addLiquidity(50 ether, 50 ether);
        require(liquidityManipulated < 50 ether, "Liquidity addition not affected by manipulation");

        // -----------------------------
        // Educational Comments:
        // -----------------------------
        // The vulnerability arises from the absence of slippage protection, as the vulnerable contract sets
        // the minimum acceptable amounts to zero in both swap and liquidity addition functions.
        // This allows a malicious actor to manipulate the market conditions (front-run) between transaction
        // initiation and execution, leading to highly unfavorable exchange rates and liquidity addition.
        //
        // To prevent this issue, developers should set non-zero minimum acceptable amounts based on current market
        // conditions and acceptable slippage thresholds. For example:
        // - Calculate expected outputs and subtract a tolerance (e.g., 1%) to set as the minimum
        // - Use oracle data or on-chain price feeds to validate trade parameters
        //
        // This educational test demonstrates both the vulnerability and a suggested mitigation approach.
    }
}
```

---

## Recommendations

For each identified vulnerability, consider implementing the following mitigations:

- **For Reentrancy**: Implement checks-effects-interactions pattern and consider using ReentrancyGuard.
- **For Arithmetic Issues**: Use SafeMath library or Solidity 0.8.x built-in overflow checking.
- **For Access Control**: Implement proper authorization checks and use the Ownable pattern.
- **For Oracle Manipulation**: Use time-weighted average prices and multiple independent oracle sources.
- **For All Vulnerabilities**: Consider a professional audit before deploying to production.

*This report was generated automatically by the Smart Contract Vulnerability Analyzer.*
