// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {ICLHooks} from "infinity-core/src/pool-cl/interfaces/ICLHooks.sol";
import {ICLPoolManager} from "infinity-core/src/pool-cl/interfaces/ICLPoolManager.sol";
import {IVault} from "infinity-core/src/interfaces/IVault.sol";
import {PoolKey} from "infinity-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "infinity-core/src/types/PoolId.sol";
import {BalanceDelta} from "infinity-core/src/types/BalanceDelta.sol";
import {
    BeforeSwapDelta, BeforeSwapDeltaLibrary, toBeforeSwapDelta
} from "infinity-core/src/types/BeforeSwapDelta.sol";
import {Currency, CurrencyLibrary} from "infinity-core/src/types/Currency.sol";
import {SafeCast} from "infinity-core/src/libraries/SafeCast.sol";
import {TickMath} from "infinity-core/src/pool-cl/libraries/TickMath.sol";
import {LPFeeLibrary} from "infinity-core/src/libraries/LPFeeLibrary.sol";
import {Constants} from "./Constants.sol";

// Hook permission constants from ICLHooks
uint8 constant HOOKS_BEFORE_INITIALIZE_OFFSET = 0;
uint8 constant HOOKS_AFTER_INITIALIZE_OFFSET = 1;
uint8 constant HOOKS_BEFORE_ADD_LIQUIDITY_OFFSET = 2;
uint8 constant HOOKS_AFTER_ADD_LIQUIDITY_OFFSET = 3;
uint8 constant HOOKS_BEFORE_REMOVE_LIQUIDITY_OFFSET = 4;
uint8 constant HOOKS_AFTER_REMOVE_LIQUIDITY_OFFSET = 5;
uint8 constant HOOKS_BEFORE_SWAP_OFFSET = 6;
uint8 constant HOOKS_AFTER_SWAP_OFFSET = 7;
uint8 constant HOOKS_BEFORE_DONATE_OFFSET = 8;
uint8 constant HOOKS_AFTER_DONATE_OFFSET = 9;
uint8 constant HOOKS_BEFORE_SWAP_RETURNS_DELTA_OFFSET = 10;
uint8 constant HOOKS_AFTER_SWAP_RETURNS_DELTA_OFFSET = 11;
uint8 constant HOOKS_AFTER_ADD_LIQUIDIY_RETURNS_DELTA_OFFSET = 12;
uint8 constant HOOKS_AFTER_REMOVE_LIQUIDIY_RETURNS_DELTA_OFFSET = 13;

/**
 * @title TaxHookPancake
 * @notice A PancakeSwap Infinity hook that applies configurable taxes on TOKEN/BNB swaps
 * @dev Supports multiple tokens sharing one hook. Always taxes native BNB, not the custom token.
 *      Owner can take a configurable cut of all taxes collected.
 */
contract TaxHookPancake is ICLHooks, Ownable, ReentrancyGuard {
    using PoolIdLibrary for PoolKey;
    using SafeCast for uint256;
    using CurrencyLibrary for Currency;

    // Pool manager reference
    ICLPoolManager public immutable poolManager;
    IVault public immutable vault;

    // Tax rate in basis points (1/100 of a percent)
    // 100 = 1%, 500 = 5%, etc.
    uint16 public constant TAX_RATE_DENOMINATOR = 10000;

    // Flag to tell PancakeSwap to use the returned fee
    uint24 public constant LP_FEE_OVERRIDE_FLAG = LPFeeLibrary.OVERRIDE_FEE_FLAG;

    // Fee override value for zero LP fees
    uint24 public constant FEE_OVERRIDE = LP_FEE_OVERRIDE_FLAG; // 0 fee with override flag

    // Price limit constants for internal token->BNB swaps
    uint160 private constant MAX_PRICE_LIMIT = TickMath.MAX_SQRT_RATIO - 1;
    uint160 private constant MIN_PRICE_LIMIT = TickMath.MIN_SQRT_RATIO + 1;

    /**
     * @notice Override LP fees explanation
     * When returning a fee from beforeSwap:
     * 1. The override flag tells PancakeSwap to use the returned fee value
     * 2. Setting the value to zero means users pay 0% LP fees
     * 3. Only taxes specified by the hook will be collected
     *
     * This allows tokens to have completely custom fee structures
     * without any of the standard PancakeSwap LP fees.
     */

    // Owner's cut of all collected taxes (in basis points, e.g., 300 = 3%)
    uint16 public ownerCutBps;

    // Structure to store tax configuration per token
    struct TokenTaxConfig {
        bool enabled; // Whether tax is enabled for this token
        uint16 taxBps; // Total tax rate in basis points
        uint256 collected; // Amount collected for token owner
        uint256 withdrawn; // Amount withdrawn by token owner
        bool exemptFromOwnerCut; // If true, owner gets no cut from this token
        address tokenOwner; // Address that registered and owns this token config
    }

    // Permissions structure for hook registration
    struct Permissions {
        bool beforeInitialize;
        bool afterInitialize;
        bool beforeAddLiquidity;
        bool afterAddLiquidity;
        bool beforeRemoveLiquidity;
        bool afterRemoveLiquidity;
        bool beforeSwap;
        bool afterSwap;
        bool beforeDonate;
        bool afterDonate;
        bool beforeSwapReturnsDelta;
        bool afterSwapReturnsDelta;
        bool afterAddLiquidityReturnsDelta;
        bool afterRemoveLiquidityReturnsDelta;
    }

    // Mapping from custom token address to its tax configuration
    mapping(address => TokenTaxConfig) public tokenTaxConfigs;

    // Global owner tax tracking (across all tokens)
    uint256 public ownerTaxCollected;
    uint256 public ownerTaxWithdrawn;

    // Flag to prevent taxing internal swaps (for token->BNB conversions)
    bool private _inInternalSwap;

    // Event emitted when tax is collected
    event TaxCollected(
        PoolId indexed poolId,
        address indexed customToken,
        uint256 totalTaxAmount,
        uint256 ownerCut,
        uint256 tokenWalletCut,
        bool isInflow
    );

    // Event emitted when a token is registered
    event TokenRegistered(
        address indexed customToken, PoolId indexed poolId, uint16 taxBps, address indexed tokenOwner
    );

    // Event emitted when taxes are withdrawn
    event TaxWithdrawn(address indexed beneficiary, uint256 amount, bool isOwnerTax);

    // Event emitted when a token is exempted from owner cut
    event TokenExemptionUpdated(address indexed customToken, bool exempt);

    // Event emitted when token ownership is transferred
    event TokenOwnershipTransferred(
        address indexed customToken, address indexed previousOwner, address indexed newOwner
    );

    // Modifier to restrict hook functions to pool manager only
    modifier poolManagerOnly() {
        require(msg.sender == address(poolManager), "TaxHookPancake: Only pool manager");
        _;
    }

    constructor(ICLPoolManager _poolManager, address _owner, uint16 _ownerCutBps) {
        require(_ownerCutBps < TAX_RATE_DENOMINATOR, "TaxHookPancake: Owner cut too high");

        poolManager = _poolManager;
        vault = _poolManager.vault();
        ownerCutBps = _ownerCutBps;

        // Transfer ownership if not deployer
        if (_owner != msg.sender) {
            _transferOwnership(_owner);
        }
    }

    /**
     * @notice Register a token with this tax hook
     * @param customToken The custom token address (not BNB)
     * @param key The pool key for TOKEN/BNB pair
     * @param taxBps Tax rate in basis points
     */
    function registerToken(address customToken, PoolKey calldata key, uint16 taxBps) external {
        require(customToken != address(0), "TaxHookPancake: Invalid custom token");
        require(taxBps <= Constants.MAX_TOKEN_TAX_BPS, "TaxHookPancake: Tax rate exceeds maximum");

        // Verify pool contains native BNB (address(0)) and customToken
        address token0 = Currency.unwrap(key.currency0);
        address token1 = Currency.unwrap(key.currency1);
        require(
            (token0 == address(0) && token1 == customToken) || (token0 == customToken && token1 == address(0)),
            "TaxHookPancake: Pool must be TOKEN/BNB pair"
        );

        // Verify exactly one currency is BNB
        require(
            (token0 == address(0)) != (token1 == address(0)),
            "TaxHookPancake: Pool must have exactly one native BNB currency"
        );

        TokenTaxConfig storage config = tokenTaxConfigs[customToken];
        require(!config.enabled, "TaxHookPancake: Token already registered");

        config.enabled = true;
        config.taxBps = taxBps;
        config.collected = 0;
        config.withdrawn = 0;
        config.exemptFromOwnerCut = false;
        config.tokenOwner = msg.sender;

        PoolId poolId = key.toId();
        emit TokenRegistered(customToken, poolId, taxBps, msg.sender);
    }

    // ============================================
    // TOKEN OWNER FUNCTIONS
    // ============================================

    /**
     * @notice Transfer ownership of a token registration
     * @param customToken The token to transfer ownership of
     * @param newOwner The new owner address
     */
    function transferTokenOwnership(address customToken, address newOwner) external {
        TokenTaxConfig storage config = tokenTaxConfigs[customToken];
        require(config.enabled, "TaxHookPancake: Token not registered");
        require(msg.sender == config.tokenOwner, "TaxHookPancake: Only token owner can transfer");

        // Validation for new owner
        require(newOwner != address(0), "TaxHookPancake: Cannot transfer to zero address");
        require(newOwner != address(this), "TaxHookPancake: Cannot transfer to hook contract");

        // If there's an active tax rate or unwithdrawn taxes, be extra cautious
        uint256 unwithdrawnTax = config.collected - config.withdrawn;
        if (config.taxBps > 0 || unwithdrawnTax > 0) {
            require(newOwner != address(0), "TaxHookPancake: Cannot transfer active config to zero address");
        }

        address previousOwner = config.tokenOwner;
        config.tokenOwner = newOwner;

        emit TokenOwnershipTransferred(customToken, previousOwner, newOwner);
    }

    /**
     * @notice Update a token's tax rate (can only decrease, not increase)
     * @param customToken The token to update
     * @param newTaxBps New tax rate in basis points (must be less than or equal to current rate)
     */
    function updateTokenTaxRate(address customToken, uint16 newTaxBps) external {
        TokenTaxConfig storage config = tokenTaxConfigs[customToken];
        require(config.enabled, "TaxHookPancake: Token not registered");
        require(msg.sender == config.tokenOwner, "TaxHookPancake: Only token owner can update");
        require(newTaxBps <= config.taxBps, "TaxHookPancake: Can only decrease tax rate");

        config.taxBps = newTaxBps;
    }

    /**
     * @notice Withdraws accumulated token-specific taxes (in native BNB)
     * @param customToken The custom token whose tax to withdraw
     * @param recipient The address to send the withdrawn tax to
     * @dev Only callable by the token owner
     */
    function withdrawTokenTax(address customToken, address recipient) external nonReentrant {
        require(recipient != address(0), "TaxHookPancake: Invalid recipient");

        TokenTaxConfig storage config = tokenTaxConfigs[customToken];
        require(config.enabled, "TaxHookPancake: Token not registered");
        require(msg.sender == config.tokenOwner, "TaxHookPancake: Only token owner can withdraw");

        uint256 unwithdrawnTotal = config.collected - config.withdrawn;
        require(unwithdrawnTotal > 0, "TaxHookPancake: No taxes to withdraw");

        // Check BNB balance
        uint256 balance = address(this).balance;
        require(balance >= unwithdrawnTotal, "TaxHookPancake: Insufficient BNB balance");

        // Update the withdrawn amount
        config.withdrawn += unwithdrawnTotal;

        // Transfer BNB to recipient
        (bool success,) = recipient.call{value: unwithdrawnTotal}("");
        require(success, "TaxHookPancake: BNB transfer failed");

        emit TaxWithdrawn(recipient, unwithdrawnTotal, false);
    }

    // ============================================
    // HOOK OWNER FUNCTIONS
    // ============================================

    /**
     * @notice Exempt a token from owner cut
     * @param customToken The token to exempt
     * @param exempt Whether to exempt the token
     */
    function exemptToken(address customToken, bool exempt) external onlyOwner {
        TokenTaxConfig storage config = tokenTaxConfigs[customToken];
        require(config.enabled, "TaxHookPancake: Token not registered");

        config.exemptFromOwnerCut = exempt;
        emit TokenExemptionUpdated(customToken, exempt);
    }

    /**
     * @notice Withdraws accumulated owner taxes (in native BNB)
     * @dev Only callable by owner. Withdraws all accumulated BNB across all tokens.
     */
    function withdrawOwnerTax() external onlyOwner nonReentrant {
        // Calculate unwithdrawn amount
        uint256 unwithdrawnTotal = ownerTaxCollected - ownerTaxWithdrawn;
        require(unwithdrawnTotal > 0, "TaxHookPancake: No owner taxes to withdraw");

        // Check BNB balance
        uint256 balance = address(this).balance;
        require(balance >= unwithdrawnTotal, "TaxHookPancake: Insufficient BNB balance");

        // Update withdrawn amount
        ownerTaxWithdrawn += unwithdrawnTotal;

        // Transfer BNB to owner
        (bool success,) = owner().call{value: unwithdrawnTotal}("");
        require(success, "TaxHookPancake: BNB transfer failed");

        emit TaxWithdrawn(owner(), unwithdrawnTotal, true);
    }

    // ============================================
    // HOOK PERMISSIONS & CORE LOGIC
    // ============================================

    /**
     * @notice Define the hook permissions
     * @return Hooks bitmap The hook's permissions as a uint16 bitmap
     */
    function getHooksRegistrationBitmap() external pure override returns (uint16) {
        return _hooksRegistrationBitmapFrom(
            Permissions({
                beforeInitialize: false,
                afterInitialize: false,
                beforeAddLiquidity: false,
                afterAddLiquidity: false,
                beforeRemoveLiquidity: false,
                afterRemoveLiquidity: false,
                beforeSwap: true, // Using beforeSwap to tax inflows
                afterSwap: true, // Using afterSwap to tax outflows
                beforeDonate: false,
                afterDonate: false,
                beforeSwapReturnsDelta: true, // Now enabling this to return a delta in beforeSwap
                afterSwapReturnsDelta: true, // Now enabling this to return a delta in afterSwap
                afterAddLiquidityReturnsDelta: false,
                afterRemoveLiquidityReturnsDelta: false
            })
        );
    }

    /**
     * @notice Helper to convert permissions struct to bitmap
     */
    function _hooksRegistrationBitmapFrom(Permissions memory permissions) internal pure returns (uint16) {
        return uint16(
            (permissions.beforeInitialize ? 1 << HOOKS_BEFORE_INITIALIZE_OFFSET : 0)
                | (permissions.afterInitialize ? 1 << HOOKS_AFTER_INITIALIZE_OFFSET : 0)
                | (permissions.beforeAddLiquidity ? 1 << HOOKS_BEFORE_ADD_LIQUIDITY_OFFSET : 0)
                | (permissions.afterAddLiquidity ? 1 << HOOKS_AFTER_ADD_LIQUIDITY_OFFSET : 0)
                | (permissions.beforeRemoveLiquidity ? 1 << HOOKS_BEFORE_REMOVE_LIQUIDITY_OFFSET : 0)
                | (permissions.afterRemoveLiquidity ? 1 << HOOKS_AFTER_REMOVE_LIQUIDITY_OFFSET : 0)
                | (permissions.beforeSwap ? 1 << HOOKS_BEFORE_SWAP_OFFSET : 0)
                | (permissions.afterSwap ? 1 << HOOKS_AFTER_SWAP_OFFSET : 0)
                | (permissions.beforeDonate ? 1 << HOOKS_BEFORE_DONATE_OFFSET : 0)
                | (permissions.afterDonate ? 1 << HOOKS_AFTER_DONATE_OFFSET : 0)
                | (permissions.beforeSwapReturnsDelta ? 1 << HOOKS_BEFORE_SWAP_RETURNS_DELTA_OFFSET : 0)
                | (permissions.afterSwapReturnsDelta ? 1 << HOOKS_AFTER_SWAP_RETURNS_DELTA_OFFSET : 0)
                | (permissions.afterAddLiquidityReturnsDelta ? 1 << HOOKS_AFTER_ADD_LIQUIDIY_RETURNS_DELTA_OFFSET : 0)
                | (
                    permissions.afterRemoveLiquidityReturnsDelta
                        ? 1 << HOOKS_AFTER_REMOVE_LIQUIDIY_RETURNS_DELTA_OFFSET
                        : 0
                )
        );
    }

    /**
     * @notice Calculate tax amount based on value and tax rate
     * @param value The value to calculate tax on
     * @param taxRateBps The tax rate in basis points
     * @return taxAmount The calculated tax amount
     */
    function _calculateTax(uint256 value, uint16 taxRateBps) internal pure returns (uint256) {
        return (value * taxRateBps) / TAX_RATE_DENOMINATOR;
    }

    /**
     * @notice Calculate tax breakdown: total, owner cut, and token wallet cut
     * @param amount The amount to calculate tax on
     * @param config The token tax configuration
     * @return totalTaxAmount Total tax to collect
     * @return ownerCut Amount going to hook owner
     * @return tokenWalletCut Amount going to token owner
     */
    function _calculateTaxBreakdown(uint256 amount, TokenTaxConfig storage config)
        internal
        view
        returns (uint256 totalTaxAmount, uint256 ownerCut, uint256 tokenWalletCut)
    {
        totalTaxAmount = _calculateTax(amount, config.taxBps);

        if (totalTaxAmount > 0) {
            ownerCut = 0;
            if (!config.exemptFromOwnerCut && ownerCutBps > 0) {
                ownerCut = _calculateTax(totalTaxAmount, ownerCutBps);
            }
            tokenWalletCut = totalTaxAmount - ownerCut;
        }
    }

    /**
     * @notice Record collected taxes in storage
     * @param customToken The token address
     * @param ownerCut Amount to add to owner's collected taxes
     * @param tokenWalletCut Amount to add to token owner's collected taxes
     */
    function _recordCollectedTax(address customToken, uint256 ownerCut, uint256 tokenWalletCut) internal {
        if (ownerCut > 0) {
            ownerTaxCollected += ownerCut;
        }
        if (tokenWalletCut > 0) {
            tokenTaxConfigs[customToken].collected += tokenWalletCut;
        }
    }

    /**
     * @notice Emit tax collected event
     * @param key The pool key
     * @param customToken The token address
     * @param totalTaxAmount Total tax collected
     * @param ownerCut Amount for hook owner
     * @param tokenWalletCut Amount for token owner
     * @param isInflow Whether this is an inflow (beforeSwap) or outflow (afterSwap)
     */
    function _emitTaxCollectedEvent(
        PoolKey calldata key,
        address customToken,
        uint256 totalTaxAmount,
        uint256 ownerCut,
        uint256 tokenWalletCut,
        bool isInflow
    ) internal {
        PoolId poolId = key.toId();
        emit TaxCollected(poolId, customToken, totalTaxAmount, ownerCut, tokenWalletCut, isInflow);
    }

    /**
     * @notice Settles swap deltas with the vault
     * @dev Handles the token debt and BNB credit settlement after an internal swap
     * @param key The pool key
     * @param delta The balance delta from the swap
     * @param bnbIsToken0 Whether BNB is currency0 in the pool
     */
    function _settleSwapDelta(PoolKey calldata key, BalanceDelta delta, bool bnbIsToken0) internal {
        Currency bnbCurrency = CurrencyLibrary.NATIVE;
        Currency tokenCurrency = bnbIsToken0 ? key.currency1 : key.currency0;

        // Get the actual deltas from the swap
        int128 tokenDelta = bnbIsToken0 ? delta.amount1() : delta.amount0();
        int128 bnbDelta = bnbIsToken0 ? delta.amount0() : delta.amount1();

        // Settle token debt (hook owes tokens to pool, delta is negative)
        if (tokenDelta < 0) {
            uint256 tokenDebt = uint256(int256(-tokenDelta));
            vault.sync(tokenCurrency);
            IERC20(Currency.unwrap(tokenCurrency)).transfer(address(vault), tokenDebt);
            vault.settle();
        }

        // Take BNB credit (pool owes BNB to hook, delta is positive)
        if (bnbDelta > 0) {
            uint256 bnbCredit = uint256(int256(bnbDelta));
            vault.take(bnbCurrency, address(this), bnbCredit);
        }
    }

    /**
     * @notice Swaps tokens to BNB via the pool
     * @dev Used when we need to convert token-denominated tax to BNB
     * @param key The pool key
     * @param tokenAmount Amount of tokens to swap
     * @return bnbReceived Amount of BNB received from the swap
     */
    function _swapTokensToBnb(PoolKey calldata key, uint256 tokenAmount) internal returns (uint256 bnbReceived) {
        uint256 bnbBefore = address(this).balance;

        // Set flag to prevent taxing this internal swap
        _inInternalSwap = true;

        // Determine currency positions
        address token0 = Currency.unwrap(key.currency0);
        bool bnbIsToken0 = (token0 == address(0));

        // Execute token -> BNB swap (exact input)
        // If BNB is currency0: swap currency1 -> currency0 (zeroForOne = false)
        // If BNB is currency1: swap currency0 -> currency1 (zeroForOne = true)
        BalanceDelta delta = poolManager.swap(
            key,
            ICLPoolManager.SwapParams({
                zeroForOne: !bnbIsToken0, // Token -> BNB
                amountSpecified: -int256(tokenAmount), // Negative = exact input
                sqrtPriceLimitX96: bnbIsToken0 ? MAX_PRICE_LIMIT : MIN_PRICE_LIMIT
            }),
            bytes("")
        );

        // Manually settle the swap deltas with vault (only needed for internal swaps)
        _settleSwapDelta(key, delta, bnbIsToken0);

        // Clear flag
        _inInternalSwap = false;

        bnbReceived = address(this).balance - bnbBefore;
    }

    /**
     * @notice Hook called before a swap to tax inflows
     * @dev Handles: Scenario 1 - Exact input swap where BNB is input (buying tokens with exact BNB)
     * @param key The pool key
     * @param params The swap parameters
     * @return selector The function selector
     * @return delta Any delta to apply
     * @return gasLimit The gas limit for the swap
     */
    function beforeSwap(address, PoolKey calldata key, ICLPoolManager.SwapParams calldata params, bytes calldata)
        external
        override
        poolManagerOnly
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        // Skip taxing internal swaps (prevents recursion when converting token tax to BNB)
        if (_inInternalSwap) {
            return (ICLHooks.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, FEE_OVERRIDE);
        }

        // Initialize with default values
        BeforeSwapDelta deltaOut = BeforeSwapDeltaLibrary.ZERO_DELTA;

        // Identify the custom token (non-BNB token)
        address token0 = Currency.unwrap(key.currency0);
        address token1 = Currency.unwrap(key.currency1);
        address customToken = (token0 == address(0)) ? token1 : token0;

        TokenTaxConfig storage config = tokenTaxConfigs[customToken];

        // Skip if tax is not enabled for this token
        if (!config.enabled) {
            return (ICLHooks.beforeSwap.selector, deltaOut, FEE_OVERRIDE);
        }

        // We always tax native BNB
        Currency taxCurrency = CurrencyLibrary.NATIVE;
        bool bnbIsToken0 = (token0 == address(0));

        // Determine if BNB is being used as input in this swap
        bool isBnbInput = (bnbIsToken0 && params.zeroForOne) || (!bnbIsToken0 && !params.zeroForOne);

        // Scenario 1: Exact input swap where BNB is input (buying tokens with exact BNB amount)
        // - amountSpecified < 0 (negative indicates exact input in V4)
        // - BNB is the input currency
        if (isBnbInput && params.amountSpecified < 0) {
            // Calculate absolute swap amount
            uint256 absAmount = uint256(-params.amountSpecified);

            // Calculate tax breakdown using helper
            (uint256 totalTaxAmount, uint256 ownerCut, uint256 tokenWalletCut) =
                _calculateTaxBreakdown(absAmount, config);

            if (totalTaxAmount > 0) {
                // Record collected taxes first (CEI pattern)
                _recordCollectedTax(customToken, ownerCut, tokenWalletCut);

                // Take the total tax from the pool using vault
                vault.take(taxCurrency, address(this), totalTaxAmount);

                // Return a POSITIVE delta - this tells poolManager user owes extra to compensate
                // The hook keeps the tax, user's settlement is adjusted by the returned delta
                deltaOut = toBeforeSwapDelta(int128(int256(totalTaxAmount)), 0);

                // Emit event using helper
                _emitTaxCollectedEvent(key, customToken, totalTaxAmount, ownerCut, tokenWalletCut, true);
            }
        }

        return (ICLHooks.beforeSwap.selector, deltaOut, FEE_OVERRIDE);
    }

    /**
     * @notice Hook called after a swap to tax BNB flows
     * @dev Handles:
     *   - Scenario 2: Exact output swap where BNB is input (buying exact tokens with BNB)
     *   - Scenario 3: Exact input swap where BNB is output (selling exact tokens for BNB)
     *   - Scenario 4: Exact output swap where BNB is output (selling tokens for exact BNB)
     * @param key The pool key
     * @param params The swap parameters
     * @param delta The balance delta from the swap
     * @return selector The function selector
     * @return afterDelta Any additional amount to withdraw
     */
    function afterSwap(address, PoolKey calldata key, ICLPoolManager.SwapParams calldata params, BalanceDelta delta, bytes calldata)
        external
        override
        poolManagerOnly
        returns (bytes4, int128)
    {
        // Skip taxing internal swaps (prevents recursion when converting token tax to BNB)
        if (_inInternalSwap) {
            return (ICLHooks.afterSwap.selector, 0);
        }

        // Default value for afterDelta
        int128 afterDelta = 0;

        // Identify the custom token (non-BNB token)
        address token0 = Currency.unwrap(key.currency0);
        address token1 = Currency.unwrap(key.currency1);
        address customToken = (token0 == address(0)) ? token1 : token0;

        TokenTaxConfig storage config = tokenTaxConfigs[customToken];

        // Skip if tax is not enabled for this token
        if (!config.enabled) {
            return (ICLHooks.afterSwap.selector, afterDelta);
        }

        // We always tax native BNB
        Currency taxCurrency = CurrencyLibrary.NATIVE;
        bool bnbIsToken0 = (token0 == address(0));

        // Get the BNB delta (amount0 if BNB is token0, otherwise amount1)
        int128 relevantDelta = bnbIsToken0 ? delta.amount0() : delta.amount1();

        // Determine swap direction
        bool isBnbInput = (bnbIsToken0 && params.zeroForOne) || (!bnbIsToken0 && !params.zeroForOne);
        bool isBnbOutput = !isBnbInput;

        // Scenario 2: Exact output swap where BNB is input (buying exact amount of tokens with BNB)
        // - amountSpecified > 0 (positive indicates exact output in V4)
        // - BNB is the input currency
        // - relevantDelta < 0 (BNB flowing INTO the pool, negative delta)
        if (isBnbInput && params.amountSpecified > 0 && relevantDelta < 0) {
            // Tax the absolute amount of BNB consumed
            uint256 absAmount = uint256(int256(-relevantDelta));

            // Calculate tax breakdown using helper
            (uint256 totalTaxAmount, uint256 ownerCut, uint256 tokenWalletCut) =
                _calculateTaxBreakdown(absAmount, config);

            if (totalTaxAmount > 0) {
                // Record collected taxes first (CEI pattern)
                _recordCollectedTax(customToken, ownerCut, tokenWalletCut);

                // Take the tax from the pool using vault
                vault.take(taxCurrency, address(this), totalTaxAmount);

                // Return a POSITIVE delta to balance out the debt created by take()
                afterDelta = int128(int256(totalTaxAmount));

                // Emit event using helper (isInflow=true because BNB is flowing in)
                _emitTaxCollectedEvent(key, customToken, totalTaxAmount, ownerCut, tokenWalletCut, true);
            }
        }
        // Scenario 3: Exact input sell (selling exact tokens for BNB)
        // - amountSpecified < 0 (negative indicates exact input)
        // - BNB is the output currency
        // - relevantDelta > 0 (BNB flowing OUT of the pool, positive delta)
        else if (isBnbOutput && relevantDelta > 0 && params.amountSpecified < 0) {
            // Tax the absolute amount of BNB received
            uint256 absAmount = uint256(int256(relevantDelta));

            // Calculate tax breakdown using helper
            (uint256 totalTaxAmount, uint256 ownerCut, uint256 tokenWalletCut) =
                _calculateTaxBreakdown(absAmount, config);

            if (totalTaxAmount > 0) {
                // Record collected taxes first (CEI pattern)
                _recordCollectedTax(customToken, ownerCut, tokenWalletCut);

                // Take the tax from the pool using vault
                vault.take(taxCurrency, address(this), totalTaxAmount);

                // Return a POSITIVE delta to balance out the debt created by take()
                afterDelta = int128(int256(totalTaxAmount));

                // Emit event using helper (isInflow=false because BNB is flowing out)
                _emitTaxCollectedEvent(key, customToken, totalTaxAmount, ownerCut, tokenWalletCut, false);
            }
        }
        // Scenario 4: Exact output sell (selling tokens for exact BNB amount)
        // - amountSpecified > 0 (positive indicates exact output)
        // - BNB is the output currency
        // - relevantDelta > 0 (BNB flowing OUT)
        // - Problem: Can't take more BNB from pool (user specified exact BNB amount)
        // - Solution: Take equivalent token tax and swap to BNB immediately
        else if (isBnbOutput && relevantDelta > 0 && params.amountSpecified > 0) {
            // User specified exact BNB output, so we tax the token input instead
            // Get token delta (the amount of tokens user sent)
            int128 tokenDelta = bnbIsToken0 ? delta.amount1() : delta.amount0();

            // Token delta should be negative (user sending tokens to pool)
            if (tokenDelta < 0) {
                uint256 tokenAmount = uint256(int256(-tokenDelta));

                // Calculate tax on tokens
                (uint256 totalTokenTax, uint256 ownerCut, uint256 tokenWalletCut) =
                    _calculateTaxBreakdown(tokenAmount, config);

                if (totalTokenTax > 0) {
                    // Note: Scenario 4 requires taking tokens and swapping them before we know the final BNB amount
                    // We cannot follow strict CEI pattern here because state update depends on swap result
                    // The _inInternalSwap flag protects against reentrancy during the swap

                    // Take token tax from pool using vault
                    Currency tokenCurrency = bnbIsToken0 ? key.currency1 : key.currency0;
                    vault.take(tokenCurrency, address(this), totalTokenTax);

                    // Immediately swap tokens to BNB
                    uint256 bnbReceived = _swapTokensToBnb(key, totalTokenTax);

                    // Now distribute the BNB received as normal
                    if (bnbReceived > 0) {
                        // Recalculate breakdown based on actual BNB received (accounts for slippage)
                        uint256 finalOwnerCut = 0;
                        if (!config.exemptFromOwnerCut && ownerCutBps > 0) {
                            finalOwnerCut = _calculateTax(bnbReceived, ownerCutBps);
                        }
                        uint256 finalTokenWalletCut = bnbReceived - finalOwnerCut;

                        // Record collected taxes (must be after swap to get correct amounts)
                        _recordCollectedTax(customToken, finalOwnerCut, finalTokenWalletCut);

                        // Emit event
                        _emitTaxCollectedEvent(key, customToken, bnbReceived, finalOwnerCut, finalTokenWalletCut, false);

                        // Return token tax amount as delta
                        afterDelta = int128(int256(totalTokenTax));
                    }
                }
            }
        }

        return (ICLHooks.afterSwap.selector, afterDelta);
    }

    // ============================================
    // REQUIRED ICLHooks INTERFACE FUNCTIONS
    // ============================================
    // These functions revert as they are not used by this hook

    function beforeInitialize(address, PoolKey calldata, uint160) external pure override returns (bytes4) {
        revert("TaxHookPancake: Not implemented");
    }

    function afterInitialize(address, PoolKey calldata, uint160, int24) external pure override returns (bytes4) {
        revert("TaxHookPancake: Not implemented");
    }

    function beforeAddLiquidity(address, PoolKey calldata, ICLPoolManager.ModifyLiquidityParams calldata, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        revert("TaxHookPancake: Not implemented");
    }

    function afterAddLiquidity(
        address,
        PoolKey calldata,
        ICLPoolManager.ModifyLiquidityParams calldata,
        BalanceDelta,
        BalanceDelta,
        bytes calldata
    ) external pure override returns (bytes4, BalanceDelta) {
        revert("TaxHookPancake: Not implemented");
    }

    function beforeRemoveLiquidity(
        address,
        PoolKey calldata,
        ICLPoolManager.ModifyLiquidityParams calldata,
        bytes calldata
    ) external pure override returns (bytes4) {
        revert("TaxHookPancake: Not implemented");
    }

    function afterRemoveLiquidity(
        address,
        PoolKey calldata,
        ICLPoolManager.ModifyLiquidityParams calldata,
        BalanceDelta,
        BalanceDelta,
        bytes calldata
    ) external pure override returns (bytes4, BalanceDelta) {
        revert("TaxHookPancake: Not implemented");
    }

    function beforeDonate(address, PoolKey calldata, uint256, uint256, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        revert("TaxHookPancake: Not implemented");
    }

    function afterDonate(address, PoolKey calldata, uint256, uint256, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        revert("TaxHookPancake: Not implemented");
    }

    // Required receive function to handle BNB transfers
    receive() external payable {}

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    /**
     * @notice Get the owner's global tax info
     * @return collected Total amount of owner tax collected (in native BNB)
     * @return withdrawn Total amount of owner tax withdrawn
     */
    function getOwnerTaxInfo() external view returns (uint256 collected, uint256 withdrawn) {
        return (ownerTaxCollected, ownerTaxWithdrawn);
    }

    /**
     * @notice Get the token-specific tax info
     * @param customToken The custom token address
     * @return collected Amount collected for the token owner (in native BNB)
     * @return withdrawn Amount withdrawn by the token owner
     */
    function getTokenTaxInfo(address customToken) external view returns (uint256 collected, uint256 withdrawn) {
        TokenTaxConfig storage config = tokenTaxConfigs[customToken];
        return (config.collected, config.withdrawn);
    }

    /**
     * @notice Get the owner of a token registration
     * @param customToken The custom token address
     * @return tokenOwner Address that owns this token's configuration
     */
    function getTokenOwner(address customToken) external view returns (address tokenOwner) {
        TokenTaxConfig storage config = tokenTaxConfigs[customToken];
        require(config.enabled, "TaxHookPancake: Token not registered");
        return config.tokenOwner;
    }
}
