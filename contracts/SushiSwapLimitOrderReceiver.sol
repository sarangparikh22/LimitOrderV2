// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.6.12;
pragma experimental ABIEncoderV2;

import "@boringcrypto/boring-solidity/contracts/libraries/BoringERC20.sol";
import "@sushiswap/core/contracts/uniswapv2/libraries/UniswapV2Library.sol";
import "@sushiswap/core/contracts/uniswapv2/libraries/TransferHelper.sol";
import "./interfaces/ILimitOrderReceiver.sol";

contract SushiSwapLimitOrderReceiver is ILimitOrderReceiver {
    using BoringERC20 for IERC20;

    address private immutable factory;

    constructor (address _factory) public {
        factory = _factory;
    }

    function onLimitOrder (IERC20, IERC20 tokenOut, uint256 amountIn, uint256 amountMinOut, bytes calldata data) override external {
        (address[] memory path, uint256 amountOutMinExternal, address to) = abi.decode(data, (address[], uint256, address));
        _swapExactTokensForTokens(address(this), amountIn, amountOutMinExternal, path, address(this));
        tokenOut.safeTransfer(msg.sender, amountMinOut);
        tokenOut.safeTransfer(to, tokenOut.balanceOf(address(this)));
    }

    // Swaps an exact amount of tokens for another token through the path passed as an argument
    // Returns the amount of the final token
    function _swapExactTokensForTokens(
        address from,
        uint256 amountIn,
        uint256 amountOutMin,
        address[] memory path,
        address to
    ) internal returns (uint256 amountOut) {
        uint256[] memory amounts = UniswapV2Library.getAmountsOut(factory, amountIn, path);
        amountOut = amounts[amounts.length - 1];
        require(amountOut >= amountOutMin, "insufficient-amount-out");
        TransferHelper.safeTransferFrom(path[0], from, UniswapV2Library.pairFor(factory, path[0], path[1]), amountIn);
        _swap(amounts, path, to);
    }

    // requires the initial amount to have already been sent to the first pair
    function _swap(
        uint256[] memory amounts,
        address[] memory path,
        address _to
    ) internal virtual {
        for (uint256 i; i < path.length - 1; i++) {
            (address input, address output) = (path[i], path[i + 1]);
            (address token0, ) = UniswapV2Library.sortTokens(input, output);
            uint256 amountOut = amounts[i + 1];
            (uint256 amount0Out, uint256 amount1Out) = input == token0
                ? (uint256(0), amountOut)
                : (amountOut, uint256(0));
            address to = i < path.length - 2 ? UniswapV2Library.pairFor(factory, output, path[i + 2]) : _to;
            IUniswapV2Pair(UniswapV2Library.pairFor(factory, input, output)).swap(
                amount0Out,
                amount1Out,
                to,
                new bytes(0)
            );
        }
    }

}