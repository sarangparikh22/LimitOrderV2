// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.6.12;
pragma experimental ABIEncoderV2;

import "@boringcrypto/boring-solidity/contracts/libraries/BoringERC20.sol";
import "@boringcrypto/boring-solidity/contracts/libraries/BoringMath.sol";
import "@sushiswap/core/contracts/uniswapv2/libraries/TransferHelper.sol";
import "@sushiswap/bentobox-sdk/contracts/IBentoBoxV1.sol";
import "./interfaces/ILimitOrderReceiver.sol";


contract SushiSwapLimitOrderReceiver is ILimitOrderReceiver {
    using BoringERC20 for IERC20;
    using BoringMath for uint256;

    string private constant EIP191_PREFIX_FOR_EIP712_STRUCTURED_DATA = "\x19\x01";
    bytes32 private constant DOMAIN_SEPARATOR_SIGNATURE_HASH = keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");
    bytes32 private constant FILL_SWAP_TYPEHASH = keccak256("FillerSwap(address tokenHave,address tokenWant,address filler,uint256 amountFillerIn,uint256 amountFillerOut,uint256 nonce)");
    bytes32 private immutable _DOMAIN_SEPARATOR;
    uint256 public immutable deploymentChainId;
    IBentoBoxV1 private immutable bentoBox;

    mapping(address => uint256) public nonces;

    constructor (IBentoBoxV1 _bentoBox) public {
        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        deploymentChainId = chainId;
        _DOMAIN_SEPARATOR = _calculateDomainSeparator(chainId);
        bentoBox = _bentoBox;
    }

    function _calculateDomainSeparator(uint256 chainId) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                DOMAIN_SEPARATOR_SIGNATURE_HASH,
                keccak256("SushiLimitOrderReceiverFiller"),
                chainId,
                address(this)
            )
        );
    }

    function DOMAIN_SEPARATOR() internal view returns (bytes32) {
        uint256 chainId;
        assembly {chainId := chainid()}
        return chainId == deploymentChainId ? _DOMAIN_SEPARATOR : _calculateDomainSeparator(chainId);
    }

    function onLimitOrder(IERC20 tokenIn, IERC20 tokenOut, uint256 amountIn, uint256 amountMinOut, bytes calldata data) override external {
        (
            IERC20 tokenHave, 
            IERC20 tokenWant, 
            address filler, 
            uint256 amountFillerIn, 
            uint256 amountFillerOut, 
            uint256 nonce, 
            uint8 v, 
            bytes32 r, 
            bytes32 s

        ) = abi.decode(data, (IERC20, IERC20, address, uint256, uint256, uint256, uint8, bytes32, bytes32));
        
        require(nonce == nonces[filler]++);
        require(filler == ecrecover(_getDigest(tokenHave, tokenWant, filler, amountFillerIn, amountFillerOut, nonce), v, r, s));

        require(tokenHave == tokenOut && tokenWant == tokenIn);
        require(amountFillerOut >= amountIn);
        require(amountFillerIn <= amountMinOut);
        bentoBox.transfer(tokenIn, address(this), filler, bentoBox.toShare(tokenIn, amountIn, true));
        bentoBox.transfer(tokenOut, filler, msg.sender, bentoBox.toShare(tokenOut, amountMinOut, true));
    }

    function _getDigest(IERC20 tokenHave, IERC20 tokenWant, address filler, uint256 amountFillerIn, uint256 amountFillerOut, uint256 nonce) internal view returns(bytes32 digest) {
        bytes32 encoded = keccak256(
            abi.encode(
                FILL_SWAP_TYPEHASH,
                tokenHave,
                tokenWant,
                filler,
                amountFillerIn,
                amountFillerOut,
                nonce
            )
        );
        
        digest =
            keccak256(
                abi.encodePacked(
                    EIP191_PREFIX_FOR_EIP712_STRUCTURED_DATA,
                    DOMAIN_SEPARATOR(),
                    encoded
                )
            );
    }
}