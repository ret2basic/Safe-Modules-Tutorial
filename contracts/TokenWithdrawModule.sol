// SPDX-License-Identifier: LGPL-3.0
pragma solidity ^0.8.0;

import "@safe-global/safe-contracts/contracts/common/Enum.sol";
import "@safe-global/safe-contracts/contracts/Safe.sol";

/**
 * @title TokenWithdrawModule
 * @dev This contract implements a Safe module that enables a user with a valid signature to
 *      transfer ERC20 tokens from a Safe contract to a specified receiver.
 */
contract TokenWithdrawModule {
    
    bytes32 public immutable PERMIT_TYPEHASH =
    keccak256(
      "TokenWithdrawModule(uint256 amount,address beneficiary,uint256 nonce,uint256 deadline)"
    );

    address public immutable safeAddress;
    address public immutable tokenAddress;

    mapping(address => uint256) public nonces;

    
    constructor(address _tokenAddress, address _safeAddress) {
        tokenAddress = _tokenAddress;
        safeAddress = _safeAddress;
    }

    /**
     * @dev Transfers the specified amount of tokens to a receiver address. The msg.sender must hold a valid signature.
     *      The msg.sender address must be used as the `beneficiary` parameter in the EIP-712 structured data for
     *      signature generation. However, msg.sender can specify a different `receiver` address to receive the tokens
     *      when withdrawing the tokens.
     * @param amount amount of tokens to be transferred
     * @param receiver address to which the tokens will be transferred
     * @param deadline deadline for the validity of the signature
     * @param signatures signatures of the Safe owner(s)
     */
    function tokenTransfer(
        uint amount,
        address receiver,
        uint256 deadline,
        bytes memory signatures
    ) public {
        // ---- Step 1: check deadline ----
        require(deadline >= block.timestamp, "expired deadline");

        // ---- Step 2: verify signatures ----
        bytes32 signatureData = keccak256(
            abi.encode(
                PERMIT_TYPEHASH,
                amount,
                msg.sender,
                nonces[msg.sender]++,
                deadline
            )
        );

        bytes32 hash = keccak256(
            abi.encodePacked("\x19\x01", getDomainSeparator(), signatureData)
        );

        // Verifying the signatures using the Safe's `checkSignatures` function to ensure that the transaction is authorized.
        Safe(payable(safeAddress)).checkSignatures(
            hash,
            abi.encodePacked(signatureData),
            signatures
        );

        // ---- Step 3: execute token transfer ----
        bytes memory data = abi.encodeWithSignature(
            "transfer(address,uint256)",
            receiver,
            amount
        );

        // Calling `execTransactionFromModule` with the transaction data to execute the token transfer through the Safe account.
        require(
            Safe(payable(safeAddress)).execTransactionFromModule(
                tokenAddress,
                0,
                data,
                Enum.Operation.Call
            ),
            "Could not execute token transfer"
        );
    }

    /**
     * @dev Generates the EIP-712 domain separator for the contract.
     *
     * @return The EIP-712 domain separator.
     */
    function getDomainSeparator() private view returns (bytes32) {
      return keccak256(
          abi.encode(
              keccak256(
                  "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
              ),
              keccak256(bytes("TokenWithdrawModule")),
              keccak256(bytes("1")),
              block.chainid,
              address(this)
          )
      );
  }
}
