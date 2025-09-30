# Safe-Modules-Tutorial

## Overview

The module gives a third party an allowance via a signature for the token that can freely be used by that third party. In the module this third party is represented as the "beneficiary" in the EIP-712 struct (mentioned in the PERMIT_TYPEHASH). To use this allowance the third party / "beneficiary" calls the tokenTransfer method and specifies which token to use and who should receive it. The Safe owners grant the permission for token transfer to the third party by signing the EIP-712 struct without requiring Safe owners to execute any on-chain transaction.

## Integration notes

TokenWithdrawModule.sol is the main logic. It calls two functions from Safe.sol:

1. Safe.checkSignatures()
2. ModuleManager.execTransactionFromModule()

### Safe.checkSignatures()

Relevant code:

```solidity
    function checkSignatures(address executor, bytes32 dataHash, bytes memory signatures) public view override {
        // Load threshold to avoid multiple storage loads.
        uint256 _threshold = threshold;
        // Check that a threshold is set.
        if (_threshold == 0) revertWithError("GS001");
        checkNSignatures(executor, dataHash, signatures, _threshold);
    }

    function checkNSignatures(
        address executor,
        bytes32 dataHash,
        bytes memory signatures,
        uint256 requiredSignatures
    ) public view override {
        // Check that the provided signature data is not too short.
        if (signatures.length < requiredSignatures.mul(65)) revertWithError("GS020");
        // There cannot be an owner with address 0.
        address lastOwner = address(0);
        address currentOwner;
        uint256 v; // Implicit conversion from uint8 to uint256 will be done for `v` received from `signatureSplit(...)`.
        bytes32 r;
        // We do not enforce the `s` to be from the lower half of the curve.
        // This essentially means that for every signature, there's another valid signature (known as ECDSA malleability).
        // Since we have other mechanisms to prevent duplicated signatures (ordered owners array) and replay protection (nonce),
        // we can safely ignore ECDSA malleability.
        bytes32 s;
        uint256 i;
        for (i = 0; i < requiredSignatures; ++i) {
            (v, r, s) = signatureSplit(signatures, i);
            if (v == 0) {
                // If `v` is 0 then it is a contract signature
                // When handling contract signatures the address of the contract is encoded into r
                currentOwner = address(uint160(uint256(r)));

                // Check that signature data pointer (`s`) is not pointing inside the static part of the signatures bytes.
                // This check is not completely accurate, since it is possible that more signatures than the threshold are sent.
                // Here we only check that the pointer is not pointing inside the part that is being processed.
                if (uint256(s) < requiredSignatures.mul(65)) revertWithError("GS021");

                // The contract signature check is extracted to a separate function for better compatibility with formal verification
                // A quote from the Certora team:
                // "The assembly code broke the pointer analysis, which switched the prover in failsafe mode, where it is (a) much slower and (b) computes different hashes than in the normal mode."
                // More info here: <https://github.com/safe-global/safe-smart-account/pull/661>.
                checkContractSignature(currentOwner, dataHash, signatures, uint256(s));
            } else if (v == 1) {
                // If `v` is 1 then it is an approved hash.
                // When handling approved hashes the address of the approver is encoded into `r`.
                currentOwner = address(uint160(uint256(r)));
                // Hashes are automatically approved by the `executor` or when they have been pre-approved via a separate transaction.
                if (executor != currentOwner && approvedHashes[currentOwner][dataHash] == 0) revertWithError("GS025");
            } else if (v > 30) {
                // If `v > 30` then default `v` (27, 28) has been adjusted to encode an `eth_sign` signature.
                // To support `eth_sign` and similar we adjust `v` and hash the `dataHash` with the EIP-191 message prefix before applying `ecrecover`.
                currentOwner = ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash)), uint8(v - 4), r, s);
            } else {
                // Default is `ecrecover` for the provided `dataHash`.
                currentOwner = ecrecover(dataHash, uint8(v), r, s);
            }
            if (currentOwner <= lastOwner || owners[currentOwner] == address(0) || currentOwner == SENTINEL_OWNERS)
                revertWithError("GS026");
            lastOwner = currentOwner;
        }
    }

    /**
     * @notice Checks whether the contract signature is valid. Reverts otherwise.
     * @dev This is extracted to a separate function for better compatibility with Certora's prover.
     *      More info here: <https://github.com/safe-global/safe-smart-account/pull/661>
     * @param owner Address of the owner used to sign the message.
     * @param dataHash Hash of the data (could be either a message hash or transaction hash).
     * @param signatures Signatures that are being verified.
     * @param offset Offset to the start of the contract signature in the {signatures} byte array.
     */
    function checkContractSignature(address owner, bytes32 dataHash, bytes memory signatures, uint256 offset) internal view {
        // Check that signature data pointer (`s`) is in bounds to read the 32-byte data length value in `signatures`.
        if (offset.add(32) > signatures.length) revertWithError("GS022");

        // Check if the contract signature is in bounds: start of data is `s + 32` and the end is `start + signatures.length`.
        uint256 contractSignatureLen;
        /* solhint-disable no-inline-assembly */
        /// @solidity memory-safe-assembly
        assembly {
            contractSignatureLen := mload(add(add(signatures, offset), 0x20))
        }
        /* solhint-enable no-inline-assembly */
        if (offset.add(32).add(contractSignatureLen) > signatures.length) revertWithError("GS023");

        // Check signature.
        bytes memory contractSignature;
        /* solhint-disable no-inline-assembly */
        /// @solidity memory-safe-assembly
        assembly {
            // The signature data for the contract is appended to the concatenated signatures and the offset is stored in `s`.
            // We already checked that it is within bounds and do not need to worry about arithmetic overflows.
            contractSignature := add(add(signatures, offset), 0x20)
        }
        /* solhint-enable no-inline-assembly */

        if (ISignatureValidator(owner).isValidSignature(dataHash, contractSignature) != EIP1271_MAGIC_VALUE) revertWithError("GS024");
    }
```

Observations:

1. The core of the signature verification is ERC1271 isValidSignature(), and each caller adds some additional checks layer by layer.
2. The key is, integrated contract (caller) must handle nonce correctly. The protection in checkNSignatures() only works iff nonce is correct in the caller, otherwise attacker can append junk data (like null bytes) to a valid signature to create another valid signature. This attack is somewhere in between signature malleability and signature replay. For a reference: https://reports.electisec.com/2025-01-Sofa-Protocol#1-medium---signature-replay-protection-is-ineffective-against-contract-signatures

### ModuleManager.execTransactionFromModule()

Relevant code:

```solidity
    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    ) external override returns (bool success) {
        (address guard, bytes32 guardHash) = preModuleExecution(to, value, data, operation);
        success = execute(to, value, data, operation, type(uint256).max);
        postModuleExecution(guard, guardHash, success);
    }

    /**
     * @notice Runs pre-execution checks for module transactions if a guard is enabled.
     * @param to Target address of module transaction.
     * @param value Native token value of module transaction.
     * @param data Data payload of module transaction.
     * @param operation Operation type (0 for `CALL`, 1 for `DELEGATECALL`) of the module transaction.
     * @return guard Guard to be used for checking.
     * @return guardHash Hash returned from the guard tx check.
     */
    function preModuleExecution(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    ) internal returns (address guard, bytes32 guardHash) {
        onBeforeExecTransactionFromModule(to, value, data, operation);
        guard = getModuleGuard();

        // Only allow-listed modules are allowed.
        if (msg.sender == SENTINEL_MODULES || modules[msg.sender] == address(0)) revertWithError("GS104");

        if (guard != address(0)) {
            guardHash = IModuleGuard(guard).checkModuleTransaction(to, value, data, operation, msg.sender);
        }
    }

    /**
     * @notice Runs post-execution checks for module transactions if a guard is enabled.
     * @dev Emits event based on module transaction success.
     * @param guard Guard to be used for checking.
     * @param guardHash Hash returned from the guard during pre execution check.
     * @param success Boolean flag indicating if the call succeeded.
     */
    function postModuleExecution(address guard, bytes32 guardHash, bool success) internal {
        if (guard != address(0)) {
            IModuleGuard(guard).checkAfterModuleExecution(guardHash, success);
        }
        if (success) emit ExecutionFromModuleSuccess(msg.sender);
        else emit ExecutionFromModuleFailure(msg.sender);
    }

    /**
     * @notice Executes either a `CALL` or `DELEGATECALL` with provided parameters.
     * @dev This method doesn't perform any sanity check of the transaction, such as:
     *      - if the contract at `to` address has code or not
     *      It is the responsibility of the caller to perform such checks.
     * @param to Destination address.
     * @param value Ether value.
     * @param data Data payload.
     * @param operation Operation type (0 for `CALL`, 1 for `DELEGATECALL`).
     * @return success boolean flag indicating if the call succeeded.
     */
    function execute(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 txGas
    ) internal returns (bool success) {
        if (operation == Enum.Operation.DelegateCall) {
            /* solhint-disable no-inline-assembly */
            /// @solidity memory-safe-assembly
            assembly {
                success := delegatecall(txGas, to, add(data, 0x20), mload(data), 0, 0)
            }
            /* solhint-enable no-inline-assembly */
        } else {
            /* solhint-disable no-inline-assembly */
            /// @solidity memory-safe-assembly
            assembly {
                success := call(txGas, to, value, add(data, 0x20), mload(data), 0, 0)
            }
            /* solhint-enable no-inline-assembly */
        }
    }
```

Observations:

1. User can specify either a CALL or a DELEGATECALL
2. preModuleExecution() and postModuleExecution() are guard features, we don't implement that in this tutorial
