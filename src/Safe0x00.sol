// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Smart Account Executor (EIP-191 v0x00)
 * @notice Allows a trusted owner to execute transactions via signatures
 * @dev Implements EIP-191 version 0x00 for wallet-like functionality
 */
contract SecureWallet {
    address public owner;
    uint256 public nonce;
    uint256 public immutable chainId;

    constructor(address _owner) {
        owner = _owner;
        chainId = block.chainid;
    }

    /**
     * @notice Execute a signed transaction
     * @param target The target contract to call
     * @param value ETH to send with the call
     * @param data The calldata to execute
     * @param v, r, s ECDSA signature components
     */
    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external payable returns (bytes memory) {
        // Prevent reentrancy
        uint256 currentNonce = nonce++;
        
        // Construct EIP-191 v0x00 message
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                bytes1(0x19),    // EIP-191 prefix
                bytes1(0x00),    // Version byte (0x00)
                address(this),   // Validator address (this contract)
                chainId,         // Replay protection
                currentNonce,    // Nonce protection
                target,          // Target contract
                value,           // ETH value
                data             // Calldata
            )
        );

        // Verify signature
        address recovered = ecrecover(messageHash, v, r, s);
        require(recovered == owner, "Invalid signature");

        // Execute the call
        (bool success, bytes memory result) = target.call{value: value}(data);
        require(success, "Execution failed");

        return result;
    }

    // Allow contract to receive ETH
    receive() external payable {}
}