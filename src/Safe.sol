// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Safe Signature Claim Contract
/// @author
/// @notice Prevents replay attacks by requiring signatures to include chain ID and contract address
/// @dev Uses EIP-191 prefixing for secure message verification
contract Safe {
    /// @notice Tracks whether an address has already claimed
    mapping(address => bool) public hasClaimed;

    /// @notice The chain ID stored at deployment to include in signed messages
    uint256 public chainId;

    /// @notice Initializes the contract and captures the current chain ID
    /// @dev This chain ID must be included in the off-chain signed message to prevent replay across chains
    constructor() {
        chainId = block.chainid;
    }

    /// @notice Verifies a claim by checking the signature against the expected signer and message structure
    /// @dev Requires an EIP-191 prefixed message containing the chain ID, contract address, and user address
    /// @param rawMessage The original message hash (without the Ethereum signed prefix) that was signed
    /// @param v The recovery byte of the signature
    /// @param r Half of the ECDSA signature pair
    /// @param s Half of the ECDSA signature pair
    function claim(bytes32 rawMessage, uint8 v, bytes32 r, bytes32 s) external {
        // Prevent multiple claims from the same address
        require(!hasClaimed[msg.sender], "Already claimed");

        // Prefix the message using the Ethereum signed message standard (EIP-191)
        bytes32 prefixedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", rawMessage)
        );

        // Recover the signer address from the signature
        address signer = ecrecover(prefixedHash, v, r, s);

        // Verify that the recovered signer is the message sender
        require(signer == msg.sender, "Invalid signature");

        // Mark the address as having claimed
        hasClaimed[msg.sender] = true;
    }
}
