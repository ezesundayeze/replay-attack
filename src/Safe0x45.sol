// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;


/// @title Safe Signature Claim Contract
/// @notice Prevents replay attacks by requiring signatures to include chain ID and contract address
/// @dev Uses EIP-191 prefixing and requires messages to contain chain ID, contract address, and claimant address
contract Safe {
    mapping(address => bool) public hasClaimed;
    uint256 public immutable chainId;

    constructor() {
        chainId = block.chainid;
    }

    /// @notice Verifies a claim with proper replay protection
    /// @dev Message must be keccak256(chainId, address(this), msg.sender)
    function claim(bytes32 rawMessage, uint8 v, bytes32 r, bytes32 s) external {
        require(!hasClaimed[msg.sender], "Already claimed");
        
        // Reconstruct expected message
        bytes32 expectedMessage = keccak256(
            abi.encodePacked(chainId, address(this), msg.sender)
        );
        require(rawMessage == expectedMessage, "Invalid message content");

        // Verify signature
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        bytes32 messageHash = keccak256(
            abi.encodePacked(prefix, rawMessage)
        );
        address signer = ecrecover(messageHash, v, r, s);
        require(signer == msg.sender, "Invalid signature");

        hasClaimed[msg.sender] = true;
    }
}