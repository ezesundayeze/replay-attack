// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Vulnerable Signature Claim Contract (Insecure Version)
/// @author
/// @notice This contract demonstrates an insecure signature verification that is vulnerable to replay attacks
/// @dev Uses raw message hashes without EIP-191 prefixing or contextual binding (e.g., chain ID, contract address)
contract Vulnerable {
    /// @notice Tracks whether an address has already claimed in this contract instance
    mapping(address => bool) public hasClaimed;

    /// @notice Verifies a claim using a raw signed message
    /// @dev The message must be keccak256(abi.encodePacked(userAddress)), signed off-chain
    ///      This verification is insecure because the same signature can be replayed on other contracts or chains
    /// @param message A raw message hash signed off-chain, usually keccak256(abi.encodePacked(userAddress))
    /// @param v The recovery byte of the signature (27 or 28)
    /// @param r Half of the ECDSA signature pair
    /// @param s Half of the ECDSA signature pair
    function claim(bytes32 message, uint8 v, bytes32 r, bytes32 s) external {
        // Ensure the sender has not already claimed
        require(!hasClaimed[msg.sender], "Already claimed");

        // Recover the address that signed the message
        address signer = ecrecover(message, v, r, s);

        // Check that the recovered signer matches the sender
        require(signer == msg.sender, "Invalid signature");

        // Mark the sender as having claimed
        hasClaimed[msg.sender] = true;
    }

    /*
        Off-chain signing instructions:
        --------------------------------
        To create a valid signature for testing this contract:

        1. Construct the message as: keccak256(abi.encodePacked(userAddress))
        2. Sign the hash with the user's private key (no prefixing)
        3. Submit the message hash and v, r, s values to the claim() function

        WARNING: This is insecure because:
          - The message is not prefixed with "\x19Ethereum Signed Message:\n32"
          - It does not bind to a specific contract or chain ID
          - The same signature can be reused (replayed) across different contract instances or blockchains
    */
}
