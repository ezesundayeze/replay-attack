// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Safe {
    mapping(address => bool) public hasClaimed;

    function claim(bytes32 message, uint8 v, bytes32 r, bytes32 s) external {
        require(!hasClaimed[msg.sender], "Already claimed");

        // Rebuild the Ethereum signed message hash (EIP-191 style)
        bytes32 prefixedHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                message
            )
        );

        // Recover signer
        address signer = ecrecover(prefixedHash, v, r, s);
        require(signer == msg.sender, "Invalid signature");

        hasClaimed[msg.sender] = true;

        // Simulate reward
    }

    // Off-chain message should be: keccak256(abi.encodePacked(msg.sender))
}

