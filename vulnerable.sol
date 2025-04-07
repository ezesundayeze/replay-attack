// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vulnerable {
    mapping(address => bool) public hasClaimed;

    function claim(bytes32 message, uint8 v, bytes32 r, bytes32 s) external {
        require(!hasClaimed[msg.sender], "Already claimed");

        // Recover the signer from the message
        address signer = ecrecover(message, v, r, s);
        require(signer == msg.sender, "Invalid signature");

        hasClaimed[msg.sender] = true;

        // Simulate reward (e.g., send token or emit event)
    }

    // Helper: generate message hash off-chain as keccak256(abi.encodePacked(msg.sender))
}

