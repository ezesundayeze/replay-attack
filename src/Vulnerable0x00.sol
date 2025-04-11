// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// UNSAFE IMPLEMENTATION - FOR EDUCATIONAL PURPOSES ONLY
contract VulnerableWallet {
    address public owner;
    uint256 public nonce;

    constructor(address _owner) {
        owner = _owner;
    }

    // INSECURE: Missing EIP-191 protections
    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external payable returns (bytes memory) {
        // 1. VULN: No chainId separation (replayable across chains)
        // 2. VULN: No validator address in signature
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                nonce++,        // Only nonce protects against replay
                target,
                value,
                data
            )
        );

        // 3. VULN: No EIP-191 prefix (vulnerable to phishing)
        address recovered = ecrecover(messageHash, v, r, s);
        require(recovered == owner, "Invalid signature");

        (bool success, bytes memory result) = target.call{value: value}(data);
        require(success, "Execution failed");
        return result;
    }

    receive() external payable {}
}