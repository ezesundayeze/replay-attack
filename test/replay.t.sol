// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Vulnerable.sol";
import "../src/Safe.sol";

/// @title Replay Attack Test Suite
/// @notice Tests the difference between vulnerable and safe smart contracts in handling signature replay attacks.
contract ReplayTest is Test {
    Vulnerable public vulnerable;
    Safe public safe;

    /// @notice Test user address, derived from private key 0x1
    address public user = vm.addr(1);

    /// @notice Raw message hash used for signing in vulnerable contract
    bytes32 public message;

    /// @notice Signature components used for vulnerable contract (shared)
    uint8 public v;
    bytes32 public r;
    bytes32 public s;

    /// @notice Deploys test contracts and prepares an example signed message for the vulnerable contract
    function setUp() public {
        vulnerable = new Vulnerable();
        safe = new Safe();

        // Construct a simple message hash (no context) for the vulnerable contract
        message = keccak256(abi.encodePacked(user));

        // Sign the message with the private key corresponding to `user`
        (v, r, s) = vm.sign(1, message);
    }

    /// @notice Tests a successful claim on the vulnerable contract with a valid signature
    /// @dev Verifies that a valid ECDSA signature allows claiming
    function testVulnerableClaim() public {
        vm.prank(user);
        vulnerable.claim(message, v, r, s);

        assertTrue(vulnerable.hasClaimed(user));
    }

    /// @notice Tests that a signature can be reused on another instance of the vulnerable contract
    /// @dev Demonstrates replay attack by reusing the same signature on a fresh deployment
    function testVulnerableReplay() public {
        vm.prank(user);
        vulnerable.claim(message, v, r, s);

        Vulnerable vulnerable2 = new Vulnerable();

        // Reuse the same signature on a different contract (attack succeeds)
        vm.prank(user);
        vulnerable2.claim(message, v, r, s);

        assertTrue(vulnerable2.hasClaimed(user));
    }

    /// @notice Tests that the Safe contract accepts a correctly signed, prefixed message with context
    /// @dev Uses EIP-191 formatted message that includes chainId, contract address, and user address
    function testSafeClaim() public {
        // Build a unique message including contract context
        bytes32 rawMessage = keccak256(
            abi.encodePacked(safe.chainId(), address(safe), user)
        );

        // Prefix using EIP-191 standard
        bytes32 prefixedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", rawMessage)
        );

        // Sign the prefixed hash using the user's private key
        (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(1, prefixedHash);

        vm.prank(user);
        safe.claim(rawMessage, _v, _r, _s);

        assertTrue(safe.hasClaimed(user));
    }

    /// @notice Tests that the Safe contract rejects replayed signatures from other contract instances
    /// @dev Confirms that contract context prevents signature reuse across deployments
    function testSafeReplayFails() public {
        bytes32 rawMessage = keccak256(
            abi.encodePacked(safe.chainId(), address(safe), user)
        );

        bytes32 prefixedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", rawMessage)
        );

        (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(1, prefixedHash);

        vm.prank(user);
        safe.claim(rawMessage, _v, _r, _s);

        // Create a new Safe contract, changing the context
        Safe safe2 = new Safe();

        // Build a new raw message with safe2's address
        bytes32 rawMessage2 = keccak256(
            abi.encodePacked(safe2.chainId(), address(safe2), user)
        );

        vm.prank(user);
        vm.expectRevert("Invalid signature");
        safe2.claim(rawMessage2, _v, _r, _s);
    }

    /// @notice Tests that the vulnerable contract accepts signatures without EIP-191 prefixing
    /// @dev Shows that raw signatures are accepted, which would fail in Safe
    function testVulnerableAcceptsRawSig() public {
        vm.prank(user);
        vulnerable.claim(message, v, r, s);

        assertTrue(vulnerable.hasClaimed(user));
    }

    /// @notice Tests that the Safe contract rejects raw (non-prefixed) signatures
    /// @dev This proves that EIP-191 formatting is enforced in Safe
    function testSafeRejectsRawSig() public {
        // Construct raw message (same format but not prefixed)
        bytes32 _message = keccak256(
            abi.encodePacked(safe.chainId(), address(safe), user)
        );

        vm.prank(user);
        vm.expectRevert("Invalid signature");
        safe.claim(_message, v, r, s); // Reuses signature from vulnerable test
    }
}
