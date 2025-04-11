// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Safe0x00.sol";
import "../src/Vulnerable0x00.sol";

contract WalletTest is Test {
    address owner = vm.addr(1);
    address attacker = vm.addr(2);
    address recipient = makeAddr("recipient");
    
    SecureWallet secureWallet;
    VulnerableWallet vulnerableWallet;
    
    uint256 chainId = 31337;

    function setUp() public {
        secureWallet = new SecureWallet(owner);
        vulnerableWallet = new VulnerableWallet(owner);
        vm.deal(address(secureWallet), 1 ether);
        vm.deal(address(vulnerableWallet), 1 ether);
    }

    function test_SecureExecution() public {
        uint256 nonce = secureWallet.nonce();
        bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", recipient, 0.5 ether);
        
        bytes32 messageHash = keccak256(abi.encodePacked(
            bytes1(0x19), bytes1(0x00), 
            address(secureWallet),
            chainId,
            nonce,
            recipient,
            uint256(0.5 ether),
            data
        ));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, messageHash);
        
        vm.prank(attacker);
        secureWallet.execute(recipient, 0.5 ether, data, v, r, s);
        
        assertEq(recipient.balance, 0.5 ether);
    }

    function test_SecureReplayProtection() public {
        test_SecureExecution();
        
        bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", recipient, 0.5 ether);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, keccak256(abi.encodePacked(
            bytes1(0x19), bytes1(0x00), 
            address(secureWallet),
            chainId,
            uint256(0),
            recipient,
            uint256(0.5 ether),
            data
        )));

        vm.expectRevert("Invalid signature");
        secureWallet.execute(recipient, 0.5 ether, data, v, r, s);
    }

    function test_VulnerableCrossChainReplay() public {
        bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", recipient, 1 ether);
        bytes32 messageHash = keccak256(abi.encodePacked(
            vulnerableWallet.nonce(),
            recipient,
            uint256(1 ether),
            data
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, messageHash);

        vulnerableWallet.execute(recipient, 1 ether, data, v, r, s);
        assertEq(recipient.balance, 1 ether);

        uint256 forkId = vm.createFork("https://polygon-rpc.com");
        vm.selectFork(forkId);
        
        VulnerableWallet forkedWallet = new VulnerableWallet(owner);
        vm.deal(address(forkedWallet), 1 ether);

        forkedWallet.execute(recipient, 1 ether, data, v, r, s);
        assertEq(recipient.balance, 1 ether);
    }

    function test_VulnerablePhishing() public {
        MaliciousContract malicious = new MaliciousContract();
        
        uint256 currentNonce = vulnerableWallet.nonce();
        address target = address(malicious);
        uint256 value = 0;
        bytes memory data = abi.encodeWithSignature(
            "transferOwnership(address)", 
            attacker
        );
        
        bytes32 messageHash = keccak256(abi.encodePacked(
            currentNonce,
            target,
            value,
            data
        ));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, messageHash);
        
        vulnerableWallet.execute(
            target,
            value,
            data,
            v,
            r,
            s
        );
        
        assertEq(malicious.owner(), attacker);
    }
}

contract MaliciousContract {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    function transferOwnership(address newOwner) external {
        owner = newOwner;
    }
}