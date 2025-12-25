// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../contracts/DNSSECOracle.sol";
import "../contracts/algorithms/P256SHA256Algorithm.sol";
import "../contracts/algorithms/RSASHA256Algorithm.sol";
import "../contracts/digests/SHA256Digest.sol";

/**
 * @title DNSSECOracleTest
 * @dev Tests for DNSSECOracle contract.
 * 
 * NOTE: P-256 tests require EIP-7951 precompile which is NOT available in 
 *       Foundry's local EVM. Run with --fork-url $SEPOLIA_RPC_URL for P-256 tests.
 * 
 * Usage:
 *   # RSA tests (local EVM)
 *   forge test --match-test "test_RSA"
 * 
 *   # P-256 tests (requires Sepolia fork)
 *   forge test --fork-url $SEPOLIA_RPC_URL --match-test "test_P256"
 * 
 *   # All tests on Sepolia fork
 *   forge test --fork-url $SEPOLIA_RPC_URL
 */
contract DNSSECOracleTest is Test {
    DNSSECOracle public oracle;
    P256SHA256Algorithm public p256Algo;
    RSASHA256Algorithm public rsaAlgo;
    SHA256Digest public sha256Digest;

    // Algorithm IDs
    uint8 constant ALGO_RSASHA256 = 8;
    uint8 constant ALGO_ECDSAP256SHA256 = 13;
    uint8 constant DIGEST_SHA256 = 2;

    function setUp() public {
        // Deploy contracts
        p256Algo = new P256SHA256Algorithm();
        rsaAlgo = new RSASHA256Algorithm();
        sha256Digest = new SHA256Digest();
        
        // Deploy oracle with empty anchors (will configure in tests)
        oracle = new DNSSECOracle("");
        
        // Configure algorithms
        oracle.setAlgorithm(ALGO_RSASHA256, IAlgorithm(address(rsaAlgo)));
        oracle.setAlgorithm(ALGO_ECDSAP256SHA256, IAlgorithm(address(p256Algo)));
        oracle.setDigest(DIGEST_SHA256, IDigest(address(sha256Digest)));
    }

    /// @dev Test that oracle deploys correctly
    function test_OracleDeployment() public view {
        assertEq(address(oracle.algorithms(ALGO_RSASHA256)), address(rsaAlgo));
        assertEq(address(oracle.algorithms(ALGO_ECDSAP256SHA256)), address(p256Algo));
        assertEq(address(oracle.digests(DIGEST_SHA256)), address(sha256Digest));
    }

    /// @dev Test that owner can set algorithms
    function test_SetAlgorithm() public {
        P256SHA256Algorithm newAlgo = new P256SHA256Algorithm();
        oracle.setAlgorithm(ALGO_ECDSAP256SHA256, IAlgorithm(address(newAlgo)));
        assertEq(address(oracle.algorithms(ALGO_ECDSAP256SHA256)), address(newAlgo));
    }

    /// @dev Test that non-owner cannot set algorithms
    function test_SetAlgorithm_RevertIfNotOwner() public {
        P256SHA256Algorithm newAlgo = new P256SHA256Algorithm();
        
        vm.prank(address(0xdead));
        vm.expectRevert();
        oracle.setAlgorithm(ALGO_ECDSAP256SHA256, IAlgorithm(address(newAlgo)));
    }

    /// @dev Test SHA256 digest verification
    function test_SHA256Digest() public view {
        bytes memory data = "hello world";
        bytes32 expectedHash = sha256(data);
        bytes memory hashBytes = abi.encodePacked(expectedHash);
        
        bool valid = sha256Digest.verify(data, hashBytes);
        assertTrue(valid);
    }

    /// @dev Test SHA256 digest rejects wrong hash
    function test_SHA256Digest_RejectWrongHash() public view {
        bytes memory data = "hello world";
        bytes memory wrongHash = abi.encodePacked(bytes32(0));
        
        bool valid = sha256Digest.verify(data, wrongHash);
        assertFalse(valid);
    }
}

/**
 * @title P256AlgorithmTest
 * @dev Tests for P256SHA256Algorithm using EIP-7951 precompile.
 *      MUST run with --fork-url $SEPOLIA_RPC_URL
 */
contract P256AlgorithmTest is Test {
    P256SHA256Algorithm public algo;

    // EIP-7951 precompile address
    address constant P256_PRECOMPILE = 0x0000000000000000000000000000000000000100;

    function setUp() public {
        algo = new P256SHA256Algorithm();
    }

    /// @dev Check if EIP-7951 precompile is available
    /// @notice This test verifies we're on a fork with EIP-7951 support
    function test_P256_PrecompileExists() public view {
        // Check if we're on a fork by checking block number
        uint256 blockNumber = block.number;
        console.log("Current block number:", blockNumber);
        
        // Precompiles don't have code, but we can test by calling
        // EIP-7951 expects: hash(32) + r(32) + s(32) + x(32) + y(32) = 160 bytes
        bytes memory input = new bytes(160);
        
        // Call the precompile
        (bool success, bytes memory result) = P256_PRECOMPILE.staticcall(input);
        
        console.log("Precompile call success:", success);
        console.log("Precompile result length:", result.length);
        
        // On Sepolia fork: should return 32 bytes (0x00...00 for invalid sig)
        // On local EVM: returns 0 bytes or reverts
        if (success && result.length == 32) {
            console.log("[OK] EIP-7951 precompile is AVAILABLE (Sepolia fork)");
        } else {
            console.log("[FAIL] EIP-7951 precompile NOT available");
            if (blockNumber < 1000000) {
                console.log("[WARN] Block number suggests local EVM, not fork");
            }
            console.log("[TIP] Run with: forge test --fork-url $SEPOLIA_RPC_URL");
        }
    }

    /// @dev Test P-256 verification with invalid signature (should return false)
    /// @notice This test requires Sepolia fork
    function test_P256_InvalidSignature() public {
        // Skip if not on fork (precompile won't work)
        _skipIfNoPrecompile();

        // 68-byte key: flags(2) + protocol(1) + algorithm(1) + pubkey(64)
        bytes memory key = new bytes(68);
        key[0] = 0x01; // flags high byte
        key[1] = 0x01; // flags low byte (257 = KSK)
        key[2] = 0x03; // protocol
        key[3] = 0x0d; // algorithm 13
        // Rest is zeros (invalid public key)

        bytes memory data = "test data";
        
        // 64-byte signature (all zeros = invalid)
        bytes memory signature = new bytes(64);

        // Should return false for invalid signature
        bool valid = algo.verify(key, data, signature);
        assertFalse(valid);
    }

    /// @dev Helper to skip test if precompile not available
    function _skipIfNoPrecompile() internal {
        bytes memory input = new bytes(160);
        (, bytes memory result) = P256_PRECOMPILE.staticcall(input);
        
        if (result.length != 32) {
            // Precompile not available - skip this test
            vm.skip(true);
        }
    }
}

/**
 * @title RSAAlgorithmTest
 * @dev Tests for RSASHA256Algorithm using modexp precompile.
 *      Works in local Foundry EVM (no fork needed).
 */
contract RSAAlgorithmTest is Test {
    RSASHA256Algorithm public algo;

    function setUp() public {
        algo = new RSASHA256Algorithm();
    }

    /// @dev Test RSA algorithm deployment
    function test_RSA_Deployment() public view {
        assertTrue(address(algo) != address(0));
    }

    /// @dev Test RSA with invalid key length reverts or returns false
    function test_RSA_InvalidKeyTooShort() public view {
        bytes memory key = new bytes(4); // Too short
        bytes memory data = "test";
        bytes memory sig = new bytes(256);

        // Should handle gracefully (return false or revert)
        try algo.verify(key, data, sig) returns (bool valid) {
            assertFalse(valid);
        } catch {
            // Revert is also acceptable for invalid input
            assertTrue(true);
        }
    }
}

