// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "forge-std/Script.sol";
import "forge-std/console.sol";

import "../contracts/DNSSECOracle.sol";
// DNSRegistrar has been moved to ../dns-claiming/contracts/
// import "../contracts/DNSRegistrar.sol"; // Moved to dns-claiming directory
import "../contracts/algorithms/P256SHA256Algorithm.sol";
import "../contracts/algorithms/RSASHA256Algorithm.sol";
import "../contracts/digests/SHA256Digest.sol";
// IENS interface moved to ../dns-claiming/contracts/interfaces/ with DNSRegistrar

/**
 * @title Deploy
 * @dev Deploys all DNSSEC oracle contracts to Sepolia.
 * 
 * Usage:
 *   forge script scripts/Deploy.s.sol:Deploy \
 *     --rpc-url $SEPOLIA_RPC_URL \
 *     --broadcast \
 *     --verify \
 *     -vvvv
 */
contract Deploy is Script {
    // Algorithm IDs
    uint8 constant ALGO_RSASHA256 = 8;
    uint8 constant ALGO_ECDSAP256SHA256 = 13;
    
    // Digest IDs
    uint8 constant DIGEST_SHA256 = 2;

    // Sepolia ENS Registry (standard ENS deployment)
    address constant SEPOLIA_ENS_REGISTRY = 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e;
    
    // Default resolver on Sepolia (Public Resolver)
    // Official address from ens-contracts deployments
    // Can also query: ens.registry.resolver(namehash("resolver.eth"))
    address constant DEFAULT_RESOLVER = 0xE99638b40E4Fff0129D56f03b55b6bbC4BBE49b5;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        console.log("=== DNSSEC Oracle Deployment ===");
        console.log("Deployer:", deployer);
        console.log("Chain ID:", block.chainid);
        console.log("");

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy Algorithm contracts
        console.log("1. Deploying Algorithm contracts...");
        
        P256SHA256Algorithm p256Algo = new P256SHA256Algorithm();
        console.log("   P256SHA256Algorithm (Algo 13):", address(p256Algo));
        
        RSASHA256Algorithm rsaAlgo = new RSASHA256Algorithm();
        console.log("   RSASHA256Algorithm (Algo 8):", address(rsaAlgo));

        // 2. Deploy Digest contracts
        console.log("2. Deploying Digest contracts...");
        
        SHA256Digest sha256Digest = new SHA256Digest();
        console.log("   SHA256Digest (Digest 2):", address(sha256Digest));

        // 3. Deploy DNSSECOracle with empty anchors (will configure later)
        console.log("3. Deploying DNSSECOracle...");
        
        // For MVP, we use empty anchors - will be set via script
        // In production, this should be the IANA root DS records
        bytes memory emptyAnchors = "";
        DNSSECOracle oracle = new DNSSECOracle(emptyAnchors);
        console.log("   DNSSECOracle:", address(oracle));

        // 4. Configure Oracle with algorithms
        console.log("4. Configuring DNSSECOracle...");
        
        oracle.setAlgorithm(ALGO_RSASHA256, IAlgorithm(address(rsaAlgo)));
        console.log("   Set Algorithm 8 (RSA/SHA-256)");
        
        oracle.setAlgorithm(ALGO_ECDSAP256SHA256, IAlgorithm(address(p256Algo)));
        console.log("   Set Algorithm 13 (P-256/SHA-256)");
        
        oracle.setDigest(DIGEST_SHA256, IDigest(address(sha256Digest)));
        console.log("   Set Digest 2 (SHA-256)");

        // 5. DNSRegistrar deployment skipped
        // DNSRegistrar has been moved to ../dns-claiming/contracts/
        // Deploy separately if needed (requires ENS registry permissions)
        console.log("5. DNSRegistrar deployment skipped");
        console.log("   DNSRegistrar contracts moved to ../dns-claiming/");
        console.log("   Deploy separately if you have ENS registry permissions");

        vm.stopBroadcast();

        // Print summary
        console.log("");
        console.log("=== Deployment Summary ===");
        console.log("P256SHA256Algorithm:", address(p256Algo));
        console.log("RSASHA256Algorithm:", address(rsaAlgo));
        console.log("SHA256Digest:", address(sha256Digest));
        console.log("DNSSECOracle:", address(oracle));
        console.log("");
        console.log("Next steps:");
        console.log("1. Set trust anchors via SetTrustAnchors.s.sol");
        console.log("2. Test oracle verification with fetched DNSSEC proofs");
    }
}

/**
 * @title DeployOracleOnly
 * @dev Deploys DNSSECOracle + algorithms for the optimized DNSSEC oracle PoC.
 * 
 * This is the MINIMUM deployment for demonstrating:
 * - EIP-7951 P-256 precompile usage
 * - DNSSEC proof verification
 * - Gas savings vs ENS's current implementation
 * 
 * Does NOT deploy:
 * - DNSRegistrar (requires ENS registry permissions)
 * - Any ENS integration (not needed for PoC)
 * 
 * Usage:
 *   source .env && forge script scripts/Deploy.s.sol:DeployOracleOnly \
 *     --rpc-url $SEPOLIA_RPC_URL \
 *     --broadcast \
 *     -vvvv
 */
contract DeployOracleOnly is Script {
    uint8 constant ALGO_RSASHA256 = 8;
    uint8 constant ALGO_ECDSAP256SHA256 = 13;
    uint8 constant DIGEST_SHA256 = 2;

    function run() external returns (
        address oracleAddr,
        address p256Addr,
        address rsaAddr,
        address digestAddr
    ) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        console.log("");
        console.log("========================================");
        console.log("  DNSSEC Oracle: Deploy Oracle Only (PoC)");
        console.log("========================================");
        console.log("");
        console.log("Deployer:", deployer);
        console.log("Chain ID:", block.chainid);
        console.log("");

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy Algorithm contracts
        console.log("[1/4] Deploying P256SHA256Algorithm (EIP-7951)...");
        P256SHA256Algorithm p256Algo = new P256SHA256Algorithm();
        console.log("      Address:", address(p256Algo));
        
        console.log("[2/4] Deploying RSASHA256Algorithm (modexp precompile)...");
        RSASHA256Algorithm rsaAlgo = new RSASHA256Algorithm();
        console.log("      Address:", address(rsaAlgo));

        // 2. Deploy Digest contract
        console.log("[3/4] Deploying SHA256Digest...");
        SHA256Digest sha256Digest = new SHA256Digest();
        console.log("      Address:", address(sha256Digest));

        // 3. Deploy Oracle with empty anchors (will set via setAnchors)
        console.log("[4/4] Deploying DNSSECOracle...");
        DNSSECOracle oracle = new DNSSECOracle("");
        console.log("      Address:", address(oracle));

        // 4. Configure Oracle
        console.log("");
        console.log("Configuring oracle...");
        
        oracle.setAlgorithm(ALGO_RSASHA256, IAlgorithm(address(rsaAlgo)));
        console.log("  - Algorithm 8 (RSA/SHA-256): SET");
        
        oracle.setAlgorithm(ALGO_ECDSAP256SHA256, IAlgorithm(address(p256Algo)));
        console.log("  - Algorithm 13 (P-256/SHA-256): SET");
        
        oracle.setDigest(DIGEST_SHA256, IDigest(address(sha256Digest)));
        console.log("  - Digest 2 (SHA-256): SET");

        vm.stopBroadcast();

        // Summary
        console.log("");
        console.log("========================================");
        console.log("  DEPLOYMENT COMPLETE");
        console.log("========================================");
        console.log("");
        console.log("Contracts deployed:");
        console.log("  DNSSECOracle:        ", address(oracle));
        console.log("  P256SHA256Algorithm: ", address(p256Algo));
        console.log("  RSASHA256Algorithm:  ", address(rsaAlgo));
        console.log("  SHA256Digest:        ", address(sha256Digest));
        console.log("");
        console.log("========================================");
        console.log("  NEXT STEPS");
        console.log("========================================");
        console.log("");
        console.log("1. Save oracle address to .env:");
        console.log("   echo 'ORACLE_ADDRESS=", address(oracle), "' >> .env");
        console.log("");
        console.log("2. Set trust anchors (required for verification):");
        console.log("   forge script scripts/SetTrustAnchors.s.sol \\");
        console.log("     --rpc-url $SEPOLIA_RPC_URL --broadcast");
        console.log("");
        console.log("3. Test with real DNSSEC proof:");
        console.log("   ORACLE_ADDRESS=", address(oracle));
        console.log("   node scripts/test_with_ensjs.mjs");
        console.log("");
        console.log("4. Compare gas with ENS oracle:");
        console.log("   node scripts/benchmark_comparison.mjs");
        console.log("");

        return (
            address(oracle),
            address(p256Algo),
            address(rsaAlgo),
            address(sha256Digest)
        );
    }
}

