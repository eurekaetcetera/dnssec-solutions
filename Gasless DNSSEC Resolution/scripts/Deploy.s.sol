// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "../lib/forge-std/src/Script.sol";
import "../contracts/algorithms/P256SHA256Algorithm.sol";
import "../contracts/DnssecP256Verifier.sol";
import "../contracts/DnssecResolver.sol";

/// @notice Deployment script for DNSSEC resolver system on Sepolia
/// @dev Run with: forge script scripts/Deploy.s.sol:Deploy --rpc-url sepolia --broadcast --verify
contract Deploy is Script {
    // Sepolia ENS Registry address
    address constant SEPOLIA_ENS_REGISTRY = 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e;

    // Gateway URL - read from .env or use default
    string GATEWAY_URL;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        // Read gateway URL from .env, fallback to localhost
        try vm.envString("GATEWAY_URL") returns (string memory url) {
            GATEWAY_URL = url;
        } catch {
            GATEWAY_URL = "http://localhost:8787/ccip-read";
        }

        console.log("Deploying from:", deployer);
        console.log("Balance:", deployer.balance / 1e18, "ETH");
        console.log("Gateway URL:", GATEWAY_URL);

        vm.startBroadcast(deployerPrivateKey);

        // Step 1: Deploy P256SHA256Algorithm
        console.log("\n=== Step 1: Deploying P256SHA256Algorithm ===");
        P256SHA256Algorithm algorithm = new P256SHA256Algorithm();
        console.log("P256SHA256Algorithm deployed at:", address(algorithm));

        // Step 2: Deploy DnssecP256Verifier
        console.log("\n=== Step 2: Deploying DnssecP256Verifier ===");
        DnssecP256Verifier verifier = new DnssecP256Verifier();
        console.log("DnssecP256Verifier deployed at:", address(verifier));

        // Step 3: Set algorithm on verifier
        console.log("\n=== Step 3: Setting algorithm on verifier ===");
        verifier.setAlgorithm(algorithm);
        console.log("Algorithm set successfully");

        // Step 4: Deploy DnssecResolver
        console.log("\n=== Step 4: Deploying DnssecResolver ===");
        DnssecResolver resolver = new DnssecResolver(
            IDnssecP256Verifier(address(verifier)),
            IENSRegistry(SEPOLIA_ENS_REGISTRY),
            GATEWAY_URL
        );
        console.log("DnssecResolver deployed at:", address(resolver));

        // Step 5: Transfer ownership (optional - if you want to transfer resolver ownership)
        // resolver.transferOwnership(newOwner);

        vm.stopBroadcast();

        console.log("\n=== Deployment Summary ===");
        console.log("P256SHA256Algorithm:", address(algorithm));
        console.log("DnssecP256Verifier:", address(verifier));
        console.log("DnssecResolver:", address(resolver));
        console.log("ENS Registry:", SEPOLIA_ENS_REGISTRY);
        console.log("Gateway URL:", GATEWAY_URL);
        console.log("\nNEXT STEPS:");
        console.log("1. Set trust anchor on verifier (see SetTrustAnchor.s.sol)");
        console.log("2. Update gateway URL if needed");
        console.log("3. Register/configure ENS name");
        console.log("4. Set resolver on ENS registry");
        console.log("5. Link DNS name on resolver");
    }
}

/// @notice Deploy only the resolver, reusing existing verifier
/// @dev Run with: forge script scripts/Deploy.s.sol:DeployResolverOnly --rpc-url sepolia --broadcast --verify
contract DeployResolverOnly is Script {
    // Sepolia ENS Registry address
    address constant SEPOLIA_ENS_REGISTRY = 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e;

    // Existing verifier contract (already deployed)
    IDnssecP256Verifier constant EXISTING_VERIFIER = IDnssecP256Verifier(0x580F2Db4Da8E6D5c654aa604182D0dFD17D5766B);

    // Gateway URL - read from .env or use default
    string GATEWAY_URL;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        // Read gateway URL from .env, fallback to localhost
        try vm.envString("GATEWAY_URL") returns (string memory url) {
            GATEWAY_URL = url;
        } catch {
            GATEWAY_URL = "http://localhost:8787/ccip-read";
        }

        console.log("Deploying from:", deployer);
        console.log("Balance:", deployer.balance / 1e18, "ETH");
        console.log("Using existing verifier:", address(EXISTING_VERIFIER));
        console.log("Gateway URL:", GATEWAY_URL);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy only the resolver with the existing verifier
        console.log("\n=== Deploying DnssecResolver (with existing verifier) ===");
        DnssecResolver resolver = new DnssecResolver(
            EXISTING_VERIFIER,
            IENSRegistry(SEPOLIA_ENS_REGISTRY),
            GATEWAY_URL
        );
        console.log("DnssecResolver deployed at:", address(resolver));

        vm.stopBroadcast();

        console.log("\n=== Deployment Summary ===");
        console.log("Existing Verifier:", address(EXISTING_VERIFIER));
        console.log("New DnssecResolver:", address(resolver));
        console.log("ENS Registry:", SEPOLIA_ENS_REGISTRY);
        console.log("Gateway URL:", GATEWAY_URL);
        console.log("\nNEXT STEPS:");
        console.log("1. Verify verifier has correct trust anchor set");
        console.log("2. Update gateway URL if needed");
        console.log("3. Register/configure ENS name");
        console.log("4. Set resolver on ENS registry");
        console.log("5. Link DNS name on resolver");
    }
}


