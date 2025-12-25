// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "../lib/forge-std/src/Script.sol";
import "../contracts/DnssecResolver.sol";

/// @notice Script to redeploy resolver with multicall support
/// @dev Run with: forge script scripts/RedeployResolver.s.sol:RedeployResolver --rpc-url sepolia --broadcast
contract RedeployResolver is Script {
    // Sepolia ENS Registry address
    address constant SEPOLIA_ENS_REGISTRY = 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e;
    
    // Existing verifier address (from previous deployment)
    address constant VERIFIER_ADDRESS = 0x580F2Db4Da8E6D5c654aa604182D0dFD17D5766B;
    
    function run() external {
        // Read gateway URL from .env
        string memory gatewayUrl = vm.envString("GATEWAY_URL");
        
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        console.log("Redeploying resolver from:", deployer);
        console.log("Verifier address:", VERIFIER_ADDRESS);
        console.log("Gateway URL:", gatewayUrl);
        
        vm.startBroadcast(deployerPrivateKey);
        
        // Deploy new resolver with multicall support
        console.log("\n=== Deploying New Resolver (with multicall) ===");
        DnssecResolver newResolver = new DnssecResolver(
            IDnssecP256Verifier(VERIFIER_ADDRESS),
            IENSRegistry(SEPOLIA_ENS_REGISTRY),
            gatewayUrl
        );
        console.log("New DnssecResolver deployed at:", address(newResolver));
        
        vm.stopBroadcast();
        
        console.log("\n=== Deployment Summary ===");
        console.log("New Resolver:", address(newResolver));
        console.log("Verifier:", VERIFIER_ADDRESS);
        console.log("ENS Registry:", SEPOLIA_ENS_REGISTRY);
        console.log("Gateway URL:", gatewayUrl);
        console.log("\nNEXT STEPS:");
        console.log("1. Update ConfigureResolver.s.sol with new resolver address");
        console.log("2. Run ConfigureResolver script to update ENS registry");
        console.log("3. Test in ENS app UI");
    }
}

