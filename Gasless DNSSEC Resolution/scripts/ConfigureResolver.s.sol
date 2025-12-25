// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "../lib/forge-std/src/Script.sol";
import "../contracts/DnssecResolver.sol";

/// @notice Script to configure resolver after deployment
/// @dev Run with: forge script scripts/ConfigureResolver.s.sol:ConfigureResolver --rpc-url sepolia --broadcast

/// @notice Extended ENS Registry interface with setter functions
interface IENSRegistryFull {
    function resolver(bytes32 node) external view returns (address);
    function owner(bytes32 node) external view returns (address);
    function setResolver(bytes32 node, address resolver) external;
}

contract ConfigureResolver is Script {
    // Sepolia ENS Registry
    address constant SEPOLIA_ENS_REGISTRY = 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e;
    
    // UPDATE THESE with your deployed addresses
    address constant RESOLVER_ADDRESS = 0x06A0388ff02830c848CbD5df80C0aE6780754827;
    bytes constant DNS_NAME_WIRE = hex"05656b65746302636f00"; // eketc.co in DNS wire format
    
    function run() external {
        require(RESOLVER_ADDRESS != address(0), "RESOLVER_ADDRESS not set");
        
        // Read ENS name from .env
        string memory ensName = vm.envString("ENS_NAME");
        
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        console.log("Configuring resolver from:", deployer);
        console.log("Resolver address:", RESOLVER_ADDRESS);
        console.log("ENS name:", ensName);
        
        // Calculate ENS node
        bytes32 ensNode = _namehash(ensName);
        console.log("ENS node:", vm.toString(ensNode));
        
        IENSRegistryFull registry = IENSRegistryFull(SEPOLIA_ENS_REGISTRY);
        DnssecResolver resolver = DnssecResolver(RESOLVER_ADDRESS);
        
        vm.startBroadcast(deployerPrivateKey);
        
        // Step 1: Verify you own the ENS name
        address nameOwner = registry.owner(ensNode);
        require(nameOwner == deployer, "You must own the ENS name");
        console.log(unicode"\n✅ Verified ownership of ENS name");
        
        // Step 2: Set resolver on ENS registry
        console.log("\n=== Step 1: Setting resolver on ENS registry ===");
        registry.setResolver(ensNode, RESOLVER_ADDRESS);
        console.log(unicode"✅ Resolver set on ENS registry");
        
        // Step 3: Link DNS name on resolver
        console.log("\n=== Step 2: Linking DNS name on resolver ===");
        console.log("DNS name (wire):", vm.toString(DNS_NAME_WIRE));
        resolver.linkDnsName(ensNode, DNS_NAME_WIRE);
        console.log(unicode"✅ DNS name linked on resolver");
        
        vm.stopBroadcast();
        
        console.log(unicode"\n✅ Resolver configuration complete!");
        console.log(unicode"\n⚠️  NEXT STEPS:");
        console.log("1. Test resolution via ENS app (Sepolia)");
        console.log("2. Set address/text records via resolver");
        console.log("3. Test DNS-verified reads");
    }
    
    /// @dev Compute namehash for ENS name
    function _namehash(string memory name) internal pure returns (bytes32) {
        bytes memory s = bytes(name);
        bytes32 node;
        uint256 labelEnd = s.length;
        for (uint256 i = s.length; i > 0; i--) {
            if (s[i - 1] == ".") {
                uint256 labelStart = i;
                uint256 labelLen = labelEnd > labelStart ? labelEnd - labelStart : 0;
                bytes32 labelHash;
                assembly {
                    labelHash := keccak256(add(add(s, 0x20), labelStart), labelLen)
                }
                node = keccak256(abi.encodePacked(node, labelHash));
                labelEnd = i - 1;
            }
        }
        if (labelEnd > 0) {
            bytes32 labelHash;
            assembly {
                labelHash := keccak256(add(add(s, 0x20), 0), labelEnd)
            }
            node = keccak256(abi.encodePacked(node, labelHash));
        }
        return node;
    }
}

/// @notice Script to update gateway URL on deployed resolver
/// @dev Run with: forge script scripts/ConfigureResolver.s.sol:UpdateGatewayUrl --rpc-url sepolia --broadcast
contract UpdateGatewayUrl is Script {
    // UPDATE THIS with your new resolver address
    address constant RESOLVER_ADDRESS = 0x06A0388ff02830c848CbD5df80C0aE6780754827;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        // Read new gateway URL from .env
        string memory newGatewayUrl = vm.envString("GATEWAY_URL");

        console.log("Updating gateway URL from:", deployer);
        console.log("Resolver address:", RESOLVER_ADDRESS);
        console.log("New gateway URL:", newGatewayUrl);

        DnssecResolver resolver = DnssecResolver(RESOLVER_ADDRESS);

        vm.startBroadcast(deployerPrivateKey);

        // Update gateway URL
        console.log("\n=== Updating Gateway URL ===");
        resolver.setGatewayUrl(newGatewayUrl);
        console.log(unicode"✅ Gateway URL updated successfully");

        vm.stopBroadcast();

        console.log(unicode"\n✅ Gateway URL configuration complete!");
        console.log("New gateway URL:", newGatewayUrl);
    }
}


