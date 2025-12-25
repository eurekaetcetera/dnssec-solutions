// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "../lib/forge-std/src/Script.sol";
import "../contracts/DnssecResolver.sol";

/// @notice Script to authorize the resolver for ENS app compatibility
/// @dev Run with: forge script scripts/AuthorizeResolver.s.sol:AuthorizeResolver --rpc-url sepolia --broadcast
contract AuthorizeResolver is Script {
    // Sepolia ENS Registry
    address constant SEPOLIA_ENS_REGISTRY = 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e;
    
    // UPDATE with your deployed resolver address
    address constant RESOLVER_ADDRESS = 0x89CED449491B7bDabbAC8C2f19Ff711fCc796013;
    
    function run() external {
        string memory ensName = vm.envString("ENS_NAME");
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        console.log("Authorizing resolver from:", deployer);
        console.log("Resolver address:", RESOLVER_ADDRESS);
        console.log("ENS name:", ensName);
        
        // Calculate ENS node
        bytes32 ensNode = _namehash(ensName);
        console.log("ENS node:", vm.toString(ensNode));
        
        DnssecResolver resolver = DnssecResolver(RESOLVER_ADDRESS);
        
        vm.startBroadcast(deployerPrivateKey);
        
        // Set delegate approval for this specific node
        // Note: Owner is already authorized by default, but this explicit approval
        // helps the ENS app recognize authorization
        console.log("\n=== Setting delegate approval for node ===");
        resolver.approve(ensNode, deployer, true);
        console.log(unicode"✅ Delegate approval set");
        
        vm.stopBroadcast();
        
        console.log(unicode"\n✅ Authorization complete!");
        console.log("\nYou can also authorize via Etherscan:");
        console.log("1. Go to: https://sepolia.etherscan.io/address/", vm.toString(RESOLVER_ADDRESS), "#writeContract");
        console.log("2. Connect your wallet");
        console.log("3. Call 'approve' with:");
        console.log("   - node: ", vm.toString(ensNode));
        console.log("   - delegate: ", vm.toString(deployer));
        console.log("   - approved: true");
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
