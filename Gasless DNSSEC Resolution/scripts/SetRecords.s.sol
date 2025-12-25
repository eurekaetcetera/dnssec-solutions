// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "../lib/forge-std/src/Script.sol";
import "../contracts/DnssecResolver.sol";

/// @notice Script to set records directly on the resolver
/// @dev Run with: forge script scripts/SetRecords.s.sol:SetRecords --rpc-url sepolia --broadcast
contract SetRecords is Script {
    // Resolver address
    address constant RESOLVER_ADDRESS = 0x89A568c2d23b9ae84b4b2441387d20644850418A;
    
    // ENS node for dnssec.eth
    bytes32 constant ENS_NODE = 0x82d3325b569c432844c072895fab47a9de9616a8c761824e2d89a323a094f636;
    
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        console.log("Setting records from:", deployer);
        console.log("Resolver address:", RESOLVER_ADDRESS);
        console.log("ENS node:", vm.toString(ENS_NODE));
        
        DnssecResolver resolver = DnssecResolver(RESOLVER_ADDRESS);
        
        vm.startBroadcast(deployerPrivateKey);
        
        // Set an address record
        address testAddr = address(0x1234567890123456789012345678901234567890);
        console.log("\n=== Setting Address Record ===");
        resolver.setAddr(ENS_NODE, testAddr);
        console.log(unicode"✅ Address set to:", testAddr);
        
        // Set a text record
        string memory testKey = "test_key";
        string memory testValue = "test_value";
        console.log("\n=== Setting Text Record ===");
        resolver.setText(ENS_NODE, testKey, testValue);
        console.log(unicode"✅ Text record set:", testKey, "=", testValue);
        
        vm.stopBroadcast();
        
        console.log(unicode"\n✅ Records set successfully!");
        console.log("\nYou can now test resolution via cast call");
    }
}
