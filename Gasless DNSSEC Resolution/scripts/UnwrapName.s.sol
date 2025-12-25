// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "../lib/forge-std/src/Script.sol";

interface IENSRegistry {
    function owner(bytes32 node) external view returns (address);
}

interface INameWrapper {
    function ownerOf(uint256 id) external view returns (address);
    function unwrapETH2LD(bytes32 labelhash, address registrant, address controller) external;
}

/// @notice Script to unwrap an ENS name from NameWrapper
/// @dev Run with: forge script scripts/UnwrapName.s.sol:UnwrapName --rpc-url sepolia --broadcast
contract UnwrapName is Script {
    // Sepolia addresses
    address constant SEPOLIA_ENS_REGISTRY = 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e;
    address constant SEPOLIA_NAME_WRAPPER = 0x0635513f179D50A207757E05759CbD106d7dFcE8;
    
    function run() external {
        string memory ensName = vm.envString("ENS_NAME");
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        console.log("Unwrapping name from:", deployer);
        console.log("ENS name:", ensName);
        
        // Calculate ENS node and labelhash
        bytes32 ensNode = _namehash(ensName);
        bytes32 labelhash = keccak256(bytes(_getLabel(ensName)));
        
        console.log("ENS node:", vm.toString(ensNode));
        console.log("Labelhash:", vm.toString(labelhash));
        
        IENSRegistry registry = IENSRegistry(SEPOLIA_ENS_REGISTRY);
        INameWrapper nameWrapper = INameWrapper(SEPOLIA_NAME_WRAPPER);
        
        // Check if name is wrapped
        address registryOwner = registry.owner(ensNode);
        address wrapperOwner = nameWrapper.ownerOf(uint256(ensNode));
        
        console.log("\n=== Checking name status ===");
        console.log("Registry owner:", registryOwner);
        console.log("NameWrapper owner:", wrapperOwner);
        
        if (registryOwner != SEPOLIA_NAME_WRAPPER) {
            console.log(unicode"✅ Name is already unwrapped!");
            return;
        }
        
        if (wrapperOwner != deployer) {
            revert("You must own the wrapped name to unwrap it");
        }
        
        console.log(unicode"\n⚠️  Name is wrapped. Unwrapping...");
        
        vm.startBroadcast(deployerPrivateKey);
        
        // Unwrap the name
        // registrant: address that will own the ERC721 token in the registrar
        // controller: address that will be the manager in the registry
        nameWrapper.unwrapETH2LD(labelhash, deployer, deployer);
        
        vm.stopBroadcast();
        
        console.log(unicode"\n✅ Name unwrapped successfully!");
        console.log("Registry owner should now be:", deployer);
    }
    
    /// @dev Get the label from an ENS name (e.g., "dnssec" from "dnssec.eth")
    function _getLabel(string memory name) internal pure returns (string memory) {
        bytes memory s = bytes(name);
        uint256 dotIndex = 0;
        for (uint256 i = 0; i < s.length; i++) {
            if (s[i] == ".") {
                dotIndex = i;
                break;
            }
        }
        if (dotIndex == 0) return name;
        
        bytes memory label = new bytes(dotIndex);
        for (uint256 i = 0; i < dotIndex; i++) {
            label[i] = s[i];
        }
        return string(label);
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

