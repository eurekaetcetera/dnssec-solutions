// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "../lib/forge-std/src/Script.sol";
import "../contracts/DnssecP256Verifier.sol";

/// @notice Script to set the pinned trust anchor (KSK) for eketc.co
/// @dev Run with: forge script scripts/SetTrustAnchor.s.sol:SetTrustAnchor --rpc-url sepolia --broadcast
/// @dev Update VERIFIER_ADDRESS with your deployed verifier address
contract SetTrustAnchor is Script {
    // UPDATE THIS with your deployed verifier address
    address constant VERIFIER_ADDRESS = 0x580F2Db4Da8E6D5c654aa604182D0dFD17D5766B;
    
    // Trust anchor data for eketc.co KSK (Profile A)
    // These values should be extracted from the DNSKEY record
    // You can get them from: node scripts/fetch_dnssec_proof.mjs --name "eketc.co" --type DNSKEY
    bytes constant ZONE_NAME_WIRE = hex"05656b65746302636f00"; // eketc.co in DNS wire format
    uint256 constant PUB_X = 0x99db2cc14cabdc33d6d77da63a2f15f71112584f234e8d1dc428e39e8a4a97e1; // KSK public key X
    uint256 constant PUB_Y = 0xaa271a555dc90701e17e2a4c4b6f120b7c32d44f4ac02bd894cf2d4be7778a19; // KSK public key Y
    uint16 constant KEY_TAG = 2371; // KSK key tag for eketc.co
    
    function run() external {
        require(VERIFIER_ADDRESS != address(0), "VERIFIER_ADDRESS not set");
        require(PUB_X != 0 || PUB_Y != 0, "Public key not set");
        require(KEY_TAG != 0, "Key tag not set");
        
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        console.log("Setting trust anchor from:", deployer);
        console.log("Verifier address:", VERIFIER_ADDRESS);
        
        DnssecP256Verifier verifier = DnssecP256Verifier(VERIFIER_ADDRESS);
        
        vm.startBroadcast(deployerPrivateKey);
        
        console.log("\n=== Setting Pinned Trust Anchor ===");
        console.log("Zone name (wire):", vm.toString(ZONE_NAME_WIRE));
        console.log("Public key X:", PUB_X);
        console.log("Public key Y:", PUB_Y);
        console.log("Key tag:", KEY_TAG);
        
        verifier.setPinnedTrustAnchor(
            ZONE_NAME_WIRE,
            PUB_X,
            PUB_Y,
            KEY_TAG
        );
        
        vm.stopBroadcast();
        
        console.log(unicode"\n✅ Trust anchor set successfully!");
        console.log(unicode"\n⚠️  To extract trust anchor data, run:");
        console.log("node scripts/fetch_dnssec_proof.mjs --name 'eketc.co' --type DNSKEY");
        console.log("Then extract the KSK (flags=257) public key and key tag");
    }
    
    /// @notice Helper to extract trust anchor from proof bundle JSON
    /// @dev This can be used to populate the constants above
    function extractTrustAnchorFromProof() external pure {
        // This is a reference - actual extraction should be done offchain
        // The proof bundle contains:
        // - trustAnchor.zoneNameWire (hex string)
        // - dnskeyProof.dnskey.publicKey (64 bytes, extract X and Y)
        // - dnskeyProof.dnskey.keyTag (uint16)
        // Look for DNSKEY with flags=257 (KSK)
    }
}

