// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "forge-std/Script.sol";
import "forge-std/console.sol";

import "../contracts/DNSSECOracle.sol";

/**
 * @title SetTrustAnchors
 * @dev Sets the IANA root trust anchors on the DNSSECOracle.
 * 
 * The trust anchors are the root zone's DS records that start the chain of trust.
 * These are published by IANA at: https://data.iana.org/root-anchors/root-anchors.xml
 * 
 * Current root KSKs (as of 2024):
 * - Key Tag 20326 (KSK-2017, Algorithm 8, Digest Type 2)
 * - Key Tag 38696 (KSK-2024, Algorithm 8, Digest Type 2)
 * 
 * Usage:
 *   ORACLE_ADDRESS=0x... forge script scripts/SetTrustAnchors.s.sol:SetTrustAnchors \
 *     --rpc-url $SEPOLIA_RPC_URL \
 *     --broadcast \
 *     -vvvv
 */
contract SetTrustAnchors is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address oracleAddress = vm.envAddress("ORACLE_ADDRESS");
        
        console.log("=== Set Trust Anchors ===");
        console.log("Oracle:", oracleAddress);

        // Build the root DS records in DNS wire format
        // Format: name(1 byte: 0x00 for root) + type(2) + class(2) + ttl(4) + rdlength(2) + rdata
        bytes memory anchors = buildRootDSRecords();
        
        console.log("Trust anchor data length:", anchors.length);

        vm.startBroadcast(deployerPrivateKey);

        // Note: DNSSECOracle stores anchors in constructor, 
        // but we can redeploy or use a setter if added
        // For now, this demonstrates the anchor format
        
        // If you need to update anchors, you'd need to:
        // 1. Add a setAnchors() function to DNSSECOracle, or
        // 2. Redeploy with new anchors
        
        console.log("Anchors built successfully");
        console.log("To use these anchors, redeploy DNSSECOracle with this data");

        vm.stopBroadcast();
    }

    /**
     * @dev Builds the root DS records in DNS RR wire format.
     *      These are the IANA root trust anchors.
     */
    function buildRootDSRecords() internal pure returns (bytes memory) {
        // Root DS record for KSK-2017 (Key Tag 20326)
        // DS RDATA: keytag(2) + algorithm(1) + digesttype(1) + digest(32 for SHA-256)
        bytes memory ds1 = buildDSRecord(
            20326,  // Key Tag
            8,      // Algorithm (RSASHA256)
            2,      // Digest Type (SHA-256)
            // SHA-256 digest of the KSK-2017 DNSKEY
            hex"E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
        );

        // Root DS record for KSK-2024 (Key Tag 38696)
        bytes memory ds2 = buildDSRecord(
            38696,  // Key Tag
            8,      // Algorithm (RSASHA256)
            2,      // Digest Type (SHA-256)
            // SHA-256 digest of the KSK-2024 DNSKEY
            hex"683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"
        );

        // Concatenate both DS records
        return abi.encodePacked(ds1, ds2);
    }

    /**
     * @dev Builds a single DS record in DNS RR wire format.
     * @param keyTag The key tag
     * @param algorithm The algorithm number
     * @param digestType The digest type
     * @param digest The digest bytes
     */
    function buildDSRecord(
        uint16 keyTag,
        uint8 algorithm,
        uint8 digestType,
        bytes memory digest
    ) internal pure returns (bytes memory) {
        // DNS RR format:
        // name: 0x00 (root)
        // type: 0x002B (DS = 43)
        // class: 0x0001 (IN)
        // ttl: 0x00015180 (86400 seconds = 1 day)
        // rdlength: 4 + digest.length
        // rdata: keytag(2) + algorithm(1) + digesttype(1) + digest
        
        uint16 rdlength = uint16(4 + digest.length);
        
        return abi.encodePacked(
            bytes1(0x00),           // Root name
            uint16(43),             // Type: DS
            uint16(1),              // Class: IN
            uint32(86400),          // TTL: 1 day
            rdlength,               // RDATA length
            keyTag,                 // Key Tag
            algorithm,              // Algorithm
            digestType,             // Digest Type
            digest                  // Digest
        );
    }
}

/**
 * @title GenerateAnchorsForDeploy
 * @dev Generates anchor bytes to copy into Deploy.s.sol
 */
contract GenerateAnchorsForDeploy is Script {
    function run() external pure {
        // KSK-2017 DS record
        bytes memory ds1 = abi.encodePacked(
            bytes1(0x00),           // Root name
            uint16(43),             // Type: DS
            uint16(1),              // Class: IN
            uint32(86400),          // TTL
            uint16(36),             // RDATA length (4 + 32)
            uint16(20326),          // Key Tag
            uint8(8),               // Algorithm
            uint8(2),               // Digest Type
            hex"E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
        );

        // KSK-2024 DS record
        bytes memory ds2 = abi.encodePacked(
            bytes1(0x00),
            uint16(43),
            uint16(1),
            uint32(86400),
            uint16(36),
            uint16(38696),
            uint8(8),
            uint8(2),
            hex"683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"
        );

        bytes memory anchors = abi.encodePacked(ds1, ds2);
        
        console.log("Root DS anchors hex:");
        console.logBytes(anchors);
        console.log("");
        console.log("Length:", anchors.length, "bytes");
    }
}


