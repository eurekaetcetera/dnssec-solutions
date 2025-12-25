// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

// Note: These imports reference the Onchain DNS Import project contracts
import "@onchain-dns-import/contracts/DNSSEC.sol";
import "@onchain-dns-import/contracts/libraries/RRUtils.sol";
import "@onchain-dns-import/contracts/utils/BytesUtils.sol";
import "./utils/HexUtils.sol";
import "@ensdomains/buffer/contracts/Buffer.sol";

/**
 * @title DNSClaimChecker
 * @dev Library for parsing _ens TXT records to extract owner address.
 *      Expects TXT record format: "a=0x<40-char-hex-address>"
 */
library DNSClaimChecker {
    using BytesUtils for bytes;
    using HexUtils for bytes;
    using RRUtils for *;
    using Buffer for Buffer.buffer;

    uint16 constant CLASS_INET = 1;
    uint16 constant TYPE_TXT = 16;

    /**
     * @dev Extracts the owner address from a TXT record.
     * @param name The DNS name being claimed (without _ens prefix).
     * @param data The RR data containing TXT records.
     * @return The owner address, or address(0) if not found.
     * @return True if an owner address was found.
     */
    function getOwnerAddress(
        bytes memory name,
        bytes memory data
    ) internal pure returns (address, bool) {
        // Add "_ens." prefix to the name
        // DNS wire format: length byte + "\_ens" = 0x04 + "_ens"
        Buffer.buffer memory buf;
        buf.init(name.length + 5);
        buf.append("\x04_ens");
        buf.append(name);

        // Iterate through all RRs in the data
        for (
            RRUtils.RRIterator memory iter = data.iterateRRs(0);
            !iter.done();
            iter.next()
        ) {
            // Check if this RR's name matches "_ens.<name>"
            if (iter.name().compareNames(buf.buf) != 0) continue;
            
            bool found;
            address addr;
            (addr, found) = parseRR(data, iter.rdataOffset, iter.nextOffset);
            if (found) {
                return (addr, true);
            }
        }

        return (address(0x0), false);
    }

    /**
     * @dev Parses a TXT record's RDATA to extract an address.
     * @param rdata The full RR data.
     * @param idx The start of the RDATA section.
     * @param endIdx The end of the RDATA section.
     * @return The parsed address, or address(0) if not found.
     * @return True if an address was found.
     */
    function parseRR(
        bytes memory rdata,
        uint256 idx,
        uint256 endIdx
    ) internal pure returns (address, bool) {
        // TXT records consist of one or more <length><string> pairs
        while (idx < endIdx) {
            uint256 len = rdata.readUint8(idx);
            idx += 1;

            bool found;
            address addr;
            (addr, found) = parseString(rdata, idx, len);

            if (found) return (addr, true);
            idx += len;
        }

        return (address(0x0), false);
    }

    /**
     * @dev Parses a single TXT string for the "a=0x..." format.
     * @param str The byte string containing the TXT record.
     * @param idx The starting index of the string content.
     * @param len The length of the string.
     * @return The parsed address, or address(0) if not found.
     * @return True if the string contains a valid "a=0x<address>" format.
     */
    function parseString(
        bytes memory str,
        uint256 idx,
        uint256 len
    ) internal pure returns (address, bool) {
        // Check for "a=0x" prefix (0x613d3078 in big-endian)
        // 'a' = 0x61, '=' = 0x3d, '0' = 0x30, 'x' = 0x78
        if (len < 44) return (address(0x0), false); // "a=0x" + 40 hex chars
        if (str.readUint32(idx) != 0x613d3078) return (address(0x0), false);
        
        // Parse the 40-character hex address
        return str.hexToAddress(idx + 4, idx + len);
    }
}

