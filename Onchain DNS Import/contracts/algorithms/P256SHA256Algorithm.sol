// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "../interfaces/IAlgorithm.sol";

/**
 * @title P256SHA256Algorithm
 * @dev DNSSEC Algorithm 13 (ECDSAP256SHA256) using EIP-7951 precompile.
 * 
 * @notice This implementation is compatible with ENS's DNSSECImpl.sol:
 *         - Accepts 68-byte key (4-byte DNSKEY header + 64-byte public key)
 *         - Accepts 64-byte signature (r, s)
 *         - Uses EIP-7951 precompile at 0x100 for ~3k gas verification
 */
contract P256SHA256Algorithm is IAlgorithm {
    address internal constant P256_PRECOMPILE =
        0x0000000000000000000000000000000000000100;

    error InvalidP256SignatureLength();
    error InvalidP256KeyLength();

    /**
     * @dev Verifies a P-256 signature using EIP-7951 precompile.
     * @param key DNSKEY RDATA: [2-byte flags][1-byte protocol][1-byte algorithm][64-byte pubkey]
     *            Total: 68 bytes. Public key starts at offset 4.
     * @param data The signed data (RRSIG header + canonical RRset).
     * @param signature 64-byte signature (r || s), each 32 bytes.
     * @return True if the signature is valid.
     */
    function verify(
        bytes calldata key,
        bytes calldata data,
        bytes calldata signature
    ) external view override returns (bool) {
        // Signature must be exactly 64 bytes (r, s)
        if (signature.length != 64) revert InvalidP256SignatureLength();
        
        // Key must be 68 bytes: 4-byte header + 64-byte public key
        // DNSKEY RDATA format: flags(2) + protocol(1) + algorithm(1) + pubkey(64)
        if (key.length != 68) revert InvalidP256KeyLength();

        bytes32 r;
        bytes32 s;
        bytes32 qx;
        bytes32 qy;

        assembly {
            // Signature: r at offset 0, s at offset 32
            r := calldataload(add(signature.offset, 0))
            s := calldataload(add(signature.offset, 32))
            
            // Key: public key starts at offset 4 (after flags, protocol, algorithm)
            // qx at offset 4, qy at offset 36
            qx := calldataload(add(key.offset, 4))
            qy := calldataload(add(key.offset, 36))
        }

        // Hash the signed data with SHA-256
        bytes32 messageHash = sha256(data);

        // EIP-7951 precompile input: hash(32) + r(32) + s(32) + x(32) + y(32) = 160 bytes
        bytes memory input = abi.encodePacked(messageHash, r, s, qx, qy);

        // Call the P-256 precompile
        (bool success, bytes memory result) = P256_PRECOMPILE.staticcall(input);
        
        // Precompile returns 32 bytes: 0x00...01 for valid, 0x00...00 or empty for invalid
        if (!success || result.length != 32) return false;

        return result[31] == bytes1(0x01);
    }
}


