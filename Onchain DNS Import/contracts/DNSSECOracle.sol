// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./Owned.sol";
import "./DNSSEC.sol";
import "./libraries/RRUtils.sol";
import "./interfaces/IAlgorithm.sol";
import "./interfaces/IDigest.sol";
import "./utils/BytesUtils.sol";
import "@ensdomains/buffer/contracts/Buffer.sol";

/**
 * @title DNSSECOracle
 * @dev Verifies DNSSEC proofs using Algorithm 8 (RSA/SHA-256) and Algorithm 13 (P-256/SHA-256).
 *      Based on ENS's DNSSECImpl.sol but optimized for the EIP-7951 P-256 precompile.
 * 
 * @notice Key differences from ENS DNSSECImpl:
 *         - Uses EIP-7951 precompile for Algorithm 13 (~3k gas vs ~400k gas)
 *         - Same trust model: full DS chain from IANA root
 *         - Same wire format parsing via RRUtils
 */
contract DNSSECOracle is DNSSEC, Owned {
    using Buffer for Buffer.buffer;
    using BytesUtils for bytes;
    using RRUtils for *;

    // DNS constants
    uint16 constant DNSCLASS_IN = 1;
    uint16 constant DNSTYPE_DS = 43;
    uint16 constant DNSTYPE_DNSKEY = 48;
    uint256 constant DNSKEY_FLAG_ZONEKEY = 0x100;

    // Custom errors for gas efficiency
    error InvalidLabelCount(bytes name, uint256 labelsExpected);
    error SignatureNotValidYet(uint32 inception, uint32 now);
    error SignatureExpired(uint32 expiration, uint32 now);
    error InvalidClass(uint16 class);
    error InvalidRRSet();
    error SignatureTypeMismatch(uint16 rrsetType, uint16 sigType);
    error InvalidSignerName(bytes rrsetName, bytes signerName);
    error InvalidProofType(uint16 proofType);
    error ProofNameMismatch(bytes signerName, bytes proofName);
    error NoMatchingProof(bytes signerName);
    error AlgorithmNotSupported(uint8 algorithm);
    error DigestNotSupported(uint8 digestType);

    // Registries for pluggable algorithms and digests
    mapping(uint8 => IAlgorithm) public algorithms;
    mapping(uint8 => IDigest) public digests;

    /**
     * @dev Constructor.
     * @param _anchors The binary format RR entries for the root DS records.
     *                 These are the IANA trust anchors that start the chain of trust.
     */
    constructor(bytes memory _anchors) {
        anchors = _anchors;
    }

    /**
     * @dev Sets the trust anchors (IANA root DS records).
     *      Can only be called by the owner.
     * @param _anchors The binary format RR entries for the root DS records.
     */
    function setAnchors(bytes memory _anchors) public owner_only {
        anchors = _anchors;
    }

    /**
     * @dev Sets the contract address for a signature verification algorithm.
     * @param id The algorithm ID (8 = RSA/SHA-256, 13 = P-256/SHA-256)
     * @param algo The address of the algorithm contract.
     */
    function setAlgorithm(uint8 id, IAlgorithm algo) public owner_only {
        algorithms[id] = algo;
        emit AlgorithmUpdated(id, address(algo));
    }

    /**
     * @dev Sets the contract address for a digest verification algorithm.
     * @param id The digest ID (2 = SHA-256)
     * @param digest The address of the digest contract.
     */
    function setDigest(uint8 id, IDigest digest) public owner_only {
        digests[id] = digest;
        emit DigestUpdated(id, address(digest));
    }

    /**
     * @dev Verifies a chain of signed DNS records.
     * @param input A list of signed RRSets forming a chain of trust.
     * @return rrs The RRData from the last RRSet in the chain.
     * @return inception The inception time of the signed record set.
     */
    function verifyRRSet(
        RRSetWithSignature[] memory input
    )
        external
        view
        virtual
        override
        returns (bytes memory rrs, uint32 inception)
    {
        return verifyRRSet(input, block.timestamp);
    }

    /**
     * @dev Verifies a chain of signed DNS records at a specific time.
     * @param input A list of signed RRSets forming a chain of trust.
     * @param timestamp The Unix timestamp to validate the records at.
     * @return rrs The RRData from the last RRSet in the chain.
     * @return inception The inception time of the signed record set.
     */
    function verifyRRSet(
        RRSetWithSignature[] memory input,
        uint256 timestamp
    )
        public
        view
        virtual
        override
        returns (bytes memory rrs, uint32 inception)
    {
        // Start with the trust anchors (root DS records)
        bytes memory proof = anchors;
        
        // Validate each RRSet in the chain
        for (uint256 i = 0; i < input.length; i++) {
            RRUtils.SignedSet memory rrset = validateSignedSet(
                input[i],
                proof,
                timestamp
            );
            proof = rrset.data;
            inception = rrset.inception;
        }
        
        return (proof, inception);
    }

    /**
     * @dev Validates an RRSet against an already trusted RR.
     * @param input The signed RR set with RRSIG data.
     * @param proof The DNSKEY or DS to validate the signature against.
     * @param timestamp The current timestamp.
     * @return rrset The parsed and validated SignedSet.
     */
    function validateSignedSet(
        RRSetWithSignature memory input,
        bytes memory proof,
        uint256 timestamp
    ) internal view returns (RRUtils.SignedSet memory rrset) {
        // Parse the RRSIG header and RRset data
        rrset = input.rrset.readSignedSet();

        // Validate RRs and extract the name
        bytes memory name = validateRRs(rrset, rrset.typeCovered);
        
        // Verify label count matches (RFC4035 requirement)
        if (name.labelCount(0) != rrset.labels) {
            revert InvalidLabelCount(name, rrset.labels);
        }
        rrset.name = name;

        // Time validation using RFC1982 serial number arithmetic
        // Signature must not have expired
        if (!RRUtils.serialNumberGte(rrset.expiration, uint32(timestamp))) {
            revert SignatureExpired(rrset.expiration, uint32(timestamp));
        }
        
        // Signature must be valid (inception time passed)
        if (!RRUtils.serialNumberGte(uint32(timestamp), rrset.inception)) {
            revert SignatureNotValidYet(rrset.inception, uint32(timestamp));
        }

        // Validate the cryptographic signature
        verifySignature(name, rrset, input, proof);

        return rrset;
    }

    /**
     * @dev Validates a set of RRs for consistency.
     * @param rrset The RR set.
     * @param typecovered The type covered by the RRSIG record.
     * @return name The DNS name from the RRs.
     */
    function validateRRs(
        RRUtils.SignedSet memory rrset,
        uint16 typecovered
    ) internal pure returns (bytes memory name) {
        for (
            RRUtils.RRIterator memory iter = rrset.rrs();
            !iter.done();
            iter.next()
        ) {
            // Only support class IN (Internet)
            if (iter.class != DNSCLASS_IN) {
                revert InvalidClass(iter.class);
            }

            if (name.length == 0) {
                name = iter.name();
            } else {
                // All RRs must have the same name
                if (
                    name.length != iter.data.nameLength(iter.offset) ||
                    !name.equals(0, iter.data, iter.offset, name.length)
                ) {
                    revert InvalidRRSet();
                }
            }

            // RRSIG type covered must match RR type
            if (iter.dnstype != typecovered) {
                revert SignatureTypeMismatch(iter.dnstype, typecovered);
            }
        }
    }

    /**
     * @dev Performs signature verification using the appropriate proof type.
     * @param name The DNS name being verified.
     * @param rrset The parsed RRset.
     * @param data The original signed data.
     * @param proof A DS or DNSKEY record that's already verified.
     */
    function verifySignature(
        bytes memory name,
        RRUtils.SignedSet memory rrset,
        RRSetWithSignature memory data,
        bytes memory proof
    ) internal view {
        // Signer's Name must be the zone that contains the RRset
        if (!name.isSubdomainOf(rrset.signerName)) {
            revert InvalidSignerName(name, rrset.signerName);
        }

        RRUtils.RRIterator memory proofRR = proof.iterateRRs(0);
        
        // Dispatch based on proof type
        if (proofRR.dnstype == DNSTYPE_DS) {
            verifyWithDS(rrset, data, proofRR);
        } else if (proofRR.dnstype == DNSTYPE_DNSKEY) {
            verifyWithKnownKey(rrset, data, proofRR);
        } else {
            revert InvalidProofType(proofRR.dnstype);
        }
    }

    /**
     * @dev Verifies a signed RRSET against an already known public key (DNSKEY).
     * @param rrset The signed set to verify.
     * @param data The original data with signature.
     * @param proof The DNSKEY records to verify against.
     */
    function verifyWithKnownKey(
        RRUtils.SignedSet memory rrset,
        RRSetWithSignature memory data,
        RRUtils.RRIterator memory proof
    ) internal view {
        for (; !proof.done(); proof.next()) {
            bytes memory proofName = proof.name();
            if (!proofName.equals(rrset.signerName)) {
                revert ProofNameMismatch(rrset.signerName, proofName);
            }

            bytes memory keyrdata = proof.rdata();
            RRUtils.DNSKEY memory dnskey = keyrdata.readDNSKEY(
                0,
                keyrdata.length
            );
            
            if (verifySignatureWithKey(dnskey, keyrdata, rrset, data)) {
                return;
            }
        }
        revert NoMatchingProof(rrset.signerName);
    }

    /**
     * @dev Attempts to verify data using a specific DNSKEY.
     * @param dnskey The parsed DNSKEY.
     * @param keyrdata The raw DNSKEY RDATA.
     * @param rrset The signed RRSET.
     * @param data The original signed data.
     * @return True if the signature is valid.
     */
    function verifySignatureWithKey(
        RRUtils.DNSKEY memory dnskey,
        bytes memory keyrdata,
        RRUtils.SignedSet memory rrset,
        RRSetWithSignature memory data
    ) internal view returns (bool) {
        // Protocol Field MUST be 3 (RFC4034 2.1.2)
        if (dnskey.protocol != 3) {
            return false;
        }

        // Algorithm must match
        if (dnskey.algorithm != rrset.algorithm) {
            return false;
        }
        
        // Key tag must match
        uint16 computedkeytag = keyrdata.computeKeytag();
        if (computedkeytag != rrset.keytag) {
            return false;
        }

        // Zone Flag bit must be set
        if (dnskey.flags & DNSKEY_FLAG_ZONEKEY == 0) {
            return false;
        }

        // Get the algorithm contract
        IAlgorithm algorithm = algorithms[dnskey.algorithm];
        if (address(algorithm) == address(0)) {
            return false;
        }
        
        // Verify the signature
        return algorithm.verify(keyrdata, data.rrset, data.sig);
    }

    /**
     * @dev Verifies a signed RRSET against DS records (for DNSKEY self-signatures).
     * @param rrset The signed set to verify.
     * @param data The original data with signature.
     * @param proof The DS records to verify against.
     */
    function verifyWithDS(
        RRUtils.SignedSet memory rrset,
        RRSetWithSignature memory data,
        RRUtils.RRIterator memory proof
    ) internal view {
        uint256 proofOffset = proof.offset;
        
        // Iterate through each DNSKEY in the RRset
        for (
            RRUtils.RRIterator memory iter = rrset.rrs();
            !iter.done();
            iter.next()
        ) {
            if (iter.dnstype != DNSTYPE_DNSKEY) {
                revert InvalidProofType(iter.dnstype);
            }

            bytes memory keyrdata = iter.rdata();
            RRUtils.DNSKEY memory dnskey = keyrdata.readDNSKEY(
                0,
                keyrdata.length
            );
            
            // Check if this key signs the RRset
            if (verifySignatureWithKey(dnskey, keyrdata, rrset, data)) {
                // It's self-signed - verify against DS record
                if (verifyKeyWithDS(rrset.signerName, proof, dnskey, keyrdata)) {
                    return;
                }
                // Rewind proof iterator for next DNSKEY attempt
                proof.nextOffset = proofOffset;
                proof.next();
            }
        }
        revert NoMatchingProof(rrset.signerName);
    }

    /**
     * @dev Verifies a DNSKEY against DS records.
     * @param keyname The DNS name of the key.
     * @param dsrrs The DS records to verify against.
     * @param dnskey The parsed DNSKEY.
     * @param keyrdata The raw DNSKEY RDATA.
     * @return True if a DS record verifies this key.
     */
    function verifyKeyWithDS(
        bytes memory keyname,
        RRUtils.RRIterator memory dsrrs,
        RRUtils.DNSKEY memory dnskey,
        bytes memory keyrdata
    ) internal view returns (bool) {
        uint16 keytag = keyrdata.computeKeytag();
        
        for (; !dsrrs.done(); dsrrs.next()) {
            bytes memory proofName = dsrrs.name();
            if (!proofName.equals(keyname)) {
                revert ProofNameMismatch(keyname, proofName);
            }

            RRUtils.DS memory ds = dsrrs.data.readDS(
                dsrrs.rdataOffset,
                dsrrs.nextOffset - dsrrs.rdataOffset
            );
            
            // Skip if key tag doesn't match
            if (ds.keytag != keytag) {
                continue;
            }
            
            // Skip if algorithm doesn't match
            if (ds.algorithm != dnskey.algorithm) {
                continue;
            }

            // Compute the digest: SHA256(name || DNSKEY RDATA)
            Buffer.buffer memory buf;
            buf.init(keyname.length + keyrdata.length);
            buf.append(keyname);
            buf.append(keyrdata);
            
            if (verifyDSHash(ds.digestType, buf.buf, ds.digest)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @dev Verifies a DS record's hash against computed data.
     * @param digesttype The digest type from the DS record.
     * @param data The data to hash.
     * @param digest The expected digest value.
     * @return True if the digest matches.
     */
    function verifyDSHash(
        uint8 digesttype,
        bytes memory data,
        bytes memory digest
    ) internal view returns (bool) {
        IDigest digestContract = digests[digesttype];
        if (address(digestContract) == address(0)) {
            return false;
        }
        return digestContract.verify(data, digest);
    }

    /**
     * @dev Returns the trust anchor (root DS records).
     * @return The anchors bytes.
     */
    function getAnchors() external view returns (bytes memory) {
        return anchors;
    }
}


