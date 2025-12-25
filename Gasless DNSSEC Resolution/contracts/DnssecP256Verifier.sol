// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "./interfaces/IAlgorithm.sol";

/// @notice Minimal interface for our verifier so other contracts can call it uniformly.
interface IDnssecP256Verifier {
    function verify(bytes calldata proofBundle, bytes calldata question)
        external
        view
        returns (bool ok, bytes memory canonicalRrset);
}

/// @notice Proof bundle structures matching `server.mjs`'s `PROOF_BUNDLE_SCHEMA`.
contract DnssecP256Verifier is IDnssecP256Verifier {

    IAlgorithm public algorithm;

    event AlgorithmUpdated(address indexed algorithm);

    struct TrustAnchor {
        bytes mode;
        bytes zoneNameWire;
        uint16 keyTag;
        uint8 algorithm;
        uint16 dnskeyFlags;
    }

    struct Question {
        bytes qnameWire;
        uint16 qtype;
        uint16 qclass;
    }

    struct TimePolicy {
        bytes policy;
        uint64 validationTime;
        uint64 clockSkewSeconds;
        bool requireInceptionLeNowPlusSkew;
        bool requireNowMinusSkewLeExpiration;
    }

    struct RRSIG {
        uint16 typeCovered;
        uint8 algorithm;
        uint8 labels;
        uint32 originalTTL;
        uint32 expiration;
        uint32 inception;
        uint16 keyTag;
        bytes signerNameWire;
        bytes signature;
    }

    struct DNSKEY {
        uint16 flags;
        uint8 protocol;
        uint8 algorithm;
        bytes publicKey;
    }

    struct DNSSECProof {
        bytes nameWire;
        bytes rrsetBytes;
        bytes signedDataBytes;
        RRSIG rrsig;
        DNSKEY dnskey;
    }

    struct ProofBundle {
        bytes version;
        bytes profile;
        bytes signatureFormat;
        TrustAnchor trustAnchor;
        Question question;
        TimePolicy time;
        DNSSECProof dnskeyProof;
        DNSSECProof answerProof;
    }

    struct RootAnchor {
        uint256 publicKeyX;
        uint256 publicKeyY;
        uint16 keyTag;
        uint256 validFrom;
    }

    mapping(bytes => RootAnchor) public pinnedAnchors;
    address public owner;

    error InvalidProofBundle();
    error Unauthorized();
    error InvalidZoneName();
    error AlgorithmNotSet();
    error InvalidSignature(string context);
    error InvalidProofStructure(string reason);
    error EmptyProofField(string field);
    error InvalidSignatureFormat(bytes actual);

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    event TrustAnchorSet(bytes indexed zoneNameWire, uint16 keyTag, uint256 validFrom);
    event TrustAnchorCleared(bytes indexed zoneNameWire);
    event OwnerUpdated(address indexed previousOwner, address indexed newOwner);

    /// @dev Sets deployer as owner.
    constructor() {
        owner = msg.sender;
    }

    /// @dev Transfers ownership.
    function transferOwnership(address newOwner) external onlyOwner {
        emit OwnerUpdated(owner, newOwner);
        owner = newOwner;
    }

    function setAlgorithm(IAlgorithm algorithm_) external onlyOwner {
        algorithm = algorithm_;
        emit AlgorithmUpdated(address(algorithm_));
    }

    /// @dev Stores a pinned trust anchor for the given zone.
    function setPinnedTrustAnchor(
        bytes calldata zoneNameWire,
        uint256 publicKeyX,
        uint256 publicKeyY,
        uint16 keyTag
    ) external onlyOwner {
        if (zoneNameWire.length == 0) revert InvalidZoneName();
        pinnedAnchors[zoneNameWire] = RootAnchor({
            publicKeyX: publicKeyX,
            publicKeyY: publicKeyY,
            keyTag: keyTag,
            validFrom: block.timestamp
        });
        emit TrustAnchorSet(zoneNameWire, keyTag, block.timestamp);
    }

    /// @dev Clears a pinned trust anchor.
    function clearPinnedTrustAnchor(bytes calldata zoneNameWire) external onlyOwner {
        delete pinnedAnchors[zoneNameWire];
        emit TrustAnchorCleared(zoneNameWire);
    }

    function getPinnedAnchor(bytes memory zoneNameWire)
        internal
        view
        returns (RootAnchor memory anchor)
    {
        anchor = pinnedAnchors[zoneNameWire];
        if (anchor.keyTag == 0) revert InvalidZoneName();
    }

    function verify(bytes calldata proofBundle, bytes calldata question)
        external
        view
        override
        returns (bool ok, bytes memory canonicalRrset)
    {
        ProofBundle memory proof = decodeProofBundle(proofBundle);
        Question memory decodedQuestion = question.length > 0
            ? decodeQuestion(question)
            : proof.question;

        validateProofStructure(proof);
        RootAnchor memory anchor = validateTrustAnchor(proof.trustAnchor);
        verifyDNSKEYProof(proof, anchor);
        verifyAnswerProof(proof);
        validateTimeWindows(proof);
        validateQuestion(proof, decodedQuestion);

        ok = true;
        canonicalRrset = proof.answerProof.rrsetBytes;
    }

    function decodeProofBundle(bytes calldata encoded)
        internal
        pure
        returns (ProofBundle memory proof)
    {
        (
            bytes memory version,
            bytes memory profile,
            bytes memory signatureFormat,
            TrustAnchor memory trustAnchor,
            Question memory question,
            TimePolicy memory time,
            DNSSECProof memory dnskeyProof,
            DNSSECProof memory answerProof
        ) = abi.decode(
            encoded,
            (
                bytes,
                bytes,
                bytes,
                TrustAnchor,
                Question,
                TimePolicy,
                DNSSECProof,
                DNSSECProof
            )
        );

        proof = ProofBundle({
            version: version,
            profile: profile,
            signatureFormat: signatureFormat,
            trustAnchor: trustAnchor,
            question: question,
            time: time,
            dnskeyProof: dnskeyProof,
            answerProof: answerProof
        });
    }

    function decodeQuestion(bytes calldata encoded)
        internal
        pure
        returns (Question memory question)
    {
        (question.qnameWire, question.qtype, question.qclass) = abi.decode(
            encoded,
            (bytes, uint16, uint16)
        );
    }

    function validateProofStructure(ProofBundle memory proof) internal pure {
        if (proof.version.length == 0) revert EmptyProofField("version");
        if (proof.profile.length == 0) revert EmptyProofField("profile");
        if (proof.signatureFormat.length == 0) revert EmptyProofField("signatureFormat");

        if (keccak256(proof.signatureFormat) != keccak256(bytes("p256_r_s_64"))) {
            revert InvalidSignatureFormat(proof.signatureFormat);
        }

        if (proof.trustAnchor.zoneNameWire.length == 0) revert EmptyProofField("trustAnchor.zoneNameWire");
        if (proof.question.qnameWire.length == 0) revert EmptyProofField("question.qnameWire");
        if (proof.time.policy.length == 0) revert EmptyProofField("time.policy");

        ensureProofNotEmpty(proof.dnskeyProof, "dnskeyProof");
        ensureProofNotEmpty(proof.answerProof, "answerProof");
    }

    function ensureProofNotEmpty(DNSSECProof memory proof, string memory label) internal pure {
        if (proof.nameWire.length == 0) revert InvalidProofStructure(label);
        if (proof.rrsig.signature.length != 64) revert InvalidProofStructure(label);
        if (proof.rrsig.signerNameWire.length == 0) revert InvalidProofStructure(label);
        if (proof.rrsetBytes.length == 0) revert InvalidProofStructure(label);
        if (proof.signedDataBytes.length == 0) revert InvalidProofStructure(label);
        if (proof.dnskey.publicKey.length != 64) revert InvalidProofStructure(label);
    }

    function validateTrustAnchor(TrustAnchor memory proofAnchor)
        internal
        view
        returns (RootAnchor memory anchor)
    {
        require(
            keccak256(proofAnchor.mode) ==
                keccak256(bytes("pinned_zone_ksk")),
            "unsupported trust anchor mode"
        );
        anchor = getPinnedAnchor(proofAnchor.zoneNameWire);
        require(anchor.keyTag == proofAnchor.keyTag, "key tag mismatch");
        require(proofAnchor.algorithm == 13, "trust anchor must be Algo 13");
    }

    function verifyDNSKEYProof(ProofBundle memory proof, RootAnchor memory anchor)
        internal
        view
    {
        ensureAlgorithmSet();
        require(proof.dnskeyProof.rrsig.algorithm == 13, "DNSKEY rrsig algo must be 13");
        require(proof.dnskeyProof.dnskey.algorithm == 13, "DNSKEY must be algo 13");

        bytes memory key = abi.encodePacked(
            bytes32(anchor.publicKeyX),
            bytes32(anchor.publicKeyY)
        );

        bool valid = algorithm.verify(
            key,
            proof.dnskeyProof.signedDataBytes,
            proof.dnskeyProof.rrsig.signature
        );
        if (!valid) revert InvalidSignature("dnskey");
    }

    function verifyAnswerProof(ProofBundle memory proof) internal view {
        ensureAlgorithmSet();
        require(proof.answerProof.rrsig.algorithm == 13, "answer rrsig algo must be 13");
        require(proof.answerProof.dnskey.algorithm == 13, "DNSKEY must be algo 13");
        require(proof.answerProof.dnskey.publicKey.length == 64, "invalid dnskey key length");

        bool valid = algorithm.verify(
            proof.answerProof.dnskey.publicKey,
            proof.answerProof.signedDataBytes,
            proof.answerProof.rrsig.signature
        );
        if (!valid) revert InvalidSignature("answer");
    }

    function validateTimeWindows(ProofBundle memory proof) internal view {
        uint64 nowTs = uint64(block.timestamp);
        checkRrsigTime(proof.time, proof.dnskeyProof.rrsig, nowTs);
        checkRrsigTime(proof.time, proof.answerProof.rrsig, nowTs);
    }

    function checkRrsigTime(
        TimePolicy memory policy,
        RRSIG memory rrsig,
        uint64 nowTs
    ) internal pure {
        uint64 skew = policy.clockSkewSeconds;

        if (policy.requireInceptionLeNowPlusSkew) {
            require(rrsig.inception <= nowTs + skew, "inception too late");
        }

        if (policy.requireNowMinusSkewLeExpiration) {
            require(nowTs <= rrsig.expiration + skew, "signature expired");
        }
    }

    function validateQuestion(ProofBundle memory proof, Question memory question)
        internal
        pure
    {
        require(question.qclass == 1, "only IN class supported");
        require(
            proof.answerProof.rrsig.typeCovered == question.qtype,
            "qtype mismatch"
        );
        require(
            keccak256(proof.answerProof.nameWire) == keccak256(question.qnameWire),
            "qname mismatch"
        );
    }

    function ensureAlgorithmSet() internal view {
        if (address(algorithm) == address(0)) revert AlgorithmNotSet();
    }
}
