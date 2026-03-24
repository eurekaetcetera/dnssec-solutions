// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "./interfaces/ITLDMinter.sol";
import "./interfaces/IDNSSEC.sol";
import "./interfaces/IRoot.sol";
import "./interfaces/ISecurityCouncil.sol";
import "./interfaces/IENS.sol";
import "./libraries/RRUtils.sol";
import "./utils/BytesUtils.sol";
import "./utils/HexUtils.sol";
import "@ensdomains/buffer/contracts/Buffer.sol";

/**
 * @title TLDMinter
 * @notice Policy wrapper for DNS-verified TLD minting in ENS with DAO governance safeguards.
 * @dev Allows DNS registries to claim their TLDs by providing DNSSEC proofs.
 *      Includes timelock, rate limiting, and veto mechanisms to preserve DAO sovereignty.
 */
contract TLDMinter is ITLDMinter {
    using BytesUtils for bytes;
    using HexUtils for bytes;
    using RRUtils for *;
    using Buffer for Buffer.buffer;

    // ─────────────────────────────────────────────────────────────────
    // Constants
    // ─────────────────────────────────────────────────────────────────

    uint16 private constant CLASS_INET = 1;
    uint16 private constant TYPE_TXT = 16;

    // ─────────────────────────────────────────────────────────────────
    // Immutables
    // ─────────────────────────────────────────────────────────────────

    IDNSSEC public immutable oracle;
    IRoot public immutable root;
    IENS public immutable ens;
    address public immutable daoTimelock;
    address public immutable securityCouncilMultisig;
    ISecurityCouncil public immutable securityCouncil;
    uint256 public immutable timelockDuration;
    uint256 public immutable proofMaxAge;

    // ─────────────────────────────────────────────────────────────────
    // State Variables
    // ─────────────────────────────────────────────────────────────────

    mapping(bytes32 => MintRequest) public requests;

    uint256 public mintsThisPeriod;
    uint256 public periodStart;
    uint256 public rateLimitMax;
    uint256 public rateLimitPeriod;

    bool public paused;
    bool private _securityCouncilVetoRevoked;

    mapping(bytes32 => bool) public allowedTLDs;

    // ─────────────────────────────────────────────────────────────────
    // Custom Errors
    // ─────────────────────────────────────────────────────────────────

    error ProofTooOld(uint32 inception, uint256 maxAge);
    error TLDAlreadyExists(bytes32 labelHash);
    error ClaimAlreadyPending(bytes32 labelHash);
    error NoOwnerRecordFound(bytes name);
    error TimelockNotExpired(uint256 unlockTime, uint256 currentTime);
    error ClaimWasVetoed(bytes32 labelHash);
    error RateLimitExceeded(uint256 current, uint256 max);
    error NotVetoAuthority(address caller);
    error ContractPaused();
    error NotDAO(address caller);
    error NoPendingRequest(bytes32 labelHash);
    error AlreadyVetoed(bytes32 labelHash);
    error SecurityCouncilNotExpired();
    error SecurityCouncilAlreadyRevoked();
    error InvalidNameFormat();
    error TLDNotAllowed(bytes32 labelHash);

    // ─────────────────────────────────────────────────────────────────
    // Modifiers
    // ─────────────────────────────────────────────────────────────────

    modifier whenNotPaused() {
        if (paused) revert ContractPaused();
        _;
    }

    modifier onlyDAO() {
        if (msg.sender != daoTimelock) revert NotDAO(msg.sender);
        _;
    }

    modifier onlyVetoAuthority() {
        bool isDAO = (msg.sender == daoTimelock);
        bool isSC = (
            msg.sender == securityCouncilMultisig &&
            !_securityCouncilVetoRevoked &&
            block.timestamp < securityCouncil.expiration()
        );
        if (!isDAO && !isSC) revert NotVetoAuthority(msg.sender);
        _;
    }

    // ─────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────

    constructor(
        address _oracle,
        address _root,
        address _ens,
        address _daoTimelock,
        address _securityCouncilMultisig,
        address _securityCouncilContract,
        uint256 _timelockDuration,
        uint256 _rateLimitMax,
        uint256 _rateLimitPeriod,
        uint256 _proofMaxAge
    ) {
        oracle = IDNSSEC(_oracle);
        root = IRoot(_root);
        ens = IENS(_ens);
        daoTimelock = _daoTimelock;
        securityCouncilMultisig = _securityCouncilMultisig;
        securityCouncil = ISecurityCouncil(_securityCouncilContract);
        timelockDuration = _timelockDuration;
        rateLimitMax = _rateLimitMax;
        rateLimitPeriod = _rateLimitPeriod;
        proofMaxAge = _proofMaxAge;
        periodStart = block.timestamp;
    }

    // ─────────────────────────────────────────────────────────────────
    // External Functions
    // ─────────────────────────────────────────────────────────────────

    /// @inheritdoc ITLDMinter
    function submitClaim(
        bytes calldata name,
        IDNSSEC.RRSetWithSignature[] calldata proof
    ) external whenNotPaused {
        // Step 1: Extract label hash and check allowlist (cheap, fail fast)
        bytes32 labelHash = _extractLabelHash(name);
        if (!allowedTLDs[labelHash]) revert TLDNotAllowed(labelHash);

        // Step 2: Verify DNSSEC proof via existing oracle
        (bytes memory data, uint32 inception) = oracle.verifyRRSet(proof);

        // Step 3: Check proof freshness
        if (block.timestamp - inception > proofMaxAge) {
            revert ProofTooOld(inception, proofMaxAge);
        }

        // Step 4: Parse owner from TXT record
        (address owner, bool found) = _parseOwnerFromTXT(name, data);
        if (!found) revert NoOwnerRecordFound(name);

        // Step 5: Policy checks
        if (!canClaim(labelHash)) {
            // Check which error to throw
            bytes32 node = keccak256(abi.encodePacked(bytes32(0), labelHash));
            if (ens.owner(node) != address(0)) {
                revert TLDAlreadyExists(labelHash);
            }
            revert ClaimAlreadyPending(labelHash);
        }
        _checkRateLimit();

        // Step 6: Store request with timelock
        uint256 unlockTime = block.timestamp + timelockDuration;
        requests[labelHash] = MintRequest({
            owner: owner,
            unlockTime: unlockTime,
            vetoed: false,
            proofInception: inception
        });

        emit ClaimSubmitted(labelHash, owner, name, inception, unlockTime);
    }

    /// @inheritdoc ITLDMinter
    function execute(bytes32 labelHash) external whenNotPaused {
        MintRequest memory req = requests[labelHash];

        // Validation checks
        if (req.owner == address(0)) revert NoPendingRequest(labelHash);
        if (block.timestamp < req.unlockTime) {
            revert TimelockNotExpired(req.unlockTime, block.timestamp);
        }
        if (req.vetoed) revert ClaimWasVetoed(labelHash);

        // Mint the TLD via ENS Root
        root.setSubnodeOwner(labelHash, req.owner);

        // Clean up
        delete requests[labelHash];

        emit TLDMinted(labelHash, req.owner);
    }

    /// @inheritdoc ITLDMinter
    function veto(bytes32 labelHash, string calldata reason) external onlyVetoAuthority {
        MintRequest storage req = requests[labelHash];
        if (req.owner == address(0)) revert NoPendingRequest(labelHash);
        if (req.vetoed) revert AlreadyVetoed(labelHash);

        req.vetoed = true;
        emit ClaimVetoed(labelHash, msg.sender, reason);
    }

    /// @inheritdoc ITLDMinter
    function revokeSecurityCouncilVeto() external {
        if (block.timestamp < securityCouncil.expiration()) {
            revert SecurityCouncilNotExpired();
        }
        if (_securityCouncilVetoRevoked) {
            revert SecurityCouncilAlreadyRevoked();
        }
        _securityCouncilVetoRevoked = true;
        emit SecurityCouncilVetoRevoked(msg.sender);
    }

    /// @inheritdoc ITLDMinter
    function setRateLimit(uint256 newMax, uint256 newPeriod) external onlyDAO {
        rateLimitMax = newMax;
        rateLimitPeriod = newPeriod;
        emit RateLimitUpdated(newMax, newPeriod);
    }

    /// @inheritdoc ITLDMinter
    function pause() external onlyVetoAuthority {
        paused = true;
        emit Paused(msg.sender);
    }

    /// @inheritdoc ITLDMinter
    function unpause() external onlyVetoAuthority {
        paused = false;
        emit Unpaused(msg.sender);
    }

    // ─────────────────────────────────────────────────────────────────
    // View Functions
    // ─────────────────────────────────────────────────────────────────

    /// @inheritdoc ITLDMinter
    function getRequest(bytes32 labelHash) external view returns (MintRequest memory) {
        return requests[labelHash];
    }

    /// @inheritdoc ITLDMinter
    function canClaim(bytes32 labelHash) public view returns (bool) {
        // Reject if TLD already exists in ENS
        bytes32 node = keccak256(abi.encodePacked(bytes32(0), labelHash));
        if (ens.owner(node) != address(0)) {
            return false;
        }
        // Reject if pending request exists (not yet executed or vetoed)
        MintRequest memory req = requests[labelHash];
        if (req.owner != address(0) && !req.vetoed) {
            return false;
        }
        return true;
    }

    /// @inheritdoc ITLDMinter
    function securityCouncilVetoRevoked() external view returns (bool) {
        return _securityCouncilVetoRevoked;
    }

    /// @inheritdoc ITLDMinter
    function addToAllowlist(string calldata tld) external onlyDAO {
        bytes32 tldHash = keccak256(abi.encodePacked(tld));
        allowedTLDs[tldHash] = true;
        emit TLDAllowlisted(tld);
    }

    /// @inheritdoc ITLDMinter
    function removeFromAllowlist(string calldata tld) external onlyDAO {
        bytes32 tldHash = keccak256(abi.encodePacked(tld));
        allowedTLDs[tldHash] = false;
        emit TLDRemovedFromAllowlist(tld);
    }

    /// @inheritdoc ITLDMinter
    function batchAddToAllowlist(string[] calldata tlds) external onlyDAO {
        for (uint256 i = 0; i < tlds.length; i++) {
            bytes32 tldHash = keccak256(abi.encodePacked(tlds[i]));
            allowedTLDs[tldHash] = true;
            emit TLDAllowlisted(tlds[i]);
        }
    }

    /// @inheritdoc ITLDMinter
    function version() external pure returns (string memory) {
        return "2.0.0";
    }

    // ─────────────────────────────────────────────────────────────────
    // Internal Functions
    // ─────────────────────────────────────────────────────────────────

    /**
     * @dev Checks and enforces rate limiting for TLD mints.
     */
    function _checkRateLimit() internal {
        if (block.timestamp >= periodStart + rateLimitPeriod) {
            periodStart = block.timestamp;
            mintsThisPeriod = 0;
        }
        if (mintsThisPeriod >= rateLimitMax) {
            emit RateLimitHit(mintsThisPeriod, rateLimitMax, periodStart + rateLimitPeriod);
            revert RateLimitExceeded(mintsThisPeriod, rateLimitMax);
        }
        mintsThisPeriod++;
    }

    /**
     * @dev Extracts owner address from TXT record.
     *      Expects format: _ens.nic.{tld} TXT "a=0x{40-char-lowercase-hex}"
     * @param name The TLD name in DNS wire format (e.g., 0x02636f00 for ".co")
     * @param data The verified RR data from DNSSEC oracle
     * @return owner The parsed owner address
     * @return found True if owner address was found
     */
    function _parseOwnerFromTXT(
        bytes calldata name,
        bytes memory data
    ) internal pure returns (address owner, bool found) {
        // Construct expected name: "\x04_ens\x03nic" + name
        // For name = 0x02636f00 (".co"), result is "_ens.nic.co."
        Buffer.buffer memory buf;
        buf.init(name.length + 9);
        buf.append("\x04_ens\x03nic");
        buf.append(name);

        // Iterate through all RRs in the data
        for (
            RRUtils.RRIterator memory iter = data.iterateRRs(0);
            !iter.done();
            iter.next()
        ) {
            // Check if this RR's name matches "_ens.nic.<name>"
            if (iter.name().compareNames(buf.buf) != 0) continue;

            // Check if this is a TXT record
            if (iter.dnstype != TYPE_TXT) continue;

            // Parse the TXT record
            (address addr, bool valid) = _parseRR(data, iter.rdataOffset, iter.nextOffset);
            if (valid) {
                return (addr, true);
            }
        }

        return (address(0), false);
    }

    /**
     * @dev Parses a TXT record's RDATA to extract an address.
     */
    function _parseRR(
        bytes memory rdata,
        uint256 idx,
        uint256 endIdx
    ) internal pure returns (address, bool) {
        // TXT records consist of one or more <length><string> pairs
        while (idx < endIdx) {
            uint256 len = rdata.readUint8(idx);
            idx += 1;

            (address addr, bool valid) = _parseString(rdata, idx, len);
            if (valid) return (addr, true);
            idx += len;
        }

        return (address(0), false);
    }

    /**
     * @dev Parses a single TXT string for the "a=0x..." format.
     */
    function _parseString(
        bytes memory str,
        uint256 idx,
        uint256 len
    ) internal pure returns (address, bool) {
        // Check minimum length: "a=0x" + 40 hex chars = 44
        if (len < 44) return (address(0), false);

        // Check for "a=0x" prefix (0x613d3078 in big-endian)
        // 'a' = 0x61, '=' = 0x3d, '0' = 0x30, 'x' = 0x78
        if (str.readUint32(idx) != 0x613d3078) return (address(0), false);

        // Parse the 40-character hex address
        return str.hexToAddress(idx + 4, idx + 44);
    }

    /**
     * @dev Extracts the label hash from a DNS wire format name.
     *      DNS wire format: <length><label><length><label>...<0>
     *      For TLDs, this is just: <length><tld><0>
     *      Example: 0x02636f00 -> "co" -> keccak256("co")
     */
    function _extractLabelHash(bytes calldata name) internal pure returns (bytes32) {
        // DNS wire format for TLD: <len><label><0>
        // First byte is the label length
        if (name.length < 2) revert InvalidNameFormat();

        uint8 labelLen = uint8(name[0]);
        if (name.length < labelLen + 2) revert InvalidNameFormat();

        // The label starts at index 1 and has length labelLen
        // Verify it ends with null terminator for TLD
        if (name[labelLen + 1] != 0x00) revert InvalidNameFormat();

        // Extract the label and compute hash
        bytes memory label = name[1:labelLen + 1];
        return keccak256(label);
    }
}
