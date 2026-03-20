// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "./IDNSSEC.sol";

interface ITLDMinter {
    // ─────────────────────────────────────────────────────────────────
    // Events (for off-chain monitoring and transparency)
    // ─────────────────────────────────────────────────────────────────

    /// @notice Emitted when a new TLD claim is submitted
    event ClaimSubmitted(
        bytes32 indexed labelHash,
        address indexed owner,
        bytes name,
        uint32 proofInception,
        uint256 unlockTime
    );

    /// @notice Emitted when a pending claim is vetoed
    event ClaimVetoed(bytes32 indexed labelHash, address indexed vetoer, string reason);

    /// @notice Emitted when a TLD is successfully minted
    event TLDMinted(bytes32 indexed labelHash, address indexed owner);

    /// @notice Emitted when the contract is paused/unpaused
    event Paused(address indexed by);
    event Unpaused(address indexed by);

    /// @notice Emitted when rate limit is hit (for off-chain monitoring)
    event RateLimitHit(uint256 currentCount, uint256 maxAllowed, uint256 periodEnd);

    /// @notice Emitted when rate limit parameters are updated
    event RateLimitUpdated(uint256 newMax, uint256 newPeriod);

    /// @notice Emitted when Security Council veto authority is revoked after expiration
    event SecurityCouncilVetoRevoked(address indexed revokedBy);

    /// @notice Emitted when a TLD is added to the allowlist
    event TLDAllowlisted(string tld);

    /// @notice Emitted when a TLD is removed from the allowlist
    event TLDRemovedFromAllowlist(string tld);

    // ─────────────────────────────────────────────────────────────────
    // Structs
    // ─────────────────────────────────────────────────────────────────

    struct MintRequest {
        address owner;
        uint256 unlockTime;
        bool vetoed;
        uint32 proofInception;
    }

    // ─────────────────────────────────────────────────────────────────
    // Functions
    // ─────────────────────────────────────────────────────────────────

    /// @notice Submit a TLD claim with DNSSEC proof
    /// @param name DNS name in wire format (e.g., 0x02636f00 for ".co")
    /// @param proof Chain of signed RRSets from IANA root
    function submitClaim(
        bytes calldata name,
        IDNSSEC.RRSetWithSignature[] calldata proof
    ) external;

    /// @notice Execute a pending mint after timelock expires
    /// @param labelHash keccak256 of the TLD label
    function execute(bytes32 labelHash) external;

    /// @notice Veto a pending mint (DAO or Security Council only)
    /// @param labelHash keccak256 of the TLD label
    /// @param reason Human-readable justification for transparency
    function veto(bytes32 labelHash, string calldata reason) external;

    /// @notice Get pending mint request details
    function getRequest(bytes32 labelHash) external view returns (MintRequest memory);

    /// @notice Check if a TLD can be claimed (not already minted, no pending request)
    function canClaim(bytes32 labelHash) external view returns (bool);

    /// @notice Revoke Security Council veto authority after expiration (callable by anyone)
    function revokeSecurityCouncilVeto() external;

    /// @notice Check if Security Council veto authority has been revoked
    function securityCouncilVetoRevoked() external view returns (bool);

    /// @notice Update rate limit parameters (DAO only)
    function setRateLimit(uint256 newMax, uint256 newPeriod) external;

    /// @notice Pause the contract (DAO or Security Council only)
    function pause() external;

    /// @notice Unpause the contract (DAO or Security Council only)
    function unpause() external;

    /// @notice Returns the interface version for future compatibility
    function version() external pure returns (string memory);

    /// @notice Check if a TLD is on the allowlist
    function allowedTLDs(bytes32 tldHash) external view returns (bool);

    /// @notice Add a TLD to the allowlist (DAO only)
    function addToAllowlist(string calldata tld) external;

    /// @notice Remove a TLD from the allowlist (DAO only)
    function removeFromAllowlist(string calldata tld) external;

    /// @notice Batch add TLDs to the allowlist (DAO only)
    function batchAddToAllowlist(string[] calldata tlds) external;
}
