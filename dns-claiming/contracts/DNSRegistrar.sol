// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "@ensdomains/buffer/contracts/Buffer.sol";
// Note: These imports reference the Onchain DNS Import project contracts
import "@onchain-dns-import/contracts/DNSSEC.sol";
import "@onchain-dns-import/contracts/libraries/RRUtils.sol";
import "@onchain-dns-import/contracts/utils/BytesUtils.sol";
import "./DNSClaimChecker.sol";
import "./interfaces/IDNSRegistrar.sol";
import "./interfaces/IENS.sol";
import "./interfaces/IAddrResolver.sol";

/**
 * @title DNSRegistrar
 * @dev ENS registrar for claiming DNS names using DNSSEC proofs.
 *      Uses DNSSECOracle (with EIP-7951 P-256 precompile) for verification.
 * 
 * @notice Simplified from ENS's DNSRegistrar:
 *         - No PublicSuffixList (allows any domain for MVP)
 *         - No previousRegistrar migration
 *         - Focused on Algorithm 13 (P-256) domains
 * 
 * @notice This contract is separated from Onchain DNS Import because it requires
 *         ENS registry permissions that may not be available for all TLDs.
 */
contract DNSRegistrar is IDNSRegistrar, IERC165 {
    using BytesUtils for bytes;
    using Buffer for Buffer.buffer;
    using RRUtils for *;

    /// @dev The ENS registry contract
    IENS public immutable ens;
    
    /// @dev The DNSSEC oracle for proof verification
    DNSSEC public immutable oracle;
    
    /// @dev Default resolver for claimed names
    address public immutable defaultResolver;
    
    /// @dev Tracks the most recent proof inception for each claimed domain
    /// @notice Prevents replay of older proofs
    mapping(bytes32 => uint32) public inceptions;

    // Custom errors
    error NoOwnerRecordFound();
    error PermissionDenied(address caller, address owner);
    error PreconditionNotMet();
    error StaleProof();

    /// @dev Emitted when a DNS name is claimed
    event Claim(
        bytes32 indexed node,
        address indexed owner,
        bytes dnsname,
        uint32 inception
    );

    /**
     * @dev Constructor
     * @param _oracle The DNSSEC oracle contract (DNSSECOracle)
     * @param _ens The ENS registry contract
     * @param _defaultResolver The default resolver for claimed names
     */
    constructor(
        DNSSEC _oracle,
        IENS _ens,
        address _defaultResolver
    ) {
        oracle = _oracle;
        ens = _ens;
        defaultResolver = _defaultResolver;
    }

    /**
     * @dev Claims a DNS name in ENS using DNSSEC proofs.
     *      Sets the owner to the address specified in the _ens TXT record.
     * @param name The DNS name to claim, in wire format.
     * @param input The chain of signed RRSets proving ownership.
     */
    function proveAndClaim(
        bytes memory name,
        DNSSEC.RRSetWithSignature[] memory input
    ) public override {
        (bytes32 rootNode, bytes32 labelHash, address addr) = _claim(
            name,
            input
        );
        ens.setSubnodeOwner(rootNode, labelHash, addr);
    }

    /**
     * @dev Claims a DNS name with a custom resolver and address.
     * @param name The DNS name to claim, in wire format.
     * @param input The chain of signed RRSets proving ownership.
     * @param resolver The resolver contract to set (0 = use default).
     * @param addr The address to set in the resolver's addr record.
     */
    function proveAndClaimWithResolver(
        bytes memory name,
        DNSSEC.RRSetWithSignature[] memory input,
        address resolver,
        address addr
    ) public override {
        (bytes32 rootNode, bytes32 labelHash, address owner) = _claim(
            name,
            input
        );
        
        // Only the proven owner can set custom resolver
        if (msg.sender != owner) {
            revert PermissionDenied(msg.sender, owner);
        }
        
        // Use default resolver if none specified
        address resolverToUse = resolver != address(0) ? resolver : defaultResolver;
        
        ens.setSubnodeRecord(rootNode, labelHash, owner, resolverToUse, 0);
        
        // Set the address record if provided
        if (addr != address(0)) {
            if (resolverToUse == address(0)) {
                revert PreconditionNotMet();
            }
            bytes32 node = keccak256(abi.encodePacked(rootNode, labelHash));
            IAddrResolver(resolverToUse).setAddr(node, addr);
        }
    }

    /**
     * @dev Checks interface support.
     */
    function supportsInterface(
        bytes4 interfaceID
    ) external pure override returns (bool) {
        return
            interfaceID == type(IERC165).interfaceId ||
            interfaceID == type(IDNSRegistrar).interfaceId;
    }

    /**
     * @dev Internal claim logic: verifies proof and extracts owner.
     * @param name The DNS name in wire format.
     * @param input The chain of signed RRSets.
     * @return parentNode The parent ENS node.
     * @return labelHash The keccak256 of the first label.
     * @return addr The owner address from the TXT record.
     */
    function _claim(
        bytes memory name,
        DNSSEC.RRSetWithSignature[] memory input
    ) internal returns (bytes32 parentNode, bytes32 labelHash, address addr) {
        // Verify the DNSSEC proof chain
        (bytes memory data, uint32 inception) = oracle.verifyRRSet(input);

        // Extract the first label from the name
        uint256 labelLen = name.readUint8(0);
        labelHash = name.keccak(1, labelLen);

        // Get the parent name (everything after the first label)
        bytes memory parentName = name.substring(
            labelLen + 1,
            name.length - labelLen - 1
        );

        // Compute the parent node
        parentNode = _computeNode(parentName);

        // Compute the full node
        bytes32 node = keccak256(abi.encodePacked(parentNode, labelHash));
        
        // Ensure this proof is newer than any previous proof
        if (!RRUtils.serialNumberGte(inception, inceptions[node])) {
            revert StaleProof();
        }
        inceptions[node] = inception;

        // Extract owner address from the _ens TXT record
        bool found;
        (addr, found) = DNSClaimChecker.getOwnerAddress(name, data);
        if (!found) {
            revert NoOwnerRecordFound();
        }

        emit Claim(node, addr, name, inception);
    }

    /**
     * @dev Computes the ENS node (namehash) from a DNS name.
     *      ENS namehash is computed from right to left:
     *      namehash("foo.bar.eth") = keccak256(namehash("bar.eth"), keccak256("foo"))
     *      
     *      For DNS wire format, we need to recursively process from right to left.
     * @param domain The DNS name in wire format.
     * @return node The computed namehash.
     */
    function _computeNode(bytes memory domain) internal pure returns (bytes32 node) {
        return _computeNodeRecursive(domain, 0);
    }

    /**
     * @dev Recursively computes namehash from DNS wire format.
     *      Process: go to end of current label, recurse on rest, then hash.
     */
    function _computeNodeRecursive(
        bytes memory domain,
        uint256 offset
    ) internal pure returns (bytes32 node) {
        uint256 labelLen = domain.readUint8(offset);
        
        // Base case: root (empty label)
        if (labelLen == 0) {
            return bytes32(0);
        }
        
        // Recursively compute parent node first
        bytes32 parentNode = _computeNodeRecursive(domain, offset + labelLen + 1);
        
        // Hash the current label
        bytes32 labelHash = domain.keccak(offset + 1, labelLen);
        
        // namehash = keccak256(parentNode || labelHash)
        return keccak256(abi.encodePacked(parentNode, labelHash));
    }

    /**
     * @dev Gets the DNSSEC oracle address.
     */
    function getOracle() external view returns (address) {
        return address(oracle);
    }

    /**
     * @dev Gets the ENS registry address.
     */
    function getENS() external view returns (address) {
        return address(ens);
    }
}

