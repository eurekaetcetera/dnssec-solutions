// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/**
 * @title IENS
 * @dev Minimal ENS registry interface for DNS registration.
 */
interface IENS {
    /**
     * @dev Returns the owner of a node.
     * @param node The namehash of the ENS name.
     * @return The owner address.
     */
    function owner(bytes32 node) external view returns (address);

    /**
     * @dev Sets the owner of a subnode.
     * @param node The parent node.
     * @param label The keccak256 hash of the label.
     * @param owner The new owner address.
     * @return The namehash of the new subnode.
     */
    function setSubnodeOwner(
        bytes32 node,
        bytes32 label,
        address owner
    ) external returns (bytes32);

    /**
     * @dev Sets all records for a subnode.
     * @param node The parent node.
     * @param label The keccak256 hash of the label.
     * @param owner The new owner address.
     * @param resolver The resolver address.
     * @param ttl The TTL for the node.
     */
    function setSubnodeRecord(
        bytes32 node,
        bytes32 label,
        address owner,
        address resolver,
        uint64 ttl
    ) external;

    /**
     * @dev Sets the resolver for a node.
     * @param node The namehash of the ENS name.
     * @param resolver The resolver address.
     */
    function setResolver(bytes32 node, address resolver) external;
}






