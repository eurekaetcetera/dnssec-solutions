// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "../interfaces/IENS.sol";

/**
 * @title MockENS
 * @notice Minimal ENS Registry mock for testing TLDMinter.
 * @dev Stores node ownership mappings. Used by MockRoot to record TLD assignments.
 */
contract MockENS is IENS {
    mapping(bytes32 => address) private _owners;

    event OwnerChanged(bytes32 indexed node, address owner);

    /// @inheritdoc IENS
    function owner(bytes32 node) external view override returns (address) {
        return _owners[node];
    }

    /// @inheritdoc IENS
    function setSubnodeOwner(
        bytes32 node,
        bytes32 label,
        address newOwner
    ) external override returns (bytes32) {
        bytes32 subnode = keccak256(abi.encodePacked(node, label));
        _owners[subnode] = newOwner;
        emit OwnerChanged(subnode, newOwner);
        return subnode;
    }

    /**
     * @notice Directly set owner of a node (for testing setup).
     */
    function setOwner(bytes32 node, address newOwner) external {
        _owners[node] = newOwner;
        emit OwnerChanged(node, newOwner);
    }
}
