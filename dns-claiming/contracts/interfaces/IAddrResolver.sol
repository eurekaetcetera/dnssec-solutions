// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/**
 * @title IAddrResolver
 * @dev Minimal interface for setting addresses in a resolver.
 */
interface IAddrResolver {
    /**
     * @dev Sets the address for a node.
     * @param node The namehash of the ENS name.
     * @param addr The address to set.
     */
    function setAddr(bytes32 node, address addr) external;
}






