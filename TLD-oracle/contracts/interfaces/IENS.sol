// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IENS {
    function owner(bytes32 node) external view returns (address);
    function setSubnodeOwner(bytes32 node, bytes32 label, address owner) external returns (bytes32);
}
