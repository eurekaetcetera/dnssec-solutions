// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IRoot {
    function setSubnodeOwner(bytes32 label, address owner) external returns (bytes32);
    function owner() external view returns (address);
}
