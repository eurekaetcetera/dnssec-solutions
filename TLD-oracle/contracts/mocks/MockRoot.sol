// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "../interfaces/IRoot.sol";
import "../interfaces/IENS.sol";

/**
 * @title MockRoot
 * @notice Minimal ENS Root mock for testing TLDMinter.
 * @dev Allows authorized callers to create TLDs by setting subnodes under the root node.
 */
contract MockRoot is IRoot {
    IENS public immutable ens;
    address private _owner;
    mapping(address => bool) public controllers;

    event SubnodeOwnerSet(bytes32 indexed label, address indexed owner);
    event ControllerChanged(address indexed controller, bool enabled);

    error NotAuthorized(address caller);

    modifier onlyController() {
        if (!controllers[msg.sender] && msg.sender != _owner) {
            revert NotAuthorized(msg.sender);
        }
        _;
    }

    constructor(address _ens) {
        ens = IENS(_ens);
        _owner = msg.sender;
        controllers[msg.sender] = true;
    }

    /// @inheritdoc IRoot
    function owner() external view override returns (address) {
        return _owner;
    }

    /// @inheritdoc IRoot
    function setSubnodeOwner(
        bytes32 label,
        address newOwner
    ) external override onlyController returns (bytes32) {
        bytes32 node = ens.setSubnodeOwner(bytes32(0), label, newOwner);
        emit SubnodeOwnerSet(label, newOwner);
        return node;
    }

    /**
     * @notice Add or remove a controller that can create TLDs.
     * @param controller The address to modify
     * @param enabled Whether the controller is enabled
     */
    function setController(address controller, bool enabled) external {
        require(msg.sender == _owner, "Not owner");
        controllers[controller] = enabled;
        emit ControllerChanged(controller, enabled);
    }

    /**
     * @notice Transfer ownership of the Root contract.
     */
    function transferOwnership(address newOwner) external {
        require(msg.sender == _owner, "Not owner");
        _owner = newOwner;
    }
}
