// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @notice ENSIP-10 Extended Resolver interface.
interface IExtendedResolver {
    /// @dev Resolves a DNS-encoded name with arbitrary resolution calldata.
    /// @param name DNS-encoded name (per ENSIP-10)
    /// @param data ABI-encoded function call for the resolver to execute
    /// @return result ABI-encoded return data for the requested resolution
    function resolve(bytes calldata name, bytes calldata data)
        external
        view
        returns (bytes memory result);
}

