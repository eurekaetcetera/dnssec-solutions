// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @dev Interface for DNSSEC digest verification algorithms
interface IDigest {
    /// @dev Verifies a cryptographic hash.
    /// @param data The data to hash.
    /// @param hash The hash to compare to.
    /// @return True iff the hashed data matches the provided hash value.
    function verify(
        bytes calldata data,
        bytes calldata hash
    ) external pure returns (bool);
}



