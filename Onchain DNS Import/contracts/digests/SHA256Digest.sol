// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "../interfaces/IDigest.sol";
import "../utils/BytesUtils.sol";

/// @dev Implements the DNSSEC SHA256 digest (Digest Type 2).
contract SHA256Digest is IDigest {
    using BytesUtils for *;

    function verify(
        bytes calldata data,
        bytes calldata hash
    ) external pure override returns (bool) {
        require(hash.length == 32, "Invalid sha256 hash length");
        return sha256(data) == hash.readBytes32(0);
    }
}



