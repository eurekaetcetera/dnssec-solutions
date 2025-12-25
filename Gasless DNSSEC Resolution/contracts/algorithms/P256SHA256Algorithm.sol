// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "../interfaces/IAlgorithm.sol";

contract P256SHA256Algorithm is IAlgorithm {
    address internal constant P256_PRECOMPILE =
        0x0000000000000000000000000000000000000100;

    error InvalidP256SignatureLength();
    error InvalidP256KeyLength();

    function verify(
        bytes calldata key,
        bytes calldata data,
        bytes calldata signature
    ) external view returns (bool) {
        if (signature.length != 64) revert InvalidP256SignatureLength();
        if (key.length != 64) revert InvalidP256KeyLength();

        bytes32 r;
        bytes32 s;
        bytes32 qx;
        bytes32 qy;

        assembly {
            r := calldataload(add(signature.offset, 0))
            s := calldataload(add(signature.offset, 32))
            qx := calldataload(add(key.offset, 0))
            qy := calldataload(add(key.offset, 32))
        }

        bytes32 messageHash = sha256(data);

        bytes memory input = abi.encodePacked(messageHash, r, s, qx, qy);

        (bool success, bytes memory result) = P256_PRECOMPILE.staticcall(input);
        if (!success || result.length != 32) return false;

        return result[31] == bytes1(0x01);
    }
}

