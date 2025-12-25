// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

abstract contract DNSSEC {
    bytes public anchors;

    struct RRSetWithSignature {
        bytes rrset;
        bytes sig;
    }

    event AlgorithmUpdated(uint8 id, address addr);
    event DigestUpdated(uint8 id, address addr);

    function verifyRRSet(
        RRSetWithSignature[] memory input
    ) external view virtual returns (bytes memory rrs, uint32 inception);

    function verifyRRSet(
        RRSetWithSignature[] memory input,
        uint256 timestamp
    ) public view virtual returns (bytes memory rrs, uint32 inception);
}

