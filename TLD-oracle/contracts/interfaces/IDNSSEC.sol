// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IDNSSEC {
    struct RRSetWithSignature {
        bytes rrset;
        bytes sig;
    }

    function verifyRRSet(
        RRSetWithSignature[] calldata input
    ) external view returns (bytes memory rrs, uint32 inception);

    function verifyRRSet(
        RRSetWithSignature[] calldata input,
        uint256 timestamp
    ) external view returns (bytes memory rrs, uint32 inception);
}
