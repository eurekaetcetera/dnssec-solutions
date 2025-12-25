// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

// Note: This import references the Onchain DNS Import project contracts
import "@onchain-dns-import/contracts/DNSSEC.sol";

/**
 * @title IDNSRegistrar
 * @dev Interface for DNS name registration in ENS.
 */
interface IDNSRegistrar {
    /**
     * @dev Claims a DNS name in ENS using DNSSEC proofs.
     * @param name The DNS name to claim, in wire format.
     * @param input The chain of signed RRSets proving ownership.
     */
    function proveAndClaim(
        bytes memory name,
        DNSSEC.RRSetWithSignature[] memory input
    ) external;

    /**
     * @dev Claims a DNS name in ENS with a custom resolver.
     * @param name The DNS name to claim, in wire format.
     * @param input The chain of signed RRSets proving ownership.
     * @param resolver The resolver contract to set for the name.
     * @param addr The address to set in the resolver's addr record.
     */
    function proveAndClaimWithResolver(
        bytes memory name,
        DNSSEC.RRSetWithSignature[] memory input,
        address resolver,
        address addr
    ) external;
}

