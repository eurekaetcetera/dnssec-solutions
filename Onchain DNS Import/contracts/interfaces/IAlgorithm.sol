// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/**
 * @dev Interface for DNSSEC signature verification algorithms
 */
interface IAlgorithm {
    /**
     * @dev Verifies a signature over provided data
     * @param key The public key to verify with (DNSKEY RDATA format)
     * @param data The data the signature is signing (canonical RRset)
     * @param signature The signature data
     * @return True if the signature is valid
     */
    function verify(
        bytes calldata key,
        bytes calldata data,
        bytes calldata signature
    ) external view returns (bool);
}

