// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "@ens-contracts/dnssec-oracle/algorithms/EllipticCurve.sol";

/// @title MockP256PrecompileWithVerify
/// @notice Mock EIP-7951 precompile using EllipticCurve for real P-256 verification
/// @dev Deploy this contract and use vm.etch() to copy its code to address 0x100
contract MockP256PrecompileWithVerify is EllipticCurve {
    /// @notice Fallback handles staticcall with 160 bytes input
    /// @dev Input: messageHash(32) || r(32) || s(32) || qx(32) || qy(32)
    ///      Output: 32 bytes (0x00...01 for valid, 0x00...00 for invalid)
    fallback() external payable {
        require(msg.data.length == 160, "Invalid input length");
        
        bytes32 messageHash;
        uint256 r;
        uint256 s;
        uint256 qx;
        uint256 qy;
        
        assembly {
            messageHash := calldataload(0)
            r := calldataload(32)
            s := calldataload(64)
            qx := calldataload(96)
            qy := calldataload(128)
        }
        
        // Use EllipticCurve.validateSignature for real P-256 verification
        bool valid = validateSignature(
            messageHash,
            [r, s],
            [qx, qy]
        );
        
        bytes32 result = valid ? bytes32(uint256(1)) : bytes32(0);
        
        assembly {
            mstore(0, result)
            return(0, 32)
        }
    }
}

