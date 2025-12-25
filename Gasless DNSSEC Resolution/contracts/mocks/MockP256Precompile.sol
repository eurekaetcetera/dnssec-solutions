// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @notice Mock implementation of EIP-7951 P-256 precompile for testing
/// @dev This contract mimics the behavior of the precompile at 0x100
///      Called via staticcall with 160 bytes: messageHash(32) || r(32) || s(32) || qx(32) || qy(32)
///      Returns: 32 bytes (0x00...01 for valid, empty for invalid)
contract MockP256Precompile {
    /// @notice Fallback function handles staticcall from P256SHA256Algorithm
    /// @dev msg.data contains 160 bytes: messageHash || r || s || qx || qy
    ///      Uses assembly to return 32 bytes directly
    fallback() external payable {
        require(msg.data.length == 160, "Invalid input length");
        
        // Extract components from calldata
        bytes32 r;
        bytes32 s;
        bytes32 qx;
        bytes32 qy;
        
        assembly {
            r := calldataload(32)
            s := calldataload(64)
            qx := calldataload(96)
            qy := calldataload(128)
        }
        
        // Simplified validation: return 0x00...01 if components are non-zero
        // This allows structure testing without full ECDSA verification
        // For real verification, you'd need a P-256 library
        bytes32 result;
        if (r != bytes32(0) && s != bytes32(0) && qx != bytes32(0) && qy != bytes32(0)) {
            result = bytes32(uint256(1)); // 0x00...01
        } else {
            result = bytes32(0); // Invalid
        }
        
        assembly {
            mstore(0, result)
            return(0, 32)
        }
    }
}
