// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

library HexUtils {
    /// @dev Convert `hexString[off:end]` to `bytes32`.
    ///      Accepts 0-64 hex-chars.
    ///      Uses right alignment: `1` → `0000000000000000000000000000000000000000000000000000000000000001`.
    /// @param hexString The string to parse.
    /// @param off The index to start parsing.
    /// @param end The (exclusive) index to stop parsing.
    /// @return word The parsed bytes32.
    /// @return valid True if the parse was successful.
    function hexStringToBytes32(
        bytes memory hexString,
        uint256 off,
        uint256 end
    ) internal pure returns (bytes32 word, bool valid) {
        if (end < off) return ("", false); // invalid range
        uint256 nibbles = end - off;
        if (nibbles > 64 || end > hexString.length) {
            return (bytes32(0), false); // too large or out of bounds
        }
        uint256 src;
        assembly {
            src := add(add(hexString, 32), off)
        }
        valid = unsafeBytes(src, 0, nibbles);
        assembly {
            let pad := sub(32, shr(1, add(nibbles, 1))) // number of bytes
            word := shr(shl(3, pad), mload(0)) // right align
        }
    }

    /// @dev Convert `hexString[off:end]` to `address`.
    ///      Accepts exactly 40 hex-chars.
    /// @param hexString The string to parse.
    /// @param off The index to start parsing.
    /// @param end The (exclusive) index to stop parsing.
    /// @return addr The parsed address.
    /// @return valid True if the parse was successful.
    function hexToAddress(
        bytes memory hexString,
        uint256 off,
        uint256 end
    ) internal pure returns (address addr, bool valid) {
        if (off + 40 != end) return (address(0), false); // wrong length
        bytes32 word;
        (word, valid) = hexStringToBytes32(hexString, off, end);
        addr = address(uint160(uint256(word)));
    }

    /// @dev Convert arbitrary hex-encoded memory to bytes.
    ///      If nibbles is odd, leading hex-char is padded, eg. `F` → `0x0F`.
    ///      Matches: `/^[0-9a-f]*$/i`.
    /// @param src The memory offset of first hex-char of input.
    /// @param dst The memory offset of first byte of output (cannot alias `src`).
    /// @param nibbles The number of hex-chars to convert.
    /// @return valid True if all characters were hex.
    function unsafeBytes(
        uint256 src,
        uint256 dst,
        uint256 nibbles
    ) internal pure returns (bool valid) {
        assembly {
            function getHex(c, i) -> ascii {
                c := byte(i, c)
                // chars 48-57: 0-9
                if and(gt(c, 47), lt(c, 58)) {
                    ascii := sub(c, 48)
                    leave
                }
                // chars 65-70: A-F
                if and(gt(c, 64), lt(c, 71)) {
                    ascii := add(sub(c, 65), 10)
                    leave
                }
                // chars 97-102: a-f
                if and(gt(c, 96), lt(c, 103)) {
                    ascii := add(sub(c, 97), 10)
                    leave
                }
                // invalid char
                ascii := 0x100
            }
            valid := true
            let end := add(src, nibbles)
            if and(nibbles, 1) {
                let b := getHex(mload(src), 0) // "f" -> 15
                mstore8(dst, b) // write ascii byte
                src := add(src, 1) // update pointers
                dst := add(dst, 1)
                if gt(b, 255) {
                    valid := false
                    src := end // terminate loop
                }
            }
            // prettier-ignore
            for {} lt(src, end) {
                src := add(src, 2) // 2 nibbles
                dst := add(dst, 1) // per byte
            } {
                let word := mload(src) // read word (left aligned)
                let b := or(shl(4, getHex(word, 0)), getHex(word, 1)) // "ff" -> 255
                if gt(b, 255) {
                    valid := false
                    break
                }
                mstore8(dst, b) // write ascii byte
            }
        }
    }
}






