// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "forge-std/Test.sol";
import "@ens-contracts/dnssec-oracle/algorithms/P256SHA256Algorithm.sol";
import "../contracts/MockP256PrecompileWithVerify.sol";

/// @title P256SHA256AlgorithmTest
/// @notice Tests the EIP-7951 based P256SHA256Algorithm with a mocked precompile
/// @dev Uses vm.etch to deploy mock at address 0x100
contract P256SHA256AlgorithmTest is Test {
    P256SHA256Algorithm public algorithm;
    address constant P256_PRECOMPILE = address(0x100);

    // RFC6605 Test Vector for P-256
    // example.net. 3600 IN DNSKEY 257 3 13 (
    //     GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb
    //     krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA== )
    bytes constant DNSKEY_RDATA = hex"0101030d1a88c88615d437fbb8bf9e1942a1929f28562706ae6c2bd399e7b1bfb6d1e9e75b92b4aa42917ae1c61b701ef035c3fe7be3009cbafe5a2f71316c902dcf0d00";
    
    // www.example.net. 3600 IN A 192.0.2.1 (with RRSIG digest data)
    bytes constant SIGNED_DATA = hex"00010d0300000e104c88b1374c63c737d960076578616d706c65036e65740003777777076578616d706c65036e6574000001000100000e100004c0000201";
    
    // RRSIG signature (r || s, 64 bytes)
    bytes constant SIGNATURE = hex"ab1eb02d8aa687e97da0229337aa8873e6f0eb26be289f28333d183f5d3b7a95c0c869adfb748daee3c5286eed6682c12e5533186baced9c26c167a9ebae950b";

    function setUp() public {
        // Deploy the mock precompile contract
        MockP256PrecompileWithVerify mock = new MockP256PrecompileWithVerify();
        
        // Copy mock's bytecode to address 0x100 (EIP-7951 precompile address)
        vm.etch(P256_PRECOMPILE, address(mock).code);
        
        // Deploy the algorithm contract
        algorithm = new P256SHA256Algorithm();
    }

    function test_ValidSignature() public view {
        // Test with RFC6605 test vector
        bool result = algorithm.verify(DNSKEY_RDATA, SIGNED_DATA, SIGNATURE);
        assertTrue(result, "Valid signature should return true");
    }

    function test_InvalidSignature_ModifiedData() public view {
        // Modify the signed data to invalidate signature
        bytes memory modifiedData = SIGNED_DATA;
        modifiedData[0] = 0xFF;
        
        bool result = algorithm.verify(DNSKEY_RDATA, modifiedData, SIGNATURE);
        assertFalse(result, "Modified data should return false");
    }

    function test_InvalidSignature_WrongSignature() public view {
        // Use wrong signature bytes
        bytes memory wrongSig = new bytes(64);
        wrongSig[0] = 0x01;
        wrongSig[32] = 0x01;
        
        bool result = algorithm.verify(DNSKEY_RDATA, SIGNED_DATA, wrongSig);
        assertFalse(result, "Wrong signature should return false");
    }

    function test_RevertOnInvalidKeyLength() public {
        bytes memory shortKey = new bytes(60); // Should be 68
        
        vm.expectRevert("Invalid p256 key length");
        algorithm.verify(shortKey, SIGNED_DATA, SIGNATURE);
    }

    function test_RevertOnInvalidSignatureLength() public {
        bytes memory shortSig = new bytes(32); // Should be 64
        
        vm.expectRevert("Invalid p256 signature length");
        algorithm.verify(DNSKEY_RDATA, SIGNED_DATA, shortSig);
    }

    function test_GasUsage() public {
        uint256 gasBefore = gasleft();
        algorithm.verify(DNSKEY_RDATA, SIGNED_DATA, SIGNATURE);
        uint256 gasUsed = gasBefore - gasleft();
        
        // Log gas usage for comparison
        // With real precompile: ~3,500 gas
        // With EllipticCurve mock: ~200,000+ gas
        emit log_named_uint("Gas used for P256 verification", gasUsed);
    }
}

