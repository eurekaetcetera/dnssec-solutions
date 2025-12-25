# ENS P256SHA256Algorithm Test Suite

This directory contains tests for the EIP-7951 based `P256SHA256Algorithm` contract in the [ENS contracts fork](https://github.com/eurekaetcetera/ens-contracts).

## Overview

The tests verify that the updated `P256SHA256Algorithm.sol` works correctly with the EIP-7951 P-256 precompile. Since the precompile (at address `0x100`) is not available on local test networks, we use a mock that implements real P-256 verification using the original `EllipticCurve.sol` library.

## Test Results

```
[PASS] test_ValidSignature()           - RFC6605 test vector validates correctly
[PASS] test_InvalidSignature_ModifiedData() - Modified data correctly returns false
[PASS] test_InvalidSignature_WrongSignature() - Wrong signature correctly returns false  
[PASS] test_RevertOnInvalidKeyLength() - Reverts on 60-byte key (should be 68)
[PASS] test_RevertOnInvalidSignatureLength() - Reverts on 32-byte sig (should be 64)
[PASS] test_GasUsage()                 - Logs gas consumption
```

## Gas Comparison

| Implementation | Gas per verification |
|---------------|---------------------|
| EllipticCurve (Solidity) | ~1,350,000 gas |
| EIP-7951 Precompile | ~3,500 gas |

**~99.7% gas reduction** with the native precompile.

## Running Tests

```bash
cd ens-p256-test
forge test -vv
```

## How the Mock Works

1. `MockP256PrecompileWithVerify.sol` inherits from ENS's `EllipticCurve.sol`
2. Test uses `vm.etch()` to deploy mock bytecode at address `0x100`
3. When `P256SHA256Algorithm.verify()` calls the precompile, it hits our mock
4. Mock performs real P-256 verification using `EllipticCurve.validateSignature()`

## Test Vector

Uses the RFC6605 test vector for ECDSAP256SHA256:
- Domain: `example.net.`
- Record: `www.example.net. 3600 IN A 192.0.2.1`
- Algorithm: 13 (ECDSAP256SHA256)

## Related

- [EIP-7951: P-256 Precompile](https://eips.ethereum.org/EIPS/eip-7951)
- [RFC6605: ECDSA for DNSSEC](https://datatracker.ietf.org/doc/html/rfc6605)
- [ENS Contracts Fork](https://github.com/eurekaetcetera/ens-contracts)

