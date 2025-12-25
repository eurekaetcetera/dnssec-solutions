# P-256 Precompile Test

This directory contains a test script to verify that the EIP-7951 P-256 precompile is available and can be called on the target network.

## Purpose

The `test-p256-precompile.js` script allows users to test whether:
1. The P-256 precompile (EIP-7951) is available at address `0x100`
2. The precompile can be called with valid input data
3. The network (Sepolia/mainnet) supports EIP-7951

## Usage

### Installation

```bash
cd contracts/algorithms/test
npm install
```

### Run Test

Test on Sepolia:
```bash
SEPOLIA_RPC_URL=https://your-rpc-url node test-p256-precompile.js
```

Test on Mainnet:
```bash
MAINNET_RPC_URL=https://your-rpc-url node test-p256-precompile.js
```

## Expected Output

On a network with EIP-7951 (Sepolia after Fusaka upgrade, Mainnet after Fusaka upgrade):
- ✅ Precompile code check should succeed
- ✅ Precompile call should return valid result
- ✅ Signature verification test should pass

On a network without EIP-7951:
- ❌ Precompile code check will show no code
- ❌ Precompile call will fail

## Reference

For detailed information about the P-256 precompile, see:
- `../P256_PRECOMPILE_INSTRUCTIONS.md` in the parent `algorithms/` directory
- [EIP-7951 Specification](https://eips.ethereum.org/EIPS/eip-7951)

