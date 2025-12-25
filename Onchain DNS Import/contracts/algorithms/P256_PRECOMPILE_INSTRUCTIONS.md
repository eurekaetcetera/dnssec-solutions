# P256 (secp256r1) Precompile - EIP-7951 Reference

## Status: ✅ LIVE
- **Activated**: December 3, 2025 (Fusaka upgrade)
- **Networks**: Ethereum Mainnet, Sepolia, Holesky, Hoodi
- **Source**: https://blog.ethereum.org/2025/11/06/fusaka-mainnet-announcement

## Precompile Details

| Property | Value |
|----------|-------|
| Address | `0x0000000000000000000000000000000000000100` |
| EIP | EIP-7951 |
| Curve | secp256r1 (P256 / prime256v1) |
| Gas Cost | ~3,450 gas |

## Input Format (160 bytes total)

The precompile expects exactly 160 bytes of concatenated data:

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 32 bytes | `hash` | SHA256 hash of the message |
| 32 | 32 bytes | `r` | Signature R component |
| 64 | 32 bytes | `s` | Signature S component |
| 96 | 32 bytes | `x` | Public key X coordinate |
| 128 | 32 bytes | `y` | Public key Y coordinate |

## Output Format

| Result | Meaning |
|--------|---------|
| `0x0000...0001` (32 bytes) | Signature is **VALID** |
| `0x0000...0000` or `0x` | Signature is **INVALID** |

## Usage with ethers.js v6

```javascript
import { ethers } from 'ethers';

const P256_PRECOMPILE = '0x0000000000000000000000000000000000000100';

async function verifyP256Signature(provider, messageHash, r, s, pubKeyX, pubKeyY) {
  // All inputs must be 32-byte hex strings (with 0x prefix)
  const input = ethers.concat([
    messageHash,  // 32 bytes - SHA256 hash
    r,            // 32 bytes - signature r
    s,            // 32 bytes - signature s
    pubKeyX,      // 32 bytes - public key x
    pubKeyY       // 32 bytes - public key y
  ]);

  const result = await provider.call({
    to: P256_PRECOMPILE,
    data: input
  });

  // Returns true if signature is valid
  return result === '0x0000000000000000000000000000000000000000000000000000000000000001';
}
```

## Generating P256 Keys & Signatures (Node.js)

```javascript
import crypto from 'crypto';

// Generate keypair
const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
  namedCurve: 'prime256v1'  // P256 / secp256r1
});

// Extract x, y coordinates from public key
const pubKeyDer = publicKey.export({ type: 'spki', format: 'der' });
const uncompressed = pubKeyDer.slice(-65); // Last 65 bytes: 0x04 || x || y
const x = '0x' + uncompressed.slice(1, 33).toString('hex');
const y = '0x' + uncompressed.slice(33, 65).toString('hex');

// Sign a message (use ieee-p1363 to get raw r||s format)
const message = 'Hello';
const messageHash = '0x' + crypto.createHash('sha256').update(message).digest('hex');

const sign = crypto.createSign('SHA256');
sign.update(message);
const sig = sign.sign({ key: privateKey, dsaEncoding: 'ieee-p1363' });

const r = '0x' + sig.slice(0, 32).toString('hex');
const s = '0x' + sig.slice(32, 64).toString('hex');
```

## Key Points for Implementation

1. **Hash the message with SHA256** - the precompile expects a 32-byte hash, not raw message
2. **Use ieee-p1363 signature format** - gives raw `r || s` (64 bytes), not DER-encoded
3. **Public key must be uncompressed** - extract raw x, y coordinates (32 bytes each)
4. **All values are 32 bytes** - pad with leading zeros if needed
5. **This is a static call** - no gas spent, no transaction needed for verification

## Use Cases

- **WebAuthn/Passkey verification** - browsers use P256 for FIDO2/WebAuthn
- **Apple Secure Enclave** - uses P256 for biometric auth
- **Android Keystore** - hardware-backed P256 keys
- **Smart account signature verification** - ERC-4337 passkey signers

## Reference Implementation

See `test-p256.js` for a complete working example that:
1. Generates a P256 keypair
2. Signs a message
3. Verifies locally (sanity check)
4. Calls the precompile to verify on-chain

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| Empty result `0x` | RPC not updated to Fusaka | Use updated RPC (Alchemy, Infura) |
| Returns `0x00...00` | Invalid signature | Check hash, r, s, x, y formatting |
| Input != 160 bytes | Wrong data encoding | Ensure all 5 fields are exactly 32 bytes |
