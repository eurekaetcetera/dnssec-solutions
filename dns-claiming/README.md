# DNS Claiming Contracts

This directory contains contracts and scripts for claiming DNS names on ENS using DNSSEC proofs.

## Overview

These contracts are separated from Onchain DNS Import because they require ENS registry permissions that may not be available for all TLDs (e.g., you cannot claim `.co` domains on ENS).

## Contracts

### Core Contracts

- **`DNSRegistrar.sol`** - ENS registrar for claiming DNS names using DNSSEC proofs
  - Uses DNSSECOracle from Onchain DNS Import for proof verification
  - Extracts owner address from `_ens.<domain>` TXT records
  - Claims names on ENS registry

- **`DNSClaimChecker.sol`** - Library for parsing `_ens` TXT records
  - Extracts owner address from TXT record format: `a=0x<address>`

- **`HexUtils.sol`** - Hex string parsing utilities
  - Used by DNSClaimChecker to parse addresses from hex strings

### Interfaces

- **`IENS.sol`** - Minimal ENS Registry interface
- **`IDNSRegistrar.sol`** - DNSRegistrar interface
- **`IAddrResolver.sol`** - Address resolver interface

## Dependencies

These contracts depend on Onchain DNS Import's contracts:
- `DNSSEC.sol` - DNSSEC structs and types
- `RRUtils.sol` - DNS wire format parsing
- `BytesUtils.sol` - Byte manipulation utilities
- `@ensdomains/buffer` - Buffer library

## Usage

### Prerequisites

1. Deploy DNSSECOracle (from Onchain DNS Import)
2. Set trust anchors on the oracle
3. Deploy DNSRegistrar pointing to the oracle
4. Ensure `_ens.<domain>` TXT record exists with format: `a=0x<your-address>`
5. Have permission to claim the TLD on ENS (e.g., `.eth`, not `.co`)

### Claim a DNS Name

```bash
REGISTRAR_ADDRESS=0x... \
PRIVATE_KEY=0x... \
DOMAIN=example.com \
node scripts/claim_dns_name.mjs
```

The script will:
1. Fetch DNSSEC proof using ENSjs
2. Format the proof for the contract
3. Encode the DNS name to wire format
4. Call `proveAndClaimWithResolver()` on the DNSRegistrar
5. Wait for transaction confirmation

## Limitations

⚠️ **Important**: You can only claim domains on ENS if you have permission for the TLD:
- ✅ `.eth` - Can be claimed (via ENS's registrar)
- ❌ `.co`, `.com`, etc. - Cannot be claimed (no registrar permissions)

This is why these contracts are separated from Onchain DNS Import - they demonstrate functionality but may not be usable for all domains.

## Integration with Onchain DNS Import

The DNSRegistrar uses Onchain DNS Import's optimized DNSSECOracle, which provides:
- ~94% gas savings for Algorithm 13 (P-256) domains
- Full DS chain validation from IANA root
- Support for both Algorithm 8 (RSA) and Algorithm 13 (P-256)

## Contract Deployment

To deploy DNSRegistrar, you'll need:
- DNSSECOracle address (from Onchain DNS Import)
- ENS Registry address
- Default resolver address

Example deployment (see Onchain DNS Import's `Deploy.s.sol` for reference):
```solidity
DNSRegistrar registrar = new DNSRegistrar(
    DNSSEC(oracleAddress),
    IENS(ensRegistryAddress),
    defaultResolverAddress
);
```






