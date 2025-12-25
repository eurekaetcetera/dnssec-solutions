# Onchain DNS Import: ENS-Style DNSSEC Oracle with EIP-7951 P-256 Precompile

This project implements an **ENS-style DNS import system** that uses the **EIP-7951 P-256 precompile** for efficient onchain DNSSEC verification. It enables users to claim DNS names onchain by submitting DNSSEC proofs, drastically reducing gas costs for Algorithm 13 (ECDSA P-256) zones.

## Trust Model: Option B (Full DS Chain)

We use **Option B** trust model: the **IANA root zone** trust anchors are the starting point. We verify the full DS (Delegation Signer) chain from the root zone down to the target domain. This matches ENS's DNSSEC oracle approach, ensuring compatibility with the existing ENS ecosystem.

### DNSSEC Key Structure

- **IANA Root Keys**: Trust anchors for the root zone (`.`)
  - Multiple root keys maintained by ICANN
  - Algorithm 8 (RSA/SHA-256) and Algorithm 13 (ECDSAP256SHA256)
  - Validated against ICANN's published root key material

- **Domain Keys**: DNSKEY records for each zone in the chain
  - **KSK (Key Signing Key)**: flags=257, signs the DNSKEY RRset
  - **ZSK (Zone Signing Key)**: flags=256, signs zone data (TXT, A, etc.)
  - Algorithm support: 8 (RSA/SHA-256) and 13 (ECDSAP256SHA256)

- **DS Chain**: Delegation Signer records link parent zones to child zones
  - Each DS record is signed by the parent zone's ZSK
  - Chain of trust: Root → TLD → Domain → Subdomain

## Setup

Install dependencies:

```bash
npm install
```

### Prerequisites

- Node.js (v18+)
- Foundry (for contract compilation and deployment)
- Access to Sepolia testnet (for deployment)

Install Foundry (if not already installed):

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

### Environment Configuration

1. Copy the example environment file:
```bash
cp env.example .env
```

2. Edit `.env` and fill in your values:
   - `PRIVATE_KEY` - Your deployment wallet private key
   - `SEPOLIA_RPC_URL` - Sepolia RPC endpoint
   - `ETHERSCAN_API_KEY` - Etherscan API key for contract verification
   - `ORACLE_ADDRESS` - Deployed oracle address (after deployment)

**⚠️ Important**: Never commit your `.env` file to git!

## Fetching DNSSEC Proofs

The `fetch_dnssec_proof.mjs` script queries DNS directly (using `dns-packet` library) to fetch complete DNSSEC proof material including:

- Target domain TXT record with RRSIG (signed by domain ZSK)
- Domain DNSKEY records (KSK + ZSK) with RRSIG (signed by domain KSK)
- DS records for each zone in the chain with RRSIG
- Parent zone DNSKEY records with RRSIG
- Full chain up to root zone

### Usage

Basic usage (defaults to Cloudflare DNS 1.1.1.1):

```bash
node scripts/fetch_dnssec_proof.mjs --name eketc.co --type TXT
```

With custom DNS server:

```bash
node scripts/fetch_dnssec_proof.mjs --name eketc.co --type TXT --server 8.8.8.8 --out proofs/custom_output.json
```

### Output Format

The script generates a JSON file containing:

- **Meta information**: timestamp, DNS server, query name/type
- **Trust Anchors**: IANA root zone DNSKEY records
- **RRsets**: Structured DNS records (TXT, DNSKEY, DS, RRSIG) with parsed RDATA
- **Messages**: Raw DNS response messages in base64 for ground truth preservation

Example output structure:

```json
{
  "meta": {
    "generatedAt": "2025-12-18T01:23:40.487Z",
    "dnsServer": "1.1.1.1:53",
    "qname": "eketc.co",
    "qtype": 16
  },
  "trustAnchors": [
    {
      "zone": ".",
      "dnskey": {
        "flags": 257,
        "protocol": 3,
        "algorithm": 8,
        "publicKey": "base64..."
      },
      "keyTag": 19036
    }
  ],
  "rrsets": [
    {
      "name": "eketc.co",
      "type": "TXT",
      "class": "IN",
      "ttl": 60,
      "rdata": {
        "txt": ["v=spf1 ..."]
      }
    },
    {
      "name": "eketc.co",
      "type": "RRSIG",
      "rdata": {
        "typeCovered": "TXT",
        "algorithm": 13,
        "keyTag": 34505,
        "signersName": "eketc.co",
        "signature": "base64..."
      }
    }
  ],
  "messages": [
    {
      "query": { "name": "eketc.co", "type": "TXT" },
      "responseRaw": "base64EncodedDnsResponse..."
    }
  ]
}
```

### Key Tag Computation

The script computes the DNSSEC key tag per **RFC 4034 Appendix B**:
- Key tags are computed from DNSKEY RDATA
- DS records use key tags to reference parent zone keys
- Key tags are NOT hardcoded; they're computed from the DNSKEY RDATA

## Validation Performed

The script performs the following validations:

1. **Root Trust Anchors**: Validates IANA root zone DNSKEY records
2. **DS Chain Verification**: Validates DS records link parent zones to child zones
3. **DNSKEY Verification**: Confirms each zone's DNSKEY RRset is signed by its KSK
4. **Record Verification**: Ensures target records (TXT, etc.) are signed by the domain ZSK
5. **Algorithm Support**: Validates Algorithm 8 (RSA) and Algorithm 13 (P-256) signatures
6. **Chain Completeness**: Verifies the full chain from root to target domain

All validations must pass or the script exits with an error.

## Deployment

### Deploy Contracts

Deploy the DNSSECOracle to Sepolia:

```bash
forge script scripts/Deploy.s.sol:DeployOracleOnly \
  --rpc-url sepolia \
  --broadcast \
  --verify
```

After deployment, update `ORACLE_ADDRESS` in your `.env` file.

### Set Trust Anchors

Set the IANA root trust anchors on the oracle:

```bash
# Using Foundry script
forge script scripts/SetTrustAnchors.s.sol \
  --rpc-url sepolia \
  --broadcast

# Or using Node.js script
ORACLE_ADDRESS=0x... PRIVATE_KEY=0x... node scripts/set_anchors.mjs
```

The trust anchors are the IANA root zone DNSKEY records that serve as the starting point for DNSSEC verification.

## Gas Benchmarks

This implementation achieves significant gas savings for Algorithm 13 zones:

| Operation | ENS (Pure Solidity) | This Oracle (EIP-7951) | Savings |
|-----------|---------------------|------------------------|---------|
| P-256 Verification | ~1.3M gas | ~13k gas | ~99% |
| Full RRSet Verify | ~3.4M gas | ~200k gas | ~94% |

The primary savings come from using the **EIP-7951 P-256 precompile at address `0x100`** instead of pure Solidity elliptic curve math.

### Algorithm Implementation

The `P256SHA256Algorithm.sol` contract uses the EIP-7951 precompile for efficient P-256 signature verification, resulting in ~94% gas savings compared to pure Solidity implementations.

## Architecture

### Core Contracts

1. **`DNSSECOracle.sol`** - Main oracle contract that verifies DNSSEC proofs
   - Supports Algorithm 8 (RSA/SHA-256) via Modexp precompile
   - Supports Algorithm 13 (ECDSA P-256) via EIP-7951 precompile
   - Validates full DS chain from IANA root zone
   - Similar to ENS's `DNSSECImpl` but with optimized P-256 verification

2. **Algorithm Contracts**
   - **`P256SHA256Algorithm.sol`** - Algorithm 13 verification using EIP-7951 precompile
   - **`RSASHA256Algorithm.sol`** - Algorithm 8 verification using Modexp precompile

## Testing

### Run Foundry Tests

```bash
forge test
```

## Verification

Verify the domain's DNSSEC configuration manually:

```bash
# Check TXT record with DNSSEC
dig eketc.co TXT +dnssec +multi

# Check DNSKEY
dig eketc.co DNSKEY +dnssec

# Check DS record
dig eketc.co DS +dnssec

# Check root zone keys
dig . DNSKEY +dnssec
```

All records should show `RRSIG` entries with algorithm 8 or 13 for each zone in the chain.

## Documentation

Additional documentation is available:

- **[gas-analysis/README.md](./gas-analysis/README.md)** - Gas analysis tools for benchmarking and optimization

The `gas-analysis/` directory contains tools for extracting and analyzing gas usage from Ethereum transactions:

- **Extraction Scripts**: Browser console scripts to extract gas data from Etherscan
- **Analysis Scripts**: Process extracted data to calculate gas breakdown
- **Purpose**: Benchmark DNSSEC verification costs and compare implementations

See [gas-analysis/README.md](./gas-analysis/README.md) for detailed usage instructions.

## Key Differences from Gasless DNSSEC Resolution

| Feature | Gasless DNSSEC Resolution | Onchain DNS Import |
|---------|--------------------------|-------------------|
| **Trust Model** | Pinned KSK | Full DS chain from root |
| **Flow Type** | CCIP-Read (offchain proof fetch) | Direct onchain import |
| **Transaction Type** | Read-only (view) | State-changing (writes) |
| **Use Case** | DNS-verified ENS resolution | DNS name registration/import |
| **Gas Cost** | ~124k (one resolution) | ~200k (one import) |
