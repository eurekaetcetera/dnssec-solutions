# DNSSEC Solutions: EIP-7951 P-256 Precompile Demonstrations

This repository contains four complementary projects that demonstrate different approaches to DNSSEC verification on Ethereum, all leveraging the **EIP-7951 P-256 precompile** for efficient Algorithm 13 (ECDSAP256SHA256) signature verification.

## Overview

The [EIP-7951 P-256 precompile](https://eips.ethereum.org/EIP-7951) (activated December 3, 2025 in the Fusaka upgrade) enables native secp256r1 signature verification on Ethereum at approximately **~3,450 gas** per verification. This provides massive gas savings (up to **~94%**) compared to implementing P-256 verification in Solidity.

These projects demonstrate four distinct use cases:

1. **Gasless DNSSEC Resolution** - Off-chain proof fetching with on-chain verification via CCIP-Read
2. **Onchain DNS Import** - Full on-chain DNSSEC oracle with ENS-style verification
3. **DNS Claiming** - ENS registrar contracts for claiming DNS names (2LDs) using DNSSEC proofs
4. **TLD Oracle** - DNS-verified TLD minting for ENS with DAO governance safeguards

## How The Projects Build On Each Other

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        EIP-7951 P-256 Precompile                        │
│                      (Native signature verification)                     │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
        ┌───────────────────┐           ┌───────────────────────┐
        │ Gasless DNSSEC    │           │ Onchain DNS Import    │
        │ Resolution        │           │ (DNSSECOracle)        │
        │ (CCIP-Read)       │           │                       │
        └───────────────────┘           └───────────────────────┘
                                                    │
                                    ┌───────────────┴───────────────┐
                                    ▼                               ▼
                        ┌───────────────────┐           ┌───────────────────┐
                        │ DNS Claiming      │           │ TLD Oracle        │
                        │ (2LD names)       │           │ (TLD minting)     │
                        │ example.co → ENS  │           │ .co itself → ENS  │
                        └───────────────────┘           └───────────────────┘
```

## Common Architecture: EIP-7951 P-256 Precompile

All four projects use the same core technology:

- **Precompile Address**: `0x0000000000000000000000000000000000000100`
- **Gas Cost**: ~3,450 gas per verification
- **Algorithm Support**: DNSSEC Algorithm 13 (ECDSAP256SHA256)
- **Networks**: Ethereum Mainnet, Sepolia, Holesky, Hoodi

The precompile accepts 160 bytes:
- 32 bytes: SHA256 message hash
- 32 bytes: Signature R component
- 32 bytes: Signature S component
- 32 bytes: Public key X coordinate
- 32 bytes: Public key Y coordinate

## Projects

### 1. Gasless DNSSEC Resolution

**Directory**: [`Gasless DNSSEC Resolution/`](./Gasless%20DNSSEC%20Resolution/)

A **CCIP-Read (EIP-3668)** implementation that enables gasless DNSSEC resolution by fetching proofs off-chain and verifying them on-chain.

**Key Features:**
- **Trust Model**: Option A (Pinned KSK trust anchor)
- **Gas Model**: Users pay no gas - verification happens via CCIP-Read gateway
- **Gateway Server**: Node.js server that fetches DNSSEC proofs and serves them to the resolver contract
- **Use Case**: Reading DNS records (e.g., `_ens.example.com` TXT records) without transaction costs

**Architecture:**
```
User Query → Resolver Contract → CCIP-Read Callback → Gateway Server → DNS Query → DNSSEC Proof → On-chain Verification (P-256 Precompile)
```

**When to Use:**
- Reading DNS data without paying gas
- Lightweight DNS record lookups
- Applications that don't need permanent on-chain storage

### 2. Onchain DNS Import

**Directory**: [`Onchain DNS Import/`](./Onchain%20DNS%20Import/)

An **ENS-style DNSSEC oracle** that enables full on-chain DNSSEC verification with complete DS (Delegation Signer) chain validation from the IANA root zone.

**Key Features:**
- **Trust Model**: Option B (Full IANA root DS chain)
- **Gas Model**: Users submit proofs and pay gas for on-chain verification
- **Oracle Contract**: Stores verified DNS records on-chain
- **Full Chain Validation**: Verifies complete trust chain from root zone to target domain
- **Gas Savings**: ~94% reduction for Algorithm 13 domains vs. Solidity implementation
- **Algorithm Support**: Both Algorithm 8 (RSA/SHA-256) and Algorithm 13 (ECDSAP256SHA256)

**Architecture:**
```
User Submission → DNSSEC Proof → Oracle Contract → Verify Full DS Chain → Store Verified Record On-chain
                                                      ↓
                                            P-256 Precompile (Algorithm 13)
                                            Traditional Verification (Algorithm 8)
```

**When to Use:**
- Full on-chain DNS record storage
- ENS-compatible DNSSEC verification
- Applications requiring permanent on-chain proof
- Complete trust chain validation from root

### 3. DNS Claiming

**Directory**: [`dns-claiming/`](./dns-claiming/)

Contracts for **claiming DNS names on ENS** using DNSSEC proofs. Separated from Onchain DNS Import because it requires ENS registry permissions that may not be available for all TLDs.

**Key Features:**
- **ENS Integration**: Claims DNS names as ENS names using DNSSEC proofs
- **Dependency**: Uses Onchain DNS Import's DNSSECOracle for proof verification
- **TXT Record Parsing**: Extracts owner address from `_ens.<domain>` TXT records
- **Scope**: Claims second-level domains (2LDs) like `example.co`

**Architecture:**
```
DNS Name → DNSSEC Proof → DNSRegistrar → DNSSECOracle (Onchain DNS Import) → Verify Proof → Claim ENS Name
```

**When to Use:**
- Claiming DNS names as ENS names
- Demonstrating ENS registrar functionality
- Testing DNS-to-ENS name imports

**Limitations:**
- ⚠️ Only works for TLDs where you have ENS registry permissions
- ⚠️ Claims 2LDs (e.g., `example.co`), not TLDs themselves

### 4. TLD Oracle ⭐ NEW

**Directory**: [`TLD-oracle/`](./TLD-oracle/)

**DNS-verified TLD minting for ENS.** Allows DNS registries to claim their TLDs in ENS by providing DNSSEC proofs, with DAO governance safeguards.

> **Status:** Deployed on Sepolia testnet (15-minute timelock for testing). Not yet on mainnet.

**Key Features:**
- **TLD Minting**: Claims top-level domains (`.co`, `.link`, etc.) not just 2LDs
- **Governance Safeguards**: Timelock + DAO/Security Council veto capability
- **Rate Limiting**: Prevents spam (10 TLDs per 7 days)
- **Proof Freshness**: Requires DNSSEC proofs ≤14 days old
- **Dependency**: Uses Onchain DNS Import's DNSSECOracle for proof verification

**How It Works:**
```
1. DNS Registry publishes: _ens.nic.{tld} TXT "a=0x{address}"
2. Anyone submits DNSSEC proof → TLDMinter.submitClaim()
3. 7-day timelock (15 min on testnet) for DAO review
4. Anyone executes → TLDMinter.execute() → TLD minted in ENS
```

**Architecture:**
```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│ DNS Registry│────▶│  TLDMinter   │────▶│  ENS Root   │
│ _ens.nic.co │     │  (timelock)  │     │             │
└─────────────┘     └──────────────┘     └─────────────┘
                           │
                    ┌──────┴──────┐
                    ▼             ▼
              ┌──────────┐  ┌──────────┐
              │DNSSECOracle│ │ DAO/SC   │
              │ (verify)  │  │ (veto)   │
              └──────────┘  └──────────┘
```

**Relationship to Other Projects:**
- Uses **P256SHA256Algorithm** from Gasless DNSSEC Resolution (EIP-7951)
- Uses **DNSSECOracle** from Onchain DNS Import for proof verification
- Extends **DNS Claiming** concept from 2LDs to TLDs
- Adds **governance layer** not present in other projects

**When to Use:**
- DNS registries wanting to integrate with ENS
- Scaling ENS TLD onboarding without manual DAO votes
- Testing governance-controlled namespace minting

## Comparison Table

| Feature | Gasless DNSSEC | Onchain DNS Import | DNS Claiming | TLD Oracle |
|---------|----------------|-------------------|--------------|------------|
| **Trust Model** | Option A (Pinned KSK) | Option B (IANA Root) | Option B (via Oracle) | Option B (via Oracle) |
| **Gas Payment** | None (gateway pays) | User pays | User pays | User pays |
| **On-chain Storage** | No | Yes | Yes (ENS registry) | Yes (ENS root) |
| **Scope** | Read DNS records | Store DNS records | Claim 2LDs | Mint TLDs |
| **Governance** | None | None | None | Timelock + Veto |
| **Use Case** | DNS lookups | DNS oracle | `example.co` → ENS | `.co` itself → ENS |

## Getting Started

Each project has its own detailed README with setup instructions:

1. **[Gasless DNSSEC Resolution README](./Gasless%20DNSSEC%20Resolution/README.md)**
   - Setup instructions for the gateway server
   - CCIP-Read resolver deployment
   - Usage examples

2. **[Onchain DNS Import README](./Onchain%20DNS%20Import/README.md)**
   - Oracle deployment guide
   - Trust anchor configuration
   - DNSSEC proof submission

3. **[DNS Claiming README](./dns-claiming/README.md)**
   - DNSRegistrar deployment
   - Name claiming workflow
   - Integration with Onchain DNS Import

4. **[TLD Oracle README](./TLD-oracle/README.md)**
   - TLDMinter deployment (Sepolia)
   - Submit/execute/veto workflows
   - Valid TLDs with DNSSEC records

## Prerequisites

All projects require:
- **Node.js** (v18+)
- **Foundry** (for Solidity compilation and deployment)
- Access to Ethereum network (Mainnet, Sepolia, etc.)
- Understanding of DNSSEC and DNS wire format

Install Foundry:
```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

## EIP-7951 P-256 Precompile Reference

All projects use the same precompile interface. See detailed documentation:
- **[Precompile Instructions](./Gasless%20DNSSEC%20Resolution/contracts/algorithms/P256_PRECOMPILE_INSTRUCTIONS.md)**
- **EIP-7951**: https://eips.ethereum.org/EIP-7951

**Precompile Details:**
- **Address**: `0x0000000000000000000000000000000000000100`
- **Gas Cost**: ~3,450 gas
- **Input**: 160 bytes (hash + r + s + x + y)
- **Output**: 32 bytes (0x01 = valid, 0x00 = invalid)

## Gas Benchmarks

The P-256 precompile provides significant gas savings:

| Operation | Solidity Implementation | EIP-7951 Precompile | Savings |
|-----------|------------------------|---------------------|---------|
| P-256 Signature Verification | ~50,000+ gas | ~3,450 gas | **~94%** |

These benchmarks are demonstrated in:
- **[Onchain DNS Import Gas Benchmarks](./Onchain%20DNS%20Import/README.md#gas-benchmarks)**

## Project Structure

```
dnssec-solutions/
├── Gasless DNSSEC Resolution/    # CCIP-Read resolver (Option A trust model)
│   ├── contracts/                # Resolver contracts
│   ├── scripts/                  # Gateway server & proof fetching
│   └── README.md
│
├── Onchain DNS Import/           # ENS-style oracle (Option B trust model)
│   ├── contracts/                # Oracle & algorithm contracts
│   ├── scripts/                  # Deployment & proof fetching
│   └── README.md
│
├── dns-claiming/                 # ENS registrar for 2LDs
│   ├── contracts/                # DNSRegistrar & claim checker
│   ├── scripts/                  # Name claiming scripts
│   └── README.md
│
└── TLD-oracle/                   # TLD minting with governance ⭐ NEW
    ├── contracts/                # TLDMinter, P256SHA256Algorithm
    ├── scripts/                  # Submit, execute, veto scripts
    ├── test/                     # Foundry tests
    └── README.md
```

## Trust Models Explained

### Option A (Gasless DNSSEC Resolution)
- **Trust Anchor**: Pinned KSK (Key Signing Key) for the domain
- **Validation**: Verifies domain DNSKEY → TXT record chain only
- **Limitation**: Does not verify parent zone (e.g., `.co` → root)
- **Use Case**: Faster verification, lower trust requirements

### Option B (Onchain DNS Import, DNS Claiming & TLD Oracle)
- **Trust Anchor**: IANA root zone DNSKEY records
- **Validation**: Full DS (Delegation Signer) chain from root → TLD → domain
- **Completeness**: Verifies entire trust chain to root
- **Use Case**: ENS-compatible, maximum security

## Contributing

Each project is self-contained with its own dependencies and configuration. When contributing:

1. Work within the relevant project directory
2. Follow the existing code style and patterns
3. Update the project-specific README if adding features
4. Ensure compatibility with EIP-7951 precompile usage

## License

Each project may have its own license. Check individual project directories for license information.

## Acknowledgments

- **EIP-7951**: The P-256 precompile that makes efficient DNSSEC verification possible
- **ENS (Ethereum Name Service)**: Inspiration for DNSSEC oracle design patterns
- **ICANN**: Maintains the IANA root zone trust anchors

## Related Resources

- **EIP-7951 Specification**: https://eips.ethereum.org/EIP-7951
- **EIP-3668 (CCIP-Read)**: https://eips.ethereum.org/EIP-3668
- **DNSSEC RFC 4033-4035**: DNS Security Extensions specifications
- **ENS Documentation**: https://docs.ens.domains/
