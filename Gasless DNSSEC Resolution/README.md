# DNSSEC P-256 Proof-of-Concept

This project implements DNSSEC Algorithm 13 (ECDSAP256SHA256) proof fetching and verification for the domain `eketc.co`.

## Trust Model: Option A

We use **Option A** trust model: the `eketc.co` KSK (Key Signing Key, flags=257) is the **pinned trust anchor**. We do not verify the parent DS chain to `.co` in this phase.

### DNSSEC Key Structure

- **KSK (Key Signing Key)**: flags=257, signs the DNSKEY RRset
  - Key tag: **2371** (computed via RFC 4034 Appendix B)
  - Algorithm: 13 (ECDSAP256SHA256)
  - Public key: 64 bytes (P-256: 32-byte X + 32-byte Y coordinates)

- **ZSK (Zone Signing Key)**: flags=256, signs zone data (TXT, A, etc.)
  - Signs the `_ens.eketc.co` TXT record
  - Also algorithm 13

## Setup

Install dependencies:

```bash
npm install
```

### Quick Start: Local Gateway

To test the PoC locally, you'll need to run a gateway server. See the [Gateway Server](#gateway-server-ccip-read) section for detailed setup instructions.

For a quick start:
```bash
# Start the gateway server
node server.mjs
```

This starts the CCIP-Read gateway on `http://localhost:8787`. The gateway fetches DNSSEC proofs from DNS and serves them to the resolver contract via CCIP-Read.

## Fetching DNSSEC Proofs

The `fetch_dnssec_proof.mjs` script queries DNS directly (using `dns-packet` library) to fetch complete DNSSEC proof material including:

- `_ens.eketc.co` TXT record with RRSIG (Algorithm 13, signed by ZSK)
- `eketc.co` DNSKEY records (KSK + ZSK) with RRSIG (signed by KSK)
- `eketc.co` DS record with RRSIG (for reference, not verified yet)
- `.co` DNSKEY records with RRSIG (for reference, not verified yet)

### Usage

Basic usage (defaults to Cloudflare DNS 1.1.1.1):

```bash
node scripts/fetch_dnssec_proof.mjs
```

With custom DNS server:

```bash
node scripts/fetch_dnssec_proof.mjs --server 8.8.8.8 --out proofs/custom_output.json
```

### Output Format

The script generates a JSON file containing:

- **Meta information**: timestamp, DNS server, query name/type
- **Trust Anchor**: The pinned KSK with computed key tag and public key
- **RRsets**: Structured DNS records (TXT, DNSKEY, DS, RRSIG) with parsed RDATA
- **Messages**: Raw DNS response messages in base64 for ground truth preservation

Example output structure:

```json
{
  "meta": {
    "generatedAt": "2025-12-18T01:23:40.487Z",
    "dnsServer": "1.1.1.1:53",
    "qname": "_ens.eketc.co",
    "qtype": 16
  },
  "trustAnchor": {
    "zone": "eketc.co.",
    "dnskey": {
      "flags": 257,
      "protocol": 3,
      "algorithm": 13,
      "publicKey": "base64...",
      "publicKeyHex": "0xhex..."
    },
    "keyTag": 2371,
    "source": "eketc.co DNSKEY RRset (Cloudflare)",
    "computedBy": "fetch_dnssec_proof.mjs v1.1"
  },
  "rrsets": [
    {
      "name": "_ens.eketc.co",
      "type": "TXT",
      "class": "IN",
      "ttl": 60,
      "rdata": {
        "txt": ["ens_name=estmcmxci.eth"]
      }
    },
    {
      "name": "_ens.eketc.co",
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
      "query": { "name": "_ens.eketc.co", "type": "TXT" },
      "responseRaw": "base64EncodedDnsResponse..."
    }
  ]
}
```

### Key Tag Computation

The script computes the DNSSEC key tag per **RFC 4034 Appendix B**:
- For the eketc.co KSK, the computed key tag is **2371**
- This matches the DS record key tag, confirming correct computation
- The key tag is NOT hardcoded; it's computed from the DNSKEY RDATA

## Validation Performed

The script performs the following validations:

1. **KSK Extraction**: Finds DNSKEY with flags=257, protocol=3, algorithm=13
2. **P-256 Public Key**: Validates key length is exactly 64 bytes
3. **Key Tag Computation**: Computes key tag per RFC 4034 and verifies against DS record
4. **TXT Record**: Ensures `_ens.eketc.co` TXT contains `ens_name=estmcmxci.eth`
5. **RRSIG(TXT)**: Validates algorithm=13, signer=eketc.co, typeCovered=TXT
6. **RRSIG(DNSKEY)**: Confirms DNSKEY RRset is signed by the KSK (key tag 2371)
7. **ZSK Presence**: Verifies the ZSK that signed the TXT record is in the DNSKEY RRset

All validations must pass or the script exits with an error.

## PoC Attestation Record

The domain includes a DNSSEC-signed TXT record for ENS name attestation:

- **Record**: `_ens.eketc.co`
- **Type**: TXT
- **Value**: `ens_name=estmcmxci.eth`
- **DNSSEC**: Signed by ZSK (key tag 34505) with Algorithm 13 (ECDSAP256SHA256)
- **Trust Chain**: ZSK is in DNSKEY RRset → DNSKEY RRset signed by KSK → KSK is trust anchor

## Gateway Server (CCIP-Read)

This PoC uses **CCIP-Read (EIP-3668)** to enable gasless DNSSEC resolution. The resolver contract triggers an `OffchainLookup` error, which signals that offchain data is required. The gateway server fetches DNSSEC proofs from DNS and returns them in a format the resolver can verify onchain.

### How It Works

1. **Resolver Call**: User calls `resolver.text(node, "name")`
2. **OffchainLookup**: Resolver reverts with `OffchainLookup` error containing gateway URL
3. **Gateway Request**: Client (wallet/dApp) calls gateway with DNS query parameters
4. **Proof Fetching**: Gateway runs `fetch_dnssec_proof.mjs` to get DNSSEC proof from DNS
5. **Response**: Gateway returns ABI-encoded proof bundle
6. **Callback**: Client calls `resolver.ccipCallback(proof, extraData)`
7. **Verification**: Resolver verifies proof using onchain verifier (EIP-7951 precompile)

### Setting Up Your Own Gateway

#### Option 1: Local Development (Root server.mjs)

For local testing, use the standalone server:

```bash
# Install dependencies (if not already done)
npm install

# Start the gateway server
node server.mjs
```

The server will start on `http://localhost:8787` (or the port specified in `PORT` environment variable).

**Test the gateway:**
```bash
# Health check
curl http://localhost:8787/health

# Fetch proof for a DNS record
curl -X POST http://localhost:8787/resolve \
  -H "Content-Type: application/json" \
  -d '{"name": "eketc.co", "type": "TXT"}'
```

**Configure the resolver** to use your local gateway:
```bash
# Update GATEWAY_URL in .env
GATEWAY_URL=http://localhost:8787/ccip-read

# Update resolver (see ConfigureResolver.s.sol)
forge script scripts/ConfigureResolver.s.sol:UpdateGatewayUrl \
  --rpc-url sepolia \
  --broadcast
```

#### Option 2: Production Deployment (Vercel)

The `api/server.mjs` file is configured for Vercel deployment:

1. **Deploy to Vercel:**
   ```bash
   # Install Vercel CLI (if not already)
   npm i -g vercel

   # Deploy
   vercel
   ```

2. **Update resolver** with your Vercel gateway URL:
   ```bash
   GATEWAY_URL=https://your-project.vercel.app/ccip-read
   ```

3. **Configure resolver** (as shown above)

#### Gateway Configuration

The gateway server:
- Listens on `/health` for health checks
- Listens on `/resolve` for DNS queries (POST with `{"name": "...", "type": "..."}`)
- Listens on `/ccip-read` for CCIP-Read requests (POST with `{"data": "0x..."}`)

**Environment Variables:**
- `PORT` - Server port (default: 8787)
- No API keys or secrets needed for basic operation

**Gateway Requirements:**
- Must have access to run `scripts/fetch_dnssec_proof.mjs`
- Must be publicly accessible (for production)
- No special infrastructure needed (runs on Node.js)

## Next Steps

1. **Step 1**: Fetch DNSSEC proof material (completed)
2. **Step 2**: Implement RFC 4034 canonicalization (completed offchain)
3. **Step 3**: Port verification to Solidity with EIP-7951 precompile
4. **Step 4**: Define ProofBundle ABI for onchain encoding
5. **Step 5**: End-to-end onchain verification test

## Verification

Verify the domain's DNSSEC configuration manually:

```bash
# Check TXT record with DNSSEC
dig _ens.eketc.co TXT +dnssec +multi

# Check DNSKEY
dig eketc.co DNSKEY +dnssec

# Check DS record
dig eketc.co DS +dnssec
```

All records should show `RRSIG` entries with algorithm 13 for `eketc.co` zone records.

## Documentation

Additional documentation is available in the [`docs/`](./docs/) directory:

- **[Gas Benchmarks](./docs/GAS_BENCHMARKS.md)** - Detailed gas cost analysis comparing our implementation with ENS's approach
