# TLD Oracle

DNS-verified TLD minting for ENS. Allows DNS registries to claim their TLDs in ENS by providing DNSSEC proofs.

> **Note:** Currently deployed on **Sepolia testnet only** with a 15-minute timelock for testing purposes.

## How It Works

1. **DNS Registry publishes intent** — Sets `_ens.nic.{tld}` TXT record with `a=0x{address}`
2. **Anyone submits proof** — Calls `submitClaim()` with DNSSEC proof chain
3. **Timelock period** — Window for DAO/Security Council to veto (15 min on testnet, 7 days on mainnet)
4. **Execution** — After timelock, anyone calls `execute()` to mint the TLD

```
DNS proposes → Contract verifies → DAO can veto → TLD minted
```

## Contracts

| Contract | Description |
|----------|-------------|
| `TLDMinter.sol` | Policy layer: timelock, veto, rate limiting |
| `P256SHA256Algorithm.sol` | EIP-7951 P-256 signature verification (~3k gas) |

### Deployed Contracts (Sepolia Testnet)

```
TLDMinter:        0x2451427Bab27874619C0efEa3c28ccEbd111D7fe
P256Algorithm:    0x704e859ac988d75ca00dDe96F2c0ed387d9fabB3
DNSSEC Oracle:    0x31D1acba033d8A4Ab3f6334355289034d32cFD89
MockRoot:         0x32cF38Af3c54c5D0C5305F48b6E2dE9f5191226d
MockENS:          0xebd10025876f84C7c82Bbd3Bd46714be2512be0f
```

*Not yet deployed on mainnet.*

## Usage

### Setup

```bash
cp .env.example .env
# Edit .env with your RPC URL and private key
npm install
forge install
```

### Submit a TLD Claim

```bash
node scripts/submitClaim.js <tld>
# Example: node scripts/submitClaim.js gift
```

### Execute After Timelock

```bash
node scripts/executeClaim.js <tld>
```

### Veto a Claim (DAO/SC only)

```bash
node scripts/vetoClaim.js <tld> "reason"
```

### Utility Scripts

```bash
# Check which TLDs have valid _ens.nic.{tld} records
node scripts/findValidTLDs.js

# Check proof freshness (must be ≤14 days old)
node scripts/checkProofAge.js

# Estimate gas for a claim
node scripts/estimateGas.js <tld>
```

## Valid TLDs

TLDs with correctly configured `_ens.nic.{tld}` TXT records (Algorithm 13):

| TLD | Owner |
|-----|-------|
| .link | `0x709d552b...` |
| .click | `0x709d552b...` |
| .help | `0x709d552b...` |
| .gift | `0x709d552b...` |
| .property | `0x709d552b...` |
| .sexy | `0x709d552b...` |
| .hiphop | `0x42eC164C...` |

## Development

### Build

```bash
forge build
```

### Test

```bash
forge test
```

### Deploy (Sepolia)

```bash
forge script script/DeploySepolia.s.sol --rpc-url $SEPOLIA_RPC_URL --broadcast
```

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────┐
│ DNS Registry│────▶│  TLDMinter   │────▶│ ENS Root│
│ _ens.nic.co │     │  (timelock)  │     │         │
└─────────────┘     └──────────────┘     └─────────┘
                           │
                    ┌──────┴──────┐
                    ▼             ▼
              ┌──────────┐  ┌──────────┐
              │ DNSSECImpl│  │ DAO/SC   │
              │ (verify)  │  │ (veto)   │
              └──────────┘  └──────────┘
```

## Policy Parameters (Sepolia Testnet)

| Parameter | Testnet Value | Mainnet Value | Description |
|-----------|---------------|---------------|-------------|
| Timelock | **15 minutes** | 7 days | Delay before execution |
| Proof Max Age | 14 days | 14 days | Maximum DNSSEC proof age |
| Rate Limit | 10 TLDs / 7 days | 10 TLDs / 7 days | Prevents spam |

## License

MIT
