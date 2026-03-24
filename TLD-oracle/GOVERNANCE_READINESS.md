# Governance Readiness Guide

How to take TLDMinter from testnet to mainnet via ENS DAO governance.

## Mainnet Contracts

| Contract | Address | Role |
|----------|---------|------|
| ENSRegistry | `0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e` | Read-only: `canClaim()` checks TLD existence |
| Root | `0xaB528d626EC275E3faD363fF1393A41F581c5897` | Write: `execute()` calls `root.setSubnodeOwner()` |
| DNSSECImpl | `0x0fc3152971714E5ed7723FAFa650F86A4BaF30C5` | Read: `submitClaim()` calls `oracle.verifyRRSet()` |
| ENS DAO Timelock | `0xFe89cc7aBB2C4183683ab71653C4cdc9B02D44b7` | Owner of Root, executor of proposals |
| ENS Governor | `0x323a76393544d5ecca80cd6ef2a560c6a395b7e3` | Governance voting contract |
| SecurityCouncil | `0xB8fA0cE3f91F41C5292D07475b445c35ddF63eE0` | `expiration()` read by TLDMinter veto logic |
| SC Multisig | `0xaA5cD05f6B62C3af58AE9c4F3F7A2aCC2Cdc2Cc7` | Veto authority during SC active period |

## Constructor Arguments (Mainnet)

```
_oracle:                    0x0fc3152971714E5ed7723FAFa650F86A4BaF30C5  (DNSSECImpl)
_root:                      0xaB528d626EC275E3faD363fF1393A41F581c5897  (Root)
_ens:                       0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e  (ENSRegistry)
_daoTimelock:               0xFe89cc7aBB2C4183683ab71653C4cdc9B02D44b7  (wallet.ensdao.eth)
_securityCouncilMultisig:   0xaA5cD05f6B62C3af58AE9c4F3F7A2aCC2Cdc2Cc7  (SC Multisig)
_securityCouncilContract:   0xB8fA0cE3f91F41C5292D07475b445c35ddF63eE0  (SecurityCouncil by Blockful)
_timelockDuration:          7 days
_rateLimitMax:              10
_rateLimitPeriod:           7 days
_proofMaxAge:               14 days
```

## Governance Proposal

### Why two proposals are required

Seeding the 1,166-entry gTLD allowlist requires 1,166 SSTORE operations at 20,000 gas each = 23.3M gas minimum. Combined with deployment overhead, this exceeds the 30M block gas limit in a single transaction. This is a hard EVM constraint — not a contract design choice. We explored constructor-based seeding, permissionless seeder patterns, and chunked approaches. All hit the same wall: the gas is in the storage writes, not the calling mechanism.

### Merkle root alternative (on the table for DAO consideration)

A Merkle root approach would store a single bytes32 commitment at deploy time and verify proofs at claim time — eliminating seeding gas entirely and reducing the proposal to 2 calls. This changes the claim UX (operators provide a Merkle proof when submitting a claim) and requires additional implementation and audit time. We are surfacing this as an explicit architectural option for delegates to weigh in on during the Temp Check, but defaulting to the two-proposal plan which is proven, auditable, and ready to ship now.

### CREATE2 Deployment Details

| Parameter | Value |
|-----------|-------|
| Factory | `0x4e59b44847b379578588920cA78FbF26c0B4956C` |
| Salt | `0x0000000000000000000000000000000000000000000000000000000000000000` |
| TLDMinter address | `0xf096afBc6ebD704Dbd215999045A3FE29C064b6b` |
| initCodeHash | `0x5f7592a28878e322f096d935111004a96b1c9d61ee234bb70e3bd74ce8544e88` |

The address is deterministic: `keccak256(0xff ++ factory ++ salt ++ initCodeHash)[12:]`. Delegates verify the initCodeHash before voting — what they approve is exactly what deploys.

Salt `bytes32(0)` was chosen after scanning salts 0-99 with no "clean" addresses found (4+ leading zero bytes). See `dao-proposals/script/ComputeAddress.s.sol`.

### Gas Measurements

Measured on mainnet fork via `dao-proposals/script/MeasureGas.s.sol`.

**Proposal A (~24.5M gas, 5 calls):**

| Call | Target | Data | Gas |
|------|--------|------|-----|
| 1 | CREATE2 Factory | deploy TLDMinter | 2,041,848 |
| 2 | Root | `setController(tldMinter, true)` | 27,834 |
| 3 | TLDMinter | `batchAddToAllowlist(TLDs 1-300)` | 7,473,599 |
| 4 | TLDMinter | `batchAddToAllowlist(TLDs 301-600)` | 7,484,096 |
| 5 | TLDMinter | `batchAddToAllowlist(TLDs 601-900)` | 7,494,584 |
| | | **Total** | **24,521,961** |

Contract is live and operational for 900 TLDs immediately after Proposal A executes. Headroom: 5.5M gas (18% buffer).

**Proposal B (~6.7M gas, 1 call):**

| Call | Target | Data | Gas |
|------|--------|------|-----|
| 1 | TLDMinter | `batchAddToAllowlist(TLDs 901-1166)` | 6,653,535 |

Submitted after Proposal A fully executes (post 2-day timelock).

### Optional: Set TLDMinter's reverse record

```
target: 0x231b0Ee14048e9dCcD1d247744d114a4EB5E8E63 (ReverseRegistrar)
value:  0
data:   setNameForAddr(address(tldMinter), address(tldMinter), address(resolver), "tldminter.ens.eth")
```

This sets a primary ENS name for the TLDMinter contract. Not required for functionality. Can be bundled into Proposal B or submitted separately.

### Proposal Timeline

| Phase | Duration |
|-------|----------|
| Proposal A voting | ~7 days (45,818 blocks) |
| Proposal A timelock | 2 days minimum |
| Proposal B voting | ~7 days |
| Proposal B timelock | 2 days minimum |
| **Total** | **~18 days** |

Requirements: 100,000 ENS tokens to propose, 1% quorum to pass.

## Defense in Depth

The system has four independent safety layers. No single failure can result in an unauthorized TLD mint.

### Layer 1: Allowlist (TLDMinter)

Only DAO-approved TLD strings pass `submitClaim()`. The initial 1,166 post-2012 gTLDs are seeded via `batchAddToAllowlist` across two governance proposals. The allowlist is checked first, before any expensive DNSSEC verification. Non-allowlisted TLDs revert with `TLDNotAllowed`.

### Layer 2: DNSSEC Proof Verification (DNSSECImpl)

The DNS registry operator must publish a `_ens.nic.{tld}` TXT record with `a=0x{owner}` and sign the entire chain with DNSSEC. The oracle verifies the cryptographic proof on-chain. Proofs older than 14 days are rejected.

### Layer 3: Timelock + Veto (TLDMinter)

Every claim sits in a 7-day timelock window. During this window:
- The DAO can veto (permanent authority)
- The Security Council multisig can veto (expiring authority, revocable after expiration)

A vetoed claim cannot be executed. Rate limiting (10 TLDs per 7-day period) prevents spam. Either authority can pause the contract entirely.

### Layer 4: Root `locked` Mapping (Root.sol)

Root.setSubnodeOwner enforces `require(!locked[label])`. `.eth` is permanently locked at the Root contract level. Even if TLDMinter's allowlist were compromised, locked TLDs cannot be reassigned through any controller.

## Pre-Proposal Checklist

- [x] Choose CREATE2 salt — salt `bytes32(0)`
- [x] SecurityCouncil (`0xB8fA0...`) and SC Multisig (`0xaA5cD0...`) confirmed via Etherscan — get formal sign-off from governance stewards
- [x] Run full test suite against mainnet fork (`forge test --fork-url`) — all assertions pass (see `dao-proposals/calldataCheck.t.sol`)
- [x] Compute deterministic TLDMinter address — `0xf096afBc6ebD704Dbd215999045A3FE29C064b6b`
- [x] Measure deployment gas on mainnet fork — Proposal A: 24.5M, Proposal B: 6.7M
- [x] Encode deployment calldata and update `proposalCalldata.json` — two proposals, 6 calls total
- [x] Pin compiler settings across both repos (`solc 0.8.27`, `via_ir`, `cancun`, `cbor_metadata = false`, `bytecode_hash = "none"`) — bytecodes match
- [ ] Draft governance proposal for ENS forum (RFC already posted)
- [ ] Submit Proposal A through ENS Governor
- [ ] Submit Proposal B after Proposal A executes
- [ ] Verify contract source on Etherscan post-deployment
- [ ] (Optional) Decide on ENS primary name for TLDMinter and bundle into Proposal B

## Test Coverage

22 tests across two files verify the contract against the RFC:

- `test/TLDMinterAllowlist.t.sol` — 6 tests: allowlist gating, DAO-only access control, batch operations
- `test/TLDMinterLifecycle.t.sol` — 16 tests: full claim lifecycle, veto paths, timelock enforcement, rate limiting, pause mechanics, SC expiration, proof freshness

```bash
forge test -vvv
```

## Open Questions

1. ~~**Deployment gas budget**~~ — **Resolved.** Constructor seeding hits the EVM's 20k SSTORE gas floor: 1,166 TLDs = 23.3M+ gas, exceeding the 30M block limit. Two-proposal structure confirmed: Proposal A (24.5M gas) deploys + seeds 900 TLDs, Proposal B (6.7M gas) seeds remaining 266 TLDs.
2. **Allowlist maintenance** — After the initial 1,166 gTLDs are seeded, future additions require separate DAO proposals calling `addToAllowlist()`. Is batch governance tooling needed?
3. **Merkle root alternative** — Would eliminate seeding gas entirely (single 2-call proposal) but changes claim UX and requires additional implementation + audit. Surfaced as an option for delegates during Temp Check.
