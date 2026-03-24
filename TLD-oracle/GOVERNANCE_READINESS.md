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
_initialAllowlist:          string[1166] (all post-2012 gTLDs — baked into initCode)
```

## Governance Proposal

A single proposal deploys TLDMinter (with the full allowlist baked into the constructor) and authorizes it on Root. The initial 1,166 gTLDs are committed to the CREATE2 initCode hash and seeded atomically at deployment — no second proposal is needed.

### CREATE2 Deployment Details

| Parameter | Value |
|-----------|-------|
| Factory | `0x4e59b44847b379578588920cA78FbF26c0B4956C` |
| Salt | `0x0000000000000000000000000000000000000000000000000000000000000000` |
| TLDMinter address | `0x30fFc92e09C68e308a9eb439d08358fAa675B9a4` |
| initCodeHash | `0x278e0445bb15bca6bf4359cee31dbd7c97bce0ebb09d6df68b7acfb0d8fea2bb` |

The address is deterministic: `keccak256(0xff ++ factory ++ salt ++ initCodeHash)[12:]`. Because the full allowlist is ABI-encoded into the constructor arguments, the initCode hash commits to the exact set of 1,166 TLDs. Delegates verify this hash before voting — what they approve is exactly what deploys.

Salt `bytes32(0)` was chosen after scanning salts 0-99 with no "clean" addresses found (4+ leading zero bytes). See `dao-proposals/script/ComputeAddress.s.sol`.

### Gas Considerations

Constructor-based seeding moves the allowlist cost into the CREATE2 deployment transaction. The per-TLD storage cost (~25,670 gas) is now paid during deployment rather than in separate `batchAddToAllowlist` calls.

| Call | Gas Used | Notes |
|------|----------|-------|
| CREATE2 deploy (with 1,166 TLDs) | 4,083,048 | Includes constructor loop writing all 1,166 TLDs to storage |
| setController | 27,969 | Single SSTORE |
| **Total** | **4,111,017** | **13.7% of 30M block limit — 25.9M headroom** |

Measured on mainnet fork via `dao-proposals/script/MeasureGas.s.sol`. The full 1,166-TLD constructor seeding fits comfortably in a single block with no splitting required.

### Single Proposal: Deploy + Authorize (2 calls)

| Call | Target | Data | Gas |
|------|--------|------|-----|
| 1 | CREATE2 Factory | `abi.encodePacked(salt, initCode)` | 4,083,048 |
| 2 | Root | `setController(tldMinter, true)` | 27,969 |

**Why this is better than two proposals:** The constructor now accepts `string[] memory _initialAllowlist`, so the 1,166 gTLDs are seeded during deployment. The initCode hash commits to the full allowlist — delegates verify one hash, vote once, and the system is fully operational after a single proposal executes. This mirrors the EP5.1 pattern where TLD enabling was handled outside the governance call itself, and eliminates the two-proposal sequencing risk entirely.

### Optional: Set TLDMinter's reverse record

```
target: 0x231b0Ee14048e9dCcD1d247744d114a4EB5E8E63 (ReverseRegistrar)
value:  0
data:   setNameForAddr(address(tldMinter), address(tldMinter), address(resolver), "tldminter.ens.eth")
```

This sets a primary ENS name for the TLDMinter contract. Not required for functionality. Can be bundled into the proposal (if gas headroom allows) or submitted separately.

### Proposal Timeline

| Phase | Duration |
|-------|----------|
| Voting period | ~7 days (45,818 blocks) |
| Timelock delay | 2 days minimum |
| **Total** | **~9 days** |

Requirements: 100,000 ENS tokens to propose, 1% quorum to pass.

## Defense in Depth

The system has four independent safety layers. No single failure can result in an unauthorized TLD mint.

### Layer 1: Allowlist (TLDMinter)

Only DAO-approved TLD strings pass `submitClaim()`. The initial 1,166 post-2012 gTLDs are seeded via the constructor at deployment. The allowlist is checked first, before any expensive DNSSEC verification. Non-allowlisted TLDs revert with `TLDNotAllowed`.

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
- [x] Implement constructor-based allowlist seeding — `_initialAllowlist` parameter added, eliminates second governance proposal
- [x] Recompute deterministic TLDMinter address with new initCode — `0x30fFc92e09C68e308a9eb439d08358fAa675B9a4`
- [x] Measure deployment gas on mainnet fork — 4,111,017 total (13.7% of block limit), single proposal confirmed
- [x] Re-encode deployment calldata and update `proposalCalldata.json` — single proposal, 2 calls
- [ ] Draft governance proposal for ENS forum (RFC already posted)
- [ ] Submit proposal through ENS Governor
- [ ] Verify contract source on Etherscan post-deployment
- [ ] (Optional) Decide on ENS primary name for TLDMinter and bundle into proposal

## Test Coverage

23 tests across two files verify the contract against the RFC:

- `test/TLDMinterAllowlist.t.sol` — 7 tests: allowlist gating, DAO-only access control, batch operations, constructor seeding
- `test/TLDMinterLifecycle.t.sol` — 16 tests: full claim lifecycle, veto paths, timelock enforcement, rate limiting, pause mechanics, SC expiration, proof freshness

```bash
forge test -vvv
```

## Open Questions

1. ~~**Deployment gas budget**~~ — **Resolved.** Mainnet fork measurement shows 4,111,017 gas total (4,083,048 deploy + 27,969 setController). This is 13.7% of the 30M block gas limit with 25.9M headroom. The earlier ~29.9M estimate was based on cold-storage cost per TLD; the actual constructor loop is far cheaper because ABI-encoded string arrays are processed more efficiently.
2. **Allowlist maintenance** — After the initial 1,166 gTLDs are seeded, future additions require separate DAO proposals calling `addToAllowlist()`. Is batch governance tooling needed?
