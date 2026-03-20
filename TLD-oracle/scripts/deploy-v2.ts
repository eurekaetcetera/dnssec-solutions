/**
 * TLDMinter v2 Deploy Script
 *
 * Deploys TLDMinter v2 to Sepolia and seeds the allowlist with
 * post-2012 ICANN New gTLD Program strings.
 *
 * Usage:
 *   npx ts-node scripts/deploy-v2.ts
 *
 * Environment variables (from .env):
 *   SEPOLIA_RPC_URL, PRIVATE_KEY, DNSSEC_ORACLE, MOCK_ROOT, MOCK_ENS,
 *   MOCK_DAO, MOCK_SC_MULTISIG, MOCK_SC_CONTRACT
 */

import { ethers } from "ethers";
import * as dotenv from "dotenv";
import * as fs from "fs";
import * as path from "path";

dotenv.config({ path: path.resolve(__dirname, "../.env") });

// Pre-2012 legacy gTLDs that are NOT from the 2012 New gTLD Program
const LEGACY_GTLDS = new Set([
  "COM", "NET", "ORG", "INT", "EDU", "GOV", "MIL", "ARPA",
  "AERO", "BIZ", "COOP", "INFO", "JOBS", "MOBI", "MUSEUM",
  "NAME", "POST", "PRO", "TEL", "TRAVEL", "XXX", "ASIA",
]);

// Batch size for batchAddToAllowlist calls (to avoid gas limit)
const BATCH_SIZE = 200;

async function fetchAndFilterTLDs(): Promise<string[]> {
  const response = await fetch(
    "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
  );
  const text = await response.text();

  const tlds = text
    .split("\n")
    .filter((line) => !line.startsWith("#") && line.trim().length > 0)
    .filter((tld) => tld.length > 2) // Remove 2-letter ccTLDs
    .filter((tld) => !LEGACY_GTLDS.has(tld)) // Remove pre-2012 legacy gTLDs
    .map((tld) => tld.toLowerCase()); // Lowercase

  return tlds;
}

async function main() {
  // --- Setup ---
  const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL);
  const wallet = new ethers.Wallet(process.env.PRIVATE_KEY!, provider);
  console.log(`Deployer: ${wallet.address}`);

  // --- Fetch and filter TLDs ---
  console.log("\nFetching IANA TLD list...");
  const tlds = await fetchAndFilterTLDs();
  console.log(`Filtered to ${tlds.length} post-2012 New gTLD Program strings`);

  // Verify known valid TLDs are present
  const knownValid = ["link", "click", "help", "gift", "property", "sexy", "hiphop"];
  for (const tld of knownValid) {
    if (!tlds.includes(tld)) {
      throw new Error(`Expected TLD '${tld}' not found in filtered list!`);
    }
  }
  console.log(`Verified ${knownValid.length} known valid TLDs are present`);

  // Verify pre-2012 are excluded
  const excluded = ["com", "net", "org", "info", "biz"];
  for (const tld of excluded) {
    if (tlds.includes(tld)) {
      throw new Error(`Pre-2012 TLD '${tld}' should not be in filtered list!`);
    }
  }
  console.log("Verified pre-2012 gTLDs are excluded");

  // --- Deploy TLDMinter v2 ---
  console.log("\nDeploying TLDMinter v2...");
  const artifactPath = path.resolve(
    __dirname,
    "../out/TLDMinter.sol/TLDMinter.json"
  );
  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));

  const factory = new ethers.ContractFactory(
    artifact.abi,
    artifact.bytecode.object,
    wallet
  );

  const minter = await factory.deploy(
    process.env.DNSSEC_ORACLE,
    process.env.MOCK_ROOT,
    process.env.MOCK_ENS,
    process.env.MOCK_DAO,
    process.env.MOCK_SC_MULTISIG,
    process.env.MOCK_SC_CONTRACT,
    15 * 60,       // 15 min timelock (testnet)
    10,            // rate limit: 10 per period
    7 * 24 * 3600, // rate limit period: 7 days
    14 * 24 * 3600 // proof max age: 14 days
  );

  await minter.waitForDeployment();
  const minterAddress = await minter.getAddress();
  console.log(`TLDMinter v2 deployed at: ${minterAddress}`);

  // --- Seed allowlist in batches ---
  console.log(`\nSeeding allowlist with ${tlds.length} TLDs in batches of ${BATCH_SIZE}...`);

  for (let i = 0; i < tlds.length; i += BATCH_SIZE) {
    const batch = tlds.slice(i, i + BATCH_SIZE);
    const batchNum = Math.floor(i / BATCH_SIZE) + 1;
    const totalBatches = Math.ceil(tlds.length / BATCH_SIZE);

    console.log(`  Batch ${batchNum}/${totalBatches} (${batch.length} TLDs)...`);
    const tx = await minter.batchAddToAllowlist(batch);
    await tx.wait();
    console.log(`  Batch ${batchNum} confirmed: ${tx.hash}`);
  }

  // --- Verify ---
  console.log("\nVerifying allowlist...");
  for (const tld of knownValid) {
    const hash = ethers.keccak256(ethers.toUtf8Bytes(tld));
    const allowed = await minter.allowedTLDs(hash);
    console.log(`  ${tld}: ${allowed ? "ALLOWED" : "REJECTED"}`);
  }

  const comHash = ethers.keccak256(ethers.toUtf8Bytes("com"));
  const comAllowed = await minter.allowedTLDs(comHash);
  console.log(`  com: ${comAllowed ? "ALLOWED (ERROR!)" : "REJECTED (correct)"}`);

  const version = await minter.version();
  console.log(`\nVersion: ${version}`);
  console.log(`\nDone! Update .env with TLD_MINTER_V2=${minterAddress}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
