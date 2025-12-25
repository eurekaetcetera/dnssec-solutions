#!/usr/bin/env node
/**
 * @title set_anchors.mjs
 * @description Sets the IANA root trust anchors on DNSSECOracle
 * 
 * The trust anchor is a DS record that hashes the root zone KSK (keyTag 20326).
 * Source: https://data.iana.org/root-anchors/root-anchors.xml
 * 
 * Usage:
 *   ORACLE_ADDRESS=0x... PRIVATE_KEY=0x... node scripts/set_anchors.mjs
 */

import { createPublicClient, createWalletClient, http, parseAbi, toHex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { sepolia } from 'viem/chains';
import * as dnsPacket from 'dns-packet';

// Configuration
const ORACLE_ADDRESS = process.env.ORACLE_ADDRESS;
const PRIVATE_KEY = process.env.PRIVATE_KEY;
const RPC_URL = process.env.SEPOLIA_RPC_URL || 'https://ethereum-sepolia-rpc.publicnode.com';

// IANA Root Trust Anchor - DS record for KSK 20326
// Source: https://data.iana.org/root-anchors/root-anchors.xml
// This DS record contains the SHA-256 hash of the root zone KSK
const ROOT_DS_20326 = {
  name: '.',
  type: 'DS',
  class: 'IN',
  ttl: 86400,
  data: {
    keyTag: 20326,
    algorithm: 8,  // RSASHA256
    digestType: 2, // SHA-256
    // SHA-256 digest of the root KSK (from IANA)
    digest: Buffer.from(
      'E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D',
      'hex'
    )
  }
};

// DNSSECOracle ABI
const ORACLE_ABI = parseAbi([
  'function setAnchors(bytes memory _anchors) public',
  'function anchors() public view returns (bytes memory)',
  'function owner() public view returns (address)'
]);

async function main() {
  console.log('=== Setting IANA Root Trust Anchors (DS Record) ===\n');

  if (!ORACLE_ADDRESS) {
    console.error('Error: ORACLE_ADDRESS not set');
    process.exit(1);
  }

  if (!PRIVATE_KEY) {
    console.error('Error: PRIVATE_KEY not set');
    process.exit(1);
  }

  // Create clients
  const account = privateKeyToAccount(PRIVATE_KEY);
  
  const publicClient = createPublicClient({
    chain: sepolia,
    transport: http(RPC_URL),
  });

  const walletClient = createWalletClient({
    account,
    chain: sepolia,
    transport: http(RPC_URL),
  });

  console.log('Configuration:');
  console.log('  Oracle:', ORACLE_ADDRESS);
  console.log('  Sender:', account.address);
  console.log('');

  // Encode the root DS record
  console.log('Step 1: Encoding root DS record...');
  console.log('  Key Tag: 20326');
  console.log('  Algorithm: 8 (RSASHA256)');
  console.log('  Digest Type: 2 (SHA-256)');
  console.log('  Digest:', ROOT_DS_20326.data.digest.toString('hex'));
  
  // Use dns-packet to encode the DS record in wire format
  const encodedDS = dnsPacket.answer.encode(ROOT_DS_20326);
  const anchorsHex = toHex(new Uint8Array(encodedDS));
  
  console.log('  Encoded length:', encodedDS.length, 'bytes');
  console.log('  Encoded hex:', anchorsHex);

  // Send transaction
  console.log('\nStep 2: Sending setAnchors transaction...');
  
  try {
    const hash = await walletClient.writeContract({
      address: ORACLE_ADDRESS,
      abi: ORACLE_ABI,
      functionName: 'setAnchors',
      args: [anchorsHex],
    });

    console.log('  Transaction hash:', hash);
    console.log('  Waiting for confirmation...');

    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    
    console.log('  ✅ Transaction confirmed!');
    console.log('  Block:', receipt.blockNumber);
    console.log('  Gas used:', receipt.gasUsed.toString());

  } catch (e) {
    console.error('  ❌ Transaction failed:', e.message);
    process.exit(1);
  }

  // Verify
  console.log('\nStep 3: Verifying anchors...');
  try {
    const newAnchors = await publicClient.readContract({
      address: ORACLE_ADDRESS,
      abi: ORACLE_ABI,
      functionName: 'anchors',
    });
    console.log('  New anchors:', newAnchors);
    console.log('  ✅ Trust anchors set successfully!');
  } catch (e) {
    console.log('  Could not verify:', e.message);
  }

  console.log('\n=== Done ===');
}

main().catch(console.error);
