#!/usr/bin/env node
/**
 * @title claim_dns_name.mjs
 * @description Claims a DNS name on ENS via DNSRegistrar using DNSSEC proofs
 * 
 * Prerequisites:
 * 1. _ens.<domain> TXT record must exist: "a=0x<your-address>"
 * 2. DNSRegistrar contract must be deployed
 * 3. DNSSECOracle must have trust anchors set
 * 4. You must have permission to claim the TLD on ENS (e.g., .eth, not .co)
 * 
 * Usage:
 *   REGISTRAR_ADDRESS=0x... \
 *   PRIVATE_KEY=0x... \
 *   DOMAIN=example.com \
 *   node scripts/claim_dns_name.mjs
 */

import { createPublicClient, createWalletClient, http, encodeFunctionData, decodeAbiParameters, parseAbiParameters } from 'viem';
import { sepolia } from 'viem/chains';
import { privateKeyToAccount } from 'viem/accounts';

// Import ENSjs DNS functions
import { getDnsImportData } from '@ensdomains/ensjs/dns';

// Configuration
const REGISTRAR_ADDRESS = process.env.REGISTRAR_ADDRESS;
const PRIVATE_KEY = process.env.PRIVATE_KEY;
const DOMAIN = process.env.DOMAIN || 'eketc.co';
const RPC_URL = process.env.SEPOLIA_RPC_URL || process.env.RPC_URL || 'https://ethereum-sepolia-rpc.publicnode.com';

// Sepolia ENS Registry
const SEPOLIA_ENS_REGISTRY = '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e';

// DNSRegistrar ABI (minimal)
const REGISTRAR_ABI = [
  {
    name: 'proveAndClaimWithResolver',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'name', type: 'bytes' },
      { name: 'input', type: 'tuple[]', components: [
        { name: 'rrset', type: 'bytes' },
        { name: 'sig', type: 'bytes' }
      ]},
      { name: 'resolver', type: 'address' },
      { name: 'addr', type: 'address' }
    ],
    outputs: []
  },
  {
    name: 'proveAndClaim',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'name', type: 'bytes' },
      { name: 'input', type: 'tuple[]', components: [
        { name: 'rrset', type: 'bytes' },
        { name: 'sig', type: 'bytes' }
      ]}
    ],
    outputs: []
  },
  {
    name: 'getOracle',
    type: 'function',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'address' }]
  },
  {
    name: 'getENS',
    type: 'function',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'address' }]
  }
];

async function main() {
  console.log('═══════════════════════════════════════════════════════════');
  console.log('  DNS Name Claim Script');
  console.log('═══════════════════════════════════════════════════════════\n');

  // Validate configuration
  if (!REGISTRAR_ADDRESS) {
    console.error('❌ Error: REGISTRAR_ADDRESS environment variable not set');
    console.log('\nUsage:');
    console.log('  REGISTRAR_ADDRESS=0x... \\');
    console.log('  PRIVATE_KEY=0x... \\');
    console.log('  DOMAIN=example.com \\');
    console.log('  node scripts/claim_dns_name.mjs');
    process.exit(1);
  }

  if (!PRIVATE_KEY) {
    console.error('❌ Error: PRIVATE_KEY environment variable not set');
    process.exit(1);
  }

  // Setup clients
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
  console.log(`  Domain: ${DOMAIN}`);
  console.log(`  Registrar: ${REGISTRAR_ADDRESS}`);
  console.log(`  Caller: ${account.address}`);
  console.log(`  Network: Sepolia\n`);

  try {
    // Step 1: Fetch DNSSEC proof using ENSjs
    console.log('Step 1: Fetching DNSSEC proof...');
    const dnsData = await getDnsImportData(sepolia, publicClient, {
      name: DOMAIN,
    });

    if (!dnsData || !dnsData.proof || dnsData.proof.length === 0) {
      console.error('❌ Error: Could not fetch DNSSEC proof');
      console.error('  Make sure the domain has DNSSEC enabled and _ens TXT record exists');
      process.exit(1);
    }

    console.log(`  ✓ Got ${dnsData.proof.length} proof entries\n`);

    // Step 2: Convert proof to contract format
    console.log('Step 2: Formatting proof for contract...');
    
    // ENSjs returns proof in format: { rrset: Uint8Array, sig: Uint8Array }[]
    // We need to convert to bytes arrays
    const formattedProof = dnsData.proof.map(entry => ({
      rrset: `0x${Buffer.from(entry.rrset).toString('hex')}`,
      sig: `0x${Buffer.from(entry.sig).toString('hex')}`
    }));

    console.log(`  ✓ Formatted ${formattedProof.length} proof entries\n`);

    // Step 3: Encode DNS name to wire format
    // DNS wire format: length byte + label + length byte + label + ... + 0x00
    console.log('Step 3: Encoding DNS name to wire format...');
    const nameParts = DOMAIN.split('.');
    const nameWire = Buffer.concat([
      ...nameParts.map(part => Buffer.concat([
        Buffer.from([part.length]),
        Buffer.from(part, 'ascii')
      ])),
      Buffer.from([0]) // root
    ]);
    const nameWireHex = `0x${nameWire.toString('hex')}`;
    console.log(`  ✓ Encoded: ${nameWireHex}\n`);

    // Step 4: Estimate gas
    console.log('Step 4: Estimating gas...');
    try {
      const gasEstimate = await publicClient.estimateGas({
        account: account.address,
        to: REGISTRAR_ADDRESS,
        data: encodeFunctionData({
          abi: REGISTRAR_ABI,
          functionName: 'proveAndClaimWithResolver',
          args: [nameWireHex, formattedProof, '0x0000000000000000000000000000000000000000', account.address]
        })
      });
      console.log(`  ✓ Gas estimate: ${gasEstimate.toLocaleString()} gas\n`);
    } catch (err) {
      console.log(`  ⚠️  Gas estimation failed: ${err.message}`);
      console.log('  Continuing anyway...\n');
    }

    // Step 5: Send transaction
    console.log('Step 5: Sending claim transaction...');
    console.log('  ⚠️  WARNING: This will attempt to claim the domain on ENS');
    console.log('  Make sure you have permission to claim this TLD\n');

    const hash = await walletClient.writeContract({
      address: REGISTRAR_ADDRESS,
      abi: REGISTRAR_ABI,
      functionName: 'proveAndClaimWithResolver',
      args: [nameWireHex, formattedProof, '0x0000000000000000000000000000000000000000', account.address]
    });

    console.log(`  ✓ Transaction sent: ${hash}`);
    console.log(`  ⏳ Waiting for confirmation...\n`);

    const receipt = await publicClient.waitForTransactionReceipt({ hash });

    if (receipt.status === 'success') {
      console.log('✅ Domain claimed successfully!');
      console.log(`  Block: ${receipt.blockNumber}`);
      console.log(`  Gas used: ${receipt.gasUsed.toLocaleString()}`);
      console.log(`\n  View on Etherscan:`);
      console.log(`  https://sepolia.etherscan.io/tx/${hash}`);
    } else {
      console.error('❌ Transaction failed');
      process.exit(1);
    }

  } catch (error) {
    console.error('❌ Error:', error.message);
    if (error.stack) {
      console.error(error.stack);
    }
    process.exit(1);
  }
}

main().catch((error) => {
  console.error('❌ Fatal error:', error);
  process.exit(1);
});






