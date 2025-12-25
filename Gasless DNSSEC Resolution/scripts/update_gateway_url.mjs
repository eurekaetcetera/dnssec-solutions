#!/usr/bin/env node

import { createWalletClient, createPublicClient, http } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { sepolia } from 'viem/chains';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Load contract ABI
const resolverArtifact = JSON.parse(
  readFileSync(join(__dirname, '../out/DnssecResolver.sol/DnssecResolver.json'), 'utf-8')
);

// Configuration
const RESOLVER_ADDRESS = '0x7233d88AF9ee1eC3833F6AF4f733c1C5c0587Da2';
const NEW_GATEWAY_URL = 'https://gateway.eketc.co/ccip-read';
const RPC_URL = process.env.SEPOLIA_RPC_URL || 'https://rpc.sepolia.org';

async function main() {
  // Check for private key
  if (!process.env.PRIVATE_KEY) {
    console.error('❌ Error: PRIVATE_KEY environment variable not set');
    console.log('\nUsage: PRIVATE_KEY=0x... node scripts/update_gateway_url.mjs');
    process.exit(1);
  }

  // Setup clients
  const account = privateKeyToAccount(process.env.PRIVATE_KEY);
  const publicClient = createPublicClient({
    chain: sepolia,
    transport: http(RPC_URL),
  });
  const walletClient = createWalletClient({
    account,
    chain: sepolia,
    transport: http(RPC_URL),
  });

  console.log('\n🔄 Updating Gateway URL on Sepolia...\n');
  console.log(`Resolver Contract: ${RESOLVER_ADDRESS}`);
  console.log(`Caller Address:    ${account.address}`);
  console.log(`New Gateway URL:   ${NEW_GATEWAY_URL}\n`);

  // Read current gateway URL
  console.log('📖 Reading current gateway URL...');
  const currentUrl = await publicClient.readContract({
    address: RESOLVER_ADDRESS,
    abi: resolverArtifact.abi,
    functionName: 'gatewayUrl',
  });
  console.log(`Current: ${currentUrl}\n`);

  if (currentUrl === NEW_GATEWAY_URL) {
    console.log('✅ Gateway URL is already up to date!');
    return;
  }

  // Update gateway URL
  console.log('📝 Updating gateway URL...');
  const hash = await walletClient.writeContract({
    address: RESOLVER_ADDRESS,
    abi: resolverArtifact.abi,
    functionName: 'setGatewayUrl',
    args: [NEW_GATEWAY_URL],
  });

  console.log(`Transaction hash: ${hash}`);
  console.log('⏳ Waiting for confirmation...\n');

  const receipt = await publicClient.waitForTransactionReceipt({ hash });

  if (receipt.status === 'success') {
    console.log('✅ Gateway URL updated successfully!');
    console.log(`Block number: ${receipt.blockNumber}`);
    console.log(`Gas used: ${receipt.gasUsed}`);
    
    // Verify the update
    const updatedUrl = await publicClient.readContract({
      address: RESOLVER_ADDRESS,
      abi: resolverArtifact.abi,
      functionName: 'gatewayUrl',
    });
    console.log(`\nVerified new URL: ${updatedUrl}`);
  } else {
    console.error('❌ Transaction failed');
    process.exit(1);
  }
}

main().catch((error) => {
  console.error('❌ Error:', error);
  process.exit(1);
});

