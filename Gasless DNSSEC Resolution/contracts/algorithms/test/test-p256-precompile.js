/**
 * P256 (secp256r1) Precompile Test - EIP-7951
 * 
 * Tests the secp256r1 precompile introduced in Fusaka upgrade
 * Activated: December 3, 2025 on Ethereum mainnet & Sepolia
 * https://blog.ethereum.org/2025/11/06/fusaka-mainnet-announcement
 * 
 * Precompile address: 0x0000000000000000000000000000000000000100
 * 
 * Input format (160 bytes):
 *   - hash: 32 bytes (message hash)
 *   - r: 32 bytes (signature r component)
 *   - s: 32 bytes (signature s component)
 *   - x: 32 bytes (public key x coordinate)
 *   - y: 32 bytes (public key y coordinate)
 * 
 * Output: 32 bytes
 *   - 0x01 (left-padded to 32 bytes) = valid signature
 *   - 0x00 or empty = invalid signature
 */

import 'dotenv/config';
import { ethers } from 'ethers';
import crypto from 'crypto';

// EIP-7951 Precompile address
const P256_PRECOMPILE = '0x0000000000000000000000000000000000000100';

async function main() {
  console.log('═══════════════════════════════════════════════════════════');
  console.log('  P256 (secp256r1) Precompile Test - EIP-7951 / Fusaka');
  console.log('═══════════════════════════════════════════════════════════\n');

  // Check env
  if (!process.env.SEPOLIA_RPC_URL) {
    console.error('❌ Missing SEPOLIA_RPC_URL in .env');
    console.log('   Copy .env.template to .env and add your RPC URL');
    process.exit(1);
  }

  const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL);
  
  // Check connection & chain
  try {
    const network = await provider.getNetwork();
    console.log(`✓ Connected to chain: ${network.name} (chainId: ${network.chainId})`);
    
    const blockNumber = await provider.getBlockNumber();
    console.log(`✓ Current block: ${blockNumber}\n`);
  } catch (err) {
    console.error('❌ Failed to connect to RPC:', err.message);
    process.exit(1);
  }

  // Step 1: Generate P256 keypair
  console.log('1️⃣  Generating P256 keypair...');
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1', // This is P256/secp256r1
  });

  // Export public key in uncompressed format (0x04 || x || y)
  const pubKeyRaw = publicKey.export({ type: 'spki', format: 'der' });
  // The last 65 bytes are: 0x04 (1 byte) + x (32 bytes) + y (32 bytes)
  const uncompressedKey = pubKeyRaw.slice(-65);
  const x = uncompressedKey.slice(1, 33);
  const y = uncompressedKey.slice(33, 65);
  
  console.log(`   Public Key X: 0x${x.toString('hex')}`);
  console.log(`   Public Key Y: 0x${y.toString('hex')}\n`);

  // Step 2: Create and sign a message
  console.log('2️⃣  Signing test message...');
  const message = 'Hello P256 Precompile!';
  const messageHash = crypto.createHash('sha256').update(message).digest();
  console.log(`   Message: "${message}"`);
  console.log(`   SHA256 Hash: 0x${messageHash.toString('hex')}\n`);

  // Sign with P256
  const sign = crypto.createSign('SHA256');
  sign.update(message);
  const signature = sign.sign({ key: privateKey, dsaEncoding: 'ieee-p1363' });
  
  // ieee-p1363 format gives us r || s (each 32 bytes)
  const r = signature.slice(0, 32);
  const s = signature.slice(32, 64);
  
  console.log(`   Signature R: 0x${r.toString('hex')}`);
  console.log(`   Signature S: 0x${s.toString('hex')}\n`);

  // Step 3: Verify locally first
  console.log('3️⃣  Local verification (sanity check)...');
  const verify = crypto.createVerify('SHA256');
  verify.update(message);
  const localValid = verify.verify(
    { key: publicKey, dsaEncoding: 'ieee-p1363' },
    signature
  );
  console.log(`   Local verify: ${localValid ? '✓ VALID' : '✗ INVALID'}\n`);

  if (!localValid) {
    console.error('❌ Local signature verification failed - something is wrong');
    process.exit(1);
  }

  // Step 4: Call the precompile
  console.log('4️⃣  Calling P256 precompile at', P256_PRECOMPILE, '...');
  
  // Build input: hash (32) + r (32) + s (32) + x (32) + y (32) = 160 bytes
  // Convert Buffers to hex strings for ethers.concat
  const input = ethers.concat([
    '0x' + messageHash.toString('hex'),
    '0x' + r.toString('hex'),
    '0x' + s.toString('hex'),
    '0x' + x.toString('hex'),
    '0x' + y.toString('hex')
  ]);
  
  console.log(`   Input length: ${ethers.dataLength(input)} bytes (expected: 160)`);
  console.log(`   Input: ${input.slice(0, 66)}...`);
  
  try {
    const result = await provider.call({
      to: P256_PRECOMPILE,
      data: input
    });
    
    console.log(`\n   Raw result: ${result}`);
    
    if (result === '0x' || result === '0x0000000000000000000000000000000000000000000000000000000000000000') {
      console.log('\n⚠️  Precompile returned 0 or empty');
      console.log('   Possible causes:');
      console.log('   - Invalid signature (unlikely, local verify passed)');
      console.log('   - RPC node not updated to Fusaka yet');
      console.log('   - Precompile address different than expected');
    } else if (result === '0x0000000000000000000000000000000000000000000000000000000000000001') {
      console.log('\n✅ SUCCESS! P256 precompile is working!');
      console.log('   Signature verified on-chain via EIP-7951 precompile');
    } else {
      console.log(`\n❓ Unexpected result: ${result}`);
    }
    
  } catch (err) {
    console.log('\n❌ Precompile call failed:', err.message);
    
    if (err.message.includes('execution reverted')) {
      console.log('\n⚠️  The precompile may not be available on this RPC.');
      console.log('   Fusaka activated Dec 3, 2025 - your RPC may need to update.');
      console.log('   Try a different RPC provider (Alchemy, Infura, QuickNode).');
    }
  }

  console.log('\n═══════════════════════════════════════════════════════════');
}

main().catch(console.error);
