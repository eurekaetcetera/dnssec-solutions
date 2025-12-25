#!/usr/bin/env node

/**
 * Query DNSRegistrar Claim events on mainnet to find DNS names that have been imported on-chain
 * 
 * Prerequisites:
 *   - Run from ens-contracts directory: cd ens-contracts && node ../query-dns-claims.mjs
 *   - Or install viem in root: npm install viem
 * 
 * Usage:
 *   node query-dns-claims.mjs [--from-block BLOCK] [--to-block BLOCK] [--limit N]
 * 
 * Examples:
 *   cd ens-contracts && node ../query-dns-claims.mjs
 *   cd ens-contracts && node ../query-dns-claims.mjs --from-block 15000000 --limit 10
 *   cd ens-contracts && node ../query-dns-claims.mjs --from-block 18000000 --to-block 19000000
 */

import { createPublicClient, http, decodeEventLog, toBytes, bytesToString } from 'viem'
import { mainnet } from 'viem/chains'
import { readFileSync, existsSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, join, resolve } from 'path'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

// DNSRegistrar address on mainnet
const DNS_REGISTRAR_ADDRESS = '0xB32cB5677a7C971689228EC835800432B339bA2B'

// Find DNSRegistrar deployment file (works from root or ens-contracts directory)
function findDeploymentFile() {
  const possiblePaths = [
    join(__dirname, 'ens-contracts/deployments/mainnet/DNSRegistrar.json'),
    join(__dirname, 'deployments/mainnet/DNSRegistrar.json'),
    resolve(process.cwd(), 'ens-contracts/deployments/mainnet/DNSRegistrar.json'),
    resolve(process.cwd(), 'deployments/mainnet/DNSRegistrar.json'),
  ]
  
  for (const path of possiblePaths) {
    if (existsSync(path)) {
      return path
    }
  }
  
  throw new Error(
    `Could not find DNSRegistrar.json deployment file.\n` +
    `Tried: ${possiblePaths.join('\n')}\n` +
    `Please run from the project root or ens-contracts directory.`
  )
}

// Load DNSRegistrar ABI
const deploymentPath = findDeploymentFile()
const deployment = JSON.parse(readFileSync(deploymentPath, 'utf-8'))
const DNS_REGISTRAR_ABI = deployment.abi

/**
 * Decode DNS wire format to human-readable name
 * @param {string} dnsHex - DNS name in wire format (hex string)
 * @returns {string} Decoded DNS name (e.g., "example.com")
 */
function dnsDecodeName(dnsHex) {
  const v = toBytes(dnsHex)
  const labels = []
  let pos = 0
  while (pos < v.length) {
    const size = v[pos++]
    if (size === 0 || pos + size > v.length) break
    labels.push(bytesToString(v.subarray(pos, (pos += size))))
  }
  if (pos !== v.length) {
    throw new Error(`malformed DNS-encoding: ${dnsHex} @ ${pos}`)
  }
  return labels.join('.')
}

/**
 * Query Claim events from DNSRegistrar
 */
async function queryDNSClaims(options = {}) {
  const {
    fromBlock = 'earliest',
    toBlock = 'latest',
    limit = 50
  } = options

  console.log('🔍 Querying DNSRegistrar Claim events on mainnet...')
  console.log(`   Contract: ${DNS_REGISTRAR_ADDRESS}`)
  console.log(`   From block: ${fromBlock}`)
  console.log(`   To block: ${toBlock}`)
  console.log(`   Limit: ${limit}`)
  console.log('')

  // Create public client for mainnet
  const publicClient = createPublicClient({
    chain: mainnet,
    transport: http()
  })

  // Get current block number if using 'latest'
  let toBlockNumber = toBlock
  if (toBlock === 'latest') {
    toBlockNumber = await publicClient.getBlockNumber()
    console.log(`   Current block: ${toBlockNumber}`)
    console.log('')
  }

  // Query Claim events
  const claimEventAbi = DNS_REGISTRAR_ABI.find(
    item => item.type === 'event' && item.name === 'Claim'
  )

  if (!claimEventAbi) {
    throw new Error('Claim event not found in ABI')
  }

  // RPC providers typically limit getLogs to 1000 blocks per query
  const MAX_BLOCK_RANGE = 1000n
  const fromBlockNum = fromBlock === 'earliest' ? 0n : BigInt(fromBlock)
  const toBlockNum = typeof toBlockNumber === 'bigint' ? toBlockNumber : BigInt(toBlockNumber)
  
  // Batch queries if range is too large
  const logs = []
  let currentFrom = fromBlockNum
  const totalBlocks = toBlockNum - fromBlockNum
  
  if (totalBlocks > MAX_BLOCK_RANGE) {
    console.log(`   Range too large (${totalBlocks} blocks), batching queries...`)
    const numBatches = Math.ceil(Number(totalBlocks) / Number(MAX_BLOCK_RANGE))
    console.log(`   Querying in ${numBatches} batches of ~${MAX_BLOCK_RANGE} blocks each...`)
  }

  while (currentFrom <= toBlockNum) {
    const currentTo = currentFrom + MAX_BLOCK_RANGE > toBlockNum 
      ? toBlockNum 
      : currentFrom + MAX_BLOCK_RANGE - 1n
    
    try {
      const batchLogs = await publicClient.getLogs({
        address: DNS_REGISTRAR_ADDRESS,
        event: claimEventAbi,
        fromBlock: currentFrom,
        toBlock: currentTo,
      })
      logs.push(...batchLogs)
      
      if (totalBlocks > MAX_BLOCK_RANGE) {
        const progress = ((Number(currentTo - fromBlockNum) / Number(totalBlocks)) * 100).toFixed(1)
        console.log(`   Progress: ${progress}% (blocks ${currentFrom} to ${currentTo})`)
      }
    } catch (error) {
      console.error(`   Error querying blocks ${currentFrom}-${currentTo}:`, error.message)
      // Continue with next batch
    }
    
    currentFrom = currentTo + 1n
    
    // Stop if we've collected enough results
    if (logs.length >= limit) {
      break
    }
  }

  console.log(`📊 Found ${logs.length} Claim events\n`)

  if (logs.length === 0) {
    console.log('No DNS names have been claimed yet in this block range.')
    return []
  }

  // Decode and format results
  const claims = logs
    .slice(0, limit)
    .map((log, index) => {
      try {
        const decoded = decodeEventLog({
          abi: [claimEventAbi],
          data: log.data,
          topics: log.topics,
        })

        const dnsName = dnsDecodeName(decoded.args.dnsname)
        
        return {
          index: index + 1,
          blockNumber: log.blockNumber.toString(),
          transactionHash: log.transactionHash,
          node: decoded.args.node,
          owner: decoded.args.owner,
          dnsName,
          inception: decoded.args.inception.toString(),
        }
      } catch (error) {
        console.error(`Error decoding log at block ${log.blockNumber}:`, error.message)
        return null
      }
    })
    .filter(Boolean)

  // Display results
  console.log('📋 DNS Names Claimed on ENS:\n')
  console.log('─'.repeat(100))
  
  claims.forEach((claim) => {
    console.log(`${claim.index}. ${claim.dnsName}`)
    console.log(`   Node: ${claim.node}`)
    console.log(`   Owner: ${claim.owner}`)
    console.log(`   Block: ${claim.blockNumber}`)
    console.log(`   TX: ${claim.transactionHash}`)
    console.log(`   Inception: ${claim.inception}`)
    console.log('')
  })

  console.log('─'.repeat(100))
  console.log(`\n✅ Displayed ${claims.length} of ${logs.length} total claims`)
  
  if (logs.length > limit) {
    console.log(`   (showing first ${limit}, use --limit to see more)`)
  }

  return claims
}

// Parse command line arguments
function parseArgs() {
  const args = process.argv.slice(2)
  const options = {
    fromBlock: 'earliest',
    toBlock: 'latest',
    limit: 50
  }

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--from-block' && args[i + 1]) {
      options.fromBlock = args[i + 1]
      i++
    } else if (args[i] === '--to-block' && args[i + 1]) {
      options.toBlock = args[i + 1]
      i++
    } else if (args[i] === '--limit' && args[i + 1]) {
      options.limit = parseInt(args[i + 1], 10)
      i++
    } else if (args[i] === '--help' || args[i] === '-h') {
      console.log(`
Query DNSRegistrar Claim events on mainnet

Usage:
  node query-dns-claims.mjs [options]

Options:
  --from-block BLOCK    Starting block number (default: earliest)
  --to-block BLOCK      Ending block number (default: latest)
  --limit N             Maximum number of results to display (default: 50)
  --help, -h            Show this help message

Examples:
  node query-dns-claims.mjs
  node query-dns-claims.mjs --from-block 15000000 --limit 10
  node query-dns-claims.mjs --from-block 18000000 --to-block 19000000
      `)
      process.exit(0)
    }
  }

  return options
}

// Main execution
async function main() {
  try {
    const options = parseArgs()
    await queryDNSClaims(options)
  } catch (error) {
    console.error('❌ Error:', error.message)
    if (error.stack) {
      console.error(error.stack)
    }
    process.exit(1)
  }
}

main()

