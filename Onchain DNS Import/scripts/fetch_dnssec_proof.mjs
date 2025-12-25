#!/usr/bin/env node

import dnsPacket from 'dns-packet';
import dgram from 'dgram';
import { writeFile } from 'fs/promises';
import { dirname } from 'path';
import { mkdir } from 'fs/promises';

const SCRIPT_VERSION = 'fetch_dnssec_proof.mjs v1.2 (ABI-ready Profile A)';

/**
 * Compute DNSSEC key tag per RFC 4034 Appendix B
 * @param {Buffer} dnskeyRdata - Full DNSKEY RDATA (flags + protocol + algorithm + publicKey)
 * @returns {number} Key tag (uint16)
 */
function computeKeyTag(dnskeyRdata) {
  let ac = 0;
  
  for (let i = 0; i < dnskeyRdata.length; i++) {
    if (i & 1) {
      ac += dnskeyRdata[i];
    } else {
      ac += dnskeyRdata[i] << 8;
    }
  }
  
  ac += (ac >> 16) & 0xFFFF;
  return ac & 0xFFFF;
}

/**
 * Encode DNSKEY RDATA to wire format for key tag computation
 * @param {object} dnskeyData - Parsed DNSKEY data from dns-packet
 * @returns {Buffer} DNSKEY RDATA in wire format
 */
function encodeDNSKEYRdata(dnskeyData) {
  const publicKeyBuf = Buffer.isBuffer(dnskeyData.key || dnskeyData.publicKey)
    ? (dnskeyData.key || dnskeyData.publicKey)
    : Buffer.from(dnskeyData.key || dnskeyData.publicKey, 'base64');
  
  const rdata = Buffer.alloc(4 + publicKeyBuf.length);
  rdata.writeUInt16BE(dnskeyData.flags, 0);
  rdata.writeUInt8(dnskeyData.protocol || 3, 2);
  rdata.writeUInt8(dnskeyData.algorithm, 3);
  publicKeyBuf.copy(rdata, 4);
  
  return rdata;
}

/**
 * Normalize DNS name (ensure trailing dot)
 */
function normalizeDNSName(name) {
  return name.endsWith('.') ? name : name + '.';
}

/**
 * Normalize DNS name to lowercase wire format
 * @param {string} name - DNS name (may or may not have trailing dot)
 * @returns {Buffer} Wire format DNS name
 */
function canonicalDNSName(name) {
  if (!name || typeof name !== 'string') {
    throw new Error(`Invalid DNS name: ${name}`);
  }
  const normalized = name.toLowerCase();
  const labels = normalized.endsWith('.')
    ? normalized.slice(0, -1).split('.')
    : normalized.split('.');

  const buf = Buffer.alloc(labels.reduce((sum, l) => sum + 1 + l.length, 0) + 1);
  let offset = 0;

  for (const label of labels) {
    buf.writeUInt8(label.length, offset++);
    buf.write(label, offset, 'ascii');
    offset += label.length;
  }
  buf.writeUInt8(0, offset); // Root label

  return buf;
}

/**
 * Encode TXT RDATA to wire format
 * @param {Array<string>} txtStrings - Array of TXT strings
 * @returns {Buffer}
 */
function encodeTXTRdata(txtStrings) {
  const buffers = [];
  for (const str of txtStrings) {
    const strBuf = Buffer.from(str, 'utf8');
    const lenBuf = Buffer.alloc(1);
    lenBuf.writeUInt8(strBuf.length, 0);
    buffers.push(lenBuf, strBuf);
  }
  return Buffer.concat(buffers);
}

/**
 * Convert DNS type string to number
 */
function typeToNumber(type) {
  if (typeof type === 'number') return type;
  const typeMap = {
    'A': 1, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12, 'MX': 15,
    'TXT': 16, 'AAAA': 28, 'DS': 43, 'RRSIG': 46, 'NSEC': 47,
    'DNSKEY': 48, 'NSEC3': 50, 'OPT': 41
  };
  return typeMap[type.toUpperCase()] || 0;
}

/**
 * Build canonical RRset for signature verification (RFC 4034 Section 3.1.8)
 * @param {object} rrsig - RRSIG record data
 * @param {Array<object>} rrset - Array of RRs (same owner, type, class)
 * @returns {object} { canonicalRRsetBytes, signedDataBytes }
 */
function buildCanonicalRRset(rrsig, rrset) {
  // Step 1: RRSIG RDATA (minus signature itself)
  const rrsigRdata = Buffer.alloc(18);

  // Type covered (2 bytes)
  const typeNum = typeToNumber(rrsig.typeCovered);
  rrsigRdata.writeUInt16BE(typeNum, 0);

  // Algorithm (1 byte)
  rrsigRdata.writeUInt8(rrsig.algorithm, 2);

  // Labels (1 byte)
  rrsigRdata.writeUInt8(rrsig.labels, 3);

  // Original TTL (4 bytes)
  rrsigRdata.writeUInt32BE(rrsig.originalTTL, 4);

  // Expiration (4 bytes)
  rrsigRdata.writeUInt32BE(rrsig.expiration, 8);

  // Inception (4 bytes)
  rrsigRdata.writeUInt32BE(rrsig.inception, 12);

  // Key tag (2 bytes)
  rrsigRdata.writeUInt16BE(rrsig.keyTag, 16);

  // Signer's name (variable)
  const signerName = canonicalDNSName(rrsig.signerName);

  // Step 2: Build canonical RRset
  const canonicalRRs = [];

  for (const rr of rrset) {
    const ownerName = canonicalDNSName(rr.name);
    const rrType = Buffer.alloc(2);
    const typeValue = typeToNumber(rr.type);
    rrType.writeUInt16BE(typeValue, 0);

    const rrClass = Buffer.alloc(2);
    const classValue = rr.class === 'IN' || rr.class === undefined ? 1 : rr.class;
    rrClass.writeUInt16BE(classValue, 0);

    const rrTtl = Buffer.alloc(4);
    rrTtl.writeUInt32BE(rrsig.originalTTL, 0); // Use RRSIG's original TTL

    // Encode RDATA
    let rdata;
    if (rr.type === 'TXT' || typeValue === 16) {
      // Our rrsets store TXT data in rdata.txt
      const txtStrings = rr.rdata?.txt || [];
      rdata = encodeTXTRdata(txtStrings);
    } else if (rr.type === 'DNSKEY' || typeValue === 48) {
      // Our rrsets store DNSKEY data in rdata
      const dnskeyData = rr.rdata;
      console.log(`     DEBUG: DNSKEY rdata for ${rr.name}:`, JSON.stringify(dnskeyData, null, 2));
      rdata = encodeDNSKEYRdata({
        flags: dnskeyData.flags,
        protocol: dnskeyData.protocol || 3,
        algorithm: dnskeyData.algorithm,
        publicKey: dnskeyData.publicKey
      });
    } else {
      throw new Error(`Unsupported RR type for canonicalization: ${rr.type}`);
    }

    const rdlength = Buffer.alloc(2);
    rdlength.writeUInt16BE(rdata.length, 0);

    const canonicalRR = Buffer.concat([
      ownerName,
      rrType,
      rrClass,
      rrTtl,
      rdlength,
      rdata
    ]);

    canonicalRRs.push({ rdata, canonical: canonicalRR });
  }

  // Step 3: Sort RRs by canonical RDATA (RFC 4034 Section 6.3)
  canonicalRRs.sort((a, b) => Buffer.compare(a.rdata, b.rdata));

  // Step 4: Concatenate all canonical RRs
  const canonicalRRsetBytes = Buffer.concat(canonicalRRs.map(crr => crr.canonical));

  // Step 5: Build signed data (RRSIG_RDATA + SignerName + CanonicalRRset)
  const signedDataBytes = Buffer.concat([
    rrsigRdata,
    signerName,
    canonicalRRsetBytes
  ]);

  return {
    canonicalRRsetBytes: '0x' + canonicalRRsetBytes.toString('hex'),
    signedDataBytes: '0x' + signedDataBytes.toString('hex')
  };
}

/**
 * Encode a DNS name to wire format (length-prefixed labels)
 * @param {string} name - DNS name (e.g., "eketc.co" or "eketc.co.")
 * @returns {Buffer} Wire format name
 */
function encodeDNSNameWire(name) {
  const normalized = name.endsWith('.') ? name.slice(0, -1) : name;
  if (!normalized) return Buffer.from([0]); // Root
  
  const labels = normalized.split('.');
  const buffers = [];
  
  for (const label of labels) {
    buffers.push(Buffer.from([label.length]));
    buffers.push(Buffer.from(label, 'ascii'));
  }
  buffers.push(Buffer.from([0])); // Root label
  
  return Buffer.concat(buffers);
}

/**
 * Encode a single RR to wire format
 * @param {object} record - Parsed DNS record from dns-packet
 * @returns {Buffer} RR in wire format
 */
function encodeRRWire(record) {
  // Encode owner name
  const nameWire = encodeDNSNameWire(record.name);
  
  // Get type number
  const typeMap = {
    'A': 1, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12, 'MX': 15,
    'TXT': 16, 'AAAA': 28, 'DS': 43, 'RRSIG': 46, 'NSEC': 47,
    'DNSKEY': 48, 'NSEC3': 50, 'OPT': 41
  };
  const typeNum = typeof record.type === 'number' ? record.type : (typeMap[record.type] || 0);
  
  // Get class number
  const classNum = record.class === 'IN' || record.class === undefined ? 1 : record.class;
  
  // Encode RDATA based on type
  let rdata;
  
  if (record.type === 'TXT' || typeNum === 16) {
    // TXT RDATA: one or more <length><char-string>
    const txtData = Array.isArray(record.data) ? record.data : [record.data];
    const parts = [];
    for (const str of txtData) {
      const strBuf = Buffer.isBuffer(str) ? str : Buffer.from(str, 'utf8');
      parts.push(Buffer.from([strBuf.length]));
      parts.push(strBuf);
    }
    rdata = Buffer.concat(parts);
    
  } else if (record.type === 'DNSKEY' || typeNum === 48) {
    // DNSKEY RDATA: flags(2) + protocol(1) + algorithm(1) + publicKey
    const key = Buffer.isBuffer(record.data.key) ? record.data.key : Buffer.from(record.data.key, 'base64');
    rdata = Buffer.alloc(4 + key.length);
    rdata.writeUInt16BE(record.data.flags, 0);
    rdata.writeUInt8(record.data.protocol || 3, 2);
    rdata.writeUInt8(record.data.algorithm, 3);
    key.copy(rdata, 4);
    
  } else if (record.type === 'DS' || typeNum === 43) {
    // DS RDATA: keyTag(2) + algorithm(1) + digestType(1) + digest
    const digest = Buffer.isBuffer(record.data.digest) ? record.data.digest : Buffer.from(record.data.digest, 'hex');
    rdata = Buffer.alloc(4 + digest.length);
    rdata.writeUInt16BE(record.data.keyTag, 0);
    rdata.writeUInt8(record.data.algorithm, 2);
    rdata.writeUInt8(record.data.digestType, 3);
    digest.copy(rdata, 4);
    
  } else if (record.type === 'RRSIG' || typeNum === 46) {
    // RRSIG RDATA: typeCovered(2) + algorithm(1) + labels(1) + originalTTL(4)
    //              + expiration(4) + inception(4) + keyTag(2) + signerName + signature
    const signerNameWire = encodeDNSNameWire(record.data.signersName || record.data.signerName);
    const signature = Buffer.isBuffer(record.data.signature) 
      ? record.data.signature 
      : Buffer.from(record.data.signature, 'base64');
    
    const typeCoveredMap = { 'A': 1, 'TXT': 16, 'DNSKEY': 48, 'DS': 43, 'RRSIG': 46 };
    const typeCovered = typeof record.data.typeCovered === 'number' 
      ? record.data.typeCovered 
      : (typeCoveredMap[record.data.typeCovered] || 0);
    
    rdata = Buffer.alloc(18 + signerNameWire.length + signature.length);
    rdata.writeUInt16BE(typeCovered, 0);
    rdata.writeUInt8(record.data.algorithm, 2);
    rdata.writeUInt8(record.data.labels, 3);
    rdata.writeUInt32BE(record.data.originalTTL, 4);
    rdata.writeUInt32BE(record.data.expiration, 8);
    rdata.writeUInt32BE(record.data.inception, 12);
    rdata.writeUInt16BE(record.data.keyTag, 16);
    signerNameWire.copy(rdata, 18);
    signature.copy(rdata, 18 + signerNameWire.length);
    
  } else {
    // Unknown type - return empty rdata
    rdata = Buffer.alloc(0);
  }
  
  // Build full RR: name + type(2) + class(2) + ttl(4) + rdlength(2) + rdata
  const header = Buffer.alloc(10);
  header.writeUInt16BE(typeNum, 0);
  header.writeUInt16BE(classNum, 2);
  header.writeUInt32BE(record.ttl || 0, 4);
  header.writeUInt16BE(rdata.length, 8);
  
  return Buffer.concat([nameWire, header, rdata]);
}

// Parse command line arguments
function parseArgs() {
  const args = process.argv.slice(2);
  const config = {
    server: '1.1.1.1',
    port: 53,
    out: 'proofs/eketc_co__ens_txt.raw.json',
    qname: '_ens.eketc.co',
    qtype: 'TXT',
    validationTime: Math.floor(Date.now() / 1000) // Default to now
  };

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--server' && args[i + 1]) {
      config.server = args[i + 1];
      i++;
    } else if (args[i] === '--out' && args[i + 1]) {
      config.out = args[i + 1];
      i++;
    } else if (args[i] === '--validationTime' && args[i + 1]) {
      config.validationTime = parseInt(args[i + 1], 10);
      if (isNaN(config.validationTime)) {
        throw new Error('Invalid validationTime: must be unix timestamp');
      }
      i++;
    }
  }

  return config;
}

// Query DNS with DNSSEC enabled
function queryDNS(server, port, name, type) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4');
    
    // Build DNS query with DNSSEC (DO bit set)
    const query = dnsPacket.encode({
      type: 'query',
      id: Math.floor(Math.random() * 65536),
      flags: dnsPacket.RECURSION_DESIRED,
      questions: [{
        type: type,
        class: 'IN',
        name: name
      }],
      additionals: [{
        type: 'OPT',
        name: '.',
        udpPayloadSize: 4096,
        flags: dnsPacket.DNSSEC_OK
      }]
    });

    const timeout = setTimeout(() => {
      socket.close();
      reject(new Error(`DNS query timeout for ${name} ${type}`));
    }, 5000);

    socket.on('message', (msg) => {
      clearTimeout(timeout);
      socket.close();
      
      try {
        const response = dnsPacket.decode(msg);
        resolve({ response, raw: msg });
      } catch (err) {
        reject(new Error(`Failed to decode DNS response: ${err.message}`));
      }
    });

    socket.on('error', (err) => {
      clearTimeout(timeout);
      socket.close();
      reject(err);
    });

    socket.send(query, 0, query.length, port, server);
  });
}

// Convert DNS record to structured format
function convertRecord(record, section, rrIndex) {
  // Encode the RR to wire format
  const rrWire = encodeRRWire(record);
  
  const base = {
    name: record.name,
    type: record.type,
    class: record.class || 'IN',
    ttl: record.ttl,
    raw: rrWire.toString('base64'),
    section: section,
    rrIndex: rrIndex
  };

  // Parse RDATA based on type
  if (record.type === 'TXT') {
    // Convert TXT data to strings for readability
    const txtStrings = Array.isArray(record.data) 
      ? record.data.map(d => Buffer.isBuffer(d) ? d.toString('utf8') : String(d))
      : [Buffer.isBuffer(record.data) ? record.data.toString('utf8') : String(record.data)];
    
    base.rdata = {
      txt: txtStrings
    };
  } else if (record.type === 'DNSKEY') {
    base.rdata = {
      flags: record.data.flags,
      protocol: record.data.protocol || 3, // DNSSEC always uses protocol 3
      algorithm: record.data.algorithm,
      publicKey: record.data.key ? record.data.key.toString('base64') : null
    };
  } else if (record.type === 'DS') {
    base.rdata = {
      keyTag: record.data.keyTag,
      algorithm: record.data.algorithm,
      digestType: record.data.digestType,
      digest: record.data.digest ? record.data.digest.toString('hex') : null
    };
  } else if (record.type === 'RRSIG') {
    base.rdata = {
      typeCovered: record.data.typeCovered,
      algorithm: record.data.algorithm,
      labels: record.data.labels,
      originalTTL: record.data.originalTTL,
      expiration: record.data.expiration,
      inception: record.data.inception,
      keyTag: record.data.keyTag,
      signerName: normalizeDNSName(record.data.signersName || record.data.signerName),
      signature: record.data.signature ? record.data.signature.toString('base64') : null
    };
  } else {
    base.rdata = record.data;
  }

  return base;
}

// Main execution
async function main() {
  const config = parseArgs();
  
  console.log(`Fetching DNSSEC proof for ${config.qname} ${config.qtype}`);
  console.log(`Trust Model: Full IANA root DS chain validation`);
  console.log(`DNS Server: ${config.server}:${config.port}`);
  console.log(`Output: ${config.out}\n`);

  const proof = {
    meta: {
      generatedAt: new Date().toISOString(),
      dnsServer: `${config.server}:${config.port}`,
      qname: config.qname,
      qtype: config.qtype === 'TXT' ? 16 : config.qtype
    },
    trustAnchor: null, // Will be populated after DNSKEY query
    dnskeySet: null, // Will be populated with all DNSKEYs + computed keyTags
    verificationPlan: null, // Will be populated after analysis
    rrsets: [],
    messages: []
  };

  try {
    // Query 1: _ens.eketc.co TXT
    console.log(`Querying ${config.qname} TXT +DNSSEC...`);
    const txtResult = await queryDNS(config.server, config.port, config.qname, 'TXT');
    console.log(`  ✓ Got ${txtResult.response.answers.length} answers`);
    
    proof.messages.push({
      query: { name: config.qname, type: 'TXT' },
      responseRaw: txtResult.raw.toString('base64')
    });

    // Add TXT records and their RRSIGs
    for (let i = 0; i < txtResult.response.answers.length; i++) {
      const answer = txtResult.response.answers[i];
      proof.rrsets.push(convertRecord(answer, 'answer', i));
      
      // Log TXT content if found
      if (answer.type === 'TXT' && answer.data) {
        const txtData = Array.isArray(answer.data) 
          ? answer.data.map(d => Buffer.isBuffer(d) ? d.toString() : d).join('')
          : answer.data.toString();
        console.log(`  TXT data: ${txtData}`);
      }
    }

    // Query 2: eketc.co DNSKEY
    console.log(`\nQuerying eketc.co DNSKEY +DNSSEC...`);
    const dnskeyResult = await queryDNS(config.server, config.port, 'eketc.co', 'DNSKEY');
    console.log(`  ✓ Got ${dnskeyResult.response.answers.length} answers`);
    
    proof.messages.push({
      query: { name: 'eketc.co', type: 'DNSKEY' },
      responseRaw: dnskeyResult.raw.toString('base64')
    });

    // Process all DNSKEY records and compute keyTags
    console.log(`\n🔐 Processing DNSKEY RRset and computing key tags...`);
    
    const dnskeyRecords = [];
    let kskDnskey = null;
    let dnskeyRrsig = null;
    
    for (let i = 0; i < dnskeyResult.response.answers.length; i++) {
      const answer = dnskeyResult.response.answers[i];
      const record = convertRecord(answer, 'answer', i);
      proof.rrsets.push(record);
      
      if (answer.type === 'DNSKEY') {
        const publicKeyBuf = Buffer.isBuffer(answer.data.key) 
          ? answer.data.key 
          : Buffer.from(answer.data.key, 'base64');
        
        // Compute key tag for this DNSKEY
        const dnskeyRdata = encodeDNSKEYRdata(answer.data);
        const computedKeyTag = computeKeyTag(dnskeyRdata);
        
        const isKSK = answer.data.flags === 257;
        const isZSK = answer.data.flags === 256;
        
        console.log(`  DNSKEY: flags=${answer.data.flags}, algorithm=${answer.data.algorithm}, keyTag=${computedKeyTag} (${isKSK ? 'KSK' : isZSK ? 'ZSK' : 'unknown'})`);
        
        const dnskeyInfo = {
          flags: answer.data.flags,
          protocol: answer.data.protocol || 3,
          algorithm: answer.data.algorithm,
          publicKey: publicKeyBuf.toString('base64'),
          publicKeyHex: '0x' + publicKeyBuf.toString('hex'),
          publicKeyLength: publicKeyBuf.length,
          keyTag: computedKeyTag,
          isKSK: isKSK,
          isZSK: isZSK
        };
        
        dnskeyRecords.push(dnskeyInfo);
        
        // Track the KSK for trust anchor
        if (isKSK && answer.data.algorithm === 13) {
          kskDnskey = dnskeyInfo;
        }
      } else if (answer.type === 'RRSIG' && answer.data.typeCovered === 'DNSKEY') {
        dnskeyRrsig = record.rdata;
      }
    }

    // Validate we found a KSK
    if (!kskDnskey) {
      throw new Error('No KSK found with flags=257 and algorithm=13 in eketc.co DNSKEY RRset');
    }

    // Validate KSK public key length for P-256
    if (kskDnskey.publicKeyLength !== 64) {
      throw new Error(`P-256 KSK public key must be 64 bytes, got ${kskDnskey.publicKeyLength}`);
    }
    console.log(`  ✓ KSK public key length: ${kskDnskey.publicKeyLength} bytes`);

    // Build dnskeySet object
    if (!dnskeyRrsig) {
      throw new Error('RRSIG(DNSKEY) not found in response');
    }
    
    proof.dnskeySet = {
      zone: normalizeDNSName('eketc.co'),
      keys: dnskeyRecords,
      rrsigDnskey: dnskeyRrsig
    };
    console.log(`  ✓ DNSKEY RRset signed by key tag: ${dnskeyRrsig.keyTag}`);

    // Query 3: eketc.co DS
    console.log(`\nQuerying eketc.co DS +DNSSEC...`);
    const dsResult = await queryDNS(config.server, config.port, 'eketc.co', 'DS');
    console.log(`  ✓ Got ${dsResult.response.answers.length} answers, ${dsResult.response.authorities.length} authorities`);
    
    proof.messages.push({
      query: { name: 'eketc.co', type: 'DS' },
      responseRaw: dsResult.raw.toString('base64')
    });

    // DS may be in answers or authorities - process each section separately
    for (let i = 0; i < dsResult.response.answers.length; i++) {
      const answer = dsResult.response.answers[i];
      if (answer.type === 'DS' || answer.type === 'RRSIG') {
        const record = convertRecord(answer, 'answer', i);
        proof.rrsets.push(record);
        
        if (answer.type === 'DS') {
          console.log(`  DS keyTag: ${answer.data.keyTag}, algorithm: ${answer.data.algorithm}`);
        }
      }
    }
    for (let i = 0; i < (dsResult.response.authorities || []).length; i++) {
      const auth = dsResult.response.authorities[i];
      if (auth.type === 'DS' || auth.type === 'RRSIG') {
        const record = convertRecord(auth, 'authority', i);
        proof.rrsets.push(record);
        
        if (auth.type === 'DS') {
          console.log(`  DS keyTag: ${auth.data.keyTag}, algorithm: ${auth.data.algorithm}`);
        }
      }
    }

    // Query 4: .co DNSKEY
    console.log(`\nQuerying .co DNSKEY +DNSSEC...`);
    const coDnskeyResult = await queryDNS(config.server, config.port, 'co', 'DNSKEY');
    console.log(`  ✓ Got ${coDnskeyResult.response.answers.length} answers`);
    
    proof.messages.push({
      query: { name: 'co', type: 'DNSKEY' },
      responseRaw: coDnskeyResult.raw.toString('base64')
    });

    for (let i = 0; i < coDnskeyResult.response.answers.length; i++) {
      const answer = coDnskeyResult.response.answers[i];
      const record = convertRecord(answer, 'answer', i);
      proof.rrsets.push(record);
      
      if (answer.type === 'DNSKEY') {
        console.log(`  .co DNSKEY algorithm: ${answer.data.algorithm} (flags: ${answer.data.flags})`);
      }
    }

    // Query 5: Root DS for .co (IANA trust anchor)
    console.log(`\nQuerying root DS for .co TLD +DNSSEC...`);
    const coDSRootResult = await queryDNS(config.server, config.port, 'co', 'DS');
    console.log(`  ✓ Got ${coDSRootResult.response.answers.length} answers, ${coDSRootResult.response.authorities.length} authorities`);
    
    proof.messages.push({
      query: { name: 'co', type: 'DS' },
      responseRaw: coDSRootResult.raw.toString('base64')
    });

    // Root DS may be in answers or authorities section
    let foundRootDS = false;
    for (let i = 0; i < coDSRootResult.response.answers.length; i++) {
      const answer = coDSRootResult.response.answers[i];
      if (answer.type === 'DS') {
        const record = convertRecord(answer, 'answer', i);
        proof.rrsets.push(record);
        console.log(`  Root DS for .co: keyTag=${answer.data.keyTag}, algorithm=${answer.data.algorithm}`);
        foundRootDS = true;
      }
    }
    for (let i = 0; i < (coDSRootResult.response.authorities || []).length; i++) {
      const auth = coDSRootResult.response.authorities[i];
      if (auth.type === 'DS') {
        const record = convertRecord(auth, 'authority', i);
        proof.rrsets.push(record);
        console.log(`  Root DS for .co (authority): keyTag=${auth.data.keyTag}, algorithm=${auth.data.algorithm}`);
        foundRootDS = true;
      }
    }
    
    if (!foundRootDS) {
      console.log(`  ⚠️  No root DS records found for .co - this may indicate NXDOMAIN or unsigned TLD`);
    }

    // === NOW BUILD TRUST ANCHOR (after all queries complete) ===
    console.log(`\n🔍 Building trust anchor from fetched records...`);
    const allDS = proof.rrsets.filter(r => r.type === 'DS');
    console.log(`   Found ${allDS.length} total DS records with names:`, allDS.map(r => r.name));
    
    const rootDS = proof.rrsets.find(r => 
      (r.name === 'co.' || r.name === 'co') && r.type === 'DS'
    );
    
    if (!rootDS) {
      console.log(`   ⚠️  No root DS found for .co (checked both "co" and "co.")`);
    }
    
    // Store rootDS reference for later use in verification plan
    proof._rootDS = rootDS;
    
    // Build trust anchor object from root DS (ENS-compatible)
    if (rootDS) {
      proof.trustAnchor = {
        zone: '.',
        ds: {
          keyTag: rootDS.rdata.keyTag,
          algorithm: rootDS.rdata.algorithm,
          digestType: rootDS.rdata.digestType,
          digest: rootDS.rdata.digest
        },
        source: 'IANA Root DS for .co TLD',
        computedBy: SCRIPT_VERSION
      };
      console.log(`  ✓ Trust anchor (Root DS): keyTag=${rootDS.rdata.keyTag}, algo=${rootDS.rdata.algorithm}`);
    } else {
      // Fallback: use eketc.co KSK if no root DS found (for testing)
      proof.trustAnchor = {
        zone: normalizeDNSName('eketc.co'),
        dnskey: {
          flags: kskDnskey.flags,
          protocol: kskDnskey.protocol,
          algorithm: kskDnskey.algorithm,
          publicKey: kskDnskey.publicKey,
          publicKeyHex: kskDnskey.publicKeyHex
        },
        keyTag: kskDnskey.keyTag,
        source: 'eketc.co DNSKEY RRset (Fallback - no root DS)',
        computedBy: SCRIPT_VERSION
      };
      console.log(`  ⚠️  Using fallback trust anchor (eketc.co KSK): keyTag=${proof.trustAnchor.keyTag}`);
    }

    // Build verification plan and validate invariants
    console.log(`\n🔍 Building verification plan and validating invariants...`);
    
    // Find TXT record and its RRSIG
    const txtRecord = proof.rrsets.find(r => 
      r.type === 'TXT' && r.name === config.qname
    );
    if (!txtRecord) {
      throw new Error(`❌ Invariant failed: TXT record not found for ${config.qname}`);
    }
    console.log(`  ✓ TXT record found: ${txtRecord.rdata.txt.join(', ')}`);

    const txtRrsig = proof.rrsets.find(r => 
      r.type === 'RRSIG' && 
      r.name === config.qname &&
      r.rdata.typeCovered === 'TXT'
    );
    if (!txtRrsig) {
      throw new Error(`❌ Invariant failed: RRSIG(TXT) not found for ${config.qname}`);
    }

    // Validate RRSIG(TXT) properties
    if (txtRrsig.rdata.algorithm !== 13) {
      throw new Error(`❌ Invariant failed: RRSIG(TXT) algorithm must be 13, got ${txtRrsig.rdata.algorithm}`);
    }
    console.log(`  ✓ RRSIG(TXT) algorithm is 13 (ECDSAP256SHA256)`);

    if (txtRrsig.rdata.typeCovered !== 'TXT') {
      throw new Error(`❌ Invariant failed: RRSIG typeCovered must be TXT, got ${txtRrsig.rdata.typeCovered}`);
    }
    console.log(`  ✓ RRSIG(TXT) typeCovered is TXT`);

    const signerNameNormalized = txtRrsig.rdata.signerName;
    const expectedSigner = normalizeDNSName('eketc.co');
    if (signerNameNormalized !== expectedSigner) {
      throw new Error(`❌ Invariant failed: RRSIG(TXT) signer must be ${expectedSigner}, got ${signerNameNormalized}`);
    }
    console.log(`  ✓ RRSIG(TXT) signer: ${txtRrsig.rdata.signerName}`);

    // Validate DNSKEY RRset RRSIG
    if (proof.dnskeySet.rrsigDnskey.algorithm !== 13) {
      throw new Error(`❌ Invariant failed: RRSIG(DNSKEY) algorithm must be 13, got ${proof.dnskeySet.rrsigDnskey.algorithm}`);
    }
    console.log(`  ✓ RRSIG(DNSKEY) algorithm is 13`);

    // Find the DNSKEY that matches RRSIG(DNSKEY).keyTag (should be KSK)
    const kskMatch = proof.dnskeySet.keys.find(k => k.keyTag === proof.dnskeySet.rrsigDnskey.keyTag);
    if (!kskMatch) {
      throw new Error(`❌ Invariant failed: No DNSKEY found with keyTag=${proof.dnskeySet.rrsigDnskey.keyTag} (RRSIG(DNSKEY).keyTag)`);
    }
    if (!kskMatch.isKSK) {
      throw new Error(`❌ Invariant failed: DNSKEY with keyTag=${kskMatch.keyTag} should be KSK (flags=257), got flags=${kskMatch.flags}`);
    }
    console.log(`  ✓ RRSIG(DNSKEY).keyTag=${proof.dnskeySet.rrsigDnskey.keyTag} matches KSK`);

    // Find the DNSKEY that matches RRSIG(TXT).keyTag (should be ZSK)
    const zskMatch = proof.dnskeySet.keys.find(k => k.keyTag === txtRrsig.rdata.keyTag);
    if (!zskMatch) {
      throw new Error(`❌ Invariant failed: No DNSKEY found with keyTag=${txtRrsig.rdata.keyTag} (RRSIG(TXT).keyTag)`);
    }
    if (!zskMatch.isZSK) {
      throw new Error(`❌ Invariant failed: DNSKEY with keyTag=${zskMatch.keyTag} should be ZSK (flags=256), got flags=${zskMatch.flags}`);
    }
    console.log(`  ✓ RRSIG(TXT).keyTag=${txtRrsig.rdata.keyTag} matches ZSK`);

    // Verify trust anchor keyTag matches KSK (only for fallback mode)
    if (proof.trustAnchor.dnskey && proof.trustAnchor.keyTag !== kskMatch.keyTag) {
      throw new Error(`❌ Invariant failed: Trust anchor keyTag=${proof.trustAnchor.keyTag} does not match KSK keyTag=${kskMatch.keyTag}`);
    }
    if (proof.trustAnchor.dnskey) {
      console.log(`  ✓ Trust anchor keyTag matches KSK`);
    } else {
      console.log(`  ✓ Trust anchor is root DS (skipping KSK keyTag check)`);
    }

    // Build verification plan (reuse rootDS from trust anchor section via proof._rootDS)
    if (proof._rootDS) {
      proof.verificationPlan = {
        trustModel: 'ProfileB_FullIANAChain',
        rootTrustAnchor: 'Root DS for .co',
        rootDSKeyTag: proof._rootDS.rdata.keyTag,
        chain: [
          'Root DS (keyTag=' + proof._rootDS.rdata.keyTag + ') → validates .co DNSKEY',
          '.co ZSK → signs eketc.co DS',
          'eketc.co DS → validates eketc.co DNSKEY (Algorithm 13)',
          'eketc.co ZSK (keyTag=' + txtRrsig.rdata.keyTag + ') → signs TXT (Algorithm 13 + EIP-7951)'
        ],
        notes: [
          'Full IANA root chain validation',
          'Matches ENS DNSSECImpl trust model',
          'Algorithm 8 (RSA) for root → .co',
          'Algorithm 13 (P-256 + EIP-7951) for eketc.co → TXT',
          'Two P-256 verifications use precompile = 94% gas savings'
        ]
      };
    } else {
      // Fallback plan
      proof.verificationPlan = {
        trustModel: 'OptionA_PinnedKSK_Fallback',
        pinnedKskKeyTag: proof.trustAnchor.keyTag,
        verifyDnskeyRrsetWithKeyTag: proof.dnskeySet.rrsigDnskey.keyTag,
        txtRrsigKeyTag: txtRrsig.rdata.keyTag,
        selectDnskeyForTxtByKeyTag: txtRrsig.rdata.keyTag,
        notes: [
          'Fallback: No root DS found',
          'KSK (keyTag=' + proof.trustAnchor.keyTag + ') is pinned as trust anchor',
          'KSK signs DNSKEY RRset (authenticates both KSK and ZSK)',
          'ZSK (keyTag=' + txtRrsig.rdata.keyTag + ') signs TXT RRset'
        ]
      };
    }
    console.log(`  ✓ Verification plan built`);

    // Write output
    console.log(`\n📝 Writing proof to ${config.out}...`);
    await mkdir(dirname(config.out), { recursive: true });
    await writeFile(config.out, JSON.stringify(proof, null, 2));
    
    console.log(`✅ Done! Captured ${proof.rrsets.length} RRsets in ${proof.messages.length} DNS queries`);
    
    // Summary
    const txtRecordsCount = proof.rrsets.filter(r => r.type === 'TXT').length;
    const dnskeyRecordsCount = proof.rrsets.filter(r => r.type === 'DNSKEY').length;
    const dsRecordsCount = proof.rrsets.filter(r => r.type === 'DS').length;
    const rrsigRecordsCount = proof.rrsets.filter(r => r.type === 'RRSIG').length;
    
    console.log(`\nSummary:`);
    console.log(`  - TXT records: ${txtRecordsCount}`);
    console.log(`  - DNSKEY records: ${dnskeyRecordsCount}`);
    console.log(`  - DS records: ${dsRecordsCount}`);
    console.log(`  - RRSIG records: ${rrsigRecordsCount}`);

    // Acceptance checks and wiring summary
    console.log(`\n✅ Acceptance Checks & Wiring Summary:`);
    
    if (proof.trustAnchor.ds) {
      // Root DS trust anchor
      console.log(`\n  Trust Anchor (Root DS):`);
      console.log(`    - Zone: ${proof.trustAnchor.zone}`);
      console.log(`    - Key tag: ${proof.trustAnchor.ds.keyTag}`);
      console.log(`    - Algorithm: ${proof.trustAnchor.ds.algorithm} (RSA/SHA-256)`);
      console.log(`    - Digest type: ${proof.trustAnchor.ds.digestType}`);
    } else {
      // Fallback: eketc.co KSK
      console.log(`\n  Trust Anchor (eketc.co KSK - Fallback):`);
      console.log(`    - Key tag: ${proof.trustAnchor.keyTag}`);
      console.log(`    - Public key length: ${Buffer.from(proof.trustAnchor.dnskey.publicKey, 'base64').length} bytes`);
      console.log(`    - Algorithm: ${proof.trustAnchor.dnskey.algorithm} (ECDSAP256SHA256)`);
    }
    
    const zskInfo = proof.dnskeySet.keys.find(k => k.keyTag === txtRrsig.rdata.keyTag);
    console.log(`\n  Zone Signing Key (ZSK):`);
    console.log(`    - Key tag: ${zskInfo.keyTag}`);
    console.log(`    - Flags: ${zskInfo.flags}`);
    console.log(`    - Algorithm: ${zskInfo.algorithm}`);
    
    console.log(`\n  TXT Record:`);
    console.log(`    - Name: ${config.qname}`);
    console.log(`    - Value: ${txtRecord.rdata.txt.join(', ')}`);
    console.log(`    - RRSIG key tag: ${txtRrsig.rdata.keyTag}`);
    console.log(`    - RRSIG algorithm: ${txtRrsig.rdata.algorithm}`);
    
    console.log(`\n  Verification Chain:`);
    if (proof.trustAnchor.ds) {
      console.log(`    1. Root DS (tag=${proof.trustAnchor.ds.keyTag}) → validates .co DNSKEY`);
      console.log(`    2. .co ZSK → signs eketc.co DS`);
      console.log(`    3. eketc.co DS → validates eketc.co DNSKEY`);
      console.log(`    4. eketc.co KSK (tag=${kskMatch.keyTag}) → signs eketc.co DNSKEY RRset`);
      console.log(`    5. eketc.co ZSK (tag=${zskInfo.keyTag}) → signs TXT RRset`);
    } else {
      console.log(`    1. eketc.co KSK (tag=${proof.trustAnchor.keyTag}) → signs DNSKEY RRset`);
      console.log(`    2. DNSKEY RRset contains ZSK (tag=${zskInfo.keyTag})`);
      console.log(`    3. ZSK (tag=${zskInfo.keyTag}) → signs TXT RRset`);
    }
    console.log(`\n  🎯 Wiring OK: All key tags match expected flow`);

    // ========================================================================
    // Build ABI-ready proof bundle
    // ========================================================================

    console.log(`\n🏗️  Building ABI-ready proof bundle...`);
    console.log(`   Total RRsets in proof: ${proof.rrsets.length}`);
    const rrsetTypes = {};
    proof.rrsets.forEach(r => {
      rrsetTypes[r.type] = (rrsetTypes[r.type] || 0) + 1;
    });
    console.log(`   RRset types: ${JSON.stringify(rrsetTypes)}`);

    // Debug: show all RRset names
    const names = [...new Set(proof.rrsets.map(r => r.name))];
    console.log(`   RRset names: ${JSON.stringify(names)}`);

    // Extract DNSKEY RRset (from the DNSKEY query answers)
    const dnskeyRrset = proof.rrsets.filter(r =>
      r.name === 'eketc.co' &&
      r.type === 'DNSKEY' &&
      r.section === 'answer'
    );

    console.log(`   DNSKEY RRset filter: name='eketc.co.', type='DNSKEY', section='answer'`);
    console.log(`   DNSKEY RRset: found ${dnskeyRrset.length} records`);

    // Debug: show what DNSKEY records we have
    const allDnskey = proof.rrsets.filter(r => r.type === 'DNSKEY');
    console.log(`   All DNSKEY records (${allDnskey.length}):`);
    allDnskey.forEach((r, i) => console.log(`     ${i}: name='${r.name}', section='${r.section}'`));

    const dnskeyRrsigRecord = proof.rrsets.find(r =>
      r.type === 'RRSIG' &&
      r.rdata.typeCovered === 'DNSKEY'
    );

    console.log(`   DNSKEY RRSIG: ${dnskeyRrsigRecord ? 'found' : 'not found'}`);

    if (!dnskeyRrsigRecord) {
      throw new Error('❌ DNSKEY RRSIG not found');
    }

    // Extract TXT RRset (from the TXT query answers)
    const txtRrset = proof.rrsets.filter(r =>
      r.name === config.qname &&
      r.type === 'TXT' &&
      r.section === 'answer'
    );

    console.log(`   TXT RRset filter: name='${config.qname + '.'}', type='TXT', section='answer'`);
    console.log(`   TXT RRset: found ${txtRrset.length} records`);

    // Debug: show what TXT records we have
    const allTxt = proof.rrsets.filter(r => r.type === 'TXT');
    console.log(`   All TXT records (${allTxt.length}):`);
    allTxt.forEach((r, i) => console.log(`     ${i}: name='${r.name}', section='${r.section}'`));

    const txtRrsigRecord = proof.rrsets.find(r =>
      r.type === 'RRSIG' &&
      r.rdata.typeCovered === 'TXT'
    );

    console.log(`   TXT RRSIG: ${txtRrsigRecord ? 'found' : 'not found'}`);

    if (!txtRrsigRecord) {
      throw new Error('❌ TXT RRSIG not found');
    }

    // Enforce algorithm=13 for both RRsets
    if (dnskeyRrsigRecord.rdata.algorithm !== 13) {
      throw new Error(`❌ DNSKEY RRset must be signed with algorithm 13, got ${dnskeyRrsigRecord.rdata.algorithm}`);
    }
    if (txtRrsigRecord.rdata.algorithm !== 13) {
      throw new Error(`❌ TXT RRset must be signed with algorithm 13, got ${txtRrsigRecord.rdata.algorithm}`);
    }

    // Compute canonical bytes for both RRsets
    console.log(`   Computing canonical bytes for DNSKEY RRset...`);
    const dnskeyCanonical = buildCanonicalRRset(dnskeyRrsigRecord.rdata, dnskeyRrset);
    console.log(`   Computing canonical bytes for TXT RRset...`);
    const txtCanonical = buildCanonicalRRset(txtRrsigRecord.rdata, txtRrset);

    // Build question binding
    const qnameWire = '0x' + canonicalDNSName(config.qname).toString('hex');
    const expectedOwnerNameWire = qnameWire; // For TXT query, answer owner = question name

    // Build ABI-ready JSON structure
    const abiReadyProof = {
      question: {
        qnameWire: qnameWire,
        qtype: config.qtype === 'TXT' ? 16 : config.qtype,
        qclass: 1
      },
      time: {
        validationTime: config.validationTime,
        policy: "strict"
      },

      rrsets: {
        dnskey: {
          nameWire: '0x' + canonicalDNSName('eketc.co').toString('hex'),
          type: 48,
          class: 1,
          ttl: dnskeyRrset[0].ttl,
          rdata: dnskeyRrset.map(rr => rr.raw),
          rrsig: {
            typeCovered: 48,
            algorithm: dnskeyRrsigRecord.rdata.algorithm,
            labels: dnskeyRrsigRecord.rdata.labels,
            originalTTL: dnskeyRrsigRecord.rdata.originalTTL,
            expiration: dnskeyRrsigRecord.rdata.expiration,
            inception: dnskeyRrsigRecord.rdata.inception,
            keyTag: dnskeyRrsigRecord.rdata.keyTag,
            signerNameWire: '0x' + canonicalDNSName(dnskeyRrsigRecord.rdata.signerName).toString('hex'),
            signature: '0x' + Buffer.from(dnskeyRrsigRecord.rdata.signature, 'base64').toString('hex')
          },
          canonicalRRsetBytes: dnskeyCanonical.canonicalRRsetBytes,
          signedDataBytes: dnskeyCanonical.signedDataBytes
        },
        answer: {
          nameWire: expectedOwnerNameWire,
          type: 16,
          class: 1,
          ttl: txtRrset[0].ttl,
          rdata: txtRrset.map(rr => rr.raw),
          rrsig: {
            typeCovered: 16,
            algorithm: txtRrsigRecord.rdata.algorithm,
            labels: txtRrsigRecord.rdata.labels,
            originalTTL: txtRrsigRecord.rdata.originalTTL,
            expiration: txtRrsigRecord.rdata.expiration,
            inception: txtRrsigRecord.rdata.inception,
            keyTag: txtRrsigRecord.rdata.keyTag,
            signerNameWire: '0x' + canonicalDNSName(txtRrsigRecord.rdata.signerName).toString('hex'),
            signature: '0x' + Buffer.from(txtRrsigRecord.rdata.signature, 'base64').toString('hex')
          },
          canonicalRRsetBytes: txtCanonical.canonicalRRsetBytes,
          signedDataBytes: txtCanonical.signedDataBytes
        }
      },

      extra: {
        dsChain: proof.rrsets.filter(r => r.type === 'DS').map(rr => ({
          name: rr.name,
          type: rr.type,
          class: rr.class,
          ttl: rr.ttl,
          rdata: rr.rdata,
          raw: rr.raw,
          section: rr.section,
          rrIndex: rr.rrIndex
        })),
        parentDnskeys: proof.rrsets.filter(r =>
          r.name === 'co.' &&
          r.type === 'DNSKEY'
        ).map(rr => ({
          name: rr.name,
          type: rr.type,
          class: rr.class,
          ttl: rr.ttl,
          rdata: rr.rdata,
          raw: rr.raw,
          section: rr.section,
          rrIndex: rr.rrIndex
        })),
        trustAnchor: proof.trustAnchor,
        dnskeySet: proof.dnskeySet,
        verificationPlan: proof.verificationPlan
      },

      abi: {
        question: {
          qnameWire: qnameWire,
          qtype: config.qtype === 'TXT' ? 16 : config.qtype,
          qclass: 1
        },
        time: {
          validationTime: config.validationTime,
          policy: "strict"
        },
        dnskeyProof: {
          nameWire: '0x' + canonicalDNSName('eketc.co').toString('hex'),
          rdata: dnskeyRrset.map(rr => rr.raw),
          rrsig: {
            algorithm: dnskeyRrsigRecord.rdata.algorithm,
            labels: dnskeyRrsigRecord.rdata.labels,
            originalTTL: dnskeyRrsigRecord.rdata.originalTTL,
            expiration: dnskeyRrsigRecord.rdata.expiration,
            inception: dnskeyRrsigRecord.rdata.inception,
            keyTag: dnskeyRrsigRecord.rdata.keyTag,
            signerNameWire: '0x' + canonicalDNSName(dnskeyRrsigRecord.rdata.signerName).toString('hex'),
            signature: '0x' + Buffer.from(dnskeyRrsigRecord.rdata.signature, 'base64').toString('hex')
          },
          canonicalRRsetBytes: dnskeyCanonical.canonicalRRsetBytes,
          signedDataBytes: dnskeyCanonical.signedDataBytes
        },
        answerProof: {
          nameWire: expectedOwnerNameWire,
          rdata: txtRrset.map(rr => rr.raw),
          rrsig: {
            algorithm: txtRrsigRecord.rdata.algorithm,
            labels: txtRrsigRecord.rdata.labels,
            originalTTL: txtRrsigRecord.rdata.originalTTL,
            expiration: txtRrsigRecord.rdata.expiration,
            inception: txtRrsigRecord.rdata.inception,
            keyTag: txtRrsigRecord.rdata.keyTag,
            signerNameWire: '0x' + canonicalDNSName(txtRrsigRecord.rdata.signerName).toString('hex'),
            signature: '0x' + Buffer.from(txtRrsigRecord.rdata.signature, 'base64').toString('hex')
          },
          canonicalRRsetBytes: txtCanonical.canonicalRRsetBytes,
          signedDataBytes: txtCanonical.signedDataBytes
        }
      },

      // Keep original data for debugging
      meta: proof.meta,
      rrsets: proof.rrsets,
      messages: proof.messages
    };

    // Clean up temporary properties
    delete proof._rootDS;
    delete abiReadyProof._rootDS;
    
    // Write ABI-ready proof bundle
    console.log(`📝 Writing ABI-ready proof bundle to ${config.out}...`);
    await mkdir(dirname(config.out), { recursive: true });
    await writeFile(config.out, JSON.stringify(abiReadyProof, null, 2));

    console.log(`✅ Done! Generated ABI-ready proof bundle`);
    console.log(`   - DNSKEY proof: ${dnskeyRrset.length} RRs, canonical=${dnskeyCanonical.canonicalRRsetBytes.length/2-2} bytes`);
    console.log(`   - TXT proof: ${txtRrset.length} RRs, canonical=${txtCanonical.canonicalRRsetBytes.length/2-2} bytes`);
    console.log(`   - Question binding: ${qnameWire.substring(0, 20)}...`);
    console.log(`   - Validation time: ${config.validationTime}`);

  } catch (err) {
    console.error(`\n❌ Error: ${err.message}`);
    process.exit(1);
  }
}

main();
