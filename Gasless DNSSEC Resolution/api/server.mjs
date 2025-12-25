import { URL } from 'url';
import { spawn } from 'child_process';
import {
  decodeAbiParameters,
  encodeAbiParameters,
  hexToBytes,
  parseAbiParameters
} from 'viem';
const ALLOWED_TYPES = ['TXT', 'DNSKEY', 'DS', 'A', 'AAAA', 'CNAME'];

// Mapping of qtype numbers to resolver-friendly names
const QTYPE_TO_NAME = {
  1: 'A',
  5: 'CNAME',
  16: 'TXT',
  28: 'AAAA',
  43: 'DS',
  48: 'DNSKEY'
};

// ABI schema for CCIP-Read callData: (bytes qname, uint16 qtype)
const CALLDATA_SCHEMA = parseAbiParameters('bytes qname,uint16 qtype');

// ABI schema for the gas-optimized ProofBundle (all metadata as bytes)
// Note: parseAbiParameters expects comma-separated parameters, not a tuple wrapper
const PROOF_BUNDLE_SCHEMA = parseAbiParameters(`
  bytes version,
  bytes profile,
  bytes signatureFormat,
  (bytes mode, bytes zoneNameWire, uint16 keyTag, uint8 algorithm, uint16 dnskeyFlags) trustAnchor,
  (bytes qnameWire, uint16 qtype, uint16 qclass) question,
  (bytes policy, uint64 validationTime, uint64 clockSkewSeconds, bool requireInceptionLeNowPlusSkew, bool requireNowMinusSkewLeExpiration) time,
  (bytes nameWire, bytes rrsetBytes, bytes signedDataBytes, (uint16 typeCovered, uint8 algorithm, uint8 labels, uint32 originalTTL, uint32 expiration, uint32 inception, uint16 keyTag, bytes signerNameWire, bytes signature) rrsig, (uint16 flags, uint8 protocol, uint8 algorithm, bytes publicKey) dnskey) dnskeyProof,
  (bytes nameWire, bytes rrsetBytes, bytes signedDataBytes, (uint16 typeCovered, uint8 algorithm, uint8 labels, uint32 originalTTL, uint32 expiration, uint32 inception, uint16 keyTag, bytes signerNameWire, bytes signature) rrsig, (uint16 flags, uint8 protocol, uint8 algorithm, bytes publicKey) dnskey) answerProof
`);

function addCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, ngrok-skip-browser-warning');
}

function sendJson(res, statusCode, payload) {
  addCors(res);
  res.status(statusCode).json(payload);
}

function normalizeType(type) {
  if (!type) return null;
  const upper = String(type).toUpperCase();
  return ALLOWED_TYPES.includes(upper) ? upper : null;
}

function wireToName(bytes) {
  const labels = [];
  let offset = 0;
  while (offset < bytes.length) {
    const len = bytes[offset];
    if (len === 0) break;
    offset += 1;
    const end = offset + len;
    labels.push(Buffer.from(bytes.slice(offset, end)).toString('utf8'));
    offset = end;
  }
  return labels.join('.');
}

function ensureHexString(value, field) {
  if (typeof value !== 'string' || !value.startsWith('0x')) {
    throw new Error(`invalid_hex_string:${field}`);
  }
  return value;
}

function hexToBytesSafe(value, field) {
  ensureHexString(value, field);
  return hexToBytes(value);
}

function base64ToBytesSafe(value, field) {
  try {
    return Buffer.from(value, 'base64');
  } catch (err) {
    throw new Error(`invalid_base64:${field}:${(err && err.message) || 'decode_failed'}`);
  }
}

function validateSignatureHex(hex, field) {
  ensureHexString(hex, field);
  const byteLen = (hex.length - 2) / 2;
  if (byteLen !== 64) {
    throw new Error(`invalid_signature_length:${field}:expected_64_bytes:got_${byteLen}`);
  }
}

function validatePublicKeyBytes(bytes, field) {
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) {
    throw new Error(`invalid_publickey:${field}:not_bytes`);
  }
  if (bytes.length !== 64) {
    throw new Error(`invalid_publickey_length:${field}:expected_64_bytes:got_${bytes.length}`);
  }
}

function parseJsonFromStdout(stdout) {
  const jsonStart = stdout.lastIndexOf('\n{');
  const extract = (startIndex) => {
    let jsonStr = stdout.substring(startIndex);
    let braceCount = 0;
    let jsonEnd = -1;
    for (let i = 0; i < jsonStr.length; i++) {
      if (jsonStr[i] === '{') braceCount++;
      if (jsonStr[i] === '}') {
        braceCount--;
        if (braceCount === 0) {
          jsonEnd = i + 1;
          break;
        }
      }
    }
    if (jsonEnd === -1) {
      throw new Error('Incomplete JSON object in stdout');
    }
    return JSON.parse(jsonStr.substring(0, jsonEnd));
  };

  if (jsonStart === -1) {
    const fallbackStart = stdout.lastIndexOf('{');
    if (fallbackStart === -1) throw new Error('No JSON object found in stdout');
    return extract(fallbackStart);
  }
  return extract(jsonStart + 1);
}

function runProofPromise(name, type) {
  return new Promise((resolve, reject) => {
    const scriptPath = `${process.cwd()}/scripts/fetch_dnssec_proof.mjs`;
    const outputPath = `/tmp/proof_${Date.now()}.json`;
    const args = [
      scriptPath,
      '--name', name,
      '--type', type,
      '--out', outputPath
    ];

    const child = spawn('node', args, { stdio: ['ignore', 'pipe', 'pipe'] });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });

    child.on('error', (err) => {
      reject({ code: 'spawn_error', message: err.message, stderr });
    });

    child.on('close', (code) => {
      if (code !== 0) {
        return reject({ code: 'proof_error', message: 'proof builder failed', exitCode: code, stderr });
      }
      try {
        const parsed = parseJsonFromStdout(stdout);
        resolve(parsed);
      } catch (err) {
        reject({ code: 'parse_error', message: err.message, stderr });
      }
    });
  });
}

function runProof(name, type, res) {
  runProofPromise(name, type)
    .then((parsed) => sendJson(res, 200, parsed))
    .catch((err) => {
      sendJson(res, 500, { error: err.code || 'proof_error', details: err.message, stderr: err.stderr, exitCode: err.exitCode });
    });
}

function handleHealth(_req, res) {
  sendJson(res, 200, { ok: true });
}

function handleResolveGet(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const name = url.searchParams.get('name');
  const type = url.searchParams.get('type');

  if (!name || !type) {
    return sendJson(res, 400, { error: 'invalid_request', details: 'missing name or type query param' });
  }

  const normalizedType = normalizeType(type);
  if (!normalizedType) {
    return sendJson(res, 400, { error: 'invalid_request', details: `unsupported type '${type}'. allowed: ${ALLOWED_TYPES.join(', ')}` });
  }

  runProof(name, normalizedType, res);
}

function handleResolvePost(req, res) {
  // In Vercel, req.body is already parsed
  const parsed = req.body || {};
  const { name, type } = parsed;
  if (typeof name !== 'string' || name.trim() === '') {
    return sendJson(res, 400, { error: 'invalid_request', details: 'name must be a non-empty string' });
  }
  if (!type) {
    return sendJson(res, 400, { error: 'invalid_request', details: 'type is required' });
  }

  const normalizedType = normalizeType(type);
  if (!normalizedType) {
    return sendJson(res, 400, { error: 'invalid_request', details: `unsupported type '${type}'. allowed: ${ALLOWED_TYPES.join(', ')}` });
  }

  runProof(name.trim(), normalizedType, res);
}

function decodeDNSSECCallData(dataHex) {
  const decoded = decodeAbiParameters(CALLDATA_SCHEMA, dataHex);
  // viem returns bytes as hex string, convert to Uint8Array
  const qnameBytesHex = decoded[0];
  const qnameBytes = hexToBytes(qnameBytesHex);
  const qtype = Number(decoded[1]);
  const qname = wireToName(qnameBytes);
  return { qname, qtype, qnameWire: Buffer.from(qnameBytes) };
}

function selectPublicKeyBytes(dnskey) {
  if (dnskey.publicKeyHex) {
    const bytes = hexToBytesSafe(dnskey.publicKeyHex, 'dnskey.publicKeyHex');
    validatePublicKeyBytes(Buffer.from(bytes), 'dnskey.publicKeyHex');
    return Buffer.from(bytes);
  }
  if (!dnskey.publicKey) {
    throw new Error('invalid_proof_structure:dnskey.publicKey_missing');
  }
  const bytes = base64ToBytesSafe(dnskey.publicKey, 'dnskey.publicKey');
  validatePublicKeyBytes(bytes, 'dnskey.publicKey');
  return bytes;
}

function validateProofStructure(abiObj) {
  const requiredTop = ['version', 'profile', 'signatureFormat', 'trustAnchor', 'question', 'time', 'dnskeyProof', 'answerProof'];
  for (const key of requiredTop) {
    if (!(key in abiObj)) throw new Error(`invalid_proof_structure:missing_${key}`);
  }

  const { trustAnchor, question, time, dnskeyProof, answerProof } = abiObj;
  ensureHexString(trustAnchor.zoneNameWire, 'trustAnchor.zoneNameWire');
  ensureHexString(question.qnameWire, 'question.qnameWire');
  ensureHexString(dnskeyProof.nameWire, 'dnskeyProof.nameWire');
  ensureHexString(dnskeyProof.rrsetBytes, 'dnskeyProof.rrsetBytes');
  ensureHexString(dnskeyProof.signedDataBytes, 'dnskeyProof.signedDataBytes');
  ensureHexString(dnskeyProof.rrsig.signerNameWire, 'dnskeyProof.rrsig.signerNameWire');
  validateSignatureHex(dnskeyProof.rrsig.signature, 'dnskeyProof.rrsig.signature');

  ensureHexString(answerProof.nameWire, 'answerProof.nameWire');
  ensureHexString(answerProof.rrsetBytes, 'answerProof.rrsetBytes');
  ensureHexString(answerProof.signedDataBytes, 'answerProof.signedDataBytes');
  ensureHexString(answerProof.rrsig.signerNameWire, 'answerProof.rrsig.signerNameWire');
  validateSignatureHex(answerProof.rrsig.signature, 'answerProof.rrsig.signature');

  selectPublicKeyBytes(dnskeyProof.dnskey);
  selectPublicKeyBytes(answerProof.dnskey);

  // Basic type checks
  if (dnskeyProof.rrsig.algorithm !== 13 || answerProof.rrsig.algorithm !== 13) {
    throw new Error('invalid_proof_structure:algorithm_must_be_13');
  }
}

function toBytesUtf8(str) {
  return Buffer.from(String(str), 'utf8');
}

function bytesToHex(bytes) {
  if (Buffer.isBuffer(bytes)) {
    return '0x' + bytes.toString('hex');
  }
  if (bytes instanceof Uint8Array) {
    return '0x' + Buffer.from(bytes).toString('hex');
  }
  throw new Error('Invalid bytes type for hex conversion');
}

function encodeProofBundle(abiObj) {
  validateProofStructure(abiObj);

  // Validate and convert public keys to hex strings
  const dnskeyProofPublicKeyBytes = selectPublicKeyBytes(abiObj.dnskeyProof.dnskey);
  const answerProofPublicKeyBytes = selectPublicKeyBytes(abiObj.answerProof.dnskey);
  const dnskeyProofPublicKeyHex = bytesToHex(dnskeyProofPublicKeyBytes);
  const answerProofPublicKeyHex = bytesToHex(answerProofPublicKeyBytes);

  // Convert UTF-8 strings to hex strings for viem
  const versionHex = bytesToHex(toBytesUtf8(abiObj.version));
  const profileHex = bytesToHex(toBytesUtf8(abiObj.profile));
  const signatureFormatHex = bytesToHex(toBytesUtf8(abiObj.signatureFormat));
  const modeHex = bytesToHex(toBytesUtf8(abiObj.trustAnchor.mode));
  const policyHex = bytesToHex(toBytesUtf8(abiObj.time.policy));

  const packed = [
    versionHex,
    profileHex,
    signatureFormatHex,
    [
      modeHex,
      abiObj.trustAnchor.zoneNameWire, // Already hex string
      BigInt(abiObj.trustAnchor.keyTag),
      BigInt(abiObj.trustAnchor.algorithm),
      BigInt(abiObj.trustAnchor.dnskeyFlags)
    ],
    [
      abiObj.question.qnameWire, // Already hex string
      BigInt(abiObj.question.qtype),
      BigInt(abiObj.question.qclass)
    ],
    [
      policyHex,
      BigInt(abiObj.time.validationTime),
      BigInt(abiObj.time.clockSkewSeconds),
      !!abiObj.time.requireInceptionLeNowPlusSkew,
      !!abiObj.time.requireNowMinusSkewLeExpiration
    ],
    [
      abiObj.dnskeyProof.nameWire, // Already hex string
      abiObj.dnskeyProof.rrsetBytes, // Already hex string
      abiObj.dnskeyProof.signedDataBytes, // Already hex string
      [
        BigInt(abiObj.dnskeyProof.rrsig.typeCovered),
        BigInt(abiObj.dnskeyProof.rrsig.algorithm),
        BigInt(abiObj.dnskeyProof.rrsig.labels),
        BigInt(abiObj.dnskeyProof.rrsig.originalTTL),
        BigInt(abiObj.dnskeyProof.rrsig.expiration),
        BigInt(abiObj.dnskeyProof.rrsig.inception),
        BigInt(abiObj.dnskeyProof.rrsig.keyTag),
        abiObj.dnskeyProof.rrsig.signerNameWire, // Already hex string
        abiObj.dnskeyProof.rrsig.signature // Already hex string
      ],
      [
        BigInt(abiObj.dnskeyProof.dnskey.flags),
        BigInt(abiObj.dnskeyProof.dnskey.protocol),
        BigInt(abiObj.dnskeyProof.dnskey.algorithm),
        dnskeyProofPublicKeyHex
      ]
    ],
    [
      abiObj.answerProof.nameWire, // Already hex string
      abiObj.answerProof.rrsetBytes, // Already hex string
      abiObj.answerProof.signedDataBytes, // Already hex string
      [
        BigInt(abiObj.answerProof.rrsig.typeCovered),
        BigInt(abiObj.answerProof.rrsig.algorithm),
        BigInt(abiObj.answerProof.rrsig.labels),
        BigInt(abiObj.answerProof.rrsig.originalTTL),
        BigInt(abiObj.answerProof.rrsig.expiration),
        BigInt(abiObj.answerProof.rrsig.inception),
        BigInt(abiObj.answerProof.rrsig.keyTag),
        abiObj.answerProof.rrsig.signerNameWire, // Already hex string
        abiObj.answerProof.rrsig.signature // Already hex string
      ],
      [
        BigInt(abiObj.answerProof.dnskey.flags),
        BigInt(abiObj.answerProof.dnskey.protocol),
        BigInt(abiObj.answerProof.dnskey.algorithm),
        answerProofPublicKeyHex
      ]
    ]
  ];

  return encodeAbiParameters(PROOF_BUNDLE_SCHEMA, packed);
}

async function handleCCIPRead(req, res) {
  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }

  if (req.method !== 'POST') {
    return sendJson(res, 405, { error: 'method_not_allowed' });
  }

  // In Vercel, req.body is already parsed
  const parsed = req.body || {};
  const { data } = parsed;
  if (typeof data !== 'string' || !data.startsWith('0x')) {
    return sendJson(res, 400, { error: 'missing_data_field', details: 'data must be hex string from OffchainLookup' });
  }

  let decoded;
  try {
    decoded = decodeDNSSECCallData(data);
  } catch (err) {
    return sendJson(res, 400, { error: 'invalid_calldata', details: err.message });
  }

  const typeName = QTYPE_TO_NAME[decoded.qtype];
  if (!typeName) {
    return sendJson(res, 400, { error: 'invalid_qtype', details: `unsupported qtype ${decoded.qtype}` });
  }

  // Log the incoming request
  console.log(`\n[CCIP-Read Request] ${new Date().toISOString()}`);
  console.log(`  DNS Name: ${decoded.qname}`);
  console.log(`  QType: ${decoded.qtype} (${typeName})`);
  console.log(`  Fetching DNSSEC proof...`);

  try {
    const proof = await runProofPromise(decoded.qname, typeName);
    if (!proof || !proof.abi) {
      console.log(`  ❌ Proof generation failed: missing abi section`);
      return sendJson(res, 500, { error: 'proof_generation_failed', details: 'missing abi section in proof bundle' });
    }

    let encoded;
    try {
      encoded = encodeProofBundle(proof.abi);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const isValidation = message.startsWith('invalid_');
      console.log(`  ❌ Encoding failed: ${message}`);
      return sendJson(res, isValidation ? 400 : 500, { error: isValidation ? 'invalid_proof_structure' : 'encoding_failed', details: message });
    }

    // Encode the question: (bytes qnameWire, uint16 qtype, uint16 qclass)
    // qclass is typically 1 (IN - Internet class)
    const qclass = 1;
    // Convert Buffer to hex string for encoding
    const qnameWireHex = '0x' + Buffer.from(decoded.qnameWire).toString('hex');
    const questionEncoded = encodeAbiParameters(
      parseAbiParameters('bytes qnameWire, uint16 qtype, uint16 qclass'),
      [qnameWireHex, decoded.qtype, qclass]
    );

    // Return both proof bundle and question: (bytes proofBundle, bytes question)
    const responseEncoded = encodeAbiParameters(
      parseAbiParameters('bytes proofBundle, bytes question'),
      [encoded, questionEncoded]
    );

    console.log(`  ✅ Proof bundle generated and encoded (${encoded.length} bytes)`);
    console.log(`  ✅ Question encoded (${questionEncoded.length} bytes)`);
    console.log(`  ✅ Returning response to resolver\n`);
    return sendJson(res, 200, { data: responseEncoded });
  } catch (err) {
    const status = err && err.code === 'proof_error' ? 500 : 500;
    console.log(`  ❌ Error: ${err.message || 'failed to build proof'}`);
    if (err.stderr) console.log(`  stderr: ${err.stderr}`);
    console.log('');
    return sendJson(res, status, {
      error: err.code || 'proof_generation_failed',
      details: err.message || 'failed to build proof',
      stderr: err.stderr,
      exitCode: err.exitCode
    });
  }
}


// Vercel serverless handler
export default async function handler(req, res) {
  addCors(res);

  if (!req.url) {
    return sendJson(res, 400, { error: 'invalid_request', details: 'invalid url' });
  }

  // Preflight
  if (req.method === 'OPTIONS' && (req.url.startsWith('/resolve') || req.url.startsWith('/ccip-read'))) {
    res.status(204).end();
    return;
  }

  if (req.method === 'GET' && req.url.startsWith('/health')) {
    return handleHealth(req, res);
  }

  if (req.method === 'GET' && req.url.startsWith('/resolve')) {
    return handleResolveGet(req, res);
  }

  if (req.method === 'POST' && req.url.startsWith('/resolve')) {
    return handleResolvePost(req, res);
  }

  if (req.url.startsWith('/ccip-read')) {
    return handleCCIPRead(req, res);
  }

  sendJson(res, 404, { error: 'not_found' });
}
