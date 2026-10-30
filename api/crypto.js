import { randomBytes } from 'node:crypto';
import * as aes from '../lib/aes.js';
import * as rsa from '../lib/rsa.js';

function toBigInt(value, name) {
  try {
    return BigInt(value);
  } catch {
    throw new Error(`Invalid ${name}: ${value}`);
  }
}

function parseCiphertext(input) {
  if (Array.isArray(input)) return input.map(String);
  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (trimmed.startsWith('[')) {
      const parsed = JSON.parse(trimmed);
      if (!Array.isArray(parsed)) throw new Error('Ciphertext JSON must be an array');
      return parsed.map(String);
    }
    return trimmed
      .split(/[\s,]+/)
      .filter(Boolean)
      .map(String);
  }
  throw new Error('Ciphertext must be an array or string');
}

async function dispatch(action, payload) {
  switch (action) {
    case 'rsa-generate-keypair':
      return rsa.generateKeyPair(toBigInt(payload.p, 'p'), toBigInt(payload.q, 'q'), toBigInt(payload.e, 'e'));

    case 'rsa-encrypt': {
      const keys = rsa.generateKeyPair(toBigInt(payload.p, 'p'), toBigInt(payload.q, 'q'), toBigInt(payload.e, 'e'));
      const ciphertext = rsa.encryptBytesForStudy(Buffer.from(payload.message ?? '', 'utf8'), keys.publicKey);
      return { ...keys, ciphertext };
    }

    case 'rsa-decrypt': {
      const ciphertext = parseCiphertext(payload.ciphertext);
      const plaintext = rsa.decryptBytesForStudy(ciphertext, {
        d: payload.d,
        n: payload.n,
      });
      return { plaintext: plaintext.toString('utf8') };
    }

    case 'aes-encrypt': {
      const key = payload.key ? Buffer.from(payload.key, 'base64') : randomBytes(32);
      const iv = payload.iv ? Buffer.from(payload.iv, 'base64') : randomBytes(16);
      const envelope = aes.encryptText(payload.message ?? '', key, iv);
      return {
        algorithm: envelope.algorithm,
        key: key.toString('base64'),
        iv: iv.toString('base64'),
        ciphertext: Buffer.from(envelope.ciphertext, 'hex').toString('base64'),
      };
    }

    case 'aes-decrypt': {
      const key = Buffer.from(payload.key, 'base64');
      const envelope = {
        iv: Buffer.from(payload.iv, 'base64').toString('hex'),
        ciphertext: Buffer.from(payload.ciphertext, 'base64').toString('hex'),
      };
      return { plaintext: aes.decryptText(envelope, key) };
    }

    case 'hybrid-encrypt': {
      const keys = rsa.generateKeyPair(toBigInt(payload.p, 'p'), toBigInt(payload.q, 'q'), toBigInt(payload.e, 'e'));
      const aesKey = randomBytes(32);
      const iv = randomBytes(16);
      const envelope = aes.encryptText(payload.message ?? '', aesKey, iv);
      const wrappedKey = rsa.encryptBytesForStudy(aesKey, keys.publicKey);
      return {
        ...keys,
        iv: iv.toString('base64'),
        ciphertext: Buffer.from(envelope.ciphertext, 'hex').toString('base64'),
        wrappedKey,
      };
    }

    case 'hybrid-decrypt': {
      const wrappedKey = parseCiphertext(payload.wrappedKey);
      const aesKey = rsa.decryptBytesForStudy(wrappedKey, {
        d: payload.d,
        n: payload.n,
      });
      const envelope = {
        iv: Buffer.from(payload.iv, 'base64').toString('hex'),
        ciphertext: Buffer.from(payload.ciphertext, 'base64').toString('hex'),
      };
      return { plaintext: aes.decryptText(envelope, aesKey) };
    }

    default:
      throw new Error(`Unknown action: ${action}`);
  }
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { action, payload } = req.body || {};
    if (!action) throw new Error('Missing action');
    const result = await dispatch(action, payload || {});
    return res.status(200).json(result);
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
}
