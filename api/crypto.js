import {
  constants,
  createHash,
  createPrivateKey,
  createPublicKey,
  privateDecrypt,
  publicEncrypt,
  randomBytes,
} from 'node:crypto';
import * as aes from '../lib/aes.js';

function requireKey(key, name) {
  if (typeof key !== 'string' || !key.trim()) throw new Error(`${name} không được để trống.`);
  return key;
}

function formatKey(key, type, name = type) {
  const value = requireKey(key, name).trim();
  if (value.includes('-----BEGIN')) return value;

  const base64 = value.replace(/\s+/g, '');
  const lines = base64.match(/.{1,64}/g);
  if (!lines) throw new Error(`${name} không hợp lệ.`);
  return `-----BEGIN ${type}-----\n${lines.join('\n')}\n-----END ${type}-----`;
}

function readCiphertext(value) {
  let blocks = value;
  if (typeof value === 'string') {
    const text = value.trim();
    if (text.startsWith('[')) {
      try {
        blocks = JSON.parse(text);
      } catch {
        throw new Error('Ciphertext RSA không hợp lệ.');
      }
    } else {
      blocks = text.split(/[\s,]+/).filter(Boolean);
    }
  }
  if (!Array.isArray(blocks)) throw new Error('Ciphertext RSA phải là mảng JSON.');
  if (blocks.some((block) => typeof block !== 'string')) {
    throw new Error('Mỗi block ciphertext RSA phải là chuỗi Base64.');
  }
  return blocks;
}

function aesKey(secretKey, isRawKey = false) {
  if (typeof secretKey !== 'string' || !secretKey) throw new Error('SECRET KEY không được để trống.');
  if (isRawKey) {
    const key = Buffer.from(secretKey, 'base64');
    if (key.length !== 32 || key.toString('base64') !== secretKey) throw new Error('AES key không hợp lệ.');
    return key;
  }
  return createHash('sha256').update(secretKey, 'utf8').digest();
}

function rsaEncrypt({ key, plaintext }) {
  const publicKey = createPublicKey(formatKey(key, 'PUBLIC KEY'));
  if (publicKey.asymmetricKeyType !== 'rsa') throw new Error('PUBLIC KEY phải là khóa RSA.');
  const input = Buffer.from(plaintext ?? '', 'utf8');
  const keyBytes = Math.ceil(publicKey.asymmetricKeyDetails.modulusLength / 8);
  // OAEP với SHA-256 dành 2 * 32 + 2 byte trong mỗi block RSA.
  const chunkSize = keyBytes - 2 * 32 - 2;
  const blockCount = input.length ? Math.ceil(input.length / chunkSize) : 1;
  const ciphertext = Array.from({ length: blockCount }, (_, index) => {
    const start = index * chunkSize;
    const block = input.length ? input.subarray(start, start + chunkSize) : Buffer.alloc(0);
    const encryptedBlock = publicEncrypt({
      key: publicKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    }, block);
    return encryptedBlock.toString('base64');
  });
  return { ciphertext };
}

function rsaDecrypt({ key, ciphertext }) {
  const privateKey = createPrivateKey(formatKey(key, 'PRIVATE KEY', 'SECRET KEY'));
  if (privateKey.asymmetricKeyType !== 'rsa') throw new Error('SECRET KEY phải là khóa RSA.');
  const plaintext = readCiphertext(ciphertext).map((block) => privateDecrypt({
    key: privateKey,
    padding: constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256',
  }, Buffer.from(block, 'base64')));
  return { plaintext: Buffer.concat(plaintext).toString('utf8') };
}

function aesEncrypt({ secretKey, plaintext, rawKey }) {
  const key = aesKey(secretKey, rawKey);
  const iv = randomBytes(16);
  const encrypted = aes.encryptText(plaintext ?? '', key, iv);
  return {
    iv: iv.toString('base64'),
    ciphertext: Buffer.from(encrypted.ciphertext, 'hex').toString('base64'),
  };
}

function aesDecrypt({ secretKey, ciphertext, rawKey }) {
  const key = aesKey(secretKey, rawKey);
  let envelope;
  if (typeof ciphertext === 'string') {
    const value = ciphertext.trim();
    if (value.startsWith('{')) {
      try {
        envelope = JSON.parse(value);
      } catch {
        throw new Error('Ciphertext AES không hợp lệ.');
      }
    } else {
      const separator = value.indexOf(':');
      if (separator < 1) throw new Error('Ciphertext AES không hợp lệ.');
      envelope = { iv: value.slice(0, separator), ciphertext: value.slice(separator + 1) };
    }
  } else {
    envelope = ciphertext;
  }
  if (!envelope || typeof envelope.iv !== 'string' || typeof envelope.ciphertext !== 'string') {
    throw new Error('Ciphertext AES cần có iv và ciphertext.');
  }
  const plaintext = aes.decryptText({
    iv: Buffer.from(envelope.iv, 'base64').toString('hex'),
    ciphertext: Buffer.from(envelope.ciphertext, 'base64').toString('hex'),
  }, key);
  return { plaintext };
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { action, payload = {} } = req.body || {};
  const operations = {
    'rsa-encrypt': rsaEncrypt,
    'rsa-decrypt': rsaDecrypt,
    'aes-encrypt': aesEncrypt,
    'aes-decrypt': aesDecrypt,
  };
  const operation = operations[action];
  if (!operation) return res.status(400).json({ error: `Unknown action: ${action}` });

  try {
    return res.status(200).json(operation(payload));
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
}
