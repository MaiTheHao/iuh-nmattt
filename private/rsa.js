import { generatePrimeSync } from 'node:crypto';
import { bytesToBigInt, bigIntToBytes, gcd, keyByteLength, modInverse, modPow } from './math.js';

const E = 65537n;
const PUBLIC_KEY_PREFIX = 1;
const PRIVATE_KEY_PREFIX = 2;

function generateKeyPair(bits = 256) {
  const half = bits / 2;

  for (;;) {
    const p = generatePrimeSync(half, { bigint: true });
    const q = generatePrimeSync(half, { bigint: true });
    if (p === q) continue;

    const n = p * q;
    const phi = (p - 1n) * (q - 1n);
    if (gcd(E, phi) !== 1n) continue;

    const d = modInverse(E, phi);
    const keyLength = keyByteLength(n);

    return {
      publicKey: encodeKey(PUBLIC_KEY_PREFIX, bigIntToBytes(n, keyLength)),
      privateKey: encodeKey(PRIVATE_KEY_PREFIX, bigIntToBytes(n, keyLength), bigIntToBytes(d, keyLength)),
    };
  }
}

function encodeKey(prefix, ...parts) {
  return Buffer.concat([Buffer.from([prefix]), ...parts]).toString('base64');
}

function fromBase64(text, label) {
  const clean = String(text ?? '').replace(/\s+/g, '');

  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(clean) || clean.length % 4 !== 0) {
    throw new Error(`${label} phải là chuỗi base64 hợp lệ.`);
  }

  return Buffer.from(clean, 'base64');
}

function parsePublicKey(text) {
  const bytes = fromBase64(text, 'Public key');
  if (bytes[0] !== PUBLIC_KEY_PREFIX) throw new Error('Đây không phải public key.');

  const n = bytesToBigInt(bytes.subarray(1));

  if (keyByteLength(n) !== bytes.length - 1) throw new Error('Public key không hợp lệ.');
  return { n, e: E };
}

function parsePrivateKey(text) {
  const bytes = fromBase64(text, 'Private key');
  if (bytes[0] !== PRIVATE_KEY_PREFIX) throw new Error('Đây không phải private key.');

  const body = bytes.subarray(1);
  if (body.length !== 64) throw new Error('Private key không hợp lệ.');

  const half = body.length / 2;
  const n = bytesToBigInt(body.subarray(0, half));
  const d = bytesToBigInt(body.subarray(half));

  if (keyByteLength(n) !== half) throw new Error('Private key không hợp lệ.');
  return { n, d };
}

function encryptText(text, publicKeyText) {
  if (typeof text !== 'string') throw new TypeError('Plaintext phải là chuỗi.');

  const { n, e } = parsePublicKey(publicKeyText);

  const keyLength = keyByteLength(n);
  const blockSize = keyLength - 1;
  if (blockSize < 1) throw new Error('Modulus n quá nhỏ.');

  const data = Buffer.from(text, 'utf8');
  const ciphertext = [];

  for (let offset = 0; offset < data.length; offset += blockSize) {
    const m = bytesToBigInt(data.subarray(offset, offset + blockSize));
    ciphertext.push(bigIntToBytes(modPow(m, e, n), keyLength).toString('base64'));
  }

  return ciphertext.join(' ');
}

function decryptText(ciphertext, privateKeyText) {
  const { n, d } = parsePrivateKey(privateKeyText);

  const input = String(ciphertext ?? '');
  const blocks = input.split(/\s+/).filter(Boolean);
  if (!blocks.length) return '';

  const keyLength = keyByteLength(n);
  const blockSize = keyLength - 1;
  if (blockSize < 1) throw new Error('Modulus n quá nhỏ.');

  const parts = [];

  for (const block of blocks) {
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(block) || block.length % 4 !== 0) {
      throw new Error('Ciphertext phải là base64 hợp lệ.');
    }

    const bytes = Buffer.from(block, 'base64');
    if (bytes.length !== keyLength) {
      throw new Error(`Mỗi block ciphertext phải dài đúng ${keyLength} byte.`);
    }

    const c = bytesToBigInt(bytes);
    if (c >= n) throw new Error('Giá trị ciphertext không hợp lệ.');

    const plain = bigIntToBytes(modPow(c, d, n));
    if (plain.length > blockSize) {
      throw new Error('Giải mã thất bại: sai khóa hoặc ciphertext bị hỏng.');
    }

    parts.push(plain);
  }

  return Buffer.concat(parts).toString('utf8');
}

export { generateKeyPair, encryptText, decryptText };
