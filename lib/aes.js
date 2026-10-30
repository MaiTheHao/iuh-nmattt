'use strict';

/**
 * aes.js — educational AES-CBC for Node.js 24 (CommonJS).
 * No external dependencies. AES block cipher and CBC mode are implemented here.
 *
 * SECURITY WARNING: CBC does not authenticate data. This module is for learning
 * and review, not production protection. Use a reviewed authenticated-encryption
 * implementation (for example AES-GCM) for real application data.
 */

const BLOCK_SIZE = 16;

function gfMul(a, b) {
  let result = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) result ^= a;
    const high = a & 0x80;
    a = (a << 1) & 0xff;
    if (high) a ^= 0x1b;
    b >>>= 1;
  }
  return result;
}
function gfPow(a, exponent) {
  let result = 1;
  while (exponent > 0) {
    if (exponent & 1) result = gfMul(result, a);
    a = gfMul(a, a);
    exponent >>>= 1;
  }
  return result;
}
function rotByte(x, n) {
  return ((x << n) | (x >>> (8 - n))) & 0xff;
}
function createSBoxes() {
  const sbox = new Uint8Array(256);
  const inverse = new Uint8Array(256);
  for (let x = 0; x < 256; x++) {
    const inv = x === 0 ? 0 : gfPow(x, 254);
    const y = inv ^ rotByte(inv, 1) ^ rotByte(inv, 2) ^ rotByte(inv, 3) ^ rotByte(inv, 4) ^ 0x63;
    sbox[x] = y;
    inverse[y] = x;
  }
  return { sbox, inverse };
}
const { sbox: SBOX, inverse: INV_SBOX } = createSBoxes();

function expandKey(key) {
  if (!Buffer.isBuffer(key) || ![16, 24, 32].includes(key.length)) {
    throw new TypeError('key must be a Buffer of 16, 24, or 32 bytes');
  }
  const nk = key.length / 4;
  const nr = nk + 6;
  const expanded = new Uint8Array(16 * (nr + 1));
  expanded.set(key);
  let generated = key.length;
  let rcon = 1;
  while (generated < expanded.length) {
    const temp = Array.from(expanded.slice(generated - 4, generated));
    if (generated % key.length === 0) {
      temp.push(temp.shift());
      for (let i = 0; i < 4; i++) temp[i] = SBOX[temp[i]];
      temp[0] ^= rcon;
      rcon = gfMul(rcon, 2);
    } else if (nk === 8 && generated % key.length === 16) {
      for (let i = 0; i < 4; i++) temp[i] = SBOX[temp[i]];
    }
    for (let i = 0; i < 4 && generated < expanded.length; i++, generated++) {
      expanded[generated] = expanded[generated - key.length] ^ temp[i];
    }
  }
  const roundKeys = [];
  for (let r = 0; r <= nr; r++) roundKeys.push(expanded.slice(r * 16, (r + 1) * 16));
  return { roundKeys, nr };
}
function addRoundKey(s, k) {
  for (let i = 0; i < 16; i++) s[i] ^= k[i];
}
function subBytes(s) {
  for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]];
}
function invSubBytes(s) {
  for (let i = 0; i < 16; i++) s[i] = INV_SBOX[s[i]];
}
function shiftRows(s) {
  const old = s.slice();
  for (let r = 1; r < 4; r++) for (let c = 0; c < 4; c++) s[r + 4 * c] = old[r + 4 * ((c + r) % 4)];
}
function invShiftRows(s) {
  const old = s.slice();
  for (let r = 1; r < 4; r++) for (let c = 0; c < 4; c++) s[r + 4 * c] = old[r + 4 * ((c - r + 4) % 4)];
}
function mixColumns(s) {
  for (let c = 0; c < 4; c++) {
    const i = c * 4,
      a = [s[i], s[i + 1], s[i + 2], s[i + 3]];
    s[i] = gfMul(a[0], 2) ^ gfMul(a[1], 3) ^ a[2] ^ a[3];
    s[i + 1] = a[0] ^ gfMul(a[1], 2) ^ gfMul(a[2], 3) ^ a[3];
    s[i + 2] = a[0] ^ a[1] ^ gfMul(a[2], 2) ^ gfMul(a[3], 3);
    s[i + 3] = gfMul(a[0], 3) ^ a[1] ^ a[2] ^ gfMul(a[3], 2);
  }
}
function invMixColumns(s) {
  for (let c = 0; c < 4; c++) {
    const i = c * 4,
      a = [s[i], s[i + 1], s[i + 2], s[i + 3]];
    s[i] = gfMul(a[0], 14) ^ gfMul(a[1], 11) ^ gfMul(a[2], 13) ^ gfMul(a[3], 9);
    s[i + 1] = gfMul(a[0], 9) ^ gfMul(a[1], 14) ^ gfMul(a[2], 11) ^ gfMul(a[3], 13);
    s[i + 2] = gfMul(a[0], 13) ^ gfMul(a[1], 9) ^ gfMul(a[2], 14) ^ gfMul(a[3], 11);
    s[i + 3] = gfMul(a[0], 11) ^ gfMul(a[1], 13) ^ gfMul(a[2], 9) ^ gfMul(a[3], 14);
  }
}
function encryptBlock(block, schedule) {
  const s = Uint8Array.from(block),
    { roundKeys, nr } = schedule;
  addRoundKey(s, roundKeys[0]);
  for (let r = 1; r < nr; r++) {
    subBytes(s);
    shiftRows(s);
    mixColumns(s);
    addRoundKey(s, roundKeys[r]);
  }
  subBytes(s);
  shiftRows(s);
  addRoundKey(s, roundKeys[nr]);
  return Buffer.from(s);
}
function decryptBlock(block, schedule) {
  const s = Uint8Array.from(block),
    { roundKeys, nr } = schedule;
  addRoundKey(s, roundKeys[nr]);
  for (let r = nr - 1; r > 0; r--) {
    invShiftRows(s);
    invSubBytes(s);
    addRoundKey(s, roundKeys[r]);
    invMixColumns(s);
  }
  invShiftRows(s);
  invSubBytes(s);
  addRoundKey(s, roundKeys[0]);
  return Buffer.from(s);
}
function xorBlock(a, b) {
  const out = Buffer.alloc(BLOCK_SIZE);
  for (let i = 0; i < BLOCK_SIZE; i++) out[i] = a[i] ^ b[i];
  return out;
}
function pkcs7Pad(data) {
  const n = BLOCK_SIZE - (data.length % BLOCK_SIZE);
  return Buffer.concat([data, Buffer.alloc(n, n)]);
}
function pkcs7Unpad(data) {
  if (data.length === 0 || data.length % BLOCK_SIZE !== 0) throw new Error('Invalid padded plaintext length');
  const n = data[data.length - 1];
  if (n < 1 || n > BLOCK_SIZE) throw new Error('Invalid PKCS#7 padding');
  for (let i = data.length - n; i < data.length; i++) if (data[i] !== n) throw new Error('Invalid PKCS#7 padding');
  return data.subarray(0, data.length - n);
}
function validateIv(iv) {
  if (!Buffer.isBuffer(iv) || iv.length !== BLOCK_SIZE) throw new TypeError('iv must be a 16-byte Buffer');
}
function aesCbcEncrypt(plaintext, key, iv) {
  if (!Buffer.isBuffer(plaintext)) throw new TypeError('plaintext must be a Buffer');
  validateIv(iv);
  const schedule = expandKey(key),
    padded = pkcs7Pad(plaintext),
    out = Buffer.alloc(padded.length);
  let previous = Buffer.from(iv);
  for (let offset = 0; offset < padded.length; offset += BLOCK_SIZE) {
    const encrypted = encryptBlock(xorBlock(padded.subarray(offset, offset + BLOCK_SIZE), previous), schedule);
    encrypted.copy(out, offset);
    previous = encrypted;
  }
  return out;
}
function aesCbcDecrypt(ciphertext, key, iv) {
  if (!Buffer.isBuffer(ciphertext)) throw new TypeError('ciphertext must be a Buffer');
  validateIv(iv);
  if (ciphertext.length === 0 || ciphertext.length % BLOCK_SIZE !== 0) throw new Error('ciphertext must contain complete AES blocks');
  const schedule = expandKey(key),
    out = Buffer.alloc(ciphertext.length);
  let previous = Buffer.from(iv);
  for (let offset = 0; offset < ciphertext.length; offset += BLOCK_SIZE) {
    const block = ciphertext.subarray(offset, offset + BLOCK_SIZE);
    xorBlock(decryptBlock(block, schedule), previous).copy(out, offset);
    previous = Buffer.from(block);
  }
  return pkcs7Unpad(out);
}

// String/JSON-friendly wrappers. IV must be supplied by the caller and stored
// alongside ciphertext. Use a fresh unpredictable IV for every encryption.
function encryptText(text, key, iv) {
  if (typeof text !== 'string') throw new TypeError('text must be a string');
  const ciphertext = aesCbcEncrypt(Buffer.from(text, 'utf8'), key, iv);
  return { algorithm: `AES-${key.length * 8}-CBC`, iv: iv.toString('hex'), ciphertext: ciphertext.toString('hex') };
}
function decryptText(envelope, key) {
  if (!envelope || typeof envelope.iv !== 'string' || typeof envelope.ciphertext !== 'string') {
    throw new TypeError('envelope must contain hex iv and ciphertext');
  }
  const iv = Buffer.from(envelope.iv, 'hex');
  const ciphertext = Buffer.from(envelope.ciphertext, 'hex');
  if (iv.toString('hex') !== envelope.iv.toLowerCase() || ciphertext.toString('hex') !== envelope.ciphertext.toLowerCase()) {
    throw new Error('iv/ciphertext must be valid even-length hex strings');
  }
  return aesCbcDecrypt(ciphertext, key, iv).toString('utf8');
}

export { aesCbcEncrypt, aesCbcDecrypt, encryptText, decryptText };
