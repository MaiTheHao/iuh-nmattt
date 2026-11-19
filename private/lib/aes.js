'use strict';

import { timingSafeEqual } from 'node:crypto';

const BLOCK_SIZE = 16;

const ERR_INVALID_KEY = 'key must be a Buffer of 16, 24, or 32 bytes';
const ERR_INVALID_IV = 'iv must be a 16-byte Buffer';
const ERR_INVALID_PLAINTEXT = 'plaintext must be a Buffer';
const ERR_INVALID_CIPHERTEXT = 'ciphertext must be a Buffer';
const ERR_INCOMPLETE_BLOCKS = 'ciphertext must contain complete AES blocks';
const ERR_INVALID_PADDED_LENGTH = 'Invalid padded plaintext length';
const ERR_INVALID_PADDING = 'Invalid PKCS#7 padding';
const ERR_INVALID_TEXT = 'text must be a string';
const ERR_INVALID_ENVELOPE = 'envelope must contain hex iv and ciphertext';
const ERR_INVALID_HEX_STRING = 'iv/ciphertext must be valid even-length hex strings';

const ERRORS = {
  INVALID_KEY: ERR_INVALID_KEY,
  INVALID_IV: ERR_INVALID_IV,
  INVALID_PLAINTEXT: ERR_INVALID_PLAINTEXT,
  INVALID_CIPHERTEXT: ERR_INVALID_CIPHERTEXT,
  INCOMPLETE_BLOCKS: ERR_INCOMPLETE_BLOCKS,
  INVALID_PADDED_LENGTH: ERR_INVALID_PADDED_LENGTH,
  INVALID_PADDING: ERR_INVALID_PADDING,
  INVALID_TEXT: ERR_INVALID_TEXT,
  INVALID_ENVELOPE: ERR_INVALID_ENVELOPE,
  INVALID_HEX_STRING: ERR_INVALID_HEX_STRING,
};

// 1: Galois Field & S-Box
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

// 2: Key expansion
function expandKey(key) {
  if (!Buffer.isBuffer(key) || ![16, 24, 32].includes(key.length)) {
    throw new TypeError(ERR_INVALID_KEY);
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
  for (let r = 0; r <= nr; r++) roundKeys.push(expanded.subarray(r * 16, (r + 1) * 16));
  return { roundKeys, nr };
}

// 3: Round transformations
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

// 4: Block cipher
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

// 5: PKCS#7 padding & block utils
function xorBlock(a, b) {
  const out = Buffer.allocUnsafe(BLOCK_SIZE);
  for (let i = 0; i < BLOCK_SIZE; i++) out[i] = a[i] ^ b[i];
  return out;
}

function validateIv(iv) {
  if (!Buffer.isBuffer(iv) || iv.length !== BLOCK_SIZE) {
    throw new TypeError(ERR_INVALID_IV);
  }
}

function pkcs7Pad(data) {
  const n = BLOCK_SIZE - (data.length % BLOCK_SIZE);
  return Buffer.concat([data, Buffer.alloc(n, n)]);
}

function pkcs7Unpad(data) {
  if (data.length === 0 || data.length % BLOCK_SIZE !== 0) {
    throw new Error(ERR_INVALID_PADDED_LENGTH);
  }
  const n = data[data.length - 1];
  if (n < 1 || n > BLOCK_SIZE) {
    throw new Error(ERR_INVALID_PADDING);
  }
  const pad = data.subarray(data.length - n);
  if (!timingSafeEqual(pad, Buffer.alloc(n, n))) {
    throw new Error(ERR_INVALID_PADDING);
  }
  return data.subarray(0, data.length - n);
}

// 6: AES-CBC mode
function aesCbcEncrypt(plaintext, key, iv) {
  if (!Buffer.isBuffer(plaintext)) {
    throw new TypeError(ERR_INVALID_PLAINTEXT);
  }
  validateIv(iv);
  const schedule = expandKey(key);
  const padded = pkcs7Pad(plaintext);
  const out = Buffer.alloc(padded.length);
  let previous = iv;
  for (let offset = 0; offset < padded.length; offset += BLOCK_SIZE) {
    const block = padded.subarray(offset, offset + BLOCK_SIZE);
    const encrypted = encryptBlock(xorBlock(block, previous), schedule);
    encrypted.copy(out, offset);
    previous = encrypted;
  }
  return out;
}

function aesCbcDecrypt(ciphertext, key, iv) {
  if (!Buffer.isBuffer(ciphertext)) {
    throw new TypeError(ERR_INVALID_CIPHERTEXT);
  }
  validateIv(iv);
  if (ciphertext.length === 0 || ciphertext.length % BLOCK_SIZE !== 0) {
    throw new Error(ERR_INCOMPLETE_BLOCKS);
  }
  const schedule = expandKey(key);
  const out = Buffer.alloc(ciphertext.length);
  let previous = iv;
  for (let offset = 0; offset < ciphertext.length; offset += BLOCK_SIZE) {
    const block = ciphertext.subarray(offset, offset + BLOCK_SIZE);
    const decrypted = xorBlock(decryptBlock(block, schedule), previous);
    decrypted.copy(out, offset);
    previous = block;
  }
  return pkcs7Unpad(out);
}

// 7: Text API
function encryptText(text, key, iv) {
  if (typeof text !== 'string') {
    throw new TypeError(ERR_INVALID_TEXT);
  }
  const ciphertext = aesCbcEncrypt(Buffer.from(text, 'utf8'), key, iv);
  return { algorithm: `AES-${key.length * 8}-CBC`, iv: iv.toString('hex'), ciphertext: ciphertext.toString('hex') };
}

function decryptText(envelope, key) {
  if (!envelope || typeof envelope.iv !== 'string' || typeof envelope.ciphertext !== 'string') {
    throw new TypeError(ERR_INVALID_ENVELOPE);
  }
  const iv = Buffer.from(envelope.iv, 'hex');
  const ciphertext = Buffer.from(envelope.ciphertext, 'hex');
  if (iv.toString('hex') !== envelope.iv.toLowerCase() || ciphertext.toString('hex') !== envelope.ciphertext.toLowerCase()) {
    throw new Error(ERR_INVALID_HEX_STRING);
  }
  return aesCbcDecrypt(ciphertext, key, iv).toString('utf8');
}

export {
  BLOCK_SIZE,
  ERRORS,
  ERR_INVALID_KEY,
  ERR_INVALID_IV,
  ERR_INVALID_PLAINTEXT,
  ERR_INVALID_CIPHERTEXT,
  ERR_INCOMPLETE_BLOCKS,
  ERR_INVALID_PADDED_LENGTH,
  ERR_INVALID_PADDING,
  ERR_INVALID_TEXT,
  ERR_INVALID_ENVELOPE,
  ERR_INVALID_HEX_STRING,
  gfMul,
  gfPow,
  rotByte,
  createSBoxes,
  SBOX,
  INV_SBOX,
  expandKey,
  addRoundKey,
  subBytes,
  invSubBytes,
  shiftRows,
  invShiftRows,
  mixColumns,
  invMixColumns,
  encryptBlock,
  decryptBlock,
  xorBlock,
  validateIv,
  pkcs7Pad,
  pkcs7Unpad,
  aesCbcEncrypt,
  aesCbcDecrypt,
  encryptText,
  decryptText,
};
