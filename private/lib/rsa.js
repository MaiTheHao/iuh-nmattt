'use strict';

import { checkPrimeSync, generatePrimeSync } from 'node:crypto';

const ERR_NOT_BIGINT = (name) => `${name} must be a BigInt`;
const ERR_MODULUS_RANGE = 'modulus must be > 1';
const ERR_EXPONENT_RANGE = 'exponent must be >= 0';
const ERR_NO_MOD_INVERSE = 'Modular inverse does not exist';
const ERR_INVALID_PRIMES = 'p and q must be distinct prime BigInts (educational-size only)';
const ERR_INVALID_PUBLIC_EXPONENT = 'e must satisfy 1 < e < phi and gcd(e, phi) = 1';
const ERR_EXPECTED_PUBLIC_KEY = 'Expected public key { e, n }';
const ERR_EXPECTED_PRIVATE_KEY = 'Expected private key { d, n }';
const ERR_MESSAGE_RANGE = 'message must satisfy 0 <= message < n';
const ERR_CIPHERTEXT_RANGE = 'ciphertext must satisfy 0 <= ciphertext < n';
const ERR_DATA_BUFFER = 'data must be a Buffer';
const ERR_N_ENCRYPT_BYTES = 'n must be > 255 to encrypt byte values';
const ERR_CIPHERTEXT_ARRAY = 'ciphertextBlocks must be an array';
const ERR_N_RECOVER_BYTES = 'n must be > 255 to recover byte values';
const ERR_BYTE_MISMATCH = 'Recovered value is not a byte; ciphertext/key mismatch';

const ERRORS = {
  NOT_BIGINT: ERR_NOT_BIGINT,
  MODULUS_RANGE: ERR_MODULUS_RANGE,
  EXPONENT_RANGE: ERR_EXPONENT_RANGE,
  NO_MOD_INVERSE: ERR_NO_MOD_INVERSE,
  INVALID_PRIMES: ERR_INVALID_PRIMES,
  INVALID_PUBLIC_EXPONENT: ERR_INVALID_PUBLIC_EXPONENT,
  EXPECTED_PUBLIC_KEY: ERR_EXPECTED_PUBLIC_KEY,
  EXPECTED_PRIVATE_KEY: ERR_EXPECTED_PRIVATE_KEY,
  MESSAGE_RANGE: ERR_MESSAGE_RANGE,
  CIPHERTEXT_RANGE: ERR_CIPHERTEXT_RANGE,
  DATA_BUFFER: ERR_DATA_BUFFER,
  N_ENCRYPT_BYTES: ERR_N_ENCRYPT_BYTES,
  CIPHERTEXT_ARRAY: ERR_CIPHERTEXT_ARRAY,
  N_RECOVER_BYTES: ERR_N_RECOVER_BYTES,
  BYTE_MISMATCH: ERR_BYTE_MISMATCH,
};

// 1: Math primitives
function assertBigInt(value, name) {
  if (typeof value !== 'bigint') throw new TypeError(ERR_NOT_BIGINT(name));
}

function isPrime(n) {
  assertBigInt(n, 'n');
  return n >= 2n && checkPrimeSync(n);
}

function gcd(a, b) {
  while (b !== 0n) [a, b] = [b, a % b];
  return a < 0n ? -a : a;
}

function modPow(base, exponent, modulus) {
  assertBigInt(base, 'base');
  assertBigInt(exponent, 'exponent');
  assertBigInt(modulus, 'modulus');
  if (modulus <= 1n) throw new RangeError(ERR_MODULUS_RANGE);
  if (exponent < 0n) throw new RangeError(ERR_EXPONENT_RANGE);
  let result = 1n;
  base = ((base % modulus) + modulus) % modulus;
  while (exponent > 0n) {
    if (exponent & 1n) result = (result * base) % modulus;
    base = (base * base) % modulus;
    exponent >>= 1n;
  }
  return result;
}

function modInverse(a, modulus) {
  let oldR = a,
    r = modulus;
  let oldS = 1n,
    s = 0n;
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) throw new Error(ERR_NO_MOD_INVERSE);
  return ((oldS % modulus) + modulus) % modulus;
}

// 2: Key generation
function normalizePublicKey(key) {
  if (!key || key.e == null || key.n == null) throw new TypeError(ERR_EXPECTED_PUBLIC_KEY);
  return { e: BigInt(key.e), n: BigInt(key.n) };
}

function normalizePrivateKey(key) {
  if (!key || key.d == null || key.n == null) throw new TypeError(ERR_EXPECTED_PRIVATE_KEY);
  return { d: BigInt(key.d), n: BigInt(key.n) };
}

function generateKeyPair(p, q, e = 65537n) {
  if (p == null && q == null) {
    p = generatePrimeSync(16, { bigint: true });
    q = generatePrimeSync(16, { bigint: true });
    while (p === q) {
      q = generatePrimeSync(16, { bigint: true });
    }
  }

  assertBigInt(p, 'p');
  assertBigInt(q, 'q');
  assertBigInt(e, 'e');
  if (!isPrime(p) || !isPrime(q) || p === q) {
    throw new RangeError(ERR_INVALID_PRIMES);
  }
  const n = p * q;
  const phi = (p - 1n) * (q - 1n);
  if (e <= 1n || e >= phi || gcd(e, phi) !== 1n) {
    throw new RangeError(ERR_INVALID_PUBLIC_EXPONENT);
  }
  const d = modInverse(e, phi);
  return {
    publicKey: { e: e.toString(), n: n.toString() },
    privateKey: { d: d.toString(), n: n.toString() },
    parameters: { p: p.toString(), q: q.toString(), phi: phi.toString() },
  };
}

// 3: Integer cipher
function encryptInteger(message, publicKey) {
  assertBigInt(message, 'message');
  const { e, n } = normalizePublicKey(publicKey);
  if (message < 0n || message >= n) throw new RangeError(ERR_MESSAGE_RANGE);
  return modPow(message, e, n).toString();
}

function decryptInteger(ciphertext, privateKey) {
  const c = BigInt(ciphertext);
  const { d, n } = normalizePrivateKey(privateKey);
  if (c < 0n || c >= n) throw new RangeError(ERR_CIPHERTEXT_RANGE);
  return modPow(c, d, n);
}

// 4: Byte cipher
function encryptBytesForStudy(data, publicKey) {
  if (!Buffer.isBuffer(data)) throw new TypeError(ERR_DATA_BUFFER);
  const { n } = normalizePublicKey(publicKey);
  if (n <= 255n) throw new RangeError(ERR_N_ENCRYPT_BYTES);
  return data.length === 0 ? [] : Array.from(data, (byte) => encryptInteger(BigInt(byte), publicKey));
}

function decryptBytesForStudy(ciphertextBlocks, privateKey) {
  if (!Array.isArray(ciphertextBlocks)) throw new TypeError(ERR_CIPHERTEXT_ARRAY);
  const { n } = normalizePrivateKey(privateKey);
  if (n <= 255n) throw new RangeError(ERR_N_RECOVER_BYTES);
  return Buffer.from(
    ciphertextBlocks.map((block) => {
      const value = decryptInteger(block, privateKey);
      if (value > 255n) throw new Error(ERR_BYTE_MISMATCH);
      return Number(value);
    }),
  );
}

export {
  ERRORS,
  ERR_NOT_BIGINT,
  ERR_MODULUS_RANGE,
  ERR_EXPONENT_RANGE,
  ERR_NO_MOD_INVERSE,
  ERR_INVALID_PRIMES,
  ERR_INVALID_PUBLIC_EXPONENT,
  ERR_EXPECTED_PUBLIC_KEY,
  ERR_EXPECTED_PRIVATE_KEY,
  ERR_MESSAGE_RANGE,
  ERR_CIPHERTEXT_RANGE,
  ERR_DATA_BUFFER,
  ERR_N_ENCRYPT_BYTES,
  ERR_CIPHERTEXT_ARRAY,
  ERR_N_RECOVER_BYTES,
  ERR_BYTE_MISMATCH,
  assertBigInt,
  isPrime,
  isPrime as isPrimeSmall,
  gcd,
  modPow,
  modInverse,
  normalizePublicKey,
  normalizePrivateKey,
  generateKeyPair,
  encryptInteger,
  decryptInteger,
  encryptBytesForStudy,
  decryptBytesForStudy,
};
