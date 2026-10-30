'use strict';

function assertBigInt(value, name) {
  if (typeof value !== 'bigint') throw new TypeError(`${name} must be a BigInt`);
}

function gcd(a, b) {
  while (b !== 0n) [a, b] = [b, a % b];
  return a < 0n ? -a : a;
}

function modPow(base, exponent, modulus) {
  assertBigInt(base, 'base');
  assertBigInt(exponent, 'exponent');
  assertBigInt(modulus, 'modulus');
  if (modulus <= 1n) throw new RangeError('modulus must be > 1');
  if (exponent < 0n) throw new RangeError('exponent must be >= 0');
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
  if (oldR !== 1n) throw new Error('Modular inverse does not exist');
  return ((oldS % modulus) + modulus) % modulus;
}

// Trial division is intentionally simple and only suitable for small examples.
function isPrimeSmall(n) {
  assertBigInt(n, 'n');
  if (n < 2n) return false;
  if (n === 2n || n === 3n) return true;
  if (n % 2n === 0n) return false;
  for (let d = 3n; d * d <= n; d += 2n) {
    if (n % d === 0n) return false;
  }
  return true;
}

function generateKeyPair(p, q, e = 65537n) {
  assertBigInt(p, 'p');
  assertBigInt(q, 'q');
  assertBigInt(e, 'e');
  if (!isPrimeSmall(p) || !isPrimeSmall(q) || p === q) {
    throw new RangeError('p and q must be distinct prime BigInts (educational-size only)');
  }
  const n = p * q;
  const phi = (p - 1n) * (q - 1n);
  if (e <= 1n || e >= phi || gcd(e, phi) !== 1n) {
    throw new RangeError('e must satisfy 1 < e < phi and gcd(e, phi) = 1');
  }
  const d = modInverse(e, phi);
  return {
    publicKey: { e: e.toString(), n: n.toString() },
    privateKey: { d: d.toString(), n: n.toString() },
    parameters: { p: p.toString(), q: q.toString(), phi: phi.toString() },
  };
}

function normalizePublicKey(key) {
  if (!key || key.e == null || key.n == null) throw new TypeError('Expected public key { e, n }');
  return { e: BigInt(key.e), n: BigInt(key.n) };
}
function normalizePrivateKey(key) {
  if (!key || key.d == null || key.n == null) throw new TypeError('Expected private key { d, n }');
  return { d: BigInt(key.d), n: BigInt(key.n) };
}

function encryptInteger(message, publicKey) {
  assertBigInt(message, 'message');
  const { e, n } = normalizePublicKey(publicKey);
  if (message < 0n || message >= n) throw new RangeError('message must satisfy 0 <= message < n');
  return modPow(message, e, n).toString();
}

function decryptInteger(ciphertext, privateKey) {
  const c = BigInt(ciphertext);
  const { d, n } = normalizePrivateKey(privateKey);
  if (c < 0n || c >= n) throw new RangeError('ciphertext must satisfy 0 <= ciphertext < n');
  return modPow(c, d, n);
}

// Convenience byte-oriented demo API. Each byte is encrypted independently.
// This is deliberately NOT a secure text-encryption format: no padding and
// deterministic per-byte RSA make it unsuitable for real applications.
function encryptBytesForStudy(data, publicKey) {
  if (!Buffer.isBuffer(data)) throw new TypeError('data must be a Buffer');
  const { n } = normalizePublicKey(publicKey);
  if (n <= 255n) throw new RangeError('n must be > 255 to encrypt byte values');
  return data.length === 0 ? [] : Array.from(data, (byte) => encryptInteger(BigInt(byte), publicKey));
}

function decryptBytesForStudy(ciphertextBlocks, privateKey) {
  if (!Array.isArray(ciphertextBlocks)) throw new TypeError('ciphertextBlocks must be an array');
  const { n } = normalizePrivateKey(privateKey);
  if (n <= 255n) throw new RangeError('n must be > 255 to recover byte values');
  const bytes = ciphertextBlocks.map((block) => {
    const value = decryptInteger(block, privateKey);
    if (value > 255n) throw new Error('Recovered value is not a byte; ciphertext/key mismatch');
    return Number(value);
  });
  return Buffer.from(bytes);
}

export { gcd, modPow, modInverse, isPrimeSmall, generateKeyPair, encryptInteger, decryptInteger, encryptBytesForStudy, decryptBytesForStudy };
