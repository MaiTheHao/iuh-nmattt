function gcd(a, b) {
  while (b !== 0n) [a, b] = [b, a % b];
  return a < 0n ? -a : a;
}

function modPow(base, exponent, modulus) {
  let result = 1n;
  let b = base % modulus;
  if (b < 0n) b += modulus;

  while (exponent > 0n) {
    if (exponent % 2n === 1n) result = (result * b) % modulus;
    b = (b * b) % modulus;
    exponent = exponent / 2n;
  }

  return result;
}

function modInverse(a, modulus) {
  let oldR = a;
  let r = modulus;
  let oldS = 1n;
  let s = 0n;

  while (r !== 0n) {
    const quotient = oldR / r;
    [oldR, r] = [r, oldR - quotient * r];
    [oldS, s] = [s, oldS - quotient * s];
  }

  if (oldR !== 1n) throw new Error('Không tồn tại nghịch đảo modulo.');
  return ((oldS % modulus) + modulus) % modulus;
}

function keyByteLength(n) {
  return Math.ceil(n.toString(2).length / 8);
}

function bytesToBigInt(bytes) {
  let value = 0n;
  
  for (const byte of bytes) {
    value = value * 256n + BigInt(byte);
  }
  return value;
}

function bigIntToBytes(value, length = 0) {
  const bytes = [];

  // Convert BigInt value -> Mảng các bytes (1byte = 8bit <=> n = 2^8 = 256)
  while (value > 0n) {
    bytes.unshift(Number(value % 256n));
    value /= 256n;
  }

  // Chèn để mảng bytes đủ `length`
  while (bytes.length < length) bytes.unshift(0);

  return Buffer.from(bytes);
}

export { gcd, modPow, modInverse, keyByteLength, bytesToBigInt, bigIntToBytes };
