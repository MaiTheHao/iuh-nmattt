import { checkPrimeSync, createPrivateKey, createPublicKey, generatePrimeSync } from 'node:crypto';

const PUBLIC_EXPONENT = 65537n;

function gcd(a, b) {
  while (b !== 0n) [a, b] = [b, a % b];
  return a < 0n ? -a : a;
}

function modPow(base, exponent, modulus) {
  let result = 1n;
  let b = ((base % modulus) + modulus) % modulus;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus;
    b = (b * b) % modulus;
    e >>= 1n;
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
  if (oldR !== 1n) throw new Error('Không tồn tại nghịch đảo modulo.');
  return ((oldS % modulus) + modulus) % modulus;
}

function isPrime(n) {
  return typeof n === 'bigint' && n >= 2n && checkPrimeSync(n);
}

function toBytes(value) {
  const hex = value.toString(16);
  return Buffer.from(hex.length % 2 ? `0${hex}` : hex, 'hex');
}

function fromBytes(bytes) {
  return bytes.length ? BigInt(`0x${bytes.toString('hex')}`) : 0n;
}

function keyByteLength(n) {
  return Math.ceil(n.toString(2).length / 8);
}

function toFixedBytes(value, length) {
  const bytes = toBytes(value);
  if (bytes.length > length) throw new Error('Giá trị vượt quá độ dài khóa.');
  return Buffer.concat([Buffer.alloc(length - bytes.length), bytes]);
}

function buildKeyPair(p, q, e = PUBLIC_EXPONENT) {
  if (!isPrime(p) || !isPrime(q) || p === q) {
    throw new Error('p, q phải là số nguyên tố phân biệt.');
  }

  const n = p * q;
  const phi = (p - 1n) * (q - 1n);

  if (gcd(e, phi) !== 1n) {
    throw new Error('gcd(e, phi) phải bằng 1.');
  }

  const d = modInverse(e, phi);

  const privateKeyObj = createPrivateKey({
    format: 'jwk',
    key: {
      kty: 'RSA',
      n: toBytes(n).toString('base64url'),
      e: toBytes(e).toString('base64url'),
      d: toBytes(d).toString('base64url'),
      p: toBytes(p).toString('base64url'),
      q: toBytes(q).toString('base64url'),
      dp: toBytes(d % (p - 1n)).toString('base64url'),
      dq: toBytes(d % (q - 1n)).toString('base64url'),
      qi: toBytes(modInverse(q, p)).toString('base64url'),
    },
  });

  return {
    publicKey: createPublicKey(privateKeyObj).export({ type: 'spki', format: 'pem' }),
    privateKey: privateKeyObj.export({ type: 'pkcs8', format: 'pem' }),
  };
}

function generateKeyPair(bits = 2048) {
  const primeBits = bits / 2;
  for (let i = 0; i < 10; i++) {
    const p = generatePrimeSync(primeBits, { bigint: true });
    let q = generatePrimeSync(primeBits, { bigint: true });
    while (q === p) {
      q = generatePrimeSync(primeBits, { bigint: true });
    }
    try {
      return buildKeyPair(p, q, PUBLIC_EXPONENT);
    } catch {
      continue;
    }
  }
  throw new Error('Không thể sinh cặp khóa RSA.');
}

function formatPem(key, type) {
  const text = String(key || '').trim();
  if (text.includes('-----BEGIN')) return text;
  const lines = text.replace(/\s+/g, '').match(/.{1,64}/g);
  if (!lines) throw new Error('Khóa RSA không hợp lệ.');
  return `-----BEGIN ${type}-----\n${lines.join('\n')}\n-----END ${type}-----`;
}

function parseKey(key) {
  if (key && typeof key === 'object' && key.n != null) {
    return {
      n: BigInt(key.n),
      e: key.e != null ? BigInt(key.e) : null,
      d: key.d != null ? BigInt(key.d) : null,
    };
  }

  if (typeof key === 'string' && key.trim().startsWith('{')) {
    try {
      return parseKey(JSON.parse(key));
    } catch {}
  }

  for (const type of ['PRIVATE KEY', 'PUBLIC KEY']) {
    try {
      const pem = formatPem(key, type);
      const keyObj = type === 'PRIVATE KEY' ? createPrivateKey(pem) : createPublicKey(pem);
      if (keyObj.asymmetricKeyType !== 'rsa') continue;
      const jwk = keyObj.export({ format: 'jwk' });
      return {
        n: fromBytes(Buffer.from(jwk.n, 'base64url')),
        e: jwk.e ? fromBytes(Buffer.from(jwk.e, 'base64url')) : null,
        d: jwk.d ? fromBytes(Buffer.from(jwk.d, 'base64url')) : null,
      };
    } catch {}
  }

  throw new Error('Khóa RSA không hợp lệ.');
}

function encryptText(text, publicKey) {
  if (typeof text !== 'string') {
    throw new TypeError('Plaintext phải là chuỗi.');
  }

  const { e, n } = parseKey(publicKey);
  if (e == null) throw new Error('Khóa công khai không hợp lệ.');

  const data = Buffer.from(text, 'utf8');
  const keyBytes = keyByteLength(n);
  const blockSize = Math.max(1, keyBytes - 1);

  const ciphertext = [];
  for (let offset = 0; offset < data.length; offset += blockSize) {
    const chunk = data.subarray(offset, offset + blockSize);
    const m = fromBytes(chunk);
    ciphertext.push(toFixedBytes(modPow(m, e, n), keyBytes).toString('base64'));
  }

  return { ciphertext };
}

function decodeBlocks(input) {
  return input
    .split(/\s+/)
    .filter(Boolean)
    .map((block) => {
      if (!/^[A-Za-z0-9+/]+={0,2}$/.test(block) || block.length % 4 !== 0) {
        throw new Error('Giá trị ciphertext không hợp lệ.');
      }
      return fromBytes(Buffer.from(block, 'base64'));
    });
}

function decryptText(ciphertext, privateKey) {
  const { d, n } = parseKey(privateKey);
  if (d == null) throw new Error('Khóa bí mật không hợp lệ.');

  const input = Array.isArray(ciphertext) ? ciphertext.join(' ') : String(ciphertext ?? '');
  if (!input.trim()) return '';

  const bytes = decodeBlocks(input).map((c) => {
    if (c >= n) throw new Error('Giá trị ciphertext không hợp lệ.');
    return toBytes(modPow(c, d, n));
  });

  return Buffer.concat(bytes).toString('utf8');
}

export { gcd, modPow, modInverse, isPrime, buildKeyPair, generateKeyPair, encryptText, decryptText };
