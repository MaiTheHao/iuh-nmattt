import { constants, createPrivateKey, createPublicKey, privateDecrypt, publicEncrypt } from 'node:crypto';

const ERR_KEY_REQUIRED = (name) => `${name} không được để trống.`;
const ERR_KEY_INVALID = (name) => `${name} không hợp lệ.`;
const ERR_PUBLIC_KEY_NOT_RSA = 'PUBLIC KEY phải là khóa RSA.';
const ERR_SECRET_KEY_NOT_RSA = 'SECRET KEY phải là khóa RSA.';
const ERR_CIPHERTEXT_INVALID = 'Ciphertext RSA không hợp lệ.';
const ERR_CIPHERTEXT_NOT_ARRAY = 'Ciphertext RSA phải là mảng JSON.';
const ERR_BLOCK_NOT_BASE64 = 'Mỗi block ciphertext RSA phải là chuỗi Base64.';

function requireKey(key, name) {
  if (typeof key !== 'string' || !key.trim()) {
    throw new Error(ERR_KEY_REQUIRED(name));
  }
  return key;
}

function formatKey(key, type, name = type) {
  const value = requireKey(key, name).trim();
  if (value.includes('-----BEGIN')) return value;

  const base64 = value.replace(/\s+/g, '');
  const lines = base64.match(/.{1,64}/g);
  if (!lines) throw new Error(ERR_KEY_INVALID(name));
  return `-----BEGIN ${type}-----\n${lines.join('\n')}\n-----END ${type}-----`;
}

function readRsaCiphertext(value) {
  let blocks = value;
  if (typeof value === 'string') {
    const text = value.trim();
    if (text.startsWith('[')) {
      try {
        blocks = JSON.parse(text);
      } catch {
        throw new Error(ERR_CIPHERTEXT_INVALID);
      }
    } else {
      blocks = text.split(/[\s,]+/).filter(Boolean);
    }
  }
  if (!Array.isArray(blocks)) {
    throw new Error(ERR_CIPHERTEXT_NOT_ARRAY);
  }
  if (blocks.some((block) => typeof block !== 'string')) {
    throw new Error(ERR_BLOCK_NOT_BASE64);
  }
  return blocks;
}

export class RSAService {
  static encrypt({ key, plaintext }) {
    const publicKey = createPublicKey(formatKey(key, 'PUBLIC KEY'));
    if (publicKey.asymmetricKeyType !== 'rsa') throw new Error(ERR_PUBLIC_KEY_NOT_RSA);

    const input = Buffer.from(plaintext ?? '', 'utf8');
    const keyBytes = Math.ceil(publicKey.asymmetricKeyDetails.modulusLength / 8);
    const chunkSize = keyBytes - 2 * 32 - 2;
    const blockCount = input.length ? Math.ceil(input.length / chunkSize) : 1;

    const ciphertext = Array.from({ length: blockCount }, (_, index) => {
      const start = index * chunkSize;
      const block = input.length ? input.subarray(start, start + chunkSize) : Buffer.alloc(0);
      const encryptedBlock = publicEncrypt(
        {
          key: publicKey,
          padding: constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256',
        },
        block,
      );
      return encryptedBlock.toString('base64');
    });

    return { ciphertext };
  }

  static decrypt({ key, ciphertext }) {
    const privateKey = createPrivateKey(formatKey(key, 'PRIVATE KEY', 'SECRET KEY'));
    if (privateKey.asymmetricKeyType !== 'rsa') throw new Error(ERR_SECRET_KEY_NOT_RSA);

    const plaintext = readRsaCiphertext(ciphertext).map((block) =>
      privateDecrypt(
        {
          key: privateKey,
          padding: constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256',
        },
        Buffer.from(block, 'base64'),
      ),
    );

    return { plaintext: Buffer.concat(plaintext).toString('utf8') };
  }

  encrypt(payload) {
    return RSAService.encrypt(payload);
  }

  decrypt(payload) {
    return RSAService.decrypt(payload);
  }
}

export const rsaEncrypt = RSAService.encrypt;
export const rsaDecrypt = RSAService.decrypt;
export default RSAService;
