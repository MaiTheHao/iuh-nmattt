import { createHash, randomBytes } from 'node:crypto';
import * as aes from '../lib/aes.js';

const ERR_SECRET_KEY_REQUIRED = 'SECRET KEY không được để trống.';
const ERR_AES_KEY_INVALID = 'AES key không hợp lệ.';
const ERR_CIPHERTEXT_INVALID = 'Ciphertext AES không hợp lệ.';
const ERR_ENVELOPE_REQUIRED = 'Ciphertext AES cần có iv và ciphertext.';

function aesKey(secretKey, isRawKey = false) {
  if (typeof secretKey !== 'string' || !secretKey) {
    throw new Error(ERR_SECRET_KEY_REQUIRED);
  }
  if (isRawKey) {
    const key = Buffer.from(secretKey, 'base64');
    if (key.length !== 32 || key.toString('base64') !== secretKey) {
      throw new Error(ERR_AES_KEY_INVALID);
    }
    return key;
  }
  return createHash('sha256').update(secretKey, 'utf8').digest();
}

function readAesEnvelope(ciphertext) {
  let envelope;
  if (typeof ciphertext === 'string') {
    const value = ciphertext.trim();
    if (value.startsWith('{')) {
      try {
        envelope = JSON.parse(value);
      } catch {
        throw new Error(ERR_CIPHERTEXT_INVALID);
      }
    } else {
      const separator = value.indexOf(':');
      if (separator < 1) throw new Error(ERR_CIPHERTEXT_INVALID);
      envelope = { iv: value.slice(0, separator), ciphertext: value.slice(separator + 1) };
    }
  } else {
    envelope = ciphertext;
  }

  if (!envelope || typeof envelope.iv !== 'string' || typeof envelope.ciphertext !== 'string') {
    throw new Error(ERR_ENVELOPE_REQUIRED);
  }

  return envelope;
}

export class AESService {
  static encrypt({ secretKey, plaintext, rawKey }) {
    const key = aesKey(secretKey, rawKey);
    const iv = randomBytes(16);
    const encrypted = aes.encryptText(plaintext ?? '', key, iv);

    return {
      iv: iv.toString('base64'),
      ciphertext: Buffer.from(encrypted.ciphertext, 'hex').toString('base64'),
    };
  }

  static decrypt({ secretKey, ciphertext, rawKey }) {
    const key = aesKey(secretKey, rawKey);
    const envelope = readAesEnvelope(ciphertext);

    const plaintext = aes.decryptText(
      {
        iv: Buffer.from(envelope.iv, 'base64').toString('hex'),
        ciphertext: Buffer.from(envelope.ciphertext, 'base64').toString('hex'),
      },
      key,
    );

    return { plaintext };
  }

  encrypt(payload) {
    return AESService.encrypt(payload);
  }

  decrypt(payload) {
    return AESService.decrypt(payload);
  }
}

export const aesEncrypt = AESService.encrypt;
export const aesDecrypt = AESService.decrypt;
export default AESService;
