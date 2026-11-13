import { createHash } from 'node:crypto';

export function requireKey(key, name) {
  if (typeof key !== 'string' || !key.trim()) {
    throw new Error(`${name} không được để trống.`);
  }
  return key;
}

export function formatKey(key, type, name = type) {
  const value = requireKey(key, name).trim();
  if (value.includes('-----BEGIN')) return value;

  const base64 = value.replace(/\s+/g, '');
  const lines = base64.match(/.{1,64}/g);
  if (!lines) throw new Error(`${name} không hợp lệ.`);
  return `-----BEGIN ${type}-----\n${lines.join('\n')}\n-----END ${type}-----`;
}

export function readRsaCiphertext(value) {
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
  if (!Array.isArray(blocks)) {
    throw new Error('Ciphertext RSA phải là mảng JSON.');
  }
  if (blocks.some((block) => typeof block !== 'string')) {
    throw new Error('Mỗi block ciphertext RSA phải là chuỗi Base64.');
  }
  return blocks;
}

export function aesKey(secretKey, isRawKey = false) {
  if (typeof secretKey !== 'string' || !secretKey) {
    throw new Error('SECRET KEY không được để trống.');
  }
  if (isRawKey) {
    const key = Buffer.from(secretKey, 'base64');
    if (key.length !== 32 || key.toString('base64') !== secretKey) {
      throw new Error('AES key không hợp lệ.');
    }
    return key;
  }
  return createHash('sha256').update(secretKey, 'utf8').digest();
}

export function readAesEnvelope(ciphertext) {
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

  return envelope;
}
