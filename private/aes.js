import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

const ALGORITHM = 'aes-256-cbc';
const BLOCK_SIZE = 16;

function deriveKey(secretKey) {
  if (typeof secretKey !== 'string' || !secretKey) {
    throw new Error('Khoá bí mật không được để trống.');
  }
  return createHash('sha256').update(secretKey, 'utf8').digest();
}

function parseEnvelope(input) {
  let envelope = input;
  if (typeof input === 'string') {
    const text = input.trim();
    if (text.startsWith('{')) {
      try {
        envelope = JSON.parse(text);
      } catch {
        throw new Error('Dữ liệu mã hoá không hợp lệ.');
      }
    } else {
      const idx = text.indexOf(':');
      if (idx < 1) throw new Error('Dữ liệu mã hoá không hợp lệ.');
      envelope = { iv: text.slice(0, idx), ciphertext: text.slice(idx + 1) };
    }
  }

  if (!envelope || typeof envelope.iv !== 'string' || typeof envelope.ciphertext !== 'string') {
    throw new Error('Dữ liệu mã hoá không hợp lệ.');
  }

  return {
    iv: Buffer.from(envelope.iv, 'base64'),
    ciphertext: Buffer.from(envelope.ciphertext, 'base64'),
  };
}

function encryptText(text, secretKey) {
  if (typeof text !== 'string') {
    throw new TypeError('Dữ liệu mã hoá không hợp lệ.');
  }
  const key = deriveKey(secretKey);
  const iv = randomBytes(BLOCK_SIZE);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);

  return {
    iv: iv.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
}

function decryptText(ciphertextInput, secretKey) {
  const { iv, ciphertext } = parseEnvelope(ciphertextInput);
  const key = deriveKey(secretKey);
  try {
    const decipher = createDecipheriv(ALGORITHM, key, iv);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plaintext.toString('utf8');
  } catch {
    throw new Error('Sai khoá hoặc ciphertext bị hỏng.');
  }
}

export {
  encryptText,
  decryptText,
};
