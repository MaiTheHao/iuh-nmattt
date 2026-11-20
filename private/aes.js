import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

const ALGORITHM = 'aes-256-cbc';
const IV_LENGTH = 16;

function deriveKey(secretKey) {
  if (typeof secretKey !== 'string' || !secretKey) {
    throw new Error('Khóa bí mật không được để trống.');
  }

  return createHash('sha256').update(secretKey, 'utf8').digest();
}

function encryptText(text, secretKey) {
  if (typeof text !== 'string') throw new TypeError('Plaintext phải là chuỗi.');

  const key = deriveKey(secretKey);
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);

  return { ciphertext: `${iv.toString('base64')}:${encrypted.toString('base64')}` };
}

function decryptText(ciphertext, secretKey) {
  const parts = String(ciphertext ?? '').split(':');
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new Error('Ciphertext phải có dạng IV:ciphertext (base64).');
  }

  const iv = Buffer.from(parts[0], 'base64');
  if (iv.length !== IV_LENGTH) throw new Error('IV phải dài đúng 16 byte.');

  const data = Buffer.from(parts[1], 'base64');
  if (data.length === 0 || data.length % IV_LENGTH !== 0) {
    throw new Error('Ciphertext phải là bội số của 16 byte.');
  }

  const key = deriveKey(secretKey);

  try {
    const decipher = createDecipheriv(ALGORITHM, key, iv);
    return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
  } catch {
    throw new Error('Sai khóa hoặc ciphertext bị hỏng.');
  }
}

export { encryptText, decryptText };
