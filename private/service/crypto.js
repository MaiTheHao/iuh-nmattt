import { constants, createPrivateKey, createPublicKey, privateDecrypt, publicEncrypt, randomBytes } from 'node:crypto';
import * as aes from '../lib/aes.js';
import { aesKey, formatKey, readAesEnvelope, readRsaCiphertext } from '../util/crypto.js';

export function rsaEncrypt({ key, plaintext }) {
  const publicKey = createPublicKey(formatKey(key, 'PUBLIC KEY'));
  if (publicKey.asymmetricKeyType !== 'rsa') throw new Error('PUBLIC KEY phải là khóa RSA.');

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

export function rsaDecrypt({ key, ciphertext }) {
  const privateKey = createPrivateKey(formatKey(key, 'PRIVATE KEY', 'SECRET KEY'));
  if (privateKey.asymmetricKeyType !== 'rsa') throw new Error('SECRET KEY phải là khóa RSA.');

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

export function aesEncrypt({ secretKey, plaintext, rawKey }) {
  const key = aesKey(secretKey, rawKey);
  const iv = randomBytes(16);
  const encrypted = aes.encryptText(plaintext ?? '', key, iv);

  return {
    iv: iv.toString('base64'),
    ciphertext: Buffer.from(encrypted.ciphertext, 'hex').toString('base64'),
  };
}

export function aesDecrypt({ secretKey, ciphertext, rawKey }) {
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
