import * as aes from '../private/aes.js';
import * as rsa from '../private/rsa.js';

const operations = {
  'aes-encrypt': ({ secretKey, plaintext }) => aes.encryptText(plaintext ?? '', secretKey),
  'aes-decrypt': ({ secretKey, ciphertext }) => ({ plaintext: aes.decryptText(ciphertext, secretKey) }),
  'rsa-keygen': () => rsa.generateKeyPair(),
  'rsa-encrypt': ({ key, plaintext }) => rsa.encryptText(plaintext ?? '', key),
  'rsa-decrypt': ({ key, ciphertext }) => ({ plaintext: rsa.decryptText(ciphertext, key) }),
};

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { action, payload = {} } = req.body || {};
  const operation = operations[action];
  if (!operation) {
    return res.status(400).json({ error: `Unknown action: ${action}` });
  }

  try {
    return res.status(200).json(operation(payload));
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
}
