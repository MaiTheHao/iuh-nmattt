import { aesDecrypt, aesEncrypt, rsaDecrypt, rsaEncrypt } from '../private/service/crypto.js';

const operations = {
  'rsa-encrypt': rsaEncrypt,
  'rsa-decrypt': rsaDecrypt,
  'aes-encrypt': aesEncrypt,
  'aes-decrypt': aesDecrypt,
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
    const result = operation(payload);
    return res.status(200).json(result);
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
}
