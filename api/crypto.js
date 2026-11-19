import { RSAService } from '../private/service/RSAService.js';
import { AESService } from '../private/service/AESService.js';

const operations = {
  'rsa-encrypt': (payload) => RSAService.encrypt(payload),
  'rsa-decrypt': (payload) => RSAService.decrypt(payload),
  'aes-encrypt': (payload) => AESService.encrypt(payload),
  'aes-decrypt': (payload) => AESService.decrypt(payload),
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
