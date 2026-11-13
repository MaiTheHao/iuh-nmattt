'use strict';

const API_URL = '/api/crypto';
const $ = (id) => document.getElementById(id);

async function callCryptoApi(action, payload) {
  const response = await fetch(API_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, payload }),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || `Crypto API failed (${response.status})`);
  return result;
}

function setStatus(id, message) {
  const el = $(id);
  if (el) el.textContent = message;
}

function showError(error) {
  const message = error?.message || 'Đã xảy ra lỗi.';
  alert(message.includes('DECODER routines::unsupported') ? 'Khóa RSA không hợp lệ.' : message);
}

function setBusy(buttons, busy) {
  buttons.forEach((id) => {
    const el = $(id);
    if (el) el.disabled = busy;
  });
}

function toBase64(data) {
  const bytes = new Uint8Array(data);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function createRsaKeyPair() {
  const pair = await crypto.subtle.generateKey({
    name: 'RSA-OAEP',
    modulusLength: 2048,
    publicExponent: Uint8Array.of(1, 0, 1),
    hash: 'SHA-256',
  }, true, ['encrypt', 'decrypt']);

  return {
    publicKey: toBase64(await crypto.subtle.exportKey('spki', pair.publicKey)),
    secretKey: toBase64(await crypto.subtle.exportKey('pkcs8', pair.privateKey)),
  };
}

/* ---------------- RSA ---------------- */

function updateRsaButton() {
  if (!$('rsa-direction') || !$('rsa-run')) return;
  const encrypt = $('rsa-direction').value === 'encrypt';
  const key = encrypt ? $('rsa-public-key')?.value : $('rsa-secret-key')?.value;
  $('rsa-run').disabled = !key || !key.trim();
}

async function generateRsaKeys() {
  const publicKeyField = $('rsa-public-key');
  const secretKeyField = $('rsa-secret-key');
  const generateButton = $('rsa-generate-keys');
  const modeField = $('rsa-key-mode');
  if (!publicKeyField || !secretKeyField || !generateButton) return;

  generateButton.disabled = true;
  if (modeField) modeField.disabled = true;
  publicKeyField.value = '';
  secretKeyField.value = '';
  updateRsaButton();

  try {
    const pair = await createRsaKeyPair();
    publicKeyField.value = pair.publicKey;
    secretKeyField.value = pair.secretKey;
  } catch {
    alert('Không tạo được cặp khóa RSA trong trình duyệt này.');
  } finally {
    generateButton.disabled = false;
    if (modeField) modeField.disabled = false;
    updateRsaButton();
  }
}

function updateRsaKeyMode() {
  const modeField = $('rsa-key-mode');
  const publicKeyField = $('rsa-public-key');
  const secretKeyField = $('rsa-secret-key');
  const generateButton = $('rsa-generate-keys');
  if (!modeField || !publicKeyField || !secretKeyField) return;

  const automatic = modeField.value === 'auto';
  publicKeyField.readOnly = automatic;
  secretKeyField.readOnly = automatic;
  publicKeyField.placeholder = automatic ? '' : 'Nhập public key';
  secretKeyField.placeholder = automatic ? '' : 'Nhập secret key';
  if (generateButton) generateButton.hidden = !automatic;

  if (automatic) {
    generateRsaKeys();
  } else {
    publicKeyField.value = '';
    secretKeyField.value = '';
    updateRsaButton();
  }
}

function updateRsaDirection() {
  if (!$('rsa-direction') || !$('rsa-run') || !$('rsa-input-label')) return;
  const encrypt = $('rsa-direction').value === 'encrypt';
  $('rsa-input-label').textContent = encrypt ? 'PLAINTEXT' : 'CIPHERTEXT';
  $('rsa-run').textContent = encrypt ? 'Mã hóa RSA' : 'Giải mã RSA';
  if ($('rsa-result') && $('rsa-result').textContent) {
    $('rsa-input').value = $('rsa-result').textContent;
  }
  updateRsaButton();
}

if ($('rsa-direction') && $('rsa-run')) {
  $('rsa-key-mode')?.addEventListener('change', updateRsaKeyMode);
  $('rsa-generate-keys')?.addEventListener('click', generateRsaKeys);
  $('rsa-public-key')?.addEventListener('input', updateRsaButton);
  $('rsa-secret-key')?.addEventListener('input', updateRsaButton);
  $('rsa-direction').addEventListener('change', updateRsaDirection);

  $('rsa-run').addEventListener('click', async () => {
    const encrypt = $('rsa-direction').value === 'encrypt';
    const key = encrypt ? $('rsa-public-key').value : $('rsa-secret-key').value;
    if (!key.trim()) return alert(encrypt ? 'Cần nhập PUBLIC KEY.' : 'Cần nhập SECRET KEY.');

    setBusy(['rsa-run'], true);
    setStatus('rsa-status', encrypt ? 'Đang mã hóa…' : 'Đang giải mã…');
    try {
      const payload = encrypt
        ? { key, plaintext: $('rsa-input').value }
        : { key, ciphertext: $('rsa-input').value };
      const result = await callCryptoApi(encrypt ? 'rsa-encrypt' : 'rsa-decrypt', payload);
      $('rsa-result').textContent = encrypt ? result.ciphertext.join(' ') : result.plaintext;
      setStatus('rsa-status', encrypt ? 'Đã mã hóa RSA.' : 'Đã giải mã RSA.');
    } catch (error) {
      showError(error);
    } finally {
      updateRsaButton();
    }
  });

  updateRsaDirection();
  generateRsaKeys();
}

/* ---------------- AES-CBC ---------------- */

function updateAesDirection() {
  if (!$('aes-direction') || !$('aes-run') || !$('aes-input-label') || !$('aes-input')) return;
  const encrypt = $('aes-direction').value === 'encrypt';
  $('aes-input-label').textContent = encrypt ? 'PLAINTEXT' : 'CIPHERTEXT';
  $('aes-input').placeholder = encrypt ? '' : 'IV:ciphertext';
  $('aes-run').textContent = encrypt ? 'Mã hóa AES-CBC' : 'Giải mã AES-CBC';
  if ($('aes-result') && $('aes-result').value) {
    $('aes-input').value = $('aes-result').value;
  }
}

if ($('aes-direction') && $('aes-run')) {
  $('aes-direction').addEventListener('change', updateAesDirection);
  $('aes-run').addEventListener('click', async () => {
    const encrypt = $('aes-direction').value === 'encrypt';
    setBusy(['aes-run'], true);
    setStatus('aes-status', encrypt ? 'Đang mã hóa…' : 'Đang giải mã…');
    try {
      const result = await callCryptoApi(encrypt ? 'aes-encrypt' : 'aes-decrypt', {
        secretKey: $('aes-key').value,
        [encrypt ? 'plaintext' : 'ciphertext']: $('aes-input').value,
      });
      $('aes-result').value = encrypt ? `${result.iv}:${result.ciphertext}` : result.plaintext;
      setStatus('aes-status', encrypt ? 'Đã mã hóa AES-CBC.' : 'Đã giải mã AES-CBC.');
    } catch (error) {
      showError(error);
    } finally {
      setBusy(['aes-run'], false);
    }
  });

  updateAesDirection();
}
