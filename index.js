'use strict';

/**
 * index.js — frontend cho Vercel /api/crypto.
 * Gọi POST /api/crypto với { action, payload } và cập nhật DOM.
 */

const API_URL = '/api/crypto';

async function callCryptoApi(action, payload) {
  const response = await fetch(API_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, payload }),
  });

  let result;
  try {
    result = await response.json();
  } catch {
    throw new Error(`Server trả về dữ liệu không hợp lệ (HTTP ${response.status})`);
  }

  if (!response.ok) {
    throw new Error(result.error || `Crypto API failed (HTTP ${response.status})`);
  }

  return result;
}

/* ---------------- DOM helpers ---------------- */

const $ = (id) => document.getElementById(id);

function setOutput(id, value) {
  $(id).textContent = value == null ? '' : String(value);
}

function setStatus(id, message, isError = false) {
  const el = $(id);
  el.textContent = message || '';
  el.classList.toggle('error', !!isError);
}

function setBusy(section, busy) {
  const map = {
    rsa: ['rsa-encrypt', 'rsa-decrypt'],
    aes: ['aes-encrypt', 'aes-decrypt'],
    hybrid: ['hybrid-encrypt', 'hybrid-decrypt'],
  };
  (map[section] || []).forEach((id) => {
    const el = $(id);
    if (el) el.disabled = !!busy;
  });
}

function formatPublicKey(k) {
  return `n = ${k.n}\ne = ${k.e}`;
}
function formatPrivateKey(k) {
  return `n = ${k.n}\nd = ${k.d}`;
}

/* ---------------- State ---------------- */
// Lưu khóa riêng sau khi mã hóa để bước giải mã dùng lại.
let rsaState = { n: null, d: null };
let hybridState = { n: null, d: null };

/* ---------------- RSA ---------------- */

$('rsa-encrypt').addEventListener('click', async () => {
  setStatus('rsa-status', 'Đang mã hóa…');
  setBusy('rsa', true);
  try {
    const result = await callCryptoApi('rsa-encrypt', {
      p: $('rsa-p').value.trim(),
      q: $('rsa-q').value.trim(),
      e: $('rsa-e').value.trim(),
      message: $('rsa-message').value,
    });

    setOutput('rsa-public', formatPublicKey(result.publicKey));
    setOutput('rsa-private', formatPrivateKey(result.privateKey));
    $('rsa-ciphertext').value = JSON.stringify(result.ciphertext);
    setOutput('rsa-result', '');

    rsaState = { n: result.privateKey.n, d: result.privateKey.d };
    setStatus('rsa-status', '✓ Đã mã hóa RSA (từng byte)');
  } catch (err) {
    setStatus('rsa-status', '❌ ' + err.message, true);
  } finally {
    setBusy('rsa', false);
  }
});

$('rsa-decrypt').addEventListener('click', async () => {
  setBusy('rsa', true);
  try {
    if (!rsaState.n || !rsaState.d) {
      throw new Error('Cần mã hóa trước để có khóa riêng.');
    }
    const ciphertext = $('rsa-ciphertext').value.trim();
    if (!ciphertext) throw new Error('Thiếu ciphertext.');

    setStatus('rsa-status', 'Đang giải mã…');
    const result = await callCryptoApi('rsa-decrypt', {
      ciphertext,
      d: rsaState.d,
      n: rsaState.n,
    });

    setOutput('rsa-result', result.plaintext);
    setStatus('rsa-status', '✓ Đã giải mã RSA');
  } catch (err) {
    setStatus('rsa-status', '❌ ' + err.message, true);
  } finally {
    setBusy('rsa', false);
  }
});

/* ---------------- AES ---------------- */

$('aes-encrypt').addEventListener('click', async () => {
  setStatus('aes-status', 'Đang mã hóa…');
  setBusy('aes', true);
  try {
    const result = await callCryptoApi('aes-encrypt', {
      key: $('aes-key').value.trim() || undefined,
      iv: $('aes-iv').value.trim() || undefined,
      message: $('aes-message').value,
    });

    $('aes-key').value = result.key;
    $('aes-iv').value = result.iv;
    $('aes-ciphertext').value = result.ciphertext;
    setOutput('aes-result', '');
    setStatus('aes-status', `✓ Đã mã hóa ${result.algorithm}`);
  } catch (err) {
    setStatus('aes-status', '❌ ' + err.message, true);
  } finally {
    setBusy('aes', false);
  }
});

$('aes-decrypt').addEventListener('click', async () => {
  setBusy('aes', true);
  try {
    const key = $('aes-key').value.trim();
    const iv = $('aes-iv').value.trim();
    const ciphertext = $('aes-ciphertext').value.trim();
    if (!key || !iv || !ciphertext) {
      throw new Error('Cần đủ key, iv và ciphertext (Base64).');
    }

    setStatus('aes-status', 'Đang giải mã…');
    const result = await callCryptoApi('aes-decrypt', { key, iv, ciphertext });

    setOutput('aes-result', result.plaintext);
    setStatus('aes-status', '✓ Đã giải mã AES');
  } catch (err) {
    setStatus('aes-status', '❌ ' + err.message, true);
  } finally {
    setBusy('aes', false);
  }
});

/* ---------------- Hybrid RSA + AES ---------------- */

$('hybrid-encrypt').addEventListener('click', async () => {
  setStatus('hybrid-status', 'Đang mã hóa…');
  setBusy('hybrid', true);
  try {
    const result = await callCryptoApi('hybrid-encrypt', {
      p: $('hybrid-p').value.trim(),
      q: $('hybrid-q').value.trim(),
      e: $('hybrid-e').value.trim(),
      message: $('hybrid-message').value,
    });

    setOutput('hybrid-public', formatPublicKey(result.publicKey));
    setOutput('hybrid-private', formatPrivateKey(result.privateKey));
    // API không trả raw AES key (đúng theo mô hình bảo mật),
    // chỉ trả khóa đã bọc bằng RSA.
    setOutput(
      'hybrid-aes-key',
      '(server tạo ngẫu nhiên — không trả về; chỉ khôi phục được bằng RSA private key)'
    );
    setOutput('hybrid-aes-iv', result.iv);
    setOutput('hybrid-encrypted-key', JSON.stringify(result.wrappedKey));
    $('hybrid-ciphertext').value = result.ciphertext;
    setOutput('hybrid-result', '');

    hybridState = { n: result.privateKey.n, d: result.privateKey.d };
    setStatus('hybrid-status', '✓ Đã mã hóa AES và bọc khóa bằng RSA');
  } catch (err) {
    setStatus('hybrid-status', '❌ ' + err.message, true);
  } finally {
    setBusy('hybrid', false);
  }
});

$('hybrid-decrypt').addEventListener('click', async () => {
  setBusy('hybrid', true);
  try {
    if (!hybridState.n || !hybridState.d) {
      throw new Error('Cần mã hóa trước để có khóa riêng.');
    }
    const iv = $('hybrid-aes-iv').textContent.trim();
    const wrappedKey = $('hybrid-encrypted-key').textContent.trim();
    const ciphertext = $('hybrid-ciphertext').value.trim();
    if (!iv || !wrappedKey || !ciphertext) {
      throw new Error('Thiếu dữ liệu (iv / wrappedKey / ciphertext).');
    }

    setStatus('hybrid-status', 'Đang giải mã 2 bước…');
    const result = await callCryptoApi('hybrid-decrypt', {
      wrappedKey,
      d: hybridState.d,
      n: hybridState.n,
      iv,
      ciphertext,
    });

    setOutput('hybrid-result', result.plaintext);
    setStatus('hybrid-status', '✓ Đã khôi phục AES key và giải mã nội dung');
  } catch (err) {
    setStatus('hybrid-status', '❌ ' + err.message, true);
  } finally {
    setBusy('hybrid', false);
  }
});