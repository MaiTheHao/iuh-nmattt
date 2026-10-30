'use strict';

const API_URL = '/api/crypto';
const $ = (id) => document.getElementById(id);
let hybridState = null;

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
  $(id).textContent = message;
}

function showError(error) {
  const message = error?.message || 'Đã xảy ra lỗi.';
  alert(message.includes('DECODER routines::unsupported') ? 'Khóa RSA không hợp lệ.' : message);
}

function setBusy(buttons, busy) {
  buttons.forEach((id) => { $(id).disabled = busy; });
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

function getKeyFieldIds(section) {
  return {
    mode: `${section}-key-mode`,
    publicKey: `${section}-public-key`,
    secretKey: `${section}-secret-key`,
    generateButton: `${section}-generate-keys`,
  };
}

function updateRsaButton() {
  const encrypt = $('rsa-direction').value === 'encrypt';
  const key = encrypt ? $('rsa-public-key').value : $('rsa-secret-key').value;
  $('rsa-run').disabled = !key.trim();
}

function updateHybridButtons() {
  const step = hybridState?.step ?? 0;
  const encrypt = $('hybrid-direction').value === 'encrypt';
  const key = encrypt ? $('hybrid-public-key').value : $('hybrid-secret-key').value;
  $('hybrid-init').disabled = !key.trim();
  $('hybrid-step-1').disabled = step !== 1;
  $('hybrid-step-2').disabled = step !== 2;
}

async function generateKeys(section) {
  const fields = getKeyFieldIds(section);
  const publicKeyField = $(fields.publicKey);
  const secretKeyField = $(fields.secretKey);
  const generateButton = $(fields.generateButton);

  generateButton.disabled = true;
  $(fields.mode).disabled = true;
  publicKeyField.value = '';
  secretKeyField.value = '';

  if (section === 'rsa') updateRsaButton();
  else {
    hybridState = null;
    updateHybridButtons();
  }

  try {
    const pair = await createRsaKeyPair();
    publicKeyField.value = pair.publicKey;
    secretKeyField.value = pair.secretKey;
  } catch {
    alert('Không tạo được cặp khóa RSA trong trình duyệt này.');
  } finally {
    generateButton.disabled = false;
    $(fields.mode).disabled = false;
    if (section === 'rsa') updateRsaButton();
    else updateHybridButtons();
  }
}

function updateKeyMode(section) {
  const fields = getKeyFieldIds(section);
  const automatic = $(fields.mode).value === 'auto';
  $(fields.publicKey).readOnly = automatic;
  $(fields.secretKey).readOnly = automatic;
  $(fields.publicKey).placeholder = automatic ? '' : 'Nhập public key';
  $(fields.secretKey).placeholder = automatic ? '' : 'Nhập secret key';
  $(fields.generateButton).hidden = !automatic;

  if (automatic) generateKeys(section);
  else {
    $(fields.publicKey).value = '';
    $(fields.secretKey).value = '';
    if (section === 'rsa') updateRsaButton();
    else {
      hybridState = null;
      updateHybridButtons();
    }
  }
}

for (const section of ['rsa', 'hybrid']) {
  const fields = getKeyFieldIds(section);
  $(fields.mode).addEventListener('change', () => updateKeyMode(section));
  $(fields.generateButton).addEventListener('click', () => generateKeys(section));
  $(fields.publicKey).addEventListener('input', section === 'rsa' ? updateRsaButton : updateHybridButtons);
  $(fields.secretKey).addEventListener('input', section === 'rsa' ? updateRsaButton : updateHybridButtons);
}

/* ---------------- RSA ---------------- */

function updateRsaDirection() {
  const encrypt = $('rsa-direction').value === 'encrypt';
  $('rsa-input-label').textContent = encrypt ? 'PLAINTEXT' : 'CIPHERTEXT';
  $('rsa-run').textContent = encrypt ? 'Mã hóa RSA' : 'Giải mã RSA';
  if ($('rsa-result').textContent) $('rsa-input').value = $('rsa-result').textContent;
  updateRsaButton();
}

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

/* ---------------- AES-CBC ---------------- */

function updateAesDirection() {
  const encrypt = $('aes-direction').value === 'encrypt';
  $('aes-input-label').textContent = encrypt ? 'PLAINTEXT' : 'CIPHERTEXT';
  $('aes-input').placeholder = encrypt ? '' : 'IV:ciphertext';
  $('aes-run').textContent = encrypt ? 'Mã hóa AES-CBC' : 'Giải mã AES-CBC';
  if ($('aes-result').value) $('aes-input').value = $('aes-result').value;
}

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

/* ---------------- Hybrid RSA + AES-CBC ---------------- */

function updateHybridDirection() {
  const encrypt = $('hybrid-direction').value === 'encrypt';
  $('hybrid-input-label').textContent = encrypt ? 'PLAINTEXT' : 'GÓI DỮ LIỆU';
  $('hybrid-init').textContent = encrypt ? 'Khởi tạo mã hóa' : 'Khởi tạo giải mã';
  $('hybrid-step-1').textContent = encrypt
    ? 'Bên gửi — Step 1: AES mã hóa nội dung'
    : 'Bên nhận — Step 1: RSA khôi phục AES key';
  $('hybrid-step-2').textContent = encrypt
    ? 'Bên gửi — Step 2: RSA mã hóa AES key bằng PUBLIC KEY'
    : 'Bên nhận — Step 2: AES giải mã nội dung';
  $('hybrid-result-1-label').textContent = encrypt
    ? 'Bên gửi: AES key và ciphertext'
    : 'Bên nhận: AES key khôi phục bằng SECRET KEY';
  $('hybrid-result-2-label').textContent = encrypt
    ? 'Bên gửi: AES key đã mã hóa bằng PUBLIC KEY'
    : 'Bên nhận: plaintext khôi phục';
  $('hybrid-input').value = encrypt ? 'Thông điệp mã hóa lai.' : $('hybrid-package').value;
  hybridState = null;
  updateHybridButtons();
  $('hybrid-result-1').textContent = '';
  $('hybrid-result-2').textContent = '';
  setStatus('hybrid-status', '');
}

$('hybrid-direction').addEventListener('change', updateHybridDirection);
$('hybrid-init').addEventListener('click', () => {
  try {
    const encrypt = $('hybrid-direction').value === 'encrypt';
    const publicKey = $('hybrid-public-key').value;
    const secretKey = $('hybrid-secret-key').value;
    const key = encrypt ? publicKey : secretKey;
    if (!key.trim()) throw new Error(encrypt ? 'Cần nhập PUBLIC KEY.' : 'Cần nhập SECRET KEY.');

    if (encrypt) {
      const randomBytes = crypto.getRandomValues(new Uint8Array(32));
      hybridState = {
        direction: 'encrypt',
        step: 1,
        plaintext: $('hybrid-input').value,
        publicKey,
        aesSecretKey: toBase64(randomBytes),
      };
    } else {
      const data = JSON.parse($('hybrid-input').value);
      const encryptedAesKey = data.encryptedAesKey || data.wrappedKey;
      if (!encryptedAesKey || !data.iv || !data.ciphertext) {
        throw new Error('Gói dữ liệu không hợp lệ.');
      }
      hybridState = {
        direction: 'decrypt',
        step: 1,
        package: { encryptedAesKey, iv: data.iv, ciphertext: data.ciphertext },
        secretKey,
      };
    }

    $('hybrid-result-1').textContent = '';
    $('hybrid-result-2').textContent = '';
    updateHybridButtons();
    setStatus('hybrid-status', 'Đã khởi tạo. Thực hiện Step 1.');
  } catch (error) {
    showError(error instanceof SyntaxError ? new Error('Gói dữ liệu không hợp lệ.') : error);
  }
});

$('hybrid-step-1').addEventListener('click', async () => {
  if (!hybridState) return;
  setBusy(['hybrid-init', 'hybrid-step-1', 'hybrid-step-2'], true);
  try {
    if (hybridState.direction === 'encrypt') {
      hybridState.envelope = await callCryptoApi('aes-encrypt', {
        secretKey: hybridState.aesSecretKey,
        rawKey: true,
        plaintext: hybridState.plaintext,
      });
      $('hybrid-result-1').textContent = `AES key: ${hybridState.aesSecretKey}\nIV: ${hybridState.envelope.iv}\nCiphertext: ${hybridState.envelope.ciphertext}`;
      setStatus('hybrid-status', 'Step 1 xong: nội dung đã được AES-CBC mã hóa.');
    } else {
      const result = await callCryptoApi('rsa-decrypt', {
        key: hybridState.secretKey,
        ciphertext: Array.isArray(hybridState.package.encryptedAesKey)
          ? JSON.stringify(hybridState.package.encryptedAesKey)
          : hybridState.package.encryptedAesKey,
      });
      hybridState.aesSecretKey = result.plaintext;
      $('hybrid-result-1').textContent = `AES key đã khôi phục: ${result.plaintext}`;
      setStatus('hybrid-status', 'Step 1 xong: AES key đã được RSA giải mã.');
    }
    hybridState.step = 2;
  } catch (error) {
    showError(error);
  } finally {
    updateHybridButtons();
  }
});

$('hybrid-step-2').addEventListener('click', async () => {
  if (!hybridState) return;
  setBusy(['hybrid-init', 'hybrid-step-1', 'hybrid-step-2'], true);
  try {
    if (hybridState.direction === 'encrypt') {
      const result = await callCryptoApi('rsa-encrypt', {
        key: hybridState.publicKey,
        plaintext: hybridState.aesSecretKey,
      });
      const data = {
        encryptedAesKey: result.ciphertext.join(' '),
        iv: hybridState.envelope.iv,
        ciphertext: hybridState.envelope.ciphertext,
      };
      $('hybrid-result-2').textContent = `AES key đã được RSA mã hóa bằng PUBLIC KEY:\n${data.encryptedAesKey}`;
      $('hybrid-package').value = JSON.stringify(data);
      setStatus('hybrid-status', 'Hoàn tất. Gói dữ liệu sẵn sàng chuyển sang bên nhận.');
    } else {
      const result = await callCryptoApi('aes-decrypt', {
        secretKey: hybridState.aesSecretKey,
        rawKey: true,
        ciphertext: JSON.stringify({ iv: hybridState.package.iv, ciphertext: hybridState.package.ciphertext }),
      });
      $('hybrid-result-2').textContent = `Plaintext: ${result.plaintext}`;
      setStatus('hybrid-status', 'Hoàn tất giải mã nội dung.');
    }
    hybridState.step = 3;
  } catch (error) {
    showError(error);
  } finally {
    updateHybridButtons();
  }
});

updateRsaDirection();
updateAesDirection();
updateHybridDirection();
generateKeys('rsa');
generateKeys('hybrid');
