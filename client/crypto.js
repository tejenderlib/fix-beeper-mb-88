(function () {
  'use strict';

  if (window.__beeperCrypto) return;

  var subtle = window.crypto && window.crypto.subtle;
  if (!subtle) {
    throw new Error('Web Crypto API is unavailable');
  }

  var ECDH_ALGORITHM = {
    name: 'ECDH',
    namedCurve: 'P-256'
  };

  var AES_ALGORITHM = 'AES-GCM';
  var AES_KEY_LENGTH = 256;
  var IV_LENGTH = 12;

  function bytesToBase64(bytes) {
    var binary = '';
    for (var i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function base64ToBytes(value) {
    var binary = atob(value);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  async function generateKeyPair() {
    return subtle.generateKey(
      ECDH_ALGORITHM,
      true,
      ['deriveBits']
    );
  }

  async function exportPublicKey(publicKey) {
    var raw = await subtle.exportKey('raw', publicKey);
    return bytesToBase64(new Uint8Array(raw));
  }

  async function importPublicKey(publicKeyBase64) {
    return subtle.importKey(
      'raw',
      base64ToBytes(publicKeyBase64),
      ECDH_ALGORITHM,
      false,
      []
    );
  }

  async function deriveSharedKey(privateKey, peerPublicKey) {
    var bits = await subtle.deriveBits(
      {
        name: 'ECDH',
        public: peerPublicKey
      },
      privateKey,
      256
    );

    /*
     * HKDF is deliberately used after ECDH rather than using the raw
     * ECDH output directly as the AES key.
     */
    var hkdfKey = await subtle.importKey(
      'raw',
      bits,
      'HKDF',
      false,
      ['deriveKey']
    );

    return subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new TextEncoder().encode('MB88-PHASE5'),
        info: new TextEncoder().encode('MB88-MESSAGE-KEY')
      },
      hkdfKey,
      {
        name: AES_ALGORITHM,
        length: AES_KEY_LENGTH
      },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function encrypt(key, plaintext) {
    var iv = new Uint8Array(IV_LENGTH);
    window.crypto.getRandomValues(iv);

    var encoded = new TextEncoder().encode(plaintext);

    var ciphertext = await subtle.encrypt(
      {
        name: AES_ALGORITHM,
        iv: iv
      },
      key,
      encoded
    );

    return {
      iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(new Uint8Array(ciphertext))
    };
  }

  async function decrypt(key, payload) {
    if (!payload || typeof payload.iv !== 'string' ||
        typeof payload.ciphertext !== 'string') {
      throw new Error('invalid-encrypted-message');
    }

    var plaintext = await subtle.decrypt(
      {
        name: AES_ALGORITHM,
        iv: base64ToBytes(payload.iv)
      },
      key,
      base64ToBytes(payload.ciphertext)
    );

    return new TextDecoder().decode(plaintext);
  }

  window.__beeperCrypto = {
    generateKeyPair: generateKeyPair,
    exportPublicKey: exportPublicKey,
    importPublicKey: importPublicKey,
    deriveSharedKey: deriveSharedKey,
    encrypt: encrypt,
    decrypt: decrypt
  };
})();
