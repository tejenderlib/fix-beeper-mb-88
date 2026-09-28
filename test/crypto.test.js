// test/crypto.test.js — primitives, exercised against the REAL client/crypto.js
// that the browser loads. There is no re-implementation here on purpose: a
// duplicated copy of the crypto would pass even if the shipped file were
// broken.
import test from 'node:test';
import assert from 'node:assert/strict';
import { crypto } from './helpers/e2ee.js';

/** Stand-in for a second device, using the same shipped primitives. */
async function peer() {
  const keyPair = await crypto.generateKeyPair();
  return {
    keyPair,
    publicKey: await crypto.exportPublicKey(keyPair.publicKey),
  };
}

async function session() {
  const a = await peer();
  const b = await peer();
  const aKey = await crypto.deriveSharedKey(
    a.keyPair.privateKey,
    await crypto.importPublicKey(b.publicKey)
  );
  const bKey = await crypto.deriveSharedKey(
    b.keyPair.privateKey,
    await crypto.importPublicKey(a.publicKey)
  );
  return { a, b, aKey, bKey };
}

test('an ephemeral P-256 public key is a compact base64 point', async () => {
  const { publicKey } = await peer();
  assert.equal(typeof publicKey, 'string');
  assert.match(publicKey, /^[A-Za-z0-9+/]+={0,2}$/);
  // Uncompressed P-256 point = 65 bytes -> 88 base64 chars.
  assert.equal(Buffer.from(publicKey, 'base64').length, 65);
});

test('ECDH + HKDF derives the same AES key for both peers', async () => {
  const { aKey, bKey, a, b } = await session();
  const message = 'MB-88 secure transmission';
  const env = await crypto.encrypt(aKey, message);
  assert.equal(await crypto.decrypt(bKey, env), message);
  // ...and the derivation is symmetric, not just one-directional.
  const back = await crypto.encrypt(bKey, 'REPLY');
  assert.equal(await crypto.decrypt(aKey, back), 'REPLY');
  assert.ok(a.publicKey !== b.publicKey, 'each session publishes a distinct key');
});

test('AES-GCM rejects tampered ciphertext', async () => {
  const { aKey, bKey } = await session();
  const env = await crypto.encrypt(aKey, 'DO NOT MODIFY');
  const bytes = Buffer.from(env.ciphertext, 'base64');
  bytes[0] ^= 1;
  await assert.rejects(() => crypto.decrypt(bKey, { ...env, ciphertext: bytes.toString('base64') }));
});

test('AES-GCM rejects a tampered IV', async () => {
  const { aKey, bKey } = await session();
  const env = await crypto.encrypt(aKey, 'IV IS ALSO AUTHENTICATED');
  const iv = Buffer.from(env.iv, 'base64');
  iv[0] ^= 1;
  await assert.rejects(() => crypto.decrypt(bKey, { ...env, iv: iv.toString('base64') }));
});

test('a third party holding its own key pair cannot decrypt the message', async () => {
  const { aKey, bKey } = await session();
  const eve = await peer();
  const eveKey = await crypto.deriveSharedKey(
    eve.keyPair.privateKey,
    await crypto.importPublicKey((await session()).a.publicKey)
  );
  const env = await crypto.encrypt(aKey, 'PRIVATE MESSAGE');
  await assert.rejects(() => crypto.decrypt(eveKey, env));
  // Bob's legitimate path still works — eve is the only one locked out.
  assert.equal(await crypto.decrypt(bKey, env), 'PRIVATE MESSAGE');
});

test('a malformed envelope is rejected before any crypto runs', async () => {
  const { aKey } = await session();
  for (const bad of [null, undefined, {}, { iv: 'AAAA' }, { ciphertext: 'AAAA' },
                     { iv: 1, ciphertext: 'AAAA' }, { iv: 'AAAA', ciphertext: 2 },
                     { iv: null, ciphertext: null }]) {
    await assert.rejects(
      () => crypto.decrypt(aKey, bad),
      /invalid-encrypted-message/,
      `for ${JSON.stringify(bad)}`
    );
  }
});

test('two encryptions of the same text differ (fresh IV each time)', async () => {
  const { aKey, bKey } = await session();
  const one = await crypto.encrypt(aKey, 'SAME TEXT');
  const two = await crypto.encrypt(aKey, 'SAME TEXT');
  assert.notEqual(one.iv, two.iv, 'IV must not be reused');
  assert.notEqual(one.ciphertext, two.ciphertext, 'ciphertext must not repeat');
  assert.equal(await crypto.decrypt(bKey, one), 'SAME TEXT');
  assert.equal(await crypto.decrypt(bKey, two), 'SAME TEXT');
});
