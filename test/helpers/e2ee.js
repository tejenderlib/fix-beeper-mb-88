// test/helpers/e2ee.js — the crypto half of the test harness.
//
// Loads the REAL client/crypto.js (not a copy) and provides a paired-and-encrypted
// version of the wire-level helpers, so protocol tests exercise the shipped
// primitives against the real server.
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { pair } from './client.js';

const CRYPTO_SRC = readFileSync(
  fileURLToPath(new URL('../../client/crypto.js', import.meta.url)),
  'utf8'
);

// crypto.js is a browser IIFE guarded by `if (window.__beeperCrypto) return`,
// so one shared window serves every test file in this process.
const win = { crypto: webcrypto };
globalThis.window = win;
vm.runInThisContext(CRYPTO_SRC, { filename: 'client/crypto.js' });

export const crypto = win.__beeperCrypto;
if (!crypto) throw new Error('client/crypto.js did not expose window.__beeperCrypto');

/**
 * Pair two raw protocol clients AND complete the Phase 5 key exchange, the
 * same way client/net.js does it: each side generates an ephemeral P-256 pair,
 * publishes the public key through the server, and derives the AES key from
 * the peer's. Returns the session keys so tests can encrypt/decrypt.
 */
export async function securePair(server, { durationMin = 60 } = {}) {
  const p = await pair(server, { durationMin });
  const { a, b } = p;

  const aPair = await crypto.generateKeyPair();
  const bPair = await crypto.generateKeyPair();
  const aPub = await crypto.exportPublicKey(aPair.publicKey);
  const bPub = await crypto.exportPublicKey(bPair.publicKey);

  // Each side publishes its OWN public key; the server forwards it to the peer.
  // So A receives B's key and B receives A's key.
  const forA = a.sendAndWait({ type: 'key-exchange', publicKey: aPub }, 'key-exchange');
  const forB = b.sendAndWait({ type: 'key-exchange', publicKey: bPub }, 'key-exchange');
  const [atA, atB] = await Promise.all([forA, forB]);

  const aKey = await crypto.deriveSharedKey(aPair.privateKey, await crypto.importPublicKey(atA.publicKey));
  const bKey = await crypto.deriveSharedKey(bPair.privateKey, await crypto.importPublicKey(atB.publicKey));

  return { ...p, aKey, bKey };
}

/** Encrypt with a session key and build the wire envelope. */
export async function envelope(key, text) {
  const { iv, ciphertext } = await crypto.encrypt(key, text);
  return { type: 'message', iv, ciphertext };
}

/** Wait for a relayed envelope and decrypt it with the receiver's session key. */
export async function readEnvelope(client, key) {
  const m = await client.waitFor('message');
  return { ...m, text: await crypto.decrypt(key, m) };
}
