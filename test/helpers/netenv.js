// test/helpers/netenv.js — loads the REAL client/crypto.js and client/net.js
// into a minimal browser shim so the client glue can be tested in Node.
//
// Deliberately not a re-implementation: these tests run the same two files the
// browser runs. Only the host objects the files touch are stubbed (window,
// location, document, WebSocket). Everything else — key derivation, envelope
// shape, lifecycle clearing — is the shipped code.
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { WebSocket } from 'ws';

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');
const NET_SRC = read('../../client/net.js');
const CRYPTO_SRC = read('../../client/crypto.js');

const realSetInterval = globalThis.setInterval;
const timers = [];

// The shim installs ONCE and stays. net.js reads `WebSocket`, `location` and
// `document` as globals at call time, not load time, so restoring them would
// break `isOpen()` on an already-connected socket. Only `window` is per
// instance, because net.js is a singleton guarded by `if (window.__beeperNet)`
// and each test needs a fresh one — hence runInThisContext, since import()
// would cache the module and hand back the first instance.
const locationShim = { protocol: 'http:', host: '', origin: '', pathname: '/' };

globalThis.WebSocket = WebSocket;
globalThis.location = locationShim;
globalThis.document = {
  readyState: 'complete',
  addEventListener() {},
  removeEventListener() {},
};
// net.js starts a 25s heartbeat on load. Track it so cleanup() can clear it and
// let the node:test process exit.
globalThis.setInterval = (fn, ms) => {
  const t = realSetInterval(fn, ms);
  timers.push(t);
  return t;
};

/**
 * Boot a fresh copy of client/net.js against `port`.
 * Returns { net, window, cleanup }.
 */
export function createNet(port, { pathname = '/' } = {}) {
  locationShim.host = `127.0.0.1:${port}`;
  locationShim.origin = `http://127.0.0.1:${port}`;
  locationShim.pathname = pathname;

  const win = { crypto: webcrypto, addEventListener() {}, removeEventListener() {} };
  globalThis.window = win;

  // crypto.js first — net.js reads window.__beeperCrypto when it encrypts.
  vm.runInThisContext(CRYPTO_SRC, { filename: 'client/crypto.js' });
  vm.runInThisContext(NET_SRC, { filename: 'client/net.js' });

  const net = win.__beeperNet;
  if (!net) throw new Error('client/net.js did not expose window.__beeperNet');

  return {
    net,
    window: win,
    crypto: win.__beeperCrypto,
    cleanup() {
      try { net.disconnect(); } catch { /* already down */ }
      for (const t of timers.splice(0, timers.length)) clearInterval(t);
    },
  };
}

/** Resolve on the next `evt` from net, or reject on timeout. */
export function once(net, evt, { timeout = 5000 } = {}) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`timeout waiting for "${evt}"`)), timeout);
    net.on(evt, function handler(data) {
      net.off(evt, handler);
      clearTimeout(t);
      resolve(data);
    });
  });
}

/**
 * Resolve once the socket is up. net.js connects asynchronously when the module
 * is evaluated, so a test that acts immediately would race its own socket.
 * The listener is registered before the state is re-checked, so there is no
 * window in which the transition can be missed.
 */
export function waitReady(net, { timeout = 5000 } = {}) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => {
      net.off('status', handler);
      reject(new Error('net.js socket never opened'));
    }, timeout);
    function handler(s) {
      if (s && (s.status === 'WAITING' || s.status === 'CONNECTED')) {
        clearTimeout(t);
        net.off('status', handler);
        resolve(s);
      }
    }
    net.on('status', handler);
    handler(net.snapshot());
  });
}

/**
 * Report whether `evt` fires within a short window. Pair it with a positive
 * assertion first, or this is just a flaky sleep.
 */
export async function expectNoEvent(net, evt, ms = 400) {
  let fired = false;
  const handler = () => { fired = true; };
  net.on(evt, handler);
  await new Promise((r) => setTimeout(r, ms));
  net.off(evt, handler);
  return !fired;
}
