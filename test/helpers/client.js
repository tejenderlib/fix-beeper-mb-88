// test/helpers/client.js — test harness only. No production code is imported
// or modified here; this is a black-box driver that speaks the same wire
// protocol as client/net.js and spawns the real server/server.js.
//
// Design notes (all aimed at non-flaky tests):
//   - Every server is a real child process on its own free port, started and
//     stopped by the test. `npm start` is never required.
//   - Waits are event-driven with a timeout, never fixed sleeps. The only
//     deliberate time-based assertion is expectNone(), which is always
//     sequenced AFTER a positive assertion that the event already happened,
//     so it can only fail on a real regression.
//   - waitFor() consumes a buffered message once, so a late subscriber still
//     sees a message that arrived before it started waiting. That removes the
//     classic "registered the waiter too late" race.
import { spawn } from 'node:child_process';
import net from 'node:net';
import { fileURLToPath } from 'node:url';
import { WebSocket } from 'ws';

const SERVER_PATH = fileURLToPath(new URL('../../server/server.js', import.meta.url));

export const CODE_RE = /^MB88-[A-Z0-9]{4}-[A-Z0-9]{4}$/;
export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Ask the OS for a free port, then release it for the child to bind. */
export function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

/**
 * Spawn the real server on its own port. `env` is merged over process.env so
 * a test can enable server test hooks (e.g. MB88_TEST_DURATIONS).
 */
export async function startServer({ env = {} } = {}) {
  const port = await freePort();
  const child = spawn(process.execPath, [SERVER_PATH], {
    env: { ...process.env, PORT: String(port), ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (d) => { stdout += d; });
  child.stderr.on('data', (d) => { stderr += d; });
  let exited = false;
  child.on('exit', () => { exited = true; });

  const base = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 10000;
  for (;;) {
    if (exited) {
      throw new Error(`test server exited during startup\nstdout:\n${stdout}\nstderr:\n${stderr}`);
    }
    try {
      const res = await fetch(`${base}/health`);
      if (res.ok) break;
    } catch {
      // not listening yet
    }
    if (Date.now() > deadline) {
      child.kill('SIGKILL');
      throw new Error(`test server never became healthy\nstdout:\n${stdout}\nstderr:\n${stderr}`);
    }
    await sleep(20);
  }

  return {
    port,
    base,
    wsUrl: `ws://127.0.0.1:${port}`,
    get stderr() { return stderr; },
    async stop() {
      if (exited) return;
      child.kill('SIGTERM');
      const until = Date.now() + 3000;
      while (!exited && Date.now() < until) await sleep(10);
      if (!exited) {
        child.kill('SIGKILL');
        const hard = Date.now() + 2000;
        while (!exited && Date.now() < hard) await sleep(10);
      }
    },
  };
}

/** Minimal WebSocket client speaking the MB-88 wire protocol. */
export class Client {
  constructor(wsUrl) {
    this.wsUrl = wsUrl;
    this.ws = null;
    this.log = [];      // every parsed inbound message, in arrival order
    this.consumed = new WeakSet(); // messages already handed to a caller
    this.waiters = [];
    this.closed = false;
  }

  open() {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(this.wsUrl);
      this.ws = ws;
      ws.once('open', () => resolve(this));
      ws.once('error', (e) => { if (!this.log.length) reject(e); });
      ws.on('error', () => { /* close always follows */ });
      ws.on('message', (raw) => {
        let msg;
        try { msg = JSON.parse(raw.toString()); } catch { return; }
        this._incoming(msg);
      });
      ws.on('close', () => {
        this.closed = true;
        this._failAll(new Error('socket closed'));
      });
    });
  }

  _incoming(msg) {
    this.log.push(msg);
    for (const w of this.waiters.slice()) {
      if (!w.used && w.test(msg)) {
        w.used = true;
        this.consumed.add(msg); // consume the message, not just the waiter
        clearTimeout(w.timer);
        this.waiters.splice(this.waiters.indexOf(w), 1);
        w.resolve(msg);
      }
    }
  }

  _failAll(err) {
    for (const w of this.waiters.slice()) {
      if (w.used) continue;
      w.used = true;
      clearTimeout(w.timer);
      this.waiters.splice(this.waiters.indexOf(w), 1);
      w.reject(err);
    }
  }

  _matches(type, match) {
    return (m) => m.type === type && (!match || match(m));
  }

  /** Resolves the first unconsumed inbound message of `type`. */
  waitFor(type, { match, timeout = 5000, label } = {}) {
    const test = this._matches(type, match);
    for (const m of this.log) {
      if (test(m) && !this.consumed.has(m)) {
        this.consumed.add(m);
        return Promise.resolve(m);
      }
    }
    if (this.closed) {
      return Promise.reject(new Error(`socket closed while waiting for "${type}"`));
    }
    return new Promise((resolve, reject) => {
      const w = { test, resolve, reject, used: false, timer: 0 };
      w.timer = setTimeout(() => {
        this.waiters.splice(this.waiters.indexOf(w), 1);
        reject(new Error(
          `timeout waiting for "${type}"${label ? ` (${label})` : ''}; ` +
          `saw: [${this.seen().join(', ')}]`
        ));
      }, timeout);
      this.waiters.push(w);
    });
  }

  /** Register the waiter first, then send — removes the ordering race. */
  sendAndWait(obj, type, opts) {
    const p = this.waitFor(type, opts);
    this.send(obj);
    return p;
  }

  send(obj) {
    this.ws.send(JSON.stringify(obj));
  }

  sendRaw(text) {
    this.ws.send(text);
  }

  /** Types currently buffered (for diagnostics). */
  seen() {
    return this.log.map((m) => m.type);
  }

  /**
   * Assert that no message of `type` ever arrived. Only safe to call after the
   * corresponding positive event has already been observed.
   */
  async expectNone(type, ms = 300) {
    await sleep(ms);
    return !this.log.some((m) => m.type === type);
  }

  close() {
    try { this.ws.close(); } catch { /* already gone */ }
  }
}

/**
 * Re-send a harmless read-only probe until the server reports `expected`, or
 * fail. Used where the trigger is a *local* socket close: the server processes
 * that asynchronously and sends nothing back to us, so there is no event to
 * await and a fixed sleep would be a flake risk. Polling to a converged
 * outcome is deterministic in result and immune to that race.
 */
export async function probeUntilError(client, request, expected, timeoutMs = 3000) {
  const deadline = Date.now() + timeoutMs;
  let last = null;
  for (;;) {
    last = await client.sendAndWait(request, 'error', { timeout: 2000 });
    if (last.error === expected) return last;
    if (Date.now() > deadline) {
      throw new Error(
        `expected error "${expected}" but last saw "${last.error}" ` +
        `after ${timeoutMs}ms`
      );
    }
    await sleep(20);
  }
}

/**
 * Full two-person pairing handshake over the real protocol.
 * Returns both clients, the invite code, and the two connection-established
 * payloads (creator view, requester view).
 */
export async function pair(server, { durationMin = 60 } = {}) {
  const a = await new Client(server.wsUrl).open();
  const b = await new Client(server.wsUrl).open();

  const code = (await a.sendAndWait({ type: 'create-invite', durationMin }, 'invite-created')).code;

  const pending = b.sendAndWait({ type: 'join-invite', code }, 'connection-pending');
  const request = a.waitFor('connection-request');
  await Promise.all([pending, request]);

  const forA = a.sendAndWait({ type: 'accept-connection', code }, 'connection-established');
  const forB = b.waitFor('connection-established');
  const [ma, mb] = await Promise.all([forA, forB]);

  return { a, b, code, establishedA: ma, establishedB: mb };
}
