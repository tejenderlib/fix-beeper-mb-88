// Phase 2: static server + WebSocket hello/ping + invite pairing (connections.js).
// No chat messaging yet — that lands in Phase 3. No DB, no auth.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import { WebSocketServer, WebSocket } from 'ws';
import { createConnectionStore, normalizeCode } from './connections.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const CLIENT_DIR = path.join(ROOT, 'client');
const PORT = Number(process.env.PORT || 3000);

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
};

function serveStatic(req, res) {
  let urlPath = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  // /connect/<code> serves the SAME MB-88 UI — no second page.
  // client/net.js reads the code from location.pathname and auto-joins.
  if (urlPath === '/' || urlPath === '/connect' || urlPath.startsWith('/connect/')) urlPath = '/index.html';
  const file = path.normalize(path.join(CLIENT_DIR, urlPath));
  if (!file.startsWith(CLIENT_DIR)) {
    res.writeHead(403).end('forbidden');
    return;
  }
  fs.readFile(file, (err, data) => {
    if (err) {
      res.writeHead(404).end('not found');
      return;
    }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' }).end(data);
  });
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' }).end('{"ok":true}');
    return;
  }
  serveStatic(req, res);
});

const wss = new WebSocketServer({ server, maxPayload: 4096 });
const peers = new Map(); // clientId -> ws
const store = createConnectionStore();

function send(ws, obj) {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}

function sendTo(clientId, obj) {
  const ws = peers.get(clientId);
  if (ws) send(ws, obj);
}

function isConnected(clientId) {
  const ws = peers.get(clientId);
  return !!ws && ws.readyState === WebSocket.OPEN;
}

wss.on('connection', (ws) => {
  const clientId = crypto.randomUUID();
  peers.set(clientId, ws);
  ws._clientId = clientId;
  ws.isAlive = true;
  send(ws, { type: 'welcome', clientId, serverTime: new Date().toISOString() });

  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      send(ws, { type: 'error', error: 'invalid-json' });
      return;
    }
    if (!msg || typeof msg.type !== 'string') {
      send(ws, { type: 'error', error: 'invalid-message' });
      return;
    }
    // --- Phase 1 (unchanged) ---
    if (msg.type === 'hello') {
      send(ws, { type: 'hello-ack', clientId });
      return;
    }
    if (msg.type === 'ping') {
      send(ws, { type: 'pong', echo: typeof msg.echo === 'string' ? msg.echo.slice(0, 64) : undefined });
      return;
    }
    // --- Invites + pairing (durations are server-validated, default 60) ---
    if (msg.type === 'create-invite') {
      const res = store.createInvite(clientId, msg.durationMin === undefined ? 60 : msg.durationMin);
      if (!res.ok) {
        send(ws, { type: 'error', error: res.error });
        return;
      }
      send(ws, { type: 'invite-created', code: res.code, durationMin: res.durationMin });
      return;
    }
    if (msg.type === 'join-invite') {
      const code = normalizeCode(msg.code);
      const res = store.joinInvite(code, clientId, isConnected);
      if (!res.ok) {
        send(ws, { type: 'error', error: res.error, code });
        return;
      }
      send(ws, { type: 'connection-pending', code });
      // Only the creator's id and the code — no extra requester info.
      sendTo(res.invite.creatorId, { type: 'connection-request', code, requesterId: clientId });
      return;
    }
    if (msg.type === 'accept-connection') {
      const code = normalizeCode(msg.code);
      const res = store.acceptConnection(code, clientId, isConnected);
      if (!res.ok) {
        send(ws, { type: 'error', error: res.error, code });
        return;
      }
      // Each side learns only its peer's id — server-computed, never client-provided.
      // expiresAt/durationMin are authoritative: clients display, never decide.
      sendTo(res.creatorId, { type: 'connection-established', peerId: res.requesterId, expiresAt: res.expiresAt, durationMin: res.durationMin });
      sendTo(res.requesterId, { type: 'connection-established', peerId: res.creatorId, expiresAt: res.expiresAt, durationMin: res.durationMin });
      return;
    }
    if (msg.type === 'reject-connection') {
      const code = normalizeCode(msg.code);
      const res = store.rejectConnection(code, clientId);
      if (!res.ok) {
        send(ws, { type: 'error', error: res.error, code });
        return;
      }
      sendTo(res.requesterId, { type: 'connection-rejected', code });
      send(ws, { type: 'reject-acked', code });
      return;
    }
    // --- Lifetime extension: same pair, server adds minutes to expiresAt.
    // Either member may extend; serial handling makes races deterministic.
    if (msg.type === 'extend-connection') {
      const res = store.extendConnection(clientId, msg.minutes, isConnected);
      if (!res.ok) {
        send(ws, { type: 'error', error: res.error });
        if (res.error === 'connection-expired') send(ws, { type: 'connection-expired' });
        return;
      }
      sendTo(clientId, { type: 'connection-extended', expiresAt: res.expiresAt, addedMin: res.addedMin });
      sendTo(res.peerId, { type: 'connection-extended', expiresAt: res.expiresAt, addedMin: res.addedMin });
      return;
    }
    // --- Peer messaging (no broadcast, server-authoritative) ---
    if (msg.type === 'message') {
      // Client sends ONLY {type, text}. messageId/senderId/peerId/roomId/
      // timestamp from the client are ignored — never trusted.
      if (typeof msg.text !== 'string') {
        send(ws, { type: 'error', error: 'invalid-message' });
        return;
      }
      const text = msg.text.trim();
      if (!text) {
        send(ws, { type: 'error', error: 'empty-message' });
        return;
      }
      if (text.length > 160) {
        send(ws, { type: 'error', error: 'message-too-long' });
        return;
      }
      const peerId = store.getPeer(clientId);
      // isLive also covers the sweep race: an expired pair relays nothing.
      if (!peerId || !isConnected(peerId) || !store.isLive(clientId)) {
        send(ws, { type: 'error', error: 'not-connected' });
        return;
      }
      // Sender gets NO echo — its local transmit() already made the card.
      sendTo(peerId, {
        type: 'message',
        messageId: crypto.randomUUID(),
        text,
        timestamp: new Date().toISOString(),
      });
      return;
    }
    send(ws, { type: 'error', error: 'unknown-type' });
  });

  ws.on('close', () => {
    peers.delete(clientId);
    const done = store.handleDisconnect(clientId);
    if (done.peerId) sendTo(done.peerId, { type: 'peer-disconnected' });
    if (done.cancelled) sendTo(done.cancelled.creatorId, { type: 'connection-cancelled', code: done.cancelled.code });
    for (const o of done.orphaned) sendTo(o.requesterId, { type: 'connection-cancelled', code: o.code });
  });
});

// Reap expired pairs every second: notify both sides, no auto-reconnect.
setInterval(() => {
  let expired = [];
  try {
    expired = store.sweepExpired(Date.now());
  } catch { /* never take the server down on sweep */ }
  for (const { a, b } of expired) {
    sendTo(a, { type: 'connection-expired' });
    if (b) sendTo(b, { type: 'connection-expired' });
  }
}, 1000).unref();

// Prune dead sockets every 30s (Phase 6 will add reconnect).
setInterval(() => {
  for (const [id, ws] of peers) {
    if (ws.isAlive === false) { ws.terminate(); continue; }
    ws.isAlive = false;
    try { ws.ping(); } catch { /* ignore */ }
  }
}, 30000).unref();

server.listen(PORT, () => console.log(`MB-88 server listening on http://localhost:${PORT} (conn-lifetime: server-authoritative expiry)`));
