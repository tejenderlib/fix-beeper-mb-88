// Net layer — non-visual only. No DOM/CSS/UI changes.
// Owns the WebSocket, invite pairing API, lifetimes, and connection state.
//
//   await __beeperNet.createInvite(60)            -> "MB88-XXXX-XXXX"
//   __beeperNet.getInviteUrl(code)              -> ".../connect/MB88-XXXX-XXXX"
//   await __beeperNet.joinInvite(code)          -> resolves code on connection-pending
//   await __beeperNet.acceptConnection(code)    -> resolves peerId on connection-established
//   await __beeperNet.rejectConnection(code)    -> resolves code on reject-acked
//   await __beeperNet.extendConnection(60)      -> resolves {expiresAt, addedMin}
//   __beeperNet.on('connection-request', fn)    -> creator side: {code, requesterId}
//   __beeperNet.on('connection-established', fn)-> both sides: {peerId, expiresAt, durationMin}
//   __beeperNet.on('connection-extended', fn)   -> both sides: {expiresAt, addedMin}
//   __beeperNet.on('connection-expired', fn)    -> pair reaped at expiresAt
//   __beeperNet.on('peer-disconnected', fn)
//   await __beeperNet.sendMessage(text)      -> encrypts locally, relays {iv,ciphertext}
//   __beeperNet.on('message', fn)            -> {messageId, text, timestamp} (decrypted)
//   __beeperNet.on('crypto-ready', fn)       -> {ready:true} once the session key exists
//   __beeperNet.on('error', fn)             -> 'decrypt-failed' etc.
//   __beeperNet.disconnect()                    -> close socket once, no redial
// Expiry is server-authoritative; state.expiresAt is display-only.
//
// Phase 5 (E2EE): ephemeral P-256 ECDH per session, HKDF-SHA256 -> AES-256-GCM.
// The socket only ever carries {iv, ciphertext} and public keys. The server
// relays both; it never holds a private key and never reads a message.
(function () {
  'use strict';
  if (window.__beeperNet) return;

  var CODE_RE = /^MB88-[A-Z0-9]{4}-[A-Z0-9]{4}$/;
  var TIMEOUT_MS = 10000;
  var HEARTBEAT_MS = 25000;

  // DISCONNECTED -> CONNECTING -> WAITING -> CONNECTED (peer linked)
  var state = {
    status: 'DISCONNECTED',
    connectionState: 'DISCONNECTED',
    clientId: null,
    peerId: null,
    inviteCode: null,         // latest code created by this client
    inviteDurationMin: 60,    // duration chosen for the latest invite
    pendingInviteCode: null,  // code parsed from /connect/<code>, if any
    expiresAt: null,          // server-authoritative; display only, never decided here
    durationMin: null,
  };

  var ws = null;
  var listeners = {};
  var pendings = []; // {kind, code, resolve, reject, timer}
  var autoJoinTried = false;

  // Phase 5: one ephemeral ECDH key pair + one AES-GCM session key per peer
  // session. Both live here and nowhere else — the private key is never
  // exported, never sent, and never touches the socket. resetSession() drops
  // all of it, so a new pairing can never inherit the previous key.
  var session = { keyPair: null, peerPublicKey: null, key: null };

  function resetSession() {
    session.keyPair = null;
    session.peerPublicKey = null;
    session.key = null;
  }

  function on(evt, fn) {
    (listeners[evt] = listeners[evt] || []).push(fn);
  }
  function off(evt, fn) {
    var a = listeners[evt] || [];
    var i = a.indexOf(fn);
    if (i >= 0) a.splice(i, 1);
  }
  function emit(evt, data) {
    var a = (listeners[evt] || []).slice();
    for (var i = 0; i < a.length; i++) {
      try { a[i](data); } catch (e) { setTimeout((function (err) { return function () { throw err; }; })(e), 0); }
    }
  }
  function setStatus(s) {
    state.status = s;
    state.connectionState = s;
    emit('status', snapshot());
  }
  function snapshot() {
    return {
      status: state.status,
      connectionState: state.connectionState,
      clientId: state.clientId,
      peerId: state.peerId,
      inviteCode: state.inviteCode,
      pendingInviteCode: state.pendingInviteCode,
    };
  }
  function normalizeCode(code) {
    return String(code || '').trim().toUpperCase();
  }
  function isOpen() {
    return ws && ws.readyState === WebSocket.OPEN;
  }
  function rawSend(obj) {
    if (!isOpen()) return false;
    try { ws.send(JSON.stringify(obj)); return true; }
    catch (e) { return false; }
  }
  // Register a pending promise; returns resolve/reject wrappers that self-remove.
  function defer(kind, code) {
    var entry = { kind: kind, code: code || null, resolve: null, reject: null, timer: 0 };
    var p = new Promise(function (resolve, reject) {
      entry.resolve = function (v) { remove(entry); resolve(v); };
      entry.reject = function (e) { remove(entry); reject(e); };
    });
    entry.timer = setTimeout(function () { entry.reject(new Error('timeout')); }, TIMEOUT_MS);
    var origReject = entry.reject;
    entry.reject = function (e) { clearTimeout(entry.timer); origReject(e); };
    var origResolve = entry.resolve;
    entry.resolve = function (v) { clearTimeout(entry.timer); origResolve(v); };
    pendings.push(entry);
    return { promise: p, entry: entry };
  }
  function remove(entry) {
    var i = pendings.indexOf(entry);
    if (i >= 0) pendings.splice(i, 1);
  }
  function settleAll(kind, code, ok, value) {
    for (var i = pendings.length - 1; i >= 0; i--) {
      var e = pendings[i];
      if (e.kind === kind && (code == null || e.code === code)) {
        if (ok) e.resolve(value);
        else e.reject(value instanceof Error ? value : new Error(String(value)));
      }
    }
  }

  function inviteFromUrl() {
    try {
      var m = location.pathname.match(/^\/connect\/([A-Za-z0-9-]+)/);
      return m ? normalizeCode(decodeURIComponent(m[1])) : null;
    } catch (e) { return null; }
  }
  function maybeAutoJoin() {
    if (autoJoinTried || !state.pendingInviteCode || !isOpen()) return;
    autoJoinTried = true;
    var code = state.pendingInviteCode;
    if (rawSend({ type: 'join-invite', code: code })) emit('auto-join', { code: code });
  }

  /* ---------- Phase 5: end-to-end encryption ---------- */
  // A fresh ephemeral pair per session, published through the server. The
  // server relays the public key and nothing else; it never sees a private
  // key and never derives anything.
  function startKeyExchange() {
    var bc = window.__beeperCrypto;
    if (!bc) { emit('error', { error: 'crypto-unavailable' }); return; }
    resetSession();
    bc.generateKeyPair().then(function (kp) {
      // A reset that landed while we were generating (peer vanished, socket
      // closed) must win — do not resurrect a key for a dead session.
      if (!state.peerId) return;
      session.keyPair = kp;
      return bc.exportPublicKey(kp.publicKey).then(function (pub) {
        rawSend({ type: 'key-exchange', publicKey: pub });
      });
    }).catch(function () {
      emit('error', { error: 'key-exchange-failed' });
    });
  }

  // Peer key in: derive the shared AES key locally. The server is already
  // finished with the bytes at this point.
  function handlePeerKey(msg) {
    var bc = window.__beeperCrypto;
    if (!bc || !session.keyPair || !msg || typeof msg.publicKey !== 'string') {
      emit('error', { error: 'key-exchange-failed' });
      return;
    }
    var pair = session.keyPair;
    bc.importPublicKey(msg.publicKey).then(function (peerKey) {
      return bc.deriveSharedKey(pair.privateKey, peerKey).then(function (key) {
        if (session.keyPair !== pair) return; // session ended mid-derive
        session.peerPublicKey = peerKey;
        session.key = key;
        emit('crypto-ready', { ready: true });
      });
    }).catch(function () {
      emit('error', { error: 'key-exchange-failed' });
    });
  }

  // Ciphertext in: decrypt locally, then emit the SAME shape the UI already
  // consumes. A tampered or malformed envelope fails authentication and
  // produces no 'message' event at all.
  function decryptIncoming(msg) {
    if (!session.key) {
      emit('error', { error: 'decrypt-failed', messageId: msg.messageId });
      return;
    }
    window.__beeperCrypto.decrypt(session.key, msg).then(function (text) {
      if (typeof text !== 'string' || !text.trim()) {
        emit('error', { error: 'decrypt-failed', messageId: msg.messageId });
        return;
      }
      emit('message', {
        messageId: msg.messageId,
        text: text,
        timestamp: msg.timestamp,
      });
    }).catch(function () {
      emit('error', { error: 'decrypt-failed', messageId: msg.messageId });
    });
  }

  function handleServerMessage(msg) {
    switch (msg.type) {
      case 'welcome':
      case 'hello-ack':
        if (msg.clientId) state.clientId = msg.clientId;
        if (state.connectionState !== 'CONNECTED') setStatus('WAITING');
        emit(msg.type, msg);
        maybeAutoJoin();
        break;
      case 'pong':
        break; // heartbeat ack — nothing visual
      case 'invite-created':
        state.inviteCode = msg.code;
        if (msg.durationMin) state.inviteDurationMin = msg.durationMin;
        emit('invite-created', msg);
        settleAll('create', null, true, msg.code);
        break;
      case 'connection-pending':
        emit('connection-pending', msg);
        settleAll('join', normalizeCode(msg.code), true, normalizeCode(msg.code));
        break;
      case 'connection-request':
        emit('connection-request', msg);
        break;
      case 'connection-established':
        state.peerId = msg.peerId || null;
        state.expiresAt = typeof msg.expiresAt === 'number' ? msg.expiresAt : null;
        state.durationMin = msg.durationMin || null;
        setStatus('CONNECTED');
        emit('connection-established', msg);
        settleAll('accept', null, true, msg.peerId);
        // Ephemeral keys for THIS session only — the old ones are already gone.
        startKeyExchange();
        break;
      case 'connection-rejected':
        emit('connection-rejected', msg);
        break;
      case 'reject-acked':
        emit('reject-acked', msg);
        settleAll('reject', normalizeCode(msg.code), true, normalizeCode(msg.code));
        break;
      case 'peer-disconnected':
        state.peerId = null;
        state.expiresAt = null;
        resetSession();
        setStatus('WAITING');
        emit('peer-disconnected', msg);
        break;
      case 'connection-expired':
        // Server killed the pair at expiresAt. Same UI treatment as a lost
        // peer, no auto-reconnect — the connection is really over.
        state.peerId = null;
        state.expiresAt = null;
        resetSession();
        setStatus('WAITING');
        emit('connection-expired', msg);
        emit('peer-disconnected', msg);
        break;
      case 'connection-extended':
        if (typeof msg.expiresAt === 'number') state.expiresAt = msg.expiresAt;
        emit('connection-extended', msg);
        settleAll('extend', null, true, msg);
        break;
      case 'connection-cancelled':
        emit('connection-cancelled', msg);
        break;
      case 'key-exchange':
        // Public key from our actual peer. Never from a client-named id.
        handlePeerKey(msg);
        break;
      case 'message':
        // Encrypted peer payload. net.js decrypts and re-emits the pre-Phase-5
        // shape, so the UI subscribes exactly as it did.
        if (msg && typeof msg.ciphertext === 'string') decryptIncoming(msg);
        break;
      case 'error':
        emit('error', msg);
        if (msg.code) {
          var err = new Error(msg.error || 'error');
          settleAll('join', normalizeCode(msg.code), false, err);
          settleAll('reject', normalizeCode(msg.code), false, err);
          settleAll('accept', normalizeCode(msg.code), false, err);
        } else if (msg.error === 'invalid-duration' || msg.error === 'not-connected' || msg.error === 'connection-expired') {
          settleAll('extend', null, false, new Error(msg.error));
          settleAll('create', null, false, new Error(msg.error));
        }
        break;
      default:
        break;
    }
  }

  var noReconnect = false; // set by disconnect(): one clean close, no redial.
  function connect() {
    var u;
    try { u = (location.protocol === 'https:' ? 'wss:' : 'ws:') + '//' + location.host; }
    catch (e) { return; }
    try { ws = new WebSocket(u); } catch (e) { return; }
    setStatus('CONNECTING');
    ws.addEventListener('open', function () {
      setStatus('WAITING');
      rawSend({ type: 'hello' });
      maybeAutoJoin();
    });
    ws.addEventListener('message', function (ev) {
      var msg;
      try { msg = JSON.parse(ev.data); } catch (e) { return; }
      if (msg && msg.type) handleServerMessage(msg);
    });
    ws.addEventListener('close', function () {
      state.peerId = null;
      state.expiresAt = null;
      // Never carry a session key across a socket: the next pairing is a new
      // session and must derive a new one.
      resetSession();
      setStatus('DISCONNECTED');
      autoJoinTried = false; // retry auto-join after reconnect
      settleAll('create', null, false, new Error('disconnected'));
      settleAll('join', null, false, new Error('disconnected'));
      settleAll('accept', null, false, new Error('disconnected'));
      settleAll('reject', null, false, new Error('disconnected'));
      settleAll('extend', null, false, new Error('disconnected'));
      if (noReconnect) { noReconnect = false; }
      else setTimeout(connect, 3000); // simple backoff; Phase 6 owns reconnect
    });
    ws.addEventListener('error', function () { /* close follows */ });
  }

  function requireCode(code) {
    code = normalizeCode(code);
    if (!CODE_RE.test(code)) return { error: new Error('invalid-code-format') };
    return { code: code };
  }

  // The 160-character limit lives here, in the client, because the client is
  // the only side that can read the message. Encryption happens locally and
  // only {iv, ciphertext} goes on the wire — the server never sees `text`.
  function sendMessage(text) {
    if (typeof text !== 'string' || !text.trim()) return Promise.reject(new Error('empty-message'));
    var body = text.trim();
    if (body.length > 160) return Promise.reject(new Error('message-too-long'));
    if (!isOpen()) return Promise.reject(new Error('not-connected'));
    if (state.connectionState !== 'CONNECTED' || !state.peerId || !session.key) {
      return Promise.reject(new Error('not-connected'));
    }
    return window.__beeperCrypto.encrypt(session.key, body).then(function (envelope) {
      if (!rawSend({ type: 'message', iv: envelope.iv, ciphertext: envelope.ciphertext })) {
        throw new Error('not-connected');
      }
      return true;
    });
  }

  window.__beeperNet = {
    state: state,
    on: on,
    off: off,
    snapshot: snapshot,
    createInvite: function (durationMin) {
      var d = defer('create', null);
      var dur = (durationMin === undefined || durationMin === null) ? 60 : Number(durationMin);
      if (!rawSend({ type: 'create-invite', durationMin: dur })) d.entry.reject(new Error('not-connected'));
      return d.promise;
    },
    joinInvite: function (code) {
      var c = requireCode(code);
      if (c.error) return Promise.reject(c.error);
      var d = defer('join', c.code);
      if (!rawSend({ type: 'join-invite', code: c.code })) d.entry.reject(new Error('not-connected'));
      return d.promise;
    },
    acceptConnection: function (code) {
      var c = requireCode(code);
      if (c.error) return Promise.reject(c.error);
      var d = defer('accept', c.code);
      if (!rawSend({ type: 'accept-connection', code: c.code })) d.entry.reject(new Error('not-connected'));
      return d.promise;
    },
    rejectConnection: function (code) {
      var c = requireCode(code);
      if (c.error) return Promise.reject(c.error);
      var d = defer('reject', c.code);
      if (!rawSend({ type: 'reject-connection', code: c.code })) d.entry.reject(new Error('not-connected'));
      return d.promise;
    },
    extendConnection: function (minutes) {
      var mins = Number(minutes);
      if (!Number.isFinite(mins)) return Promise.reject(new Error('invalid-duration'));
      var d = defer('extend', null);
      if (!rawSend({ type: 'extend-connection', minutes: mins })) d.entry.reject(new Error('not-connected'));
      return d.promise;
    },
    getInviteUrl: function (code) {
      try { return location.origin + '/connect/' + normalizeCode(code); }
      catch (e) { return '/connect/' + normalizeCode(code); }
    },
    sendMessage: sendMessage,
    // send(text) is the Phase 3 text API; send(object) stays as the raw escape hatch.
    send: function (msg) {
      if (typeof msg === 'string') return sendMessage(msg);
      rawSend(msg);
      return Promise.resolve(true);
    },
    reconnect: connect,
    // User-initiated teardown: close once and stay down so the server runs
    // its normal disconnect lifecycle (pair broken, invites reaped, peer
    // notified). No protocol change — the close itself is the signal.
    disconnect: function () {
      noReconnect = true;
      try { if (ws) ws.close(); } catch (e) {}
    },
  };

  // UI hook: the inline page script defines window.__beeperOnNetReady before
  // this deferred file runs, so the UI can subscribe without polling.
  try {
    if (typeof window.__beeperOnNetReady === 'function') window.__beeperOnNetReady(window.__beeperNet);
  } catch (e) {}

  state.pendingInviteCode = inviteFromUrl();
  try { window.__beeperInviteCode = state.pendingInviteCode; } catch (e) {}

  setInterval(function () {
    if (isOpen()) rawSend({ type: 'ping', echo: String(Date.now()) });
  }, HEARTBEAT_MS);

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', connect);
  else connect();
})();
