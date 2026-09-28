// server/connections.js — invites + private pairing + connection lifetime.
// No messaging, no persistence, no auth. All state is in-memory and
// server-authoritative: clients can never declare their own peer links,
// durations, or expiry. Clients only display the server-provided expiresAt.
//
// Lifecycle: AVAILABLE -> PENDING -> CONNECTED (timed) -> EXPIRED
//   createInvite(durationMin) -> AVAILABLE (creatorId + durationMin set)
//   joinInvite                -> PENDING   (requesterId set, creator notified)
//   acceptConnection          -> CONNECTED (links set, expiresAt = now + duration)
//   extendConnection(minutes) -> same pair, expiresAt += minutes (both members)
//   sweepExpired / expiry     -> links broken, invites removed, both notified
//   disconnect cleanup        -> links broken, owned invites removed,
//                                pending requests reset, peer notified by server.js
import crypto from 'node:crypto';

export const CODE_RE = /^MB88-[A-Z0-9]{4}-[A-Z0-9]{4}$/;

// Connection lifetimes the UI offers. Extra short values may be enabled for
// automated expiry tests via MB88_TEST_DURATIONS="0.05,0.1" (minutes).
// Default off in production — never accepted unless the env var is set.
export const DURATIONS_MIN = [30, 60, 120, 160];

function extraTestDurations() {
  const raw = process.env.MB88_TEST_DURATIONS || '';
  return raw
    .split(',')
    .map((s) => Number(String(s).trim()))
    .filter((n) => Number.isFinite(n) && n > 0);
}

export function allowedDurations() {
  return [...DURATIONS_MIN, ...extraTestDurations()];
}

export function normalizeDuration(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return null;
  return allowedDurations().includes(n) ? n : null;
}

// No ambiguous chars (no 0/O/1/I) so codes read cleanly off the LCD.
const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

export function generateInviteCode() {
  const pick = () => ALPHABET[crypto.randomInt(ALPHABET.length)];
  const group = () => Array.from({ length: 4 }, pick).join('');
  return `MB88-${group()}-${group()}`;
}

export function normalizeCode(code) {
  return String(code || '').trim().toUpperCase();
}

export function createConnectionStore() {
  // code -> { code, creatorId, status, requesterId, createdAt, durationMin }
  const invites = new Map();
  // clientId -> peerId (only set while CONNECTED and unexpired)
  const links = new Map();
  // clientId -> { peerId, startedAt, durationMin, expiresAt }
  const lifetimes = new Map();

  function createInvite(creatorId, durationMin = 60) {
    const dur = normalizeDuration(durationMin);
    if (dur === null) return { ok: false, error: 'invalid-duration' };
    let code;
    do {
      code = generateInviteCode();
    } while (invites.has(code));
    invites.set(code, { code, creatorId, status: 'AVAILABLE', requesterId: null, createdAt: Date.now(), durationMin: dur });
    return { ok: true, code, durationMin: dur };
  }

  function getInvite(code) {
    return invites.get(normalizeCode(code)) || null;
  }

  function joinInvite(code, requesterId, isConnected) {
    code = normalizeCode(code);
    if (!CODE_RE.test(code)) return { ok: false, error: 'invalid-code-format' };
    const inv = invites.get(code);
    if (!inv) return { ok: false, error: 'invite-not-found' };
    if (inv.creatorId === requesterId) return { ok: false, error: 'cannot-join-own-invite' };
    if (!isConnected(inv.creatorId)) return { ok: false, error: 'creator-offline' };
    if (inv.status === 'PENDING') return { ok: false, error: 'invite-pending' };
    if (inv.status === 'CONNECTED') return { ok: false, error: 'invite-already-used' };
    inv.status = 'PENDING';
    inv.requesterId = requesterId;
    return { ok: true, invite: inv };
  }

  function acceptConnection(code, clientId, isConnected) {
    code = normalizeCode(code);
    const inv = invites.get(code);
    if (!inv) return { ok: false, error: 'invite-not-found' };
    // Only the creator may accept — never trust a client-provided peer claim.
    if (inv.creatorId !== clientId) return { ok: false, error: 'not-invite-owner' };
    if (inv.status !== 'PENDING' || !inv.requesterId) return { ok: false, error: 'no-pending-request' };
    if (!isConnected(inv.requesterId)) {
      inv.status = 'AVAILABLE';
      inv.requesterId = null;
      return { ok: false, error: 'requester-offline' };
    }
    const startedAt = Date.now();
    const lifetime = { peerId: null, startedAt, durationMin: inv.durationMin, expiresAt: startedAt + inv.durationMin * 60 * 1000 };
    inv.status = 'CONNECTED';
    links.set(inv.creatorId, inv.requesterId);
    links.set(inv.requesterId, inv.creatorId);
    lifetimes.set(inv.creatorId, { ...lifetime, peerId: inv.requesterId });
    lifetimes.set(inv.requesterId, { ...lifetime, peerId: inv.creatorId });
    return { ok: true, code, creatorId: inv.creatorId, requesterId: inv.requesterId, expiresAt: lifetime.expiresAt, durationMin: inv.durationMin };
  }

  function rejectConnection(code, clientId) {
    code = normalizeCode(code);
    const inv = invites.get(code);
    if (!inv) return { ok: false, error: 'invite-not-found' };
    if (inv.creatorId !== clientId) return { ok: false, error: 'not-invite-owner' };
    if (inv.status !== 'PENDING' || !inv.requesterId) return { ok: false, error: 'no-pending-request' };
    const requesterId = inv.requesterId;
    // Invite stays usable: back to AVAILABLE so someone else (or a retry) can join.
    inv.status = 'AVAILABLE';
    inv.requesterId = null;
    return { ok: true, code, requesterId };
  }

  function getPeer(clientId) {
    return links.get(clientId) || null;
  }

  function getLifetime(clientId) {
    return lifetimes.get(clientId) || null;
  }

  // Live pair only: linked AND unexpired. Callers must treat anything else
  // as disconnected (server.js also reaps via sweepExpired).
  function isLive(clientId, now = Date.now()) {
    const peer = links.get(clientId);
    if (!peer) return false;
    const life = lifetimes.get(clientId);
    if (!life || life.peerId !== peer) return false;
    return now < life.expiresAt;
  }

  // Extend the SAME pair. Deterministic under concurrent requests: Node
  // handles messages serially, each grant adds to the current expiresAt.
  // Never accepts a client-provided timestamp — only minutes from the set.
  function extendConnection(clientId, minutes, isConnected) {
    const mins = normalizeDuration(minutes);
    if (mins === null) return { ok: false, error: 'invalid-duration' };
    const peer = links.get(clientId);
    const life = lifetimes.get(clientId);
    if (!peer || !life || life.peerId !== peer) return { ok: false, error: 'not-connected' };
    if (!isConnected(peer)) {
      breakPair(clientId);
      return { ok: false, error: 'not-connected' };
    }
    if (Date.now() >= life.expiresAt) {
      expirePair(clientId);
      return { ok: false, error: 'connection-expired' };
    }
    const expiresAt = life.expiresAt + mins * 60 * 1000;
    lifetimes.get(clientId).expiresAt = expiresAt;
    const peerLife = lifetimes.get(peer);
    if (peerLife) peerLife.expiresAt = expiresAt;
    return { ok: true, peerId: peer, expiresAt, addedMin: mins };
  }

  function breakPair(clientId) {
    const peer = links.get(clientId);
    links.delete(clientId);
    lifetimes.delete(clientId);
    if (peer) {
      links.delete(peer);
      lifetimes.delete(peer);
    }
    return peer || null;
  }

  // removes invites owned by either member of the pair (they are single-use
  // once connected) and returns who to notify.
  function expirePair(clientId) {
    const peer = breakPair(clientId);
    const removed = [];
    for (const [code, inv] of invites) {
      if (inv.creatorId === clientId || inv.creatorId === peer) {
        invites.delete(code);
        removed.push(code);
      }
    }
    return { peerId: peer, removedInvites: removed };
  }

  // Reap every pair past expiry. Returns [{a, b}] for server.js to notify.
  function sweepExpired(now = Date.now()) {
    const done = [];
    const seen = new Set();
    for (const [clientId, life] of lifetimes) {
      if (seen.has(clientId)) continue;
      if (now >= life.expiresAt) {
        const peer = life.peerId;
        expirePair(clientId);
        seen.add(clientId);
        if (peer) seen.add(peer);
        done.push({ a: clientId, b: peer });
      }
    }
    return done;
  }

  function handleDisconnect(clientId) {
    const out = { peerId: null, removedInvites: [], cancelled: null, orphaned: [] };
    const peer = links.get(clientId);
    if (peer) {
      links.delete(clientId);
      links.delete(peer);
      lifetimes.delete(clientId);
      lifetimes.delete(peer);
      out.peerId = peer;
    } else {
      lifetimes.delete(clientId);
    }
    for (const [code, inv] of invites) {
      if (inv.creatorId === clientId) {
        // A joiner stuck in PENDING on this invite must be told it is gone.
        if (inv.status === 'PENDING' && inv.requesterId) {
          out.orphaned.push({ code, requesterId: inv.requesterId });
        }
        invites.delete(code);
        out.removedInvites.push(code);
      } else if (inv.requesterId === clientId && inv.status === 'PENDING') {
        inv.status = 'AVAILABLE';
        inv.requesterId = null;
        out.cancelled = { code, creatorId: inv.creatorId };
      }
    }
    return out;
  }

  return {
    createInvite,
    getInvite,
    joinInvite,
    acceptConnection,
    rejectConnection,
    extendConnection,
    getPeer,
    getLifetime,
    isLive,
    sweepExpired,
    handleDisconnect,
    // Exposed for tests only (same process); never sent to clients.
    _invites: invites,
    _links: links,
    _lifetimes: lifetimes,
  };
}
