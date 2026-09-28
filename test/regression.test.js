// test/regression.test.js — Phase 5 (end-to-end encrypted relay) plus the
// server-authority guarantees that encryption must not break.
//
// No production code is stubbed or re-implemented. Messages are encrypted and
// decrypted with the REAL client/crypto.js (test/helpers/e2ee.js loads that
// exact file), and relayed through the real server over real WebSockets.
//
// The server-authority tests at the bottom are the ones that matter most: they
// pin down that messageId, timestamp, and routing come from the server and
// cannot be overridden by a client. Phase 5 changed the payload, never the
// authority — these prove it.
import { test, before, after, describe } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, Client, UUID_RE, CODE_RE } from './helpers/client.js';
import { securePair, envelope, readEnvelope, crypto } from './helpers/e2ee.js';

describe('Phase 5 — encrypted message relay', () => {
  let srv;
  const open = [];

  before(async () => { srv = await startServer(); });
  after(async () => {
    for (const c of open) c.close();
    await srv.stop();
  });

  /** Pair AND complete the key exchange, so both sides hold a session key. */
  async function pairUp(durationMin = 60) {
    const p = await securePair(srv, { durationMin });
    open.push(p.a, p.b);
    return p;
  }

  test('an encrypted message from A is relayed to peer B and decrypts', async () => {
    const { a, b, aKey, bKey } = await pairUp();
    const got = b.waitFor('message');
    a.send(await envelope(aKey, 'HELLO BEACON'));
    const m = await got;
    assert.equal(m.type, 'message');
    assert.equal(await crypto.decrypt(bKey, m), 'HELLO BEACON');
  });

  test('the relay never carries plaintext', async () => {
    const { a, b, aKey } = await pairUp();
    const got = b.waitFor('message');
    a.send(await envelope(aKey, 'CANARY PLAINTEXT 12345'));
    const m = await got;
    // Neither the field nor its base64 form may leak the content.
    assert.equal(m.text, undefined, 'no plaintext field on the wire');
    assert.equal(Buffer.from(m.ciphertext, 'base64').toString('utf8').includes('CANARY'), false);
    assert.equal(Buffer.from(m.iv, 'base64').toString('utf8').includes('CANARY'), false);
  });

  test('the server mints the messageId as a uuid', async () => {
    const { a, b, aKey } = await pairUp();
    const got = b.waitFor('message');
    a.send(await envelope(aKey, 'first'));
    assert.match((await got).messageId, UUID_RE);
  });

  test('the server mints an ISO-8601 timestamp', async () => {
    const { a, b, aKey } = await pairUp();
    const got = b.waitFor('message');
    a.send(await envelope(aKey, 'first'));
    const m = await got;
    assert.equal(typeof m.timestamp, 'string');
    assert.ok(Number.isFinite(Date.parse(m.timestamp)), `not ISO-8601: ${m.timestamp}`);
  });

  test('the server mints a fresh messageId per message', async () => {
    const { a, b, aKey } = await pairUp();
    const ids = new Set();
    for (const text of ['one', 'two', 'three']) {
      const got = b.waitFor('message');
      a.send(await envelope(aKey, text));
      ids.add((await got).messageId);
    }
    assert.equal(ids.size, 3, 'messageIds must be unique');
  });

  test('the sender receives no echo of its own message', async () => {
    const { a, b, aKey } = await pairUp();
    const got = b.waitFor('message');
    a.send(await envelope(aKey, 'NO ECHO'));
    // Positive assertion first: the peer definitely received it. Only then is
    // the absence check on the sender meaningful, so this cannot flake.
    await got;
    assert.equal(await a.expectNone('message'), true, 'sender must not be echoed');
  });

  test('the relayed payload carries no routing metadata', async () => {
    const { a, b, aKey } = await pairUp();
    const got = b.waitFor('message');
    a.send(await envelope(aKey, 'meta'));
    const m = await got;
    // Exactly the documented envelope fields — nothing that reveals who sent
    // it beyond the socket it arrived on.
    assert.deepEqual(Object.keys(m).sort(), ['ciphertext', 'iv', 'messageId', 'timestamp', 'type']);
  });

  test('a 160-character plaintext still fits through the relay', async () => {
    const { a, b, aKey, bKey } = await pairUp();
    const got = b.waitFor('message');
    a.send(await envelope(aKey, 'x'.repeat(160)));
    assert.equal((await crypto.decrypt(bKey, await got)).length, 160);
  });

  test('an oversized envelope is rejected with message-too-long', async () => {
    const { a, b, aKey } = await pairUp();
    // Well past the cap the server enforces on the envelope.
    const err = await a.sendAndWait(
      { type: 'message', iv: 'AAAAAAAAAAAAAAAA', ciphertext: 'A'.repeat(2048) },
      'error'
    );
    assert.equal(err.error, 'message-too-long');
    assert.equal(await b.expectNone('message'), true, 'nothing may be relayed');
  });

  test('a plaintext text field is rejected outright', async () => {
    const { a, b } = await pairUp();
    for (const extra of [{ text: 'leaking' }, { text: '' }, { text: 'x', iv: 'AAAA', ciphertext: 'AAAA' }]) {
      const err = await a.sendAndWait({ type: 'message', ...extra }, 'error');
      assert.equal(err.error, 'plaintext-not-allowed', `for ${JSON.stringify(extra)}`);
    }
    assert.equal(await b.expectNone('message'), true, 'plaintext must never be relayed');
  });

  test('a malformed envelope is rejected with invalid-message', async () => {
    const { a, b } = await pairUp();
    for (const bad of [{}, { iv: 'AAAA' }, { ciphertext: 'AAAA' },
                       { iv: 1, ciphertext: 'AAAA' }, { iv: 'AAAA', ciphertext: [] },
                       { iv: 'AAAA', ciphertext: 'not base64!!' }, { iv: 'AAAA', ciphertext: 'AAA' }]) {
      const err = await a.sendAndWait({ type: 'message', ...bad }, 'error');
      assert.equal(err.error, 'invalid-message', `for ${JSON.stringify(bad)}`);
    }
    assert.equal(await b.expectNone('message'), true);
  });

  test('an unpaired client cannot send: not-connected', async () => {
    const solo = new Client(srv.wsUrl);
    await solo.open();
    open.push(solo);
    const donor = await securePair(srv);
    open.push(donor.a, donor.b);
    const err = await solo.sendAndWait(await envelope(donor.aKey, 'anyone there?'), 'error');
    assert.equal(err.error, 'not-connected');
  });

  test('a client cannot relay to a third party by naming a peerId', async () => {
    const { a, b, aKey, bKey } = await pairUp();
    const bystander = new Client(srv.wsUrl);
    await bystander.open();
    open.push(bystander);

    const got = b.waitFor('message');
    // The client claims a different peer; the server must use its own map.
    const bystanderId = (await bystander.waitFor('welcome')).clientId;
    a.send({ ...(await envelope(aKey, 'routed by server')), peerId: bystanderId });

    // The real peer still receives it, and can read it.
    assert.equal(await crypto.decrypt(bKey, await got), 'routed by server');
    assert.equal(await bystander.expectNone('message'), true, 'the named peerId must be ignored');
  });

  test('messages flow in order over a burst', async () => {
    const { a, b, aKey, bKey } = await pairUp();
    const words = ['ALPHA', 'BRAVO', 'CHARLIE', 'DELTA', 'ECHO'];
    for (const w of words) a.send(await envelope(aKey, w));
    const received = [];
    for (let i = 0; i < words.length; i++) {
      received.push((await readEnvelope(b, bKey)).text);
    }
    assert.deepEqual(received, words);
  });

  test('a message is not relayed once the peer has disconnected', async () => {
    const { a, b, aKey } = await pairUp();
    const gone = a.waitFor('peer-disconnected');
    b.close();
    await gone;
    const err = await a.sendAndWait(await envelope(aKey, 'anyone there?'), 'error');
    assert.equal(err.error, 'not-connected');
  });
});

describe('Phase 5 — public-key exchange', () => {
  let srv;
  const open = [];

  before(async () => { srv = await startServer(); });
  after(async () => {
    for (const c of open) c.close();
    await srv.stop();
  });

  test('a public key is relayed to the actual peer', async () => {
    const { a, b, aKey, bKey } = await securePair(srv);
    open.push(a, b);
    // Both sides derived a usable key from the exchange that securePair ran.
    const got = b.waitFor('message');
    a.send(await envelope(aKey, 'keys are live'));
    assert.equal(await crypto.decrypt(bKey, await got), 'keys are live');
  });

  test('key-exchange from an unpaired client fails with not-connected', async () => {
    const solo = new Client(srv.wsUrl);
    await solo.open();
    open.push(solo);
    const paired = await securePair(srv);
    open.push(paired.a, paired.b);
    const kp = await crypto.generateKeyPair();
    const err = await solo.sendAndWait(
      { type: 'key-exchange', publicKey: await crypto.exportPublicKey(kp.publicKey) },
      'error'
    );
    assert.equal(err.error, 'not-connected');
  });

  test('a public key is never relayed to a third party', async () => {
    const { a, b } = await securePair(srv);
    open.push(a, b);
    const bystander = new Client(srv.wsUrl);
    await bystander.open();
    open.push(bystander);

    const kp = await crypto.generateKeyPair();
    const pub = await crypto.exportPublicKey(kp.publicKey);
    // The client names its own intended recipient; the server ignores it.
    a.send({ type: 'key-exchange', publicKey: pub, peerId: (await bystander.waitFor('welcome')).clientId });
    assert.equal(await bystander.expectNone('key-exchange'), true, 'third party must receive nothing');
  });

  test('a non-string or empty public key is rejected with invalid-message', async () => {
    const { a, b } = await securePair(srv);
    open.push(a, b);
    for (const bad of [null, 42, {}, [], true, '']) {
      const err = await a.sendAndWait({ type: 'key-exchange', publicKey: bad }, 'error');
      assert.equal(err.error, 'invalid-message', `for ${JSON.stringify(bad)}`);
    }
  });

  test('a malformed public key is rejected with invalid-public-key', async () => {
    const { a, b } = await securePair(srv);
    open.push(a, b);
    for (const bad of ['not base64!!', 'AAA', 'A'.repeat(600)]) {
      const err = await a.sendAndWait({ type: 'key-exchange', publicKey: bad }, 'error');
      assert.equal(err.error, 'invalid-public-key', `for ${JSON.stringify(bad)}`);
    }
  });

  test('a paired client may exchange keys, and only its own peer receives them', async () => {
    const { a, b } = await securePair(srv);
    const second = await securePair(srv);
    open.push(a, b, second.a, second.b);
    const kp = await crypto.generateKeyPair();
    const pub = await crypto.exportPublicKey(kp.publicKey);
    // Accepted, because the sender IS paired — with second.b, not with A.
    const atB = second.b.sendAndWait({ type: 'key-exchange', publicKey: pub }, 'key-exchange');
    second.a.send({ type: 'key-exchange', publicKey: pub });
    assert.equal((await atB).publicKey, pub);
    // The first pair already exchanged keys during setup, so assert on this
    // specific key never reaching them — not on the mere absence of the type.
    assert.equal(sawKey(b, pub), false, 'an unrelated pair sees nothing');
  });
});

describe('Phase 5 — server authority (must survive E2EE)', () => {
  let srv;
  const open = [];

  before(async () => { srv = await startServer(); });
  after(async () => {
    for (const c of open) c.close();
    await srv.stop();
  });

  test('a client-supplied messageId is ignored and replaced by the server', async () => {
    const { a, b, aKey } = await securePair(srv);
    open.push(a, b);
    const got = b.waitFor('message');
    a.send({
      ...(await envelope(aKey, 'spoof')),
      messageId: 'CLIENT-SUPPLIED-ID',
      senderId: 'CLIENT-SUPPLIED-SENDER',
    });
    const m = await got;
    assert.notEqual(m.messageId, 'CLIENT-SUPPLIED-ID');
    assert.match(m.messageId, UUID_RE);
    assert.equal(m.senderId, undefined, 'client cannot inject routing fields');
  });

  test('the server clock is the only timestamp source', async () => {
    const { a, b, aKey } = await securePair(srv);
    open.push(a, b);
    const before = Date.now();
    const got = b.waitFor('message');
    a.send({ ...(await envelope(aKey, 'clock')), timestamp: '1999-01-01T00:00:00.000Z' });
    const after = Date.now();
    const m = await got;
    assert.notEqual(m.timestamp, '1999-01-01T00:00:00.000Z');
    const t = Date.parse(m.timestamp);
    assert.ok(t >= before - 2000 && t <= after + 2000, `timestamp ${m.timestamp} is not server-clock`);
  });

  test('a client cannot declare a peer link that the server did not create', async () => {
    // A never creates an invite, so it has no peer. Naming B must not help.
    const pair = await securePair(srv);
    const b = pair.b;
    open.push(pair.a, pair.b);
    const a = new Client(srv.wsUrl);
    await a.open();
    open.push(a);
    const idB = (await b.waitFor('welcome')).clientId;
    const victim = await securePair(srv);
    open.push(victim.a, victim.b);
    const err = await a.sendAndWait(
      { ...(await envelope(victim.aKey, 'forced')), peerId: idB },
      'error'
    );
    assert.equal(err.error, 'not-connected');
  });

  test('a third socket cannot inject a message into an established pair', async () => {
    const { a, b, aKey } = await securePair(srv);
    open.push(a, b);
    const evil = new Client(srv.wsUrl);
    await evil.open();
    open.push(evil);
    const err = await evil.sendAndWait(await envelope(aKey, 'injected'), 'error');
    assert.equal(err.error, 'not-connected');
    assert.equal(await b.expectNone('message'), true);
  });

  test('a third socket cannot inject a key into an established pair either', async () => {
    const { a, b } = await securePair(srv);
    open.push(a, b);
    const evil = new Client(srv.wsUrl);
    await evil.open();
    open.push(evil);
    const kp = await crypto.generateKeyPair();
    const pub = await crypto.exportPublicKey(kp.publicKey);
    const err = await evil.sendAndWait({ type: 'key-exchange', publicKey: pub }, 'error');
    assert.equal(err.error, 'not-connected');
    assert.equal(sawKey(b, pub), false, "the attacker's key never reaches the pair");
  });
});

/** Did this client ever receive `pub` as a relayed key? */
function sawKey(client, pub) {
  return client.log.some((m) => m.type === 'key-exchange' && m.publicKey === pub);
}
