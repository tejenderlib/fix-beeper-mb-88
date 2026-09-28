// test/regression.test.js — Phase 3 (peer messaging) baseline, PLUS the
// server-authority guarantees that E2EE must not break in Phase 6.
//
// This file deliberately captures the CURRENT PLAINTEXT PROTOCOL. There is no
// crypto here on purpose: the baseline has to describe what the system does
// today, so that Step 2's server+client rewrite has something to be measured
// against.
//
// The server-authority tests at the bottom are the ones that matter most for
// Phase 6: they pin down that messageId, timestamp, and routing come from the
// server and cannot be overridden by a client. When `message` is replaced by
// an encrypted envelope, these invariants must survive the change.
import { test, before, after, describe } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, pair, Client, UUID_RE, sleep } from './helpers/client.js';

describe('Phase 3 — plaintext message relay (baseline, pre-E2EE)', () => {
  let srv;
  const open = [];

  before(async () => { srv = await startServer(); });
  after(async () => {
    for (const c of open) c.close();
    await srv.stop();
  });

  async function pairUp(durationMin = 60) {
    const p = await pair(srv, { durationMin });
    open.push(p.a, p.b);
    return p;
  }

  test('a message from A is relayed to peer B', async () => {
    const { a, b } = await pairUp();
    const got = b.waitFor('message');
    a.send({ type: 'message', text: 'HELLO BEACON' });
    const m = await got;
    assert.equal(m.type, 'message');
    assert.equal(m.text, 'HELLO BEACON');
  });

  test('the server mints the messageId as a uuid', async () => {
    const { a, b } = await pairUp();
    const got = b.waitFor('message');
    a.send({ type: 'message', text: 'first' });
    const m = await got;
    assert.match(m.messageId, UUID_RE);
  });

  test('the server mints an ISO-8601 timestamp', async () => {
    const { a, b } = await pairUp();
    const got = b.waitFor('message');
    a.send({ type: 'message', text: 'first' });
    const m = await got;
    assert.equal(typeof m.timestamp, 'string');
    assert.ok(Number.isFinite(Date.parse(m.timestamp)), `not ISO-8601: ${m.timestamp}`);
  });

  test('the server mints a fresh messageId per message', async () => {
    const { a, b } = await pairUp();
    const ids = new Set();
    for (const text of ['one', 'two', 'three']) {
      const got = b.sendAndWait({ type: 'message', text }, 'message');
      a.send({ type: 'message', text });
      ids.add((await got).messageId);
    }
    assert.equal(ids.size, 3, 'messageIds must be unique');
  });

  test('the sender receives no echo of its own message', async () => {
    const { a, b } = await pairUp();
    const got = b.waitFor('message');
    a.send({ type: 'message', text: 'NO ECHO' });
    // Positive assertion first: the peer definitely received it. Only then is
    // the absence check on the sender meaningful, so this cannot flake.
    await got;
    assert.equal(await a.expectNone('message'), true, 'sender must not be echoed');
  });

  test('the relayed payload carries no routing metadata', async () => {
    const { a, b } = await pairUp();
    const got = b.waitFor('message');
    a.send({ type: 'message', text: 'meta' });
    const m = await got;
    // Exactly the four documented fields — nothing that reveals who sent it
    // beyond the socket it arrived on.
    assert.deepEqual(Object.keys(m).sort(), ['messageId', 'text', 'timestamp', 'type']);
  });

  test('surrounding whitespace is trimmed by the server', async () => {
    const { a, b } = await pairUp();
    const got = b.waitFor('message');
    a.send({ type: 'message', text: '   padded   ' });
    assert.equal((await got).text, 'padded');
  });

  test('a message of exactly 160 characters is accepted', async () => {
    const { a, b } = await pairUp();
    const text = 'x'.repeat(160);
    const got = b.waitFor('message');
    a.send({ type: 'message', text });
    assert.equal((await got).text.length, 160);
  });

  test('a message of 161 characters is rejected with message-too-long', async () => {
    const { a, b } = await pairUp();
    const err = await a.sendAndWait({ type: 'message', text: 'x'.repeat(161) }, 'error');
    assert.equal(err.error, 'message-too-long');
    assert.equal(await b.expectNone('message'), true, 'nothing may be relayed');
  });

  test('the length check applies after trimming', async () => {
    const { a, b } = await pairUp();
    const text = 'y'.repeat(160);
    const got = b.sendAndWait({ type: 'message', text }, 'message');
    // 160 real characters plus surrounding spaces is still within the limit.
    a.send({ type: 'message', text: `  ${text}  ` });
    assert.equal((await got).text.length, 160, 'trimmed message must be accepted');
  });

  test('an empty message is rejected with empty-message', async () => {
    const { a, b } = await pairUp();
    const err = await a.sendAndWait({ type: 'message', text: '' }, 'error');
    assert.equal(err.error, 'empty-message');
    assert.equal(await b.expectNone('message'), true);
  });

  test('a whitespace-only message is rejected with empty-message', async () => {
    const { a, b } = await pairUp();
    const err = await a.sendAndWait({ type: 'message', text: '   \t  ' }, 'error');
    assert.equal(err.error, 'empty-message');
    assert.equal(await b.expectNone('message'), true);
  });

  test('a non-string text is rejected with invalid-message', async () => {
    const { a, b } = await pairUp();
    for (const bad of [42, null, { a: 1 }, ['x'], true]) {
      const err = await a.sendAndWait({ type: 'message', text: bad }, 'error');
      assert.equal(err.error, 'invalid-message', `for ${JSON.stringify(bad)}`);
    }
    assert.equal(await b.expectNone('message'), true);
  });

  test('a message with no text field is rejected with invalid-message', async () => {
    const { a } = await pairUp();
    const err = await a.sendAndWait({ type: 'message' }, 'error');
    assert.equal(err.error, 'invalid-message');
  });

  test('an unpaired client cannot send: not-connected', async () => {
    const solo = new Client(srv.wsUrl);
    await solo.open();
    open.push(solo);
    const err = await solo.sendAndWait({ type: 'message', text: 'anyone there?' }, 'error');
    assert.equal(err.error, 'not-connected');
  });

  test('a client cannot relay to a third party by naming a peerId', async () => {
    const { a, b } = await pairUp();
    const bystander = new Client(srv.wsUrl);
    await bystander.open();
    open.push(bystander);

    const got = b.sendAndWait({ type: 'message', text: 'routed by server' }, 'message');
    // The client claims a different peer; the server must use its own map.
    a.send({ type: 'message', text: 'routed by server', peerId: (await bystander.waitFor('welcome')).clientId });
    assert.equal((await got).text, 'routed by server');
    assert.equal(
      await bystander.expectNone('message'),
      true,
      'the named peerId must be ignored'
    );
  });

  test('messages flow in order over a burst', async () => {
    const { a, b } = await pairUp();
    const words = ['ALPHA', 'BRAVO', 'CHARLIE', 'DELTA', 'ECHO'];
    for (const w of words) a.send({ type: 'message', text: w });
    const received = [];
    for (let i = 0; i < words.length; i++) {
      received.push((await b.waitFor('message')).text);
    }
    assert.deepEqual(received, words);
  });

  test('a message is not relayed once the peer has disconnected', async () => {
    const { a, b } = await pairUp();
    const gone = a.waitFor('peer-disconnected');
    b.close();
    await gone;
    const err = await a.sendAndWait({ type: 'message', text: 'anyone there?' }, 'error');
    assert.equal(err.error, 'not-connected');
  });
});

describe('Phase 3 — server authority (must survive E2EE)', () => {
  let srv;
  const open = [];

  before(async () => { srv = await startServer(); });
  after(async () => {
    for (const c of open) c.close();
    await srv.stop();
  });

  test('a client-supplied messageId is ignored and replaced by the server', async () => {
    const a = new Client(srv.wsUrl); await a.open();
    const b = new Client(srv.wsUrl); await b.open();
    open.push(a, b);
    const code = (await a.sendAndWait({ type: 'create-invite' }, 'invite-created')).code;
    await b.sendAndWait({ type: 'join-invite', code }, 'connection-pending');
    await a.waitFor('connection-request');
    const forB = b.waitFor('connection-established');
    a.send({ type: 'accept-connection', code });
    await forB;

    const got = b.sendAndWait({ type: 'message', text: 'spoof' }, 'message');
    a.send({
      type: 'message',
      text: 'spoof',
      messageId: 'CLIENT-SUPPLIED-ID',
      senderId: 'CLIENT-SUPPLIED-SENDER',
    });
    const m = await got;
    assert.notEqual(m.messageId, 'CLIENT-SUPPLIED-ID');
    assert.match(m.messageId, UUID_RE);
    assert.equal(m.senderId, undefined, 'client cannot inject routing fields');
  });

  test('the server clock is the only timestamp source', async () => {
    const a = new Client(srv.wsUrl); await a.open();
    const b = new Client(srv.wsUrl); await b.open();
    open.push(a, b);
    const code = (await a.sendAndWait({ type: 'create-invite' }, 'invite-created')).code;
    await b.sendAndWait({ type: 'join-invite', code }, 'connection-pending');
    await a.waitFor('connection-request');
    const forB = b.waitFor('connection-established');
    a.send({ type: 'accept-connection', code });
    await forB;

    const before = Date.now();
    const got = b.sendAndWait({ type: 'message', text: 'clock' }, 'message');
    a.send({ type: 'message', text: 'clock', timestamp: '1999-01-01T00:00:00.000Z' });
    const after = Date.now();

    const m = await got;
    assert.notEqual(m.timestamp, '1999-01-01T00:00:00.000Z');
    const t = Date.parse(m.timestamp);
    assert.ok(t >= before - 2000 && t <= after + 2000, `timestamp ${m.timestamp} is not server-clock`);
  });

  test('a client cannot declare a peer link that the server did not create', async () => {
    const a = new Client(srv.wsUrl); await a.open();
    const b = new Client(srv.wsUrl); await b.open();
    open.push(a, b);
    // A never created an invite, so it has no peer. Naming B must not help.
    const idB = (await b.waitFor('welcome')).clientId;
    const err = await a.sendAndWait({ type: 'message', text: 'forced', peerId: idB }, 'error');
    assert.equal(err.error, 'not-connected');
  });

  test('a third socket cannot inject a message into an established pair', async () => {
    const a = new Client(srv.wsUrl); await a.open();
    const b = new Client(srv.wsUrl); await b.open();
    const evil = new Client(srv.wsUrl); await evil.open();
    open.push(a, b, evil);
    const code = (await a.sendAndWait({ type: 'create-invite' }, 'invite-created')).code;
    await b.sendAndWait({ type: 'join-invite', code }, 'connection-pending');
    await a.waitFor('connection-request');
    const forB = b.waitFor('connection-established');
    a.send({ type: 'accept-connection', code });
    await forB;

    const err = await evil.sendAndWait({ type: 'message', text: 'injected' }, 'error');
    assert.equal(err.error, 'not-connected');
    assert.equal(await b.expectNone('message'), true);
  });
});
