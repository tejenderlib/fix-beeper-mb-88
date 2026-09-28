# FIX BEEPER MB-88

A retro two-person real-time messaging terminal inspired by classic pagers, beepers, and message typewriters.

Two devices pair through a private invite code, then talk through a WebSocket relay. Messages are end-to-end encrypted on the device, so the relay moves ciphertext it cannot read. Received messages print as paper slips on a phosphor-green CRT desk. There are no accounts and no server-side message history.

## Features

- **End-to-end encrypted messaging** — ephemeral P-256 ECDH per session, HKDF-SHA256 → AES-256-GCM, Web Crypto API, no dependencies
- **Private invite-based pairing** — `MB88-XXXX-XXXX` codes, browser-joinable via `/connect/<code>`, no account or login
- **Real-time messaging over WebSockets** — peer-to-peer relay, no echo to the sender
- **Server-authoritative connection state** — pairing, peers, and expiry are owned by the server; clients only display it
- **Connection lifetime and expiry** — 30/60/120/160-minute invites, server-swept expiry, extendable from either side
- **`/connect` and `/clear` commands** — type them in the LCD and press TRANSMIT
- **Directional message cards** — your slips print right, received slips print left
- **Connection status and peer lifecycle handling** — offline / waiting / incoming / connected / denied / peer-lost
- **Automated protocol and regression tests** — 89 tests over the crypto primitives, the wire protocol, the server-authority boundaries, and the client session lifecycle

## How it works

A single Node process does three jobs: serve the static client, hold the WebSocket upgrade, and keep the pairing state machine.

```
client/index.html  ┐
client/net.js      ┤   ws://                              ┌── server/server.js
client/crypto.js   ┘ ▲                                    │     static file server
                     │                                      │     JSON message router
              ┌──────┴──────┐                                      │
              │             │                                      └── server/connections.js
        device A        device B      invites, pairs, expiry sweep
```

Encryption happens entirely in the browser. The server routes opaque envelopes and public keys; it holds no key material.

**1. Pair.** Device A sends `create-invite` and gets back a code. Device B sends `join-invite`; A receives a `connection-request` and either accepts or rejects. Accepting establishes a pair and tells both sides their `peerId`, `expiresAt`, and duration. The server computes the peer id from its own bookkeeping — a client can never declare who its peer is.

**2. Encrypt.** On `connection-established` each device generates an ephemeral P-256 key pair and sends only the public key, which the server relays to that one peer. Both sides run the shared secret through HKDF-SHA256 and derive the same AES-256-GCM session key locally. A fresh 12-byte IV is generated per message. Private keys are never exported and never touch the socket.

**3. Talk.** A sends `{type:'message', iv, ciphertext}`. The server validates the envelope, confirms A has a live pair, and relays it to the peer only. A's local `transmit()` already printed its slip, so there is no echo. A plaintext `text` field is rejected outright rather than quietly relayed, so a client that forgets to encrypt fails loudly instead of leaking content past the encryption boundary.

**4. Expire.** A 1-second sweep closes the pair at `expiresAt` and notifies both sides. Either side can `extend-connection` first, which adds time to what remains. The relay re-checks liveness per message, so a dead peer can never be written to. The session key is destroyed on peer disconnect, on expiry, and on socket close — a new pairing always derives a new one.

## Protocol

| Direction | Message |
| --- | --- |
| S → C | `welcome`, `hello-ack`, `pong`, `invite-created`, `connection-pending`, `connection-request`, `connection-established`, `connection-rejected`, `reject-acked`, `connection-extended`, `connection-expired`, `connection-cancelled`, `peer-disconnected`, `key-exchange`, `message`, `error` |
| C → S | `hello`, `ping`, `create-invite`, `join-invite`, `accept-connection`, `reject-connection`, `extend-connection`, `key-exchange`, `message` |
| HTTP | `GET /health` → `{"ok":true}` |

Key exchange and messaging:

```jsonc
// both directions
{ "type": "key-exchange", "publicKey": "<base64 P-256 point>" }

// client → server
{ "type": "message", "iv": "<base64, 12 bytes>", "ciphertext": "<base64>" }

// server → peer — messageId and timestamp are minted by the server
{ "type": "message", "messageId": "<uuid>", "iv": "<base64>", "ciphertext": "<base64>", "timestamp": "<ISO-8601>" }
```

The server accepts neither a client-supplied `peerId` nor a client-supplied `messageId`/`timestamp`. It validates the envelope shape, base64, and size, requires a live pair, and relays to the one peer it computed.

Errors the server can return: `invalid-json`, `invalid-message`, `invalid-public-key`, `plaintext-not-allowed`, `message-too-long`, `not-connected`, `unknown-type`. Errors raised in the browser before or after the wire: `decrypt-failed`, `key-exchange-failed`, `crypto-unavailable`, `empty-message`, `message-too-long`, `not-connected`.

## Tech stack

- **Node.js** — HTTP static server + WebSocket upgrade, no framework
- **[ws](https://github.com/websockets/ws)** — the only runtime dependency
- **Web Crypto API** — ECDH P-256, HKDF-SHA256, AES-256-GCM, in the browser via `client/crypto.js`; no crypto library
- **JavaScript** — ES modules, browser and server
- **HTML / CSS** — no build step, no framework, no bundler
- **Node test runner** — `node --test`, no test dependencies

## Local development

Requires Node.js 18+ (developed on Node 20).

```sh
git clone https://github.com/tejenderlib/fix-beeper-mb88.git
cd fix-beeper-mb88
npm install
npm start
```

Open <http://localhost:3000> in **two browser windows**, press `CREATE INVITE` on one, and either open the invite link in the other or type `/connect MB88-XXXX-XXXX` into the LCD and press TRANSMIT. Accept the request, then type a message and press TRANSMIT.

To use a different port, set it in the environment:

```sh
PORT=8080 npm start
```

## Available commands

| Command | What it does |
| --- | --- |
| `npm install` | Install the single dependency (`ws`) |
| `npm start` | Start the server on `PORT` (default `3000`) |
| `npm test` | Run the crypto, protocol, regression, and client suites |

Useful environment variables:

| Variable | Default | Notes |
| --- | --- | --- |
| `PORT` | `3000` | HTTP/WebSocket listen port |
| `MB88_TEST_DURATIONS` | *(unset)* | Test-only comma-separated sub-minute durations, e.g. `0.05,0.1`. Leave unset in production. |

## Security

**The message contents are end-to-end encrypted. The session is not authenticated, and the transport is not encrypted by this app.** Read this before trusting it with anything that matters.

What is protected:

- Message contents never reach the server in readable form. It relays `{iv, ciphertext}` and has no key material.
- Every message is authenticated by AES-GCM. A tampered ciphertext or IV fails to decrypt and is dropped — no message is ever displayed from unauthenticated bytes.
- A plaintext `text` field is rejected by the server.
- Session keys are ephemeral and destroyed on disconnect, expiry, and socket close. A new pairing derives a new key.

What is **not** protected:

- **No authenticated key exchange.** ECDH is unauthenticated. An active man-in-the-middle — including the server itself, which relays the public keys — can substitute its own public key during the exchange and read everything that follows. This protects you against a *passive or honest-but-curious* relay, not an active one. Do not treat this as authenticated E2EE.
- **TLS/WSS is still required.** The app is served over plain HTTP/WS. Encryption protects message contents only; invite codes, public keys, and session metadata all travel in the clear. Serve it behind TLS.
- **The server still sees metadata.** Message count, message size, timing, and all pairing events are visible to the relay. Traffic analysis is possible; padding and batching would reduce what can be inferred.
- **No forward secrecy.** A device that leaks its private key retroactively exposes that session's traffic, since the key is held for the session's duration.
- **A peer can re-key mid-session.** A second `key-exchange` from the paired peer re-keys the session; the last key wins. Only the real peer can do this, so it is self-inflicted rather than an attack, but it is unauthenticated.
- **The 160-character limit is client-enforced.** The server cannot read the message, so it caps the envelope size instead. A non-conforming client can exceed 160 characters slightly.

## Project status

**In progress.** Phases 1–5 are complete:

| Phase | Scope | Status |
| --- | --- | --- |
| 1 | Transport: static server, WebSocket handshake, `hello`/`ping` | Done |
| 2 | Invites, pairing, connection lifetime, expiry, extension | Done |
| 3 | Peer messaging with directional paper slips | Done |
| 4 | No-console pairing via the on-device link bar | Done |
| 5 | End-to-end encryption (ECDH + HKDF + AES-GCM) | Done |
| 6 | Reconnect and resilience | Next |

Not yet built: delivery receipts, message history, persistence, and auth.

## Future work

- **Authenticated key exchange** — long-term identity keys, with ephemeral keys signed over the exchange, so a substituted key is detected rather than trusted. This is the prerequisite for calling the E2EE real.
- **Forward secrecy** — ephemeral per-message keys instead of one key for the whole session.
- **Authenticated re-keying** — reject out-of-band re-keys, or rotate on a schedule with confirmation.
- **Metadata resistance** — padding and batching to blunt traffic analysis.
- Delivery receipts, message history, persistence, and auth.

## Screenshots

> Coming soon. The CRT desk, the link bar, and a paired two-device exchange.

## License

Released under the [MIT License](LICENSE).
