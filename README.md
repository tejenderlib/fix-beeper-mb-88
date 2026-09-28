# FIX BEEPER MB-88

**A retro two-person real-time messaging terminal inspired by classic pagers, beepers, and message typewriters.**

<p align="center">
  <video src="media/mb88-demo.mp4" controls width="880">
    Your browser does not support embedded video.
    <a href="media/mb88-demo.mp4">Watch the MB-88 demo video (MP4)</a>
  </video>
</p>

<p align="center">
  <a href="media/mb88-demo.mp4"><strong>▶ Watch the MB-88 demo video</strong></a>
  &nbsp;·&nbsp;
  <a href="https://fix-beeper-mb-88.onrender.com">Live demo</a>
  &nbsp;·&nbsp;
  <a href="https://github.com/tejenderlib/fix-beeper-mb-88">Repository</a>
</p>

Two devices pair through a private invite code, then exchange pager-style messages in real time. Message content is encrypted on the device before it reaches the wire, so the relay only moves ciphertext it cannot read. No accounts, no message history, no third party in the message path.

> **Security note:** the encryption here is **not authenticated end-to-end encryption**. It defends message content against a passive or honest-but-curious relay, not against an active man-in-the-middle. See [Security limitations](#security-limitations).

[![Live Demo](https://img.shields.io/badge/live%20demo-fix--beeper--mb--88-8bf03c?style=flat-square)](https://fix-beeper-mb-88.onrender.com)
[![License: MIT](https://img.shields.io/badge/license-MIT-8bf03c?style=flat-square)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D18-339933?style=flat-square)](https://nodejs.org)

---

## Overview

FIX BEEPER MB-88 is a two-person messaging terminal built around the interaction design of 1980s pagers and message typewriters.

One device creates a private invite code. The other joins with it. Once paired, each message prints as a paper slip on a phosphor-green CRT desk — outgoing slips on the right, incoming on the left, each stamped `✓ DELIVERED` or `← RECEIVED`. The interface is deliberately mechanical: a link bar instead of a console, typewriter keys instead of a settings panel, and a short fixed message length because pagers had no room for more.

The whole application is a single Node process: it serves the client, terminates the WebSocket connection, and owns the pairing state machine. There is no database and no build step.

## Features

| Feature | Detail |
| --- | --- |
| Real-time two-person messaging | Peer-to-peer relay over WebSocket, no echo to the sender |
| Private invite pairing | `MB88-XXXX-XXXX` codes; no account, no login, no user directory |
| Pager-style messages | 160-character limit, enforced in the client and by the input itself |
| CRT / typewriter interface | Phosphor palette, scanlines, vignette, mechanical key input |
| Delivered / received states | Every slip is stamped `✓ DELIVERED` or `← RECEIVED` |
| `/connect CODE` | Join a pair by typing the code into the LCD and pressing TRANSMIT |
| `/clear` | Clear the desk with a typed command |
| Encrypted message content | Message bodies are encrypted on the device before they hit the wire (see limitations below) |
| Responsive layout | Adapts from desktop down to mobile widths |
| WebSocket communication | One socket per device, multiplexed over the same HTTP server as the UI |
| Server-authoritative lifetimes | 30/60/120/160-minute connections, expiry swept and extended by the server |
| On-device link bar | Pairing, invite link, and time remaining without leaving the terminal |

## Encryption architecture

Message **content** is encrypted end-to-end between the two devices. The pairing metadata around it is not.

| Primitive | Detail |
| --- | --- |
| Key agreement | **P-256 ECDH**, ephemeral key pair generated per peer session |
| Key derivation | **HKDF-SHA256** over the ECDH shared secret |
| Symmetric cipher | **AES-256-GCM** |
| Randomness | Fresh **12-byte IV** generated per message |
| Implementation | **Web Crypto API** — no third-party crypto library |

How a session comes up:

1. On `connection-established`, each device generates a fresh ephemeral P-256 key pair.
2. Only the **public** key is sent, as `{ type: 'key-exchange', publicKey }`. The server relays it to that device's one paired peer.
3. Both sides run the shared secret through HKDF-SHA256 and derive the same AES-256-GCM session key **locally**.
4. Outgoing messages are encrypted before transmission, so the wire carries `{ type: 'message', iv, ciphertext }`.
5. Incoming envelopes are decrypted locally. A message event is emitted only after AES-GCM authentication succeeds.
6. The private key and session key are destroyed on peer disconnect, on expiry, and on socket close. A new pairing always derives a new key.

Private keys are never exported and never transmitted. The server holds no key material, cannot read message bodies, and rejects any message that arrives with a plaintext `text` field.

## Security limitations

This is **not** authenticated end-to-end encryption. It protects message content from a passive or honest-but-curious relay, not from an active attacker.

- **The key exchange is unauthenticated.** ECDH alone does not prove who you are talking to. An active man-in-the-middle — including the server itself, which relays the public keys — can substitute its own public key during the exchange and read everything that follows. Closing this requires signed key exchange, which is not implemented.
- **TLS/WSS is still required for transport security.** Invite codes, public keys, and session metadata all travel in the clear without it.
- **The server still observes metadata.** Message timing, message size, message count, and all pairing events are visible to the relay, which permits traffic analysis.
- **No forward-secrecy protocol.** Keys are ephemeral for the life of a session, but there is no ratchet and no per-message key evolution, so a compromised device key exposes the remainder of that session retroactively.
- **Mid-session re-keying is unauthenticated.** A second `key-exchange` from the paired peer re-keys the session, last key wins.
- **The 160-character limit is enforced client-side.** The server cannot read the message, so it caps the encrypted envelope size instead rather than the plaintext length.

## Architecture

```
                      ┌───────────────────────────────────────────────────┐
                      │ BROWSER — all cryptography happens here           │
                      ├───────────────────────────────────────────────────┤
client/index.html     │ CRT terminal, paper slips, link bar, LCD          │
client/style.css      │ phosphor theme, scanlines, responsive rules       │
client/net.js         │ pairing API, session lifecycle, envelopes         │
client/crypto.js      │ ECDH · HKDF · AES-256-GCM primitives              │
                      └───────────────────────────────────────────────────┘
                                                │
                                                ▼   WebSocket / HTTPS
                                 { key-exchange }   { iv, ciphertext }
                                                │
                      ┌───────────────────────────────────────────────────┐
                      │ SERVER — relay and authority, no key material     │
                      ├───────────────────────────────────────────────────┤
server/server.js      │ static files · WebSocket endpoint                 │
server/connections.js │ invites, pairs, expiry sweep                      │
                      │ Never sees: private keys, plaintext message bodies│
                      └───────────────────────────────────────────────────┘
```

The server is a relay and an authority, nothing more. It owns who is paired with whom, when a connection expires, and what `messageId` and `timestamp` a message carries — and it routes an opaque envelope it has no way to read.

## Protocol

JSON messages over a single WebSocket per device.

| Direction | Message types |
| --- | --- |
| Server → client | `welcome`, `hello-ack`, `pong`, `invite-created`, `connection-pending`, `connection-request`, `connection-established`, `connection-rejected`, `reject-acked`, `connection-extended`, `connection-expired`, `connection-cancelled`, `peer-disconnected`, `key-exchange`, `message`, `error` |
| Client → server | `hello`, `ping`, `create-invite`, `join-invite`, `accept-connection`, `reject-connection`, `extend-connection`, `key-exchange`, `message` |
| HTTP | `GET /health` → `{"ok":true}` |

Encrypted payloads:

```jsonc
// public key exchange — both directions
{ "type": "key-exchange", "publicKey": "<base64 P-256 point>" }

// message: client → server
{ "type": "message", "iv": "<base64, 12 bytes>", "ciphertext": "<base64>" }

// message: server → peer
// messageId and timestamp are minted by the server, never by the client
{
  "type": "message",
  "messageId": "<uuid v4>",
  "iv": "<base64, 12 bytes>",
  "ciphertext": "<base64>",
  "timestamp": "<ISO-8601>"
}
```

The server ignores any client-supplied `peerId`, `messageId`, or `timestamp`, and relays only to the peer it computed from its own pairing state.

Errors:

| Source | Codes |
| --- | --- |
| Server | `invalid-json`, `invalid-message`, `invalid-public-key`, `plaintext-not-allowed`, `message-too-long`, `not-connected`, `unknown-type` |
| Client | `decrypt-failed`, `key-exchange-failed`, `crypto-unavailable`, `empty-message`, `message-too-long`, `not-connected` |

## Tech stack

| Technology | Role |
| --- | --- |
| **Node.js** | HTTP server, WebSocket upgrade, pairing state machine |
| [**ws**](https://github.com/websockets/ws) | WebSocket server and client — the only runtime dependency |
| **Web Crypto API** | ECDH P-256, HKDF-SHA256, AES-256-GCM in the browser |
| **HTML / CSS / JavaScript** | The entire client. No framework, no bundler, no build step |
| **node:test** | Test runner — no test dependencies |

## Project structure

```
fix-beeper-mb-88/
├── client/                  Static client, served as-is
│   ├── index.html           CRT terminal markup + UI logic
│   ├── style.css            Phosphor theme, scanlines, responsive rules
│   ├── net.js               WebSocket, pairing API, encryption lifecycle
│   └── crypto.js            Web Crypto primitives (ECDH, HKDF, AES-GCM)
├── server/
│   ├── server.js            Static serving + WebSocket message router
│   └── connections.js       Invites, pairs, lifetimes, expiry sweep
├── test/
│   ├── crypto.test.js       Encryption primitives
│   ├── protocol.test.js     Transport, invites, pairing, lifetimes
│   ├── regression.test.js   Encrypted relay + server authority
│   ├── netclient.test.js    Client-side encrypt/decrypt and teardown
│   └── helpers/             Server harness, crypto bridge, browser shim
├── media/
│   └── mb88-demo.mp4        Promo video for the MB-88
├── package.json
└── README.md
```

## Testing

```sh
npm test
```

**89 tests · 89 passing · 0 failing**

| Suite | Covers |
| --- | --- |
| `crypto.test.js` | ECDH/HKDF derivation, AES-GCM round-trip, tamper and wrong-key rejection, IV freshness |
| `protocol.test.js` | Static serving, `hello`/`ping`, invite lifecycle, rejection, expiry, extension |
| `regression.test.js` | Encrypted relay, server-minted `messageId`/timestamp, no plaintext on the wire, third-party injection, peer-only key relay |
| `netclient.test.js` | The real `net.js`: envelope construction, decryption, tampered ciphertext dropped, session key teardown on disconnect, expiry, and socket close |

Tests run the real `server/server.js` as a child process and drive it over real WebSockets. The client-side tests execute the actual shipped `client/crypto.js` and `client/net.js` in a minimal browser shim rather than reimplementing their logic.

## Deployment

The application is deployed as a **Node.js Web Service on Render**.

- **Live:** <https://fix-beeper-mb-88.onrender.com>
- **Health check:** `GET /health` → `{"ok":true}`

The server reads `PORT` from the environment, falling back to `3000` for local development, and binds the wildcard address so it is reachable outside the container. WebSocket traffic is served over the same port as the UI and upgrades to `wss://` automatically on HTTPS.

## Development

Requires Node.js 18 or newer.

```sh
git clone https://github.com/tejenderlib/fix-beeper-mb-88.git
cd fix-beeper-mb-88
npm ci
npm start
```

Open <http://localhost:3000> in **two browser windows**. Press `CREATE INVITE` on one, then either open the invite link in the other or type `/connect MB88-XXXX-XXXX` into the LCD and press TRANSMIT. Accept the request, type a message, and press TRANSMIT.

| Command | Purpose |
| --- | --- |
| `npm ci` | Install dependencies |
| `npm start` | Start the server on `PORT` (default `3000`) |
| `npm test` | Run the full test suite |

```sh
PORT=8080 npm start
```

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `3000` | HTTP/WebSocket listen port |
| `MB88_TEST_DURATIONS` | *(unset)* | Test-only sub-minute durations. Leave unset outside tests. |

## Project status

**Version 1.0 — core development complete.**

| Phase | Scope | Status |
| --- | --- | --- |
| 1 | Transport: static server, WebSocket handshake, `hello`/`ping` | Done |
| 2 | Invites, pairing, connection lifetime, expiry, extension | Done |
| 3 | Peer messaging with directional paper slips | Done |
| 4 | No-console pairing through the on-device link bar | Done |
| 5 | **End-to-end encryption** — ECDH + HKDF + AES-GCM | Done |

Phase 5 covers content encryption between the two devices. The key exchange is not yet authenticated — see [Security limitations](#security-limitations) and [Future improvements](#future-improvements).

## Future improvements

- **Authenticated key exchange** — long-term identity keys with the ephemeral keys signed over the exchange, so a substituted public key is detected instead of trusted. This is the prerequisite for calling the encryption genuinely secure.
- **Forward secrecy** — a key ratchet or per-message keys, so compromising a device key does not expose the rest of the session.
- **Metadata protection** — padding and batching to blunt traffic analysis against the relay.
- **Transport hardening** — enforce WSS, add HSTS, and secure the invite-code exchange.
- Beyond security: delivery receipts, message history, persistence, and authentication.

## License

Released under the [MIT License](LICENSE).
