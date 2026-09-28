# FIX BEEPER MB-88

A retro two-person real-time messaging terminal inspired by classic pagers, beepers, and message typewriters.

Two devices pair through a private invite code, then talk directly through a WebSocket relay. Received messages print as paper slips on a phosphor-green CRT desk. There are no accounts, no server-side history, and no third party in the middle.

## Features

- **Private invite-based pairing** — `MB88-XXXX-XXXX` codes, browser-joinable via `/connect/<code>`, no account or login
- **Real-time messaging over WebSockets** — peer-to-peer relay, no echo to the sender
- **Server-authoritative connection state** — pairing, peers, and expiry are owned by the server; clients only display it
- **Connection lifetime and expiry** — 30/60/120/160-minute invites, server-swept expiry, extendable from either side
- **`/connect` and `/clear` commands** — type them in the LCD and press TRANSMIT
- **Directional message cards** — your slips print right, received slips print left
- **Connection status and peer lifecycle handling** — offline / waiting / incoming / connected / denied / peer-lost
- **Automated protocol and regression tests** — 65 tests over the wire protocol and server-authority boundaries
- **End-to-end encryption** — ephemeral P-256 ECDH per session, HKDF-SHA256 → AES-256-GCM, Web Crypto API, no dependencies. The server relays ciphertext it cannot read.

## How it works

A single Node process does three jobs: serve the static client, hold the WebSocket upgrade, and keep the pairing state machine.

```
client/index.html ─┐
client/net.js ─────┤   ws://            ┌── server/server.js
client/style.css ──┘  ▲                │     static file server
                     │                │     JSON message router
              ┌──────┴──────┐         │
              │             │         └── server/connections.js
        device A        device B            invites, pairs, expiry sweep
```

**1. Pair.** Device A sends `create-invite` and gets back a code. Device B sends `join-invite`; A receives a `connection-request` and either accepts or rejects. Accepting establishes a pair and tells both sides their `peerId`, `expiresAt`, and duration. The server computes the peer id from its own bookkeeping — a client can never declare who its peer is.

**2. Talk.** A sends `{type:'message', iv, ciphertext}`. The server validates the envelope, confirms A has a live pair, and relays it to the peer only — it cannot read the contents. A's local `transmit()` already printed its slip, so there is no echo. A plaintext `text` field is rejected outright rather than quietly relayed.

### 3. Encrypt.** On `connection-established` each device generates an ephemeral P-256 key pair and publishes only the public key, which the server relays to that one peer. Both sides derive the same AES-256-GCM session key locally via HKDF-SHA256. Messages are encrypted before they hit the socket, so the wire carries `{iv, ciphertext}` and the server never sees plaintext. The session key is destroyed on peer disconnect, on expiry, and on socket close.

### 4. Expire.** A 1-second sweep closes the pair at `expiresAt` and notifies both sides. Either side can `extend-connection` first, which adds time to what remains. The relay re-checks liveness per message, so a dead peer can never be written to.

### Protocol sketch

| Direction | Message |
| --- | --- |
| S → C | `welcome`, `invite-created`, `connection-request`, `connection-established`, `connection-extended`, `connection-expired`, `peer-disconnected`, `key-exchange`, `message`, `error` |
| C → S | `hello`, `ping`, `create-invite`, `join-invite`, `accept-connection`, `reject-connection`, `extend-connection`, `key-exchange`, `message` |
| HTTP | `GET /health` → `{"ok":true}` |

## Tech stack

- **Node.js** — HTTP static server + WebSocket upgrade, no framework
- **[ws](https://github.com/websockets/ws)** — the only runtime dependency
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
| `npm test` | Run the protocol and regression suites |

Useful environment variables:

| Variable | Default | Notes |
| --- | --- | --- |
| `PORT` | `3000` | HTTP/WebSocket listen port |
| `MB88_TEST_DURATIONS` | *(unset)* | Test-only comma-separated sub-minute durations, e.g. `0.05,0.1`. Leave unset in production. |

## Project status

**In progress.** Phases 1–4 are working: protocol handshake, invite pairing, peer messaging, and server-authoritative connection lifetime with no-console pairing through the on-device link bar.

Not yet built: delivery receipts, message history, persistence, and auth.

## Future work

**Authenticated key exchange.** ECDH gives confidentiality against a passive server, but unauthenticated ECDH does not stop an *active* one: a man-in-the-middle can substitute its own public key during the exchange and read everything. Closing that means signing the key exchange — each device publishing a long-term identity key, and the ephemeral keys being signed with it, so a substituted key is detected rather than trusted.

Other open items:

- **Peer re-keying.** Today the session key is fixed for the life of a pairing. A peer that sends a second `key-exchange` re-keys the session; the last key wins. Rotating on a schedule, and rejecting out-of-band re-keys, are both open.
- **No forward secrecy.** A device that leaks its private key retroactively exposes that session's traffic, since the private key is held for the session's duration. Ephemeral per-message keys would fix it.
- **Transport security.** The app is served over plain HTTP/WS. E2EE protects message content, but invite codes and session metadata still travel in the clear. Serve it over TLS/WSS.
- **Server-visible metadata.** Message count, size, timing, and pairing events are all visible to the relay. Padding and batching would reduce that.
- Not yet built: delivery receipts, message history, persistence, and auth.

## Screenshots

> Coming soon. The CRT desk, the link bar, and a paired two-device exchange.

## License

Released under the [MIT License](LICENSE).
