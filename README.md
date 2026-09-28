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
- **End-to-end encryption** — *in development*

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

**2. Talk.** A sends `{type:'message', text}`. The server validates the payload (string, non-blank after trim, ≤160 chars, sender has a live pair) and relays it to the peer only. The sender's own `transmit()` already printed its slip locally, so there is no echo.

**3. Expire.** A 1-second sweep closes the pair at `expiresAt` and notifies both sides. Either side can `extend-connection` first, which adds time to what remains. The relay re-checks liveness per message, so a dead peer can never be written to.

### Protocol sketch

| Direction | Message |
| --- | --- |
| S → C | `welcome`, `invite-created`, `connection-request`, `connection-established`, `connection-extended`, `connection-expired`, `peer-disconnected`, `message`, `error` |
| C → S | `hello`, `ping`, `create-invite`, `join-invite`, `accept-connection`, `reject-connection`, `extend-connection`, `message` |
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

**End-to-end encryption is the next major piece.** Today the server relays plaintext and holds the pairing state, so it is a trusted party in the path. The plan is for each device to generate a keypair during pairing and derive a shared secret, so the server routes ciphertext it cannot read. The design goal is that the current server-authority boundaries — which peer is who, and when a pair dies — survive intact once the payload is opaque to the server; the regression tests that guard those boundaries are written to keep passing.

## Screenshots

> Coming soon. The CRT desk, the link bar, and a paired two-device exchange.

## License

Released under the [MIT License](LICENSE).
