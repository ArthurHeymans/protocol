# loro-websocket-server (Rust)

Minimal async WebSocket server for the Loro protocol. Broadcasts DocUpdates between clients and provides hooks for auth and persistence. It mirrors the TypeScript server in `packages/loro-websocket`.

## Features

- Supports `%LOR`, `%EPH`, `%ELO` (experimental/WIP) and related CRDT types with fragment reassembly (≤256 KiB per message).
- Connection keepalive handling (`"ping"/"pong"` text frames).
- Workspace isolation via URL path (`/{workspace}`) and optional handshake auth.
- Load/save hooks with optional per-document metadata context to assist persistence.
- `%ELO` persistence stores the standard ELO container (latest validated snapshot plus indexed deltas). The relay does not need a document key and cannot decrypt `ct` without one, but it reads and stores plaintext ELO routing headers.

Rust persistence is periodic. Durability is therefore bounded by `save_interval_ms`; stopping an externally spawned server task does not provide an additional flush hook.

## Privacy boundary

Room IDs are cleartext protocol routing fields and storage keys. The relay and any TLS terminator receive their exact values. ELO additionally exposes plaintext record kind; raw peer IDs and delta `start`/`end` counters or snapshot peer/counter version-vector entries; `keyId`; IV; container sizes; traffic timing; and membership activity. Only the CRDT body in `ct` is end-to-end encrypted. Use non-sensitive `keyId` labels; IVs are public but must be unique per key.

Deploy with TLS and protect any separate proxy-to-relay hop. Use non-semantic base64url or hex room aliases generated from at least 128 random bits from a CSPRNG, share them through an authenticated, confidential application channel, and avoid names containing project/user details. TLS protects the path to its endpoint, not protocol fields from the endpoint or relay. An alias is still visible and correlatable by this server and is not authorization. Authenticate and authorize every join separately, and minimize metadata logging and retention.

## Quick start

Run the bundled SQLite-backed example:

```bash
cargo run -p loro-websocket-server --example simple-server -- --addr 127.0.0.1:9000 --db loro.db
```

Then connect clients to `ws://127.0.0.1:9000/ws1`.

Integrate your own storage by wiring `ServerConfig.on_load_document` and `on_save_document`.

## Tests

```bash
cargo test -p loro-websocket-server
```
