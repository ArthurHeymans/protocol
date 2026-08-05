# loro-websocket-client (Rust)

Async WebSocket client for the Loro protocol. Exposes:

- Low-level `Client` to send/receive raw `loro_protocol::ProtocolMessage`.
- High-level `LoroWebsocketClient` that joins rooms and mirrors updates into a `loro::LoroDoc`, matching the TypeScript client behavior.

%ELO support includes canonical delta packaging, application key resolution, rotation, bounded unknown-key retry, and genuine snapshot bootstrap. Key distribution/KMS remains application-owned. ELO encrypts document bodies only: room IDs and plaintext routing headers remain visible to the relay and any TLS terminator.

## Quick start

```rust
use std::sync::Arc;
use loro::{LoroDoc};
use loro_websocket_client::LoroWebsocketClient;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
let client = LoroWebsocketClient::connect("ws://127.0.0.1:9000/ws1?token=secret").await?;
let doc = Arc::new(tokio::sync::Mutex::new(LoroDoc::new()));
let _room = client.join_loro("room1", doc.clone()).await?;
// mutate doc then commit; the client auto-sends updates
{ let mut d = doc.lock().await; d.get_text("text").insert(0, "hello")?; d.commit(); }
# Ok(()) }
```

## ELO privacy boundary

Use `wss://` in production and prefer a non-semantic base64url or hex room alias generated from at least 16 bytes from an OS CSPRNG. Generate it once and share it through an authenticated, confidential application channel. TLS protects the path to its endpoint, not protocol fields from the endpoint or relay. The server still receives the exact alias and can correlate it, so it is not a credential or a substitute for join authentication/authorization. ELO record kind; raw peer IDs and delta `start`/`end` counters or snapshot peer/counter version-vector entries; `keyId`; IV; container sizes; traffic timing; and membership activity are also observable. Use non-sensitive `keyId` labels; IVs are public but must be unique per key.

## Features

- Handles protocol keepalive (`"ping"/"pong"`) and filters control frames.
- Automatic fragmentation/reassembly thresholds aligned with the server. Reassembly is bounded to 64 fragments, 8 MiB per batch, 8 in-flight batches, and 16 MiB of declared in-flight bytes; duplicate/out-of-range fragments and mismatched totals are rejected.
- %ELO adaptor helpers encrypt/decrypt canonical deltas and genuine snapshots.
- `EloKeyResolver` is the async application hook; `EloKeyring` selects an active outbound key while retaining historical read keys. `add_key` rejects conflicting key-ID reuse, and resolved key material uses redacted `Debug` output.
- `join_elo_with_key_resolver` accepts a resolver. Room handles expose FIFO `retry_pending_encrypted_records` and `publish_elo_snapshot`; publication returns `false` if the room is read-only or preparation/encryption fails.
- `join_with_adaptor_and_auth` carries application-defined join metadata on the initial request, version retries, and server-requested rejoins. Use it for bootstrap claims or room-scoped authorization.
- `EloUpdateMaterializer` lets applications own authenticated plaintext handling. Configure it with `EloDocAdaptor::with_update_materializer` to validate an application schema, reconcile disk state, and materialize the accepted update. Without one, the adaptor retains its atomic Loro import behavior.
- Structured ELO errors distinguish unknown keys, known-key authentication failures, malformed/import failures, outbound encryption failures, and pending eviction. Generic import callbacks receive the error message but not ELO plaintext/ciphertext bytes.
- Fixed-key `EloDocAdaptor::new` and `join_elo_with_adaptor` remain compatibility wrappers.

## Tests

```bash
cargo test -p loro-websocket-client
```
