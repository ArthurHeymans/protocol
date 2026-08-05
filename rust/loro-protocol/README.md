# loro-protocol (Rust)

Rust implementation of the Loro syncing protocol encoder/decoder. Mirrors the TypeScript package in `packages/loro-protocol` and follows the wire format described in `protocol.md` and the end-to-end encrypted flow in `protocol-e2ee.md`.

## Features
- Encode/decode Join, DocUpdate (with batch IDs), FragmentHeader/Fragment, Ack, RoomError, and Leave messages
- 256 KiB message size guard to match the wire spec
- Bytes utilities (`BytesWriter`, `BytesReader`) for varint/varbytes/varstring
- `%ELO` container parsing; Rust-side encryption helpers are WIP and may evolve

## Usage

Add the crate to your workspace (published crate name matches the package):

```bash
cargo add loro-protocol
```

Encode and decode messages:

```rust
use loro_protocol::{encode, decode, ProtocolMessage, CrdtType};

let msg = ProtocolMessage::JoinRequest {
    crdt: CrdtType::Loro,
    room_id: "room-123".to_string(),
    auth: vec![],
    version: vec![],
};

let bytes = encode(&msg)?;
let roundtrip = decode(&bytes)?;
assert_eq!(roundtrip, msg);
```

Streaming-friendly decode:

```rust
use loro_protocol::try_decode;

let buf = /* bytes from the wire */;
if let Some(msg) = try_decode(&buf) {
    // valid message
} else {
    // malformed or incomplete buffer
}
```

## Privacy boundary

`%ELO` encrypts document bodies, not the protocol envelope. The relay and any TLS terminator can read the exact room ID; record kind; raw peer IDs and delta `start`/`end` counters or snapshot peer/counter version-vector entries; `keyId`; and IV. Traffic sizes, timing, and membership activity also remain observable. Use non-sensitive `keyId` labels; IVs are public but must be unique per key.

For production ELO rooms, use an authenticated, encrypted transport (`wss://` for WebSockets) and a non-semantic base64url or hex room alias generated from at least 16 bytes from an OS CSPRNG. Share it through an authenticated, confidential application channel. Transport encryption protects the path to its endpoint, not protocol fields from that endpoint or relay. The alias remains visible and correlatable by the server and is not a credential; enforce authentication and authorization independently.

## Tests

```bash
cargo test -p loro-protocol
```

## Spec References

- `protocol.md` for the wire format and message semantics
- `protocol-e2ee.md` for %ELO encryption details
