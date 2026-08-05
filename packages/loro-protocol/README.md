# loro-protocol

Binary wire protocol for Loro CRDTs (TypeScript). Provides compact encoders/decoders for all protocol messages, bytes utilities, and helpers for the %ELO end-to-end encrypted flow (AES‑GCM with 12‑byte IV and exact-header AAD).

## Install

```bash
pnpm add loro-protocol
```

## Features

- Message encoding/decoding for Join/DocUpdate/Fragments/Errors/Leave
- 256 KiB message size guard with fragmentation support at higher layers
- Bytes helpers (`BytesWriter`, `BytesReader`) with varUint/varBytes/varString
- %ELO helpers: container codec, record header parsing, AES‑GCM encrypt/decrypt

See `protocol.md` and `protocol-e2ee.md` at the repo root for the ground‑truth spec.

## Usage

Encode and decode messages:

```ts
import { encode, decode, CrdtType, MessageType } from "loro-protocol";

const join = encode({
  type: MessageType.JoinRequest,
  crdt: CrdtType.Loro,
  roomId: "room-1",
  auth: new Uint8Array(), // join metadata (auth/session tokens, etc.)
  version: new Uint8Array(),
});

const msg = decode(join);
console.log(msg.type); // 0x00 JoinRequest
```

%ELO encrypted records (AES‑GCM):

```ts
import {
  EloRecordKind,
  encryptSnapshot,
  encryptDeltaSpan,
  decryptEloRecord,
  encodeEloDeltaPlaintext,
  decodeEloDeltaPlaintext,
  encodeEloContainer,
  decodeEloContainer,
  parseEloRecordHeader,
} from "loro-protocol";

// Encrypt a snapshot
const key = crypto.getRandomValues(new Uint8Array(32));
const plaintext = new Uint8Array([1, 2, 3]);
const { record } = await encryptSnapshot(
  plaintext,
  { vv: [], keyId: "k1" },
  key
);

// DeltaSpan plaintext is a canonical bounded list of Loro update blobs.
const loroUpdate = new Uint8Array([4, 5, 6]);
const deltaPlaintext = encodeEloDeltaPlaintext([loroUpdate]);
const blobs = decodeEloDeltaPlaintext(deltaPlaintext);
const delta = await encryptDeltaSpan(
  deltaPlaintext,
  { peerId: new TextEncoder().encode("42"), start: 0, end: 1, keyId: "k1" },
  key
);
const container = encodeEloContainer([record, delta.record]);

// Later, parse and decrypt
const [rec] = decodeEloContainer(container);
const parsed = parseEloRecordHeader(rec);
const out = await decryptEloRecord(rec, async () => key);
console.log(parsed.kind === EloRecordKind.Snapshot, out.plaintext);
```

Notes

- A relay without the document key cannot decrypt `ct`, but it parses the plaintext %ELO headers to index/backfill.
- Room IDs and ELO routing headers are visible to the relay and any TLS terminator. Headers expose record kind; raw peer IDs and delta `start`/`end` counters or snapshot peer/counter version-vector entries; `keyId`; and IV. Traffic timing and sizes remain observable. Use non-sensitive `keyId` labels; IVs are public but must be unique per key.
- Prefer a non-semantic base64url or hex room alias generated from at least 128 random bits from a CSPRNG. The alias remains visible to the server, can be correlated, and is not a credential; authenticate and authorize separately.
- Use an authenticated, encrypted transport in production (`wss://` for WebSockets). Transport encryption protects the path to its endpoint, not protocol fields from that endpoint or relay.
- IV must be exactly 12 bytes and unique per key; AAD is the exact encoded header.

## API Surface

- Encoding/decoding: `encode(msg)`, `decode(buf)`, `tryDecode(buf)`
- Bytes: `BytesWriter`, `BytesReader`
- %ELO: `encodeEloContainer`, `decodeEloContainer`, `encodeEloDeltaPlaintext`, `decodeEloDeltaPlaintext`, `parseEloRecordHeader`, `encryptSnapshot`, `encryptDeltaSpan`, `decryptEloRecord`

## Node/Web Compatibility

%ELO crypto uses Web Crypto (`globalThis.crypto.subtle`). Node 18+ provides it via `globalThis.crypto`.

## License

MIT
