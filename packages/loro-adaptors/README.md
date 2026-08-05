# loro-adaptors

Adaptors that bridge the Loro protocol to `loro-crdt` documents, `flock` replicas, and the ephemeral store. Includes an end‑to‑end encrypted adaptor for %ELO.

## Install

```bash
pnpm add loro-adaptors loro-protocol

# If using loro-crdt:
pnpm add loro-crdt

# If using flock:
pnpm add @loro-dev/flock

# If using yjs:
pnpm add yjs
```

## Why

The websocket client (`loro-websocket`) speaks the binary wire protocol. These adaptors connect that client to concrete CRDT state:

- `LoroAdaptor`: wraps a `LoroDoc` and streams local updates to the connection; applies remote updates on receipt
- `LoroEphemeralAdaptor`: wraps an `EphemeralStore` for transient presence/cursor data
- `LoroPersistentStoreAdaptor`: wraps an `EphemeralStore` but marks updates as persisted so the server stores them for new peers
- `EloAdaptor`: wraps a `LoroDoc` and packages updates into %ELO containers with AES‑GCM; decrypts inbound containers and imports plaintext.
- `FlockAdaptor`: wraps a `Flock` replica and streams local updates to the connection; applies remote updates on receipt.
- `YjsAwarenessServerAdaptor`: handles Yjs awareness updates on the server side (opaque blob merging).

## Usage

### Loro

```ts
import { LoroWebsocketClient } from "loro-websocket";
import {
  LoroAdaptor,
  LoroEphemeralAdaptor,
  LoroPersistentStoreAdaptor,
  EloAdaptor,
  EloKeyring,
} from "loro-adaptors/loro"; // Import from "loro-adaptors/loro" to avoid pulling in unused peer dependencies
import { LoroDoc, EphemeralStore } from "loro-crdt";

const client = new LoroWebsocketClient({ url: "ws://localhost:8787" });
await client.waitConnected();

// Plain Loro document
const doc = new LoroDoc();
doc.setPeerId(1); // configure the underlying document directly
const docAdaptor = new LoroAdaptor(doc);
const roomDoc = await client.join({ roomId: "demo", crdtAdaptor: docAdaptor });

// Ephemeral presence
const eph = new EphemeralStore(30_000);
const ephAdaptor = new LoroEphemeralAdaptor(eph);
const roomEph = await client.join({ roomId: "demo", crdtAdaptor: ephAdaptor });

// Persisted presence that should be available to late joiners
const persistedStore = new EphemeralStore(30_000);
const persistedAdaptor = new LoroPersistentStoreAdaptor(persistedStore);
const roomPersisted = await client.join({
  roomId: "demo-persisted",
  crdtAdaptor: persistedAdaptor,
});

// %ELO (end‑to‑end encrypted Loro)
const keyring = new EloKeyring([{ keyId: "k1", key: new Uint8Array(32) }], "k1");
const elo = new EloAdaptor({ keyResolver: keyring });
// Generate once from at least 16 CSPRNG bytes and share out of band.
// The relay still sees and can correlate this non-semantic alias.
const roomAlias = "<shared-random-128-bit-or-more-room-alias>";
const secure = await client.join({ roomId: roomAlias, crdtAdaptor: elo });

// Rotation changes future writes while retaining k1 for historical records.
keyring.addKey("k2", new Uint8Array(32));
keyring.setActiveKey("k2");
await elo.publishSnapshot();
// After fetching/installing a missing key:
await elo.retryPendingEncryptedRecords();

// Edits
doc.getText("content").insert(0, "hello");
doc.commit();

// Cleanup
await roomEph.destroy();
await roomDoc.destroy();
await roomPersisted.destroy();
await secure.destroy();
```

### Flock

```ts
import { LoroWebsocketClient } from "loro-websocket";
import { FlockAdaptor } from "loro-adaptors/flock"; // Import from "loro-adaptors/flock"
import { Flock } from "@loro-dev/flock";

const client = new LoroWebsocketClient({ url: "ws://localhost:8787" });
await client.waitConnected();

const flock = new Flock();
const adaptor = new FlockAdaptor(flock);
const room = await client.join({ roomId: "flock-demo", crdtAdaptor: adaptor });
```

### YJS Awareness

```ts
import { YjsAwarenessServerAdaptor } from "loro-adaptors/yjs";
// This is primarily for server-side use or specific awareness integration
```

## %ELO privacy boundary

`EloAdaptor` encrypts the Loro document body, not the wire envelope or routing metadata. The relay and any TLS terminator see the exact room ID; record kind; raw peer IDs and delta `start`/`end` counters or snapshot peer/counter version-vector entries; `keyId`; IV; container sizes; timing; and membership activity. Use non-sensitive `keyId` labels. IVs are public but must be unique per key.

Use `wss://` and a non-semantic base64url or hex room alias generated from at least 128 random bits from a CSPRNG. Generate it once and share it through an authenticated, confidential application channel. TLS protects the path to its endpoint, not fields from the endpoint or relay. An opaque alias carries less meaning than a project or user name, but it is still visible to the server, remains correlatable, and is neither authentication nor authorization.

The zero-filled keys and literal aliases in snippets are placeholders only; use application key management and CSPRNG-generated values in production.

## API

- `loro-adaptors/loro`
  - `new LoroAdaptor(doc?: LoroDoc, config?: { onImportError?, onUpdateError? })`
  - `new LoroEphemeralAdaptor(store?: EphemeralStore)`
  - `new LoroPersistentStoreAdaptor(store?: EphemeralStore)`
  - `new EloAdaptor(docOrConfig: LoroDoc | { keyResolver?, getPrivateKey?, pendingEncryptedRecords?, onEloError?, ivFactory?, onDecryptError?, onUpdateError? })`
  - `EloKeyResolver` and `EloKeyring` provide exact inbound `keyId` lookup plus active outbound key selection. Key IDs are immutable: `addKey` allows idempotent reinstall but rejects conflicting reuse, and byte keys are defensively copied.
  - `publishSnapshot()` emits a fresh snapshot under the active key after earlier queued writes; `retryPendingEncryptedRecords()` retries the bounded, byte-exact deduplicated unknown-key queue in FIFO order.
  - `onEloError` distinguishes `unknown_key`, `decrypt_failed`, malformed/import failures, outbound `encrypt_failed`, and pending eviction. The legacy generic import-error callback is still invoked, but ELO plaintext/ciphertext bytes are redacted from it. A custom `ivFactory` must return a fresh 12-byte IV; repeats are rejected before encryption.
- `loro-adaptors/flock`
  - `new FlockAdaptor(flock: Flock, config?: { onImportError?, onUpdateError? })`
- `loro-adaptors/yjs`
  - `new YjsAwarenessServerAdaptor()`

## Development

```bash
pnpm build
pnpm test
pnpm typecheck
```

## License

MIT
