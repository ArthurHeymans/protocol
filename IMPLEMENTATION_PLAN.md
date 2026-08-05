# %ELO Hardening Implementation Plan

This is a test-first, cross-language hardening effort. Each stage starts by adding the listed failing tests, implements only enough behavior to pass them, and leaves TypeScript and Rust green before the next stage begins.

## Scope and fixed decisions

- Preserve `%ELO`, the current record/header encoding, exact-header AAD, base-protocol v1 envelopes, batch IDs, ACK behavior, fragmentation, and the clear room ID.
- Use `getrandom` 0.3 directly in the Rust client for fallible 12-byte OS-random IV generation. Never use a fixed/zero fallback or emit a record after randomness fails. Keep deterministic IV injection only for tests and compatibility helpers.
- Keep `aes-gcm` 0.10 in Rust and native Web Crypto in TypeScript. Explicitly use a 128-bit GCM tag in TypeScript.
- Do not add `secrecy` 0.10 unless a focused API review demonstrates a concrete reduction in key exposure without breaking the existing `[u8; 32]` convenience API. No speculative crypto dependencies are planned.
- Encode DeltaSpan plaintext canonically as `varUint count` followed by `count × varBytes Loro update`. Outbound implementations use this form; inbound implementations temporarily support authenticated legacy single-blob plaintext through a tested, full-consumption fallback. Snapshot plaintext remains a genuine Loro snapshot blob.
- Persist opaque raw records using the existing ELO container encoding. Do not introduce serde, bincode, or a TypeScript-only/Rust-only state format.
- Retain the latest structurally valid snapshot plus indexed deltas by default. Send the snapshot before deltas it does not cover. Snapshot receipt does not delete deltas; authorized compaction is a separate policy.
- Keep existing public APIs working where practical. Fixed-key Rust constructors wrap the new resolver, and existing TypeScript callbacks may ignore added metadata. Document any unavoidable signature or error-semantics change.
- Room-name confidentiality is not part of this wire-compatible change. Recommend random, non-semantic room aliases generated from at least 128 random bits from a CSPRNG; aliases remain cleartext routing identifiers visible to the relay and TLS terminator, not credentials, and do not prevent server-side correlation.

## Stage 1: Lock the crypto and plaintext contract

**Goal**: Establish executable TypeScript/Rust conformance tests and fail-closed crypto helpers before changing client synchronization behavior.

**Success Criteria**:

- Rust production encryption obtains every 12-byte IV through fallible `getrandom::fill`; an RNG error is propagated through a typed local error and emits no record.
- Existing deterministic IV injection remains available for tests, while production defaults cannot silently select a deterministic IV.
- TypeScript uses one `globalThis.crypto` accessor for both `subtle` and `getRandomValues`, accepts real Web Crypto `CryptoKey` values, and explicitly requests `tagLength: 128`.
- Both implementations construct AAD from the exact serialized header and reject wrong keys, mutated headers/AAD, mutated IVs, truncated tags, and mutated ciphertext.
- Rust performs real AES-GCM encryption of the normative vector instead of copying its expected ciphertext.
- Shared helpers encode/decode canonical DeltaSpan plaintext as a bounded list of Loro blobs with complete-input validation; the temporary legacy raw-blob fallback is isolated to client import code.
- `protocol-e2ee.md` clarifies the canonical DeltaSpan plaintext, base v1 `Ack(0x08)`, and `varString` room ID without changing wire bytes.

**Tests**:

- Extend `packages/loro-protocol/tests/e2ee.test.ts` with decrypt round trips, real `CryptoKey` input, two production IVs under one key, invalid IV length, and tampered header/IV/ciphertext/tag rejection.
- Add canonical DeltaSpan plaintext codec tests for zero/one/multiple blobs, truncation, trailing bytes, and configured count/size bounds.
- Replace the copied-ciphertext assertion in `rust/loro-protocol/tests/elo_normative_vector.rs` or add a client-crate crypto test that actually encrypts the normative key/IV/plaintext/AAD and reproduces the specified ciphertext and tag.
- Add Rust tests with an injected failing RNG and deterministic RNG, asserting respectively that no send occurs and that the normative vector is reproducible.
- Run `pnpm --filter loro-protocol test`, its typecheck, and `cargo test -p loro-protocol -p loro-websocket-client`.

**Status**: In Progress (Rust IV generation and failure handling reviewed; focused Rust tests passing)

## Stage 2: Make client delta, key, and retry behavior correct

**Goal**: Emit accurately indexed DeltaSpan records in order, support key selection/rotation, and make inbound recovery observable and retryable in both clients.

**Success Criteria**:

- TypeScript serializes local-update packaging through one promise chain so `lastSentVV` cannot race or regress.
- Rust queues synchronous local-update callbacks into one ordered async worker that resolves keys, generates IVs, exports ranges, encrypts records, and reports failures without reordering later updates.
- Each local blob is inspected with Loro import metadata. Every forward peer interval becomes one DeltaSpan with decimal UTF-8 Loro peer ID bytes, checked non-negative/u64 counters, and exact `[start,end)` metadata; multi-peer updates use exact `updates-in-range` exports.
- Genuine snapshots contain a snapshot export and the real lexicographically sorted version vector. Snapshots are fallback/bootstrap records, not mislabeled local delta blobs.
- TypeScript keeps `getPrivateKey(keyId?)`; Rust adds an async `EloKeyResolver` that selects the outgoing key for `None` and resolves the exact incoming `keyId` for `Some`. `EloDocAdaptor::new` and `join_elo_with_adaptor` remain fixed-key convenience APIs that reject other IDs.
- Outbound key resolution occurs per record/send, allowing future writes and an explicit public `publishSnapshot()` operation to use a newly active key without moving application key policy into the adaptor.
- Resolver rejection is reported as `unknown_key`; successful resolution followed by AEAD failure is `decrypt_failed`; malformed container/header/plaintext and Loro import failures remain distinct. Errors include record kind, key ID, and delta peer/span metadata where available.
- Unknown-key records are retained in a bounded, deduplicated per-adaptor pending set. Installing/fetching a key and invoking the exposed retry operation retries the original authenticated record; eviction is observable.
- Backfill completion is checked after ordered asynchronous imports finish, so `waitForReachingServerVersion()` cannot hang on successfully decrypted backfill.
- Destroy/drop cancels subscriptions/workers and prevents queued work from sending afterward.

**Tests**:

- Extend `packages/loro-adaptors/tests/elo-adaptor.test.ts` for serialized rapid commits, accurate single- and multi-peer spans, canonical plaintext, real snapshot VV, delayed key selection, future-write rotation, explicit snapshot publication, exact incoming key ID, and no send after destroy.
- Add TypeScript tests for unknown-key retry after key installation, pending deduplication/cap eviction, wrong-known-key classification, malformed/import errors, and backfill-wait resolution after delayed decrypt/import.
- Add Rust client unit/integration tests for the same span metadata, ordered worker behavior, fixed-key compatibility, resolver rotation/history, typed failures, bounded retry, genuine snapshot metadata, and worker shutdown.
- Include regression tests that import legacy authenticated raw-delta plaintext while all newly emitted records use the canonical list encoding.
- Run `pnpm --filter loro-adaptors test`, its typecheck, and `cargo test -p loro-websocket-client`.

**Status**: In Progress (key-management substage passed cryptographic/API review in TypeScript and Rust: exact resolver contracts and preserved resolver causes, serialized outbound resolution/publication, per-room Rust adaptor locking, immutable key IDs with historical reads, redacted Rust key `Debug`, structured unknown-key/decrypt/encrypt/eviction reporting, strict bounded byte-exact FIFO pending queues with coalesced TypeScript retries, callback containment and encrypted/plain source redaction, IV-reuse rejection, fixed-key compatibility, and fresh new-key snapshot bootstrap. The remaining non-key TypeScript delta/span work and broader cross-language gates are still pending.)

## Stage 3: Correct server indexing, identity, and snapshot retention

**Goal**: Give TypeScript and Rust relays collision-free opaque indexing and deterministic late-join selection without decrypting records.

**Success Criteria**:

- Peer index keys preserve raw bytes exactly (`Vec<u8>` in Rust and a collision-free canonical byte encoding in TypeScript); invalid UTF-8 cannot collide with valid text.
- Join versions use Loro `VersionVector` encoding in both languages. Only canonical decimal peer bytes that fit Loro peer IDs participate in requester VV lookup; opaque/non-numeric peers are treated as unknown and backfilled unconditionally.
- Span override is independent of `keyId`: a new covering span replaces covered entries, a stale span already covered by an existing entry is discarded, and partial overlaps remain available in stable order.
- Servers enforce `end > start`, 12-byte IVs, peer/key length bounds, snapshot VV bounds/order, complete container parsing, and explicit invalid-update errors without logging ciphertext.
- Each room retains the latest structurally valid snapshot record and all indexed deltas. Export order is snapshot first, then deterministically ordered deltas.
- Late-join selection sends a useful retained snapshot before only those deltas extending the pointwise effective requester/snapshot version. An empty requester can bootstrap from the snapshot; a requester ahead of it does not receive redundant covered deltas.
- Snapshot retention never deletes delta coverage. Snapshot authorization and destructive compaction remain out of scope.
- Old snapshot-kind records containing delta plaintext remain opaque and cannot be reindexed as deltas; they may be relayed/retained, but recovery documentation requires a fresh genuine snapshot or client re-export.

**Tests**:

- Add direct `EloDoc` TypeScript tests for exact-byte peer identity (including `0xff` versus ASCII `ff`), canonical/noncanonical numeric peers, VersionVector round trips, malformed headers, deterministic export, full/partial overlap, contained stale replay, and key-independent replacement.
- Add matching Rust `EloRoomDoc` tests, including TypeScript-generated/Loro-generated version bytes.
- Add snapshot tests for replacement, snapshot-first export, empty and partially current requesters, snapshot plus later deltas, and no implicit delta deletion.
- Retain live relay and fragmentation regression coverage in `packages/loro-websocket/tests/e2e-elo.test.ts`, `rust/loro-websocket-server/tests/elo_accept_broadcast.rs`, and `rust/loro-websocket-server/tests/elo_fragment_reassembly.rs`.
- Run `pnpm --filter @karstenda/loro-websocket test`, its typecheck, and `cargo test -p loro-websocket-server`.

**Status**: In Progress (final persistence review added direct TypeScript/Rust coverage for byte-stable identity/order, key-independent span replacement, atomic malformed batches, snapshot/delta retention, persisted index restoration, filtered backfill, Loro counter bounds, empty-container rejection, and safe ULEB128 overflow handling. Cross-language VersionVector fixtures and the remaining full validation matrix are still pending.)

## Stage 4: Integrate durable ELO load/save and restart recovery

**Goal**: Route `%ELO` through existing persistence hooks and make saved opaque state safe against restart and concurrent updates.

**Success Criteria**:

- The TypeScript ELO server descriptor is persistent, so configured `onLoadDocument`/`onSaveDocument` callbacks receive the encoded ELO container and ELO updates mark rooms dirty.
- Rust `EloRoomDoc` implements persistence export/import with the same container, and `Hub::ensure_room_loaded` invokes existing ELO load hooks while preserving hook context.
- Both loaders rebuild state through the normal structural validation/index path and fail explicitly on corrupt persisted data instead of silently resetting to an empty valid room.
- Join logic always uses version-filtered ELO backfill; the persistence export is not blindly sent as a generic snapshot.
- TypeScript saves a captured data generation and clears `dirty` only if no update arrived while `onSaveDocument` was pending. Concurrent/periodic saves are serialized, and `stop()` awaits the final save before resolving.
- Rust marks successfully changed ELO rooms dirty and periodic saves include retained snapshot/delta records. Its documented durability remains bounded by `save_interval_ms` unless a compatible existing lifecycle hook can provide a flush; introducing a broad server-handle API is not part of this effort.
- Restored containers large enough to exceed message limits use the existing protocol fragmentation path.

**Tests**:

- Add TypeScript integration tests with shared in-memory hooks for ELO callback invocation, save/load byte validity, an update racing an awaited save, awaited stop, corrupt load failure, stop/start recovery, and fragmented restored backfill.
- Add a Rust server restart integration test using shared in-memory hooks, plus tests for hook context, dirty/save behavior, corrupt load failure, and version-filtered join after restore.
- Verify a late joiner after restart reaches the same document state from a retained snapshot plus later deltas.
- Verify saved bytes decode as a standard ELO container in both TypeScript and Rust and contain opaque original records, not decrypted CRDT data.
- Run package tests/typechecks, `cargo test --workspace`, and the persistence example where practical.

**Status**: Complete (final review fixed TypeScript shutdown and concurrent-load races, serialized generation-safe saves, kept Rust callbacks outside the hub lock with generation-safe dirty clearing, made ELO state import atomic, and bounded corrupt container/ULEB128 handling. Corrupt-load, fragmented opaque restore, no-plaintext, byte-stability, retention, index-restoration, restart/late-join, and save-race coverage passes in both languages. The focused TypeScript package tests/typechecks and Rust protocol/server suites pass.)

## Stage 5: Prove rotation, interoperability, and operational guidance

**Goal**: Close the effort with cross-language end-to-end evidence, compatible API documentation, and explicit security/operational boundaries.

**Success Criteria**:

- TypeScript and Rust clients can exchange canonical DeltaSpan and genuine snapshot records through either server implementation.
- A late joiner recovers live and after restart; large persisted output fragments and reassembles under base v1 ACK semantics.
- Rotation is demonstrated end to end: historical keys decrypt retained old records, future writes use the active key, and a fresh snapshot under the new key survives restart and bootstraps a client possessing only the new key.
- Unknown-key retry succeeds after key installation, while a known wrong key remains a distinct failure.
- Existing fixed-key/public APIs have regression coverage; new resolver, retry/error metadata, pending bounds, `publishSnapshot()`, and any unavoidable migration steps are documented.
- Server telemetry is limited to non-secret header metadata/outcomes and never includes ciphertext or key bytes.
- Documentation recommends random base64url/hex room aliases generated from at least 128 random bits from a CSPRNG, excludes semantic names from room IDs, states that aliases are not authorization, and explains that room correlation/traffic/membership remain visible.
- No room-ID AAD/encrypted-routing change, snapshot compaction policy, key distribution system, revocation guarantee, or secrecy dependency is introduced.

**Tests**:

- Enable and stabilize `rust/loro-websocket-server/tests/elo_cross_lang.rs` and `pnpm test:cross-lang` for normative encryption plus TS↔Rust delta/snapshot exchange.
- Extend ELO end-to-end suites with live late join, persistence restart, fragmented restore, historical-key rotation, new-key-only snapshot bootstrap, unknown-key retry, and malformed persisted-state cases.
- Run `pnpm check`, `pnpm build`, `cargo test --workspace`, the cross-language suite, and targeted formatter checks with the repository-pinned pnpm toolchain and approved dependency build policy.

**Status**: In Progress (room-privacy documentation substage complete and reviewed: the protocol docs, package/Rust READMEs, LLM reference, and ELO examples now state that room IDs remain visible to the relay/TLS terminator; enumerate plaintext ELO `keyId`, IV, raw peer IDs, delta counters, and snapshot version-vector metadata; describe TLS as hop protection rather than encrypted routing; and recommend ≥128-bit non-semantic aliases without presenting them as server-hidden identifiers or credentials. The wire envelope and public API remain unchanged. Interoperability, rotation, and full-workspace gates remain pending.)

## Primary risks and review gates

- **Delta plaintext compatibility**: Existing TypeScript emits raw Loro blobs and existing Rust emits mislabeled snapshots. Canonical outbound encoding plus a narrow authenticated legacy import fallback needs cross-version fixtures before release.
- **Snapshot trust/retention**: The server can validate only plaintext headers, not encrypted snapshot contents. Retaining the latest snapshot assumes join authorization is the application’s trust boundary; destructive compaction must remain separately authorized.
- **Loro version differences**: TypeScript currently targets `loro-crdt` 1.9 while Rust resolves `loro` 1.x (currently 1.5 in the lockfile). Cross-language fixtures must verify VersionVector and update-range semantics rather than assuming API parity.
- **Counter conversion**: JavaScript number precision and Rust signed `Counter` conversion can corrupt large spans unless decimal peer IDs and counters are checked explicitly.
- **Retry memory pressure**: Pending unknown-key records need conservative byte/count caps, deterministic deduplication, and visible eviction behavior.
- **Persistence races/durability**: TypeScript must not clear dirty state after saving stale data. Rust restart durability remains periodic without a compatible shutdown-flush lifecycle.
- **Legacy recovery**: A relay cannot reinterpret old encrypted snapshot-kind/delta-plaintext records. Deployments may need a connected old client to publish a fresh genuine snapshot before relying on restart/new-key bootstrap.
- **Tooling**: Use `corepack pnpm@10.17.1` and the repository-approved dependency build policy; do not introduce workspace-policy changes merely to make local gates pass.
