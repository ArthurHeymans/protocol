//! Loro WebSocket Server (simple skeleton)
//!
//! Minimal async WebSocket server that accepts connections and echoes binary
//! protocol frames back to clients. It also responds to text "ping" with
//! text "pong" as described in protocol.md keepalive section.
//!
//! This is intentionally simple and is meant as a starting point. Application
//! logic (authorization, room routing, broadcasting, etc.) should be layered
//! on top using the `loro_protocol` crate for message encoding/decoding.
//!
//! Example (not run here because it binds a socket):
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! #   let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
//! #   rt.block_on(async move {
//! loro_websocket_server::serve("127.0.0.1:9000").await?;
//! #   Ok(())
//! # })
//! # }
//! ```

use futures_util::{SinkExt, StreamExt};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    hash::{Hash, Hasher},
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::Instant,
};
use tokio_tungstenite::accept_hdr_async_with_config;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::frame::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{self, Message};

use loro::awareness::EphemeralStore;
use loro::{ExportMode, LoroDoc};
pub use loro_protocol as protocol;
use protocol::{
    try_decode, CrdtType, JoinErrorCode, Permission, ProtocolMessage, UpdateStatusCode,
};
use tracing::{debug, error, info, warn};

// Defaults protecting server memory from abusive fragment streams.
const DEFAULT_MAX_FRAGMENTS_PER_BATCH: u64 = 64;
const DEFAULT_MAX_FRAGMENT_BATCH_BYTES: u64 = 8 * 1024 * 1024;
const DEFAULT_MAX_INFLIGHT_FRAGMENT_BATCHES_PER_CONNECTION: usize = 8;
const DEFAULT_MAX_INFLIGHT_FRAGMENT_BYTES_PER_CONNECTION: u64 = 16 * 1024 * 1024;
const DEFAULT_FRAGMENT_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_OUTBOUND_FRAGMENT_SIZE: usize = 240 * 1024;
const DEFAULT_MAX_WORKSPACES: usize = 1024;
const DEFAULT_MAX_ROOMS_PER_WORKSPACE: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
struct RoomKey {
    crdt: CrdtType,
    room: String,
}
impl Hash for RoomKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // CrdtType is repr as enum with a few variants; map to u8 for hashing
        let tag = match self.crdt {
            CrdtType::Loro => 0u8,
            CrdtType::LoroEphemeralStore => 1,
            CrdtType::LoroEphemeralStorePersisted => 2,
            CrdtType::Yjs => 3,
            CrdtType::YjsAwareness => 4,
            CrdtType::Elo => 5,
            CrdtType::Flock => 6,
        };
        tag.hash(state);
        self.room.hash(state);
    }
}

type Sender = mpsc::UnboundedSender<Message>;

// Hook types
/// Snapshot payload returned by `on_load_document` alongside optional metadata
/// that will be passed through to `on_save_document`.
pub struct LoadedDoc<DocCtx> {
    pub snapshot: Option<Vec<u8>>,
    pub ctx: Option<DocCtx>,
}

/// Arguments provided to `on_load_document`.
pub struct LoadDocArgs {
    pub workspace: String,
    pub room: String,
    pub crdt: CrdtType,
}

/// Arguments provided to `on_save_document`.
pub struct SaveDocArgs<DocCtx> {
    pub workspace: String,
    pub room: String,
    pub crdt: CrdtType,
    pub data: Vec<u8>,
    pub ctx: Option<DocCtx>,
}

type LoadFuture<DocCtx> =
    Pin<Box<dyn Future<Output = Result<LoadedDoc<DocCtx>, String>> + Send + 'static>>;
type SaveFuture = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'static>>;
type LoadFn<DocCtx> = Arc<dyn Fn(LoadDocArgs) -> LoadFuture<DocCtx> + Send + Sync>;
type SaveFn<DocCtx> = Arc<dyn Fn(SaveDocArgs<DocCtx>) -> SaveFuture + Send + Sync>;

/// Arguments provided to `authenticate`.
pub struct AuthArgs {
    pub room: String,
    pub crdt: CrdtType,
    pub auth: Vec<u8>,
    pub conn_id: u64,
}

type AuthFuture =
    Pin<Box<dyn Future<Output = Result<Option<Permission>, String>> + Send + 'static>>;
type AuthFn = Arc<dyn Fn(AuthArgs) -> AuthFuture + Send + Sync>;

/// Arguments provided to `handshake_auth`.
pub struct HandshakeAuthArgs<'a> {
    pub workspace: &'a str,
    pub token: Option<&'a str>,
    pub request: &'a tungstenite::handshake::server::Request,
    pub conn_id: u64,
}

type HandshakeAuthFn = dyn Fn(HandshakeAuthArgs) -> bool + Send + Sync;

/// Arguments provided to `on_close_connection`.
pub struct CloseConnectionArgs {
    pub workspace: String,
    pub conn_id: u64,
    pub rooms: Vec<(CrdtType, String)>,
}

type CloseConnectionFuture = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'static>>;
type CloseConnectionFn = Arc<dyn Fn(CloseConnectionArgs) -> CloseConnectionFuture + Send + Sync>;

pub struct ValidateLoroSnapshotArgs<'a> {
    pub workspace: &'a str,
    pub room: &'a str,
    pub snapshot: &'a [u8],
}

type ValidateLoroSnapshotFn =
    dyn for<'a> Fn(ValidateLoroSnapshotArgs<'a>) -> Result<(), String> + Send + Sync;

#[derive(Clone)]
pub struct ServerConfig<DocCtx = ()> {
    pub on_load_document: Option<LoadFn<DocCtx>>,
    pub on_save_document: Option<SaveFn<DocCtx>>,
    pub save_interval_ms: Option<u64>,
    pub default_permission: Permission,
    pub authenticate: Option<AuthFn>,
    /// Optional handshake auth: called during WS HTTP upgrade.
    ///
    /// Parameters:
    /// - `workspace_id`: extracted from request path `/{workspace}` (empty if missing)
    /// - `token`: `token` query parameter if present
    /// - `request`: the full HTTP request (headers, uri, etc)
    /// - `conn_id`: the connection id
    ///
    /// Return true to accept, false to reject with 401.
    pub handshake_auth: Option<Arc<HandshakeAuthFn>>,
    /// Optional hook invoked after a connection fully closes.
    /// Receives the workspace id, connection id, and rooms the client had joined.
    pub on_close_connection: Option<CloseConnectionFn>,
    /// Validate candidate Loro state before mutating a room or broadcasting.
    pub validate_loro_snapshot: Option<Arc<ValidateLoroSnapshotFn>>,
    pub max_fragments_per_batch: u64,
    pub max_fragment_batch_bytes: u64,
    pub max_inflight_fragment_batches_per_connection: usize,
    /// Maximum sum of declared sizes for this connection's in-flight batches.
    pub max_inflight_fragment_bytes_per_connection: u64,
    pub fragment_reassembly_timeout: Duration,
    pub outbound_fragment_size: usize,
    /// Maximum workspace hubs retained by the registry. Hubs are not evicted.
    pub max_workspaces: Option<usize>,
    /// Maximum allocated room keys per workspace, counting loaded documents and
    /// relay-only subscriptions. Persistent documents are not evicted.
    pub max_rooms_per_workspace: Option<usize>,
}

// CRDT document abstraction to reduce match-based branching
trait CrdtDoc: Send {
    fn get_version(&self) -> Vec<u8> {
        Vec::new()
    }
    fn compute_backfill(&self, _client_version: &[u8]) -> Vec<Vec<u8>> {
        Vec::new()
    }
    fn apply_updates(&mut self, _updates: &[Vec<u8>]) -> Result<(), String> {
        Ok(())
    }
    fn apply_updates_validated(
        &mut self,
        updates: &[Vec<u8>],
        _validate: Option<&dyn Fn(&[u8]) -> Result<(), String>>,
    ) -> Result<(), String> {
        self.apply_updates(updates)
    }
    fn should_persist(&self) -> bool {
        false
    }
    fn export_snapshot(&self) -> Option<Vec<u8>> {
        None
    }
    fn import_snapshot(&mut self, _data: &[u8]) -> Result<(), String> {
        Ok(())
    }
    fn allow_backfill_when_no_other_clients(&self) -> bool {
        false
    }
    fn remove_when_last_subscriber_leaves(&self) -> bool {
        false
    }
}

struct LoroRoomDoc {
    doc: LoroDoc,
}
impl LoroRoomDoc {
    fn new() -> Self {
        Self {
            doc: LoroDoc::new(),
        }
    }
}
impl CrdtDoc for LoroRoomDoc {
    fn apply_updates(&mut self, updates: &[Vec<u8>]) -> Result<(), String> {
        self.apply_updates_validated(updates, None)
    }
    fn apply_updates_validated(
        &mut self,
        updates: &[Vec<u8>],
        validate: Option<&dyn Fn(&[u8]) -> Result<(), String>>,
    ) -> Result<(), String> {
        let candidate = self.doc.fork();
        for update in updates {
            candidate
                .import(update)
                .map_err(|error| error.to_string())?;
        }
        if let Some(validate) = validate {
            let snapshot = candidate
                .export(ExportMode::Snapshot)
                .map_err(|error| error.to_string())?;
            validate(&snapshot)?;
        }
        self.doc = candidate;
        Ok(())
    }
    fn should_persist(&self) -> bool {
        true
    }
    fn export_snapshot(&self) -> Option<Vec<u8>> {
        self.doc.export(ExportMode::Snapshot).ok()
    }
    fn import_snapshot(&mut self, data: &[u8]) -> Result<(), String> {
        self.doc.import(data).map_err(|error| error.to_string())?;
        Ok(())
    }
}

struct EphemeralRoomDoc {
    store: EphemeralStore,
}
impl EphemeralRoomDoc {
    fn new(timeout_ms: i64) -> Self {
        Self {
            store: EphemeralStore::new(timeout_ms),
        }
    }
}
impl CrdtDoc for EphemeralRoomDoc {
    fn compute_backfill(&self, _client_version: &[u8]) -> Vec<Vec<u8>> {
        let data = self.store.encode_all();
        if data.is_empty() {
            Vec::new()
        } else {
            vec![data]
        }
    }
    fn apply_updates(&mut self, updates: &[Vec<u8>]) -> Result<(), String> {
        for update in updates {
            if !update.is_empty() {
                self.store.apply(update);
            }
        }
        Ok(())
    }
    fn remove_when_last_subscriber_leaves(&self) -> bool {
        true
    }
}

struct PersistentEphemeralRoomDoc {
    store: EphemeralStore,
    timeout_ms: i64,
}
impl PersistentEphemeralRoomDoc {
    fn new(timeout_ms: i64) -> Self {
        Self {
            store: EphemeralStore::new(timeout_ms),
            timeout_ms,
        }
    }
}
impl CrdtDoc for PersistentEphemeralRoomDoc {
    fn compute_backfill(&self, _client_version: &[u8]) -> Vec<Vec<u8>> {
        let data = self.store.encode_all();
        if data.is_empty() {
            Vec::new()
        } else {
            vec![data]
        }
    }
    fn apply_updates(&mut self, updates: &[Vec<u8>]) -> Result<(), String> {
        for update in updates {
            if !update.is_empty() {
                self.store.apply(update);
            }
        }
        Ok(())
    }
    fn should_persist(&self) -> bool {
        true
    }
    fn export_snapshot(&self) -> Option<Vec<u8>> {
        Some(self.store.encode_all())
    }
    fn import_snapshot(&mut self, data: &[u8]) -> Result<(), String> {
        self.store = EphemeralStore::new(self.timeout_ms);
        if !data.is_empty() {
            self.store.apply(data);
        }
        Ok(())
    }
    fn allow_backfill_when_no_other_clients(&self) -> bool {
        true
    }
}

#[derive(Clone)]
struct EloDeltaSpanIndexEntry {
    start: u64,
    end: u64,
    record: Vec<u8>,
}

#[derive(Clone)]
struct EloSnapshotIndexEntry {
    vv: Vec<(Vec<u8>, u64)>,
    record: Vec<u8>,
}

#[derive(Clone)]
struct EloRoomDoc {
    spans_by_peer: HashMap<Vec<u8>, Vec<EloDeltaSpanIndexEntry>>,
    latest_snapshot: Option<EloSnapshotIndexEntry>,
}
impl EloRoomDoc {
    fn new() -> Self {
        Self {
            spans_by_peer: HashMap::new(),
            latest_snapshot: None,
        }
    }

    fn canonical_loro_peer(bytes: &[u8]) -> Option<u64> {
        let text = std::str::from_utf8(bytes).ok()?;
        let peer = text.parse::<u64>().ok()?;
        (peer.to_string() == text).then_some(peer)
    }

    fn requester_counter(requester: Option<&loro::VersionVector>, peer: &[u8]) -> u64 {
        let Some(peer) = Self::canonical_loro_peer(peer) else {
            return 0;
        };
        requester
            .and_then(|vv| vv.get(&peer))
            .and_then(|counter| u64::try_from(*counter).ok())
            .unwrap_or(0)
    }

    fn encode_current_vv(&self) -> Vec<u8> {
        let mut counters: HashMap<u64, u64> = HashMap::new();
        for (peer, spans) in &self.spans_by_peer {
            let Some(peer) = Self::canonical_loro_peer(peer) else {
                continue;
            };
            for span in spans {
                counters
                    .entry(peer)
                    .and_modify(|counter| *counter = (*counter).max(span.end))
                    .or_insert(span.end);
            }
        }
        if let Some(snapshot) = &self.latest_snapshot {
            for (peer, counter) in &snapshot.vv {
                let Some(peer) = Self::canonical_loro_peer(peer) else {
                    continue;
                };
                counters
                    .entry(peer)
                    .and_modify(|current| *current = (*current).max(*counter))
                    .or_insert(*counter);
            }
        }

        let mut vv = loro::VersionVector::default();
        for (peer, counter) in counters {
            if let Ok(counter) = i32::try_from(counter) {
                vv.insert(peer, counter);
            }
        }
        if vv.is_empty() {
            Vec::new()
        } else {
            vv.encode()
        }
    }

    fn export_persisted_state(&self) -> Vec<u8> {
        let mut records: Vec<&[u8]> = Vec::new();
        if let Some(snapshot) = &self.latest_snapshot {
            records.push(&snapshot.record);
        }
        let mut peers: Vec<_> = self.spans_by_peer.iter().collect();
        peers.sort_by_key(|(left, _)| *left);
        for (_, spans) in peers {
            for span in spans {
                records.push(&span.record);
            }
        }
        loro_protocol::elo::encode_elo_container(records)
    }

    fn index_updates(&mut self, updates: &[Vec<u8>]) -> Result<(), String> {
        use loro_protocol::elo::{
            decode_elo_container, parse_elo_record_header, EloHeader, EloRecordKind,
        };
        for update in updates {
            let records = decode_elo_container(update)?;
            if records.is_empty() {
                return Err("invalid ELO container: expected at least one record".into());
            }
            for record in records {
                let parsed = parse_elo_record_header(record)?;
                match parsed.header {
                    EloHeader::Delta(header) => {
                        let list = self.spans_by_peer.entry(header.peer_id).or_default();
                        if list
                            .iter()
                            .any(|entry| entry.start <= header.start && entry.end >= header.end)
                        {
                            continue;
                        }
                        list.retain(|entry| {
                            !(entry.start >= header.start && entry.end <= header.end)
                        });
                        list.push(EloDeltaSpanIndexEntry {
                            start: header.start,
                            end: header.end,
                            record: record.to_vec(),
                        });
                        list.sort_by_key(|entry| (entry.start, entry.end));
                    }
                    EloHeader::Snapshot(header) => {
                        if parsed.kind != EloRecordKind::Snapshot {
                            return Err("invalid ELO snapshot header".into());
                        }
                        if header.vv.len() > 1024 {
                            return Err(
                                "invalid ELO snapshot: version vector has more than 1024 entries"
                                    .into(),
                            );
                        }
                        if header.vv.iter().any(|(peer, _)| peer.len() > 64) {
                            return Err("invalid ELO snapshot: peerId too long".into());
                        }
                        if header
                            .vv
                            .windows(2)
                            .any(|entries| entries[0].0 >= entries[1].0)
                        {
                            return Err(
                                "invalid ELO snapshot: version vector peers not strictly sorted"
                                    .into(),
                            );
                        }
                        self.latest_snapshot = Some(EloSnapshotIndexEntry {
                            vv: header.vv,
                            record: record.to_vec(),
                        });
                    }
                }
            }
        }
        Ok(())
    }
}
impl CrdtDoc for EloRoomDoc {
    fn get_version(&self) -> Vec<u8> {
        self.encode_current_vv()
    }

    fn compute_backfill(&self, client_version: &[u8]) -> Vec<Vec<u8>> {
        let requester = (!client_version.is_empty())
            .then(|| loro::VersionVector::decode(client_version).ok())
            .flatten();
        let mut effective: HashMap<Vec<u8>, u64> = HashMap::new();
        for peer in self.spans_by_peer.keys() {
            effective.insert(
                peer.clone(),
                Self::requester_counter(requester.as_ref(), peer),
            );
        }

        let mut records: Vec<Vec<u8>> = Vec::new();
        if let Some(snapshot) = &self.latest_snapshot {
            let requester_covers_snapshot = requester.is_some()
                && snapshot.vv.iter().all(|(peer, counter)| {
                    Self::requester_counter(requester.as_ref(), peer) >= *counter
                });
            if !requester_covers_snapshot {
                records.push(snapshot.record.clone());
                for (peer, counter) in &snapshot.vv {
                    effective
                        .entry(peer.clone())
                        .and_modify(|known| *known = (*known).max(*counter))
                        .or_insert(*counter);
                }
            }
        }

        let mut peers: Vec<_> = self.spans_by_peer.iter().collect();
        peers.sort_by_key(|(left, _)| *left);
        for (peer, spans) in peers {
            let known = effective.get(peer).copied().unwrap_or(0);
            for span in spans {
                if span.end > known {
                    records.push(span.record.clone());
                }
            }
        }
        if records.is_empty() {
            Vec::new()
        } else {
            vec![loro_protocol::elo::encode_elo_container(records)]
        }
    }

    fn apply_updates(&mut self, updates: &[Vec<u8>]) -> Result<(), String> {
        let mut candidate = self.clone();
        candidate.index_updates(updates)?;
        *self = candidate;
        Ok(())
    }

    fn should_persist(&self) -> bool {
        true
    }

    fn export_snapshot(&self) -> Option<Vec<u8>> {
        Some(self.export_persisted_state())
    }

    fn import_snapshot(&mut self, data: &[u8]) -> Result<(), String> {
        let mut candidate = Self::new();
        if !data.is_empty() {
            candidate.index_updates(&[data.to_vec()])?;
        }
        *self = candidate;
        Ok(())
    }

    fn allow_backfill_when_no_other_clients(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod elo_room_doc_tests {
    use super::*;
    use loro_protocol::bytes::BytesWriter;
    use loro_protocol::elo::{decode_elo_container, encode_elo_container};

    #[test]
    fn persistence_round_trip_retains_snapshot_and_restores_delta_index() {
        let snapshot = snapshot_record(&[(b"7", 2)], 1);
        let covered = delta_record(b"7", 0, 2, "old-key", 2);
        let later = delta_record(b"7", 2, 3, "new-key", 3);
        let persisted =
            encode_elo_container([snapshot.as_slice(), covered.as_slice(), later.as_slice()]);
        let mut restored = EloRoomDoc::new();

        restored.import_snapshot(&persisted).unwrap();
        assert_eq!(restored.export_persisted_state(), persisted);
        let backfill = restored.compute_backfill(&[]);
        assert_eq!(backfill.len(), 1);
        assert_eq!(
            decode_elo_container(&backfill[0]).unwrap(),
            vec![snapshot.as_slice(), later.as_slice()]
        );

        let mut current = loro::VersionVector::default();
        current.insert(7, 3);
        assert!(restored.compute_backfill(&current.encode()).is_empty());
    }

    #[test]
    fn indexing_is_byte_stable_atomic_and_key_independent() {
        let old = delta_record(b"7", 1, 2, "old-key", 1);
        let covering = delta_record(b"7", 0, 3, "new-key", 2);
        let stale = delta_record(b"7", 1, 2, "third-key", 3);
        let partial = delta_record(b"7", 2, 4, "partial-key", 4);
        let ascii_ff = delta_record(b"ff", 0, 1, "key", 5);
        let opaque_ff = delta_record(&[0xff], 0, 1, "key", 6);
        let mut document = EloRoomDoc::new();
        document
            .apply_updates(&[encode_elo_container([
                old.as_slice(),
                covering.as_slice(),
                stale.as_slice(),
                partial.as_slice(),
                opaque_ff.as_slice(),
                ascii_ff.as_slice(),
            ])])
            .unwrap();

        assert_eq!(
            decode_elo_container(&document.export_persisted_state()).unwrap(),
            vec![
                covering.as_slice(),
                partial.as_slice(),
                ascii_ff.as_slice(),
                opaque_ff.as_slice(),
            ]
        );
        let before = document.export_persisted_state();
        assert!(document.apply_updates(&[vec![0xff]]).is_err());
        assert_eq!(document.export_persisted_state(), before);
        assert!(document
            .apply_updates(&[encode_elo_container(Vec::<Vec<u8>>::new())])
            .is_err());
        assert_eq!(document.export_persisted_state(), before);
    }

    fn snapshot_record(vv: &[(&[u8], u64)], marker: u8) -> Vec<u8> {
        let mut record = BytesWriter::new();
        record.push_byte(0x01);
        record.push_uleb128(vv.len() as u64);
        for (peer, counter) in vv {
            record.push_var_bytes(peer);
            record.push_uleb128(*counter);
        }
        record.push_var_string("key-1");
        record.push_var_bytes(&[marker; 12]);
        record.push_var_bytes(&[marker]);
        record.finalize()
    }

    fn delta_record(peer: &[u8], start: u64, end: u64, key: &str, marker: u8) -> Vec<u8> {
        let mut record = BytesWriter::new();
        record.push_byte(0x00);
        record.push_var_bytes(peer);
        record.push_uleb128(start);
        record.push_uleb128(end);
        record.push_var_string(key);
        record.push_var_bytes(&[marker; 12]);
        record.push_var_bytes(&[marker]);
        record.finalize()
    }
}

impl<DocCtx> Default for ServerConfig<DocCtx> {
    fn default() -> Self {
        Self {
            on_load_document: None,
            on_save_document: None,
            save_interval_ms: None,
            default_permission: Permission::Write,
            authenticate: None,
            handshake_auth: None,
            on_close_connection: None,
            validate_loro_snapshot: None,
            max_fragments_per_batch: DEFAULT_MAX_FRAGMENTS_PER_BATCH,
            max_fragment_batch_bytes: DEFAULT_MAX_FRAGMENT_BATCH_BYTES,
            max_inflight_fragment_batches_per_connection:
                DEFAULT_MAX_INFLIGHT_FRAGMENT_BATCHES_PER_CONNECTION,
            max_inflight_fragment_bytes_per_connection:
                DEFAULT_MAX_INFLIGHT_FRAGMENT_BYTES_PER_CONNECTION,
            fragment_reassembly_timeout: DEFAULT_FRAGMENT_REASSEMBLY_TIMEOUT,
            outbound_fragment_size: DEFAULT_OUTBOUND_FRAGMENT_SIZE,
            max_workspaces: Some(DEFAULT_MAX_WORKSPACES),
            max_rooms_per_workspace: Some(DEFAULT_MAX_ROOMS_PER_WORKSPACE),
        }
    }
}

struct RoomDocState<DocCtx> {
    doc: Box<dyn CrdtDoc>,
    dirty: bool,
    generation: u64,
    ctx: Option<DocCtx>,
}

struct Hub<DocCtx> {
    // room -> vec of (conn_id, sender)
    subs: HashMap<RoomKey, Vec<(u64, Sender)>>,
    // room -> document state (Loro persistent, Ephemeral in-memory, Elo index)
    docs: HashMap<RoomKey, RoomDocState<DocCtx>>,
    config: ServerConfig<DocCtx>,
    // (conn_id, room) -> permission
    perms: HashMap<(u64, RoomKey), Permission>,
    workspace: String,
    // Fragment reassembly state: per room + batch id
    fragments: HashMap<(RoomKey, protocol::BatchId), FragmentBatch>,
}

impl<DocCtx> Hub<DocCtx>
where
    DocCtx: Clone + Send + Sync + 'static,
{
    fn new(config: ServerConfig<DocCtx>, workspace: String) -> Self {
        Self {
            subs: HashMap::new(),
            docs: HashMap::new(),
            config,
            perms: HashMap::new(),
            workspace,
            fragments: HashMap::new(),
        }
    }

    const EPHEMERAL_TIMEOUT_MS: i64 = 60_000;

    fn join(&mut self, conn_id: u64, room: RoomKey, tx: &Sender) {
        let entry = self.subs.entry(room).or_default();
        if !entry.iter().any(|(id, _)| *id == conn_id) {
            entry.push((conn_id, tx.clone()));
        }
    }

    fn has_room(&self, room: &RoomKey) -> bool {
        self.docs.contains_key(room) || self.subs.contains_key(room)
    }

    fn allocated_room_count(&self) -> usize {
        self.docs.len()
            + self
                .subs
                .keys()
                .filter(|room| !self.docs.contains_key(*room))
                .count()
    }

    fn room_limit_reached(&self, room: &RoomKey) -> bool {
        !self.has_room(room)
            && self
                .config
                .max_rooms_per_workspace
                .is_some_and(|limit| self.allocated_room_count() >= limit)
    }

    fn leave_all(&mut self, conn_id: u64) {
        let mut emptied: Vec<RoomKey> = Vec::new();
        for (k, vec) in self.subs.iter_mut() {
            vec.retain(|(id, _)| *id != conn_id);
            if vec.is_empty() {
                emptied.push(k.clone());
            }
        }
        // Drop empty rooms from subscription map
        for k in &emptied {
            let _ = self.subs.remove(k);
        }

        // Remove permissions for this connection
        self.perms.retain(|(id, _), _| *id != conn_id);

        // Clean up ephemeral state for rooms that no longer have subscribers
        for k in emptied.clone() {
            if let Some(state) = self.docs.get(&k) {
                if state.doc.remove_when_last_subscriber_leaves() {
                    self.docs.remove(&k);
                    debug!(room=?k.room, "cleaned up ephemeral doc after last subscriber left");
                }
            }
        }

        // Clean up in-flight fragment batches started by this connection, or for rooms now emptied
        if !self.fragments.is_empty() {
            use std::collections::HashSet;
            let emptied_set: HashSet<RoomKey> = emptied.into_iter().collect();
            self.fragments
                .retain(|(rk, _), b| b.from_conn != conn_id && !emptied_set.contains(rk));
        }
    }

    fn broadcast(&mut self, room: &RoomKey, from: u64, msg: Message) {
        if let Some(list) = self.subs.get_mut(room) {
            // drop dead senders
            let mut dead: HashSet<u64> = HashSet::new();
            for (id, tx) in list.iter() {
                if *id == from {
                    continue;
                }
                if tx.send(msg.clone()).is_err() {
                    dead.insert(*id);
                }
            }
            if !dead.is_empty() {
                list.retain(|(id, _)| !dead.contains(id));
                debug!(room=?room.room, removed=%dead.len(), "removed dead subscribers");
            }
        }
    }

    async fn ensure_room_loaded(&mut self, room: &RoomKey) -> Result<(), String> {
        if self.docs.contains_key(room) {
            return Ok(());
        }
        match room.crdt {
            CrdtType::Loro => {
                let mut d = LoroRoomDoc::new();
                let mut ctx = None;
                if let Some(loader) = &self.config.on_load_document {
                    let args = LoadDocArgs {
                        workspace: self.workspace.clone(),
                        room: room.room.clone(),
                        crdt: room.crdt,
                    };
                    match (loader)(args).await {
                        Ok(loaded) => {
                            if let Some(bytes) = loaded.snapshot {
                                d.import_snapshot(&bytes)
                                    .map_err(|error| format!("load document failed: {error}"))?;
                            }
                            ctx = loaded.ctx;
                        }
                        Err(error) => {
                            return Err(format!("load document failed: {error}"));
                        }
                    }
                }
                self.docs.insert(
                    room.clone(),
                    RoomDocState {
                        doc: Box::new(d),
                        dirty: false,
                        generation: 0,
                        ctx,
                    },
                );
            }
            CrdtType::LoroEphemeralStore => {
                let d = EphemeralRoomDoc::new(Self::EPHEMERAL_TIMEOUT_MS);
                self.docs.insert(
                    room.clone(),
                    RoomDocState {
                        doc: Box::new(d),
                        dirty: false,
                        generation: 0,
                        ctx: None,
                    },
                );
            }
            CrdtType::LoroEphemeralStorePersisted => {
                let mut d = PersistentEphemeralRoomDoc::new(Self::EPHEMERAL_TIMEOUT_MS);
                let mut ctx = None;
                if let Some(loader) = &self.config.on_load_document {
                    let args = LoadDocArgs {
                        workspace: self.workspace.clone(),
                        room: room.room.clone(),
                        crdt: room.crdt,
                    };
                    match (loader)(args).await {
                        Ok(loaded) => {
                            if let Some(bytes) = loaded.snapshot {
                                d.import_snapshot(&bytes).map_err(|error| {
                                    format!("load persisted ephemeral store failed: {error}")
                                })?;
                            }
                            ctx = loaded.ctx;
                        }
                        Err(error) => {
                            return Err(format!("load persisted ephemeral store failed: {error}"));
                        }
                    }
                }
                self.docs.insert(
                    room.clone(),
                    RoomDocState {
                        doc: Box::new(d),
                        dirty: false,
                        generation: 0,
                        ctx,
                    },
                );
            }
            CrdtType::Elo => {
                let mut document = EloRoomDoc::new();
                let mut ctx = None;
                if let Some(loader) = &self.config.on_load_document {
                    let args = LoadDocArgs {
                        workspace: self.workspace.clone(),
                        room: room.room.clone(),
                        crdt: room.crdt,
                    };
                    match (loader)(args).await {
                        Ok(loaded) => {
                            if let Some(bytes) = loaded.snapshot {
                                document.import_snapshot(&bytes).map_err(|error| {
                                    format!("load persisted ELO state failed: {error}")
                                })?;
                            }
                            ctx = loaded.ctx;
                        }
                        Err(error) => {
                            return Err(format!("load persisted ELO state failed: {error}"));
                        }
                    }
                }
                self.docs.insert(
                    room.clone(),
                    RoomDocState {
                        doc: Box::new(document),
                        dirty: false,
                        generation: 0,
                        ctx,
                    },
                );
            }
            _ => {}
        }
        Ok(())
    }

    fn current_version_bytes(&self, room: &RoomKey) -> Vec<u8> {
        match self.docs.get(room) {
            Some(state) => state.doc.get_version(),
            None => Vec::new(),
        }
    }

    fn apply_updates(&mut self, room: &RoomKey, updates: &[Vec<u8>]) -> Result<(), String> {
        let validate = self.config.validate_loro_snapshot.clone();
        let validate_candidate = |snapshot: &[u8]| {
            if room.crdt == CrdtType::Loro {
                if let Some(validate) = &validate {
                    validate(ValidateLoroSnapshotArgs {
                        workspace: &self.workspace,
                        room: &room.room,
                        snapshot,
                    })?;
                }
            }
            Ok(())
        };
        let validator = (room.crdt == CrdtType::Loro && validate.is_some())
            .then_some(&validate_candidate as &dyn Fn(&[u8]) -> Result<(), String>);
        let state = self
            .docs
            .get_mut(room)
            .ok_or_else(|| "room not found".to_string())?;
        let persisted_before = (room.crdt == CrdtType::Elo)
            .then(|| state.doc.export_snapshot())
            .flatten();
        state
            .doc
            .apply_updates_validated(updates, validator)
            .map_err(|error| {
                warn!(room=?room.room, %error, "apply_updates failed");
                error
            })?;
        let changed = room.crdt != CrdtType::Elo || persisted_before != state.doc.export_snapshot();
        if state.doc.should_persist() && changed {
            state.dirty = true;
            state.generation = state.generation.wrapping_add(1);
        }
        Ok(())
    }

    fn snapshot_bytes(&self, room: &RoomKey) -> Option<Vec<u8>> {
        let Some(data) = self.docs.get(room).and_then(|s| s.doc.export_snapshot()) else {
            return None;
        };
        if data.is_empty() {
            None
        } else {
            Some(data)
        }
    }
}

struct FragmentBatch {
    from_conn: u64,
    fragment_count: u64,
    total_size: u64,
    received: u64,
    received_size: u64,
    expires_at: Instant,
    timeout_tx: Sender,
    chunks: Vec<Option<Vec<u8>>>,
}

struct CompletedFragmentBatch {
    payload: Vec<u8>,
    fragment_sizes: Vec<usize>,
    fragment_count: u64,
    total_size: u64,
}

enum FragmentBatchError {
    PayloadTooLarge,
    SizeMismatch,
}

impl<DocCtx> Hub<DocCtx>
where
    DocCtx: Clone + Send + Sync + 'static,
{
    fn start_fragment_batch(
        &mut self,
        room: &RoomKey,
        from_conn: u64,
        batch_id: protocol::BatchId,
        fragment_count: u64,
        total_size: u64,
        timeout_tx: &Sender,
    ) -> Result<(), FragmentBatchError> {
        let key = (room.clone(), batch_id);
        let chunks_len =
            usize::try_from(fragment_count).map_err(|_| FragmentBatchError::PayloadTooLarge)?;
        let batch = FragmentBatch {
            from_conn,
            fragment_count,
            total_size,
            received: 0,
            received_size: 0,
            expires_at: Instant::now() + self.config.fragment_reassembly_timeout,
            timeout_tx: timeout_tx.clone(),
            chunks: vec![None; chunks_len],
        };
        self.fragments.insert(key, batch);
        Ok(())
    }

    fn expire_fragment_batches(&mut self, now: Instant) {
        let expired: Vec<_> = self
            .fragments
            .iter()
            .filter(|(_, batch)| batch.expires_at <= now)
            .map(|((room, batch_id), batch)| {
                (
                    room.clone(),
                    *batch_id,
                    batch.from_conn,
                    batch.timeout_tx.clone(),
                )
            })
            .collect();
        for (room, batch_id, from_conn, timeout_tx) in expired {
            self.fragments.remove(&(room.clone(), batch_id));
            debug!(room=?room.room, from_conn, "fragment batch timed out");
            send_ack(
                &timeout_tx,
                room.crdt,
                &room.room,
                batch_id,
                UpdateStatusCode::FragmentTimeout,
            );
        }
    }

    /// Returns the completed batch and removes it from the reassembly map.
    fn add_fragment_and_maybe_finish(
        &mut self,
        room: &RoomKey,
        batch_id: protocol::BatchId,
        index: u64,
        fragment: Vec<u8>,
    ) -> Result<Option<CompletedFragmentBatch>, FragmentBatchError> {
        let key = (room.clone(), batch_id);
        let mut too_large = false;
        let complete;
        {
            let batch = self
                .fragments
                .get_mut(&key)
                .ok_or(FragmentBatchError::SizeMismatch)?;
            let idx = usize::try_from(index).map_err(|_| FragmentBatchError::SizeMismatch)?;
            if idx >= batch.chunks.len() {
                return Err(FragmentBatchError::SizeMismatch);
            }
            if batch.chunks[idx].is_some() {
                return Ok(None);
            }
            let fragment_size =
                u64::try_from(fragment.len()).map_err(|_| FragmentBatchError::PayloadTooLarge)?;
            let received_size = batch.received_size.checked_add(fragment_size);
            if let Some(received_size) = received_size.filter(|size| *size <= batch.total_size) {
                batch.received_size = received_size;
                batch.chunks[idx] = Some(fragment);
                batch.received += 1;
                complete = batch.received == batch.fragment_count;
            } else {
                too_large = true;
                complete = false;
            }
        }
        if too_large {
            self.fragments.remove(&key);
            return Err(FragmentBatchError::PayloadTooLarge);
        }
        if !complete {
            return Ok(None);
        }

        let batch = self
            .fragments
            .remove(&key)
            .ok_or(FragmentBatchError::SizeMismatch)?;
        if batch.received_size != batch.total_size {
            return Err(FragmentBatchError::SizeMismatch);
        }
        let fragments = batch
            .chunks
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or(FragmentBatchError::SizeMismatch)?;
        let mut payload = Vec::with_capacity(batch.total_size as usize);
        let mut fragment_sizes = Vec::with_capacity(fragments.len());
        for fragment in fragments {
            fragment_sizes.push(fragment.len());
            payload.extend(fragment);
        }
        Ok(Some(CompletedFragmentBatch {
            payload,
            fragment_sizes,
            fragment_count: batch.fragment_count,
            total_size: batch.total_size,
        }))
    }
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_BATCH_ID: AtomicU64 = AtomicU64::new(1);

fn next_batch_id() -> protocol::BatchId {
    protocol::BatchId(NEXT_BATCH_ID.fetch_add(1, Ordering::Relaxed).to_be_bytes())
}

fn send_update(
    tx: &Sender,
    crdt: CrdtType,
    room: &str,
    update: Vec<u8>,
    configured_fragment_size: usize,
) -> Result<(), String> {
    let batch_id = next_batch_id();
    let fragment_size = configured_fragment_size
        .min(DEFAULT_OUTBOUND_FRAGMENT_SIZE)
        .max(1);
    if update.len() <= fragment_size {
        let message = ProtocolMessage::DocUpdate {
            crdt,
            room_id: room.to_string(),
            updates: vec![update],
            batch_id,
        };
        let bytes = loro_protocol::encode(&message).map_err(|error| error.to_string())?;
        return tx
            .send(Message::Binary(bytes.into()))
            .map_err(|_| "connection closed while sending update".to_string());
    }

    let fragment_count = update.len().div_ceil(fragment_size);
    let header = ProtocolMessage::DocUpdateFragmentHeader {
        crdt,
        room_id: room.to_string(),
        batch_id,
        fragment_count: fragment_count as u64,
        total_size_bytes: update.len() as u64,
    };
    let bytes = loro_protocol::encode(&header).map_err(|error| error.to_string())?;
    tx.send(Message::Binary(bytes.into()))
        .map_err(|_| "connection closed while sending fragment header".to_string())?;

    for (index, fragment) in update.chunks(fragment_size).enumerate() {
        let message = ProtocolMessage::DocUpdateFragment {
            crdt,
            room_id: room.to_string(),
            batch_id,
            index: index as u64,
            fragment: fragment.to_vec(),
        };
        let bytes = loro_protocol::encode(&message).map_err(|error| error.to_string())?;
        tx.send(Message::Binary(bytes.into()))
            .map_err(|_| "connection closed while sending fragment".to_string())?;
    }
    Ok(())
}

fn send_ack(
    tx: &Sender,
    crdt: CrdtType,
    room: &str,
    ref_id: protocol::BatchId,
    status: UpdateStatusCode,
) {
    let ack = ProtocolMessage::Ack {
        crdt,
        room_id: room.to_string(),
        ref_id,
        status,
    };
    if let Ok(bytes) = loro_protocol::encode(&ack) {
        let _ = tx.send(Message::Binary(bytes.into()));
    }
}

struct HubRegistry<DocCtx> {
    config: ServerConfig<DocCtx>,
    hubs: tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<Hub<DocCtx>>>>>,
}

impl<DocCtx> HubRegistry<DocCtx>
where
    DocCtx: Clone + Send + Sync + 'static,
{
    fn new(config: ServerConfig<DocCtx>) -> Self {
        Self {
            config,
            hubs: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    async fn get_or_create(&self, workspace: &str) -> Option<Arc<tokio::sync::Mutex<Hub<DocCtx>>>> {
        let mut map = self.hubs.lock().await;
        if let Some(hub) = map.get(workspace) {
            return Some(hub.clone());
        }
        if self
            .config
            .max_workspaces
            .is_some_and(|limit| map.len() >= limit)
        {
            return None;
        }
        let hub = Arc::new(tokio::sync::Mutex::new(Hub::new(
            self.config.clone(),
            workspace.to_string(),
        )));
        // One periodic sweep per workspace bounds timeout work independently of batch churn.
        let timeout_hub = hub.clone();
        let sweep_period = self
            .config
            .fragment_reassembly_timeout
            .min(Duration::from_secs(1))
            .max(Duration::from_millis(1));
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(sweep_period);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                timeout_hub
                    .lock()
                    .await
                    .expire_fragment_batches(Instant::now());
            }
        });

        // Spawn saver task for this hub if configured
        if let (Some(ms), Some(saver)) = (
            self.config.save_interval_ms,
            self.config.on_save_document.clone(),
        ) {
            let hub_clone = hub.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_millis(ms));
                loop {
                    interval.tick().await;
                    let jobs = {
                        let guard = hub_clone.lock().await;
                        let workspace = guard.workspace.clone();
                        guard
                            .docs
                            .iter()
                            .filter_map(|(room, state)| {
                                if !state.dirty || !state.doc.should_persist() {
                                    return None;
                                }
                                let data = state.doc.export_snapshot()?;
                                Some((
                                    room.clone(),
                                    state.generation,
                                    SaveDocArgs {
                                        workspace: workspace.clone(),
                                        room: room.room.clone(),
                                        crdt: room.crdt,
                                        data,
                                        ctx: state.ctx.clone(),
                                    },
                                ))
                            })
                            .collect::<Vec<_>>()
                    };

                    for (room, generation, args) in jobs {
                        let started = std::time::Instant::now();
                        let workspace = args.workspace.clone();
                        let room_name = args.room.clone();
                        match (saver)(args).await {
                            Ok(()) => {
                                let mut guard = hub_clone.lock().await;
                                if let Some(state) = guard.docs.get_mut(&room) {
                                    if state.generation == generation {
                                        state.dirty = false;
                                    }
                                }
                                debug!(workspace=%workspace, room=%room_name, ms=%started.elapsed().as_millis(), "snapshot saved");
                            }
                            Err(error) => {
                                warn!(workspace=%workspace, room=%room_name, %error, "snapshot save failed");
                            }
                        }
                    }
                }
            });
        }
        map.insert(workspace.to_string(), hub.clone());
        Some(hub)
    }
}

/// Start a simple broadcast server on the given socket address.
pub async fn serve(addr: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!(%addr, "binding TCP listener");
    let listener = TcpListener::bind(addr).await?;
    serve_incoming_with_config::<()>(listener, ServerConfig::default()).await
}

/// Serve a pre-bound listener. Useful for tests to bind on port 0.
pub async fn serve_incoming(
    listener: TcpListener,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    serve_incoming_with_config::<()>(listener, ServerConfig::default()).await
}

pub async fn serve_incoming_with_config<DocCtx>(
    listener: TcpListener,
    config: ServerConfig<DocCtx>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    DocCtx: Clone + Send + Sync + 'static,
{
    let registry = Arc::new(HubRegistry::new(config.clone()));

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                debug!(remote=%peer, "accepted TCP connection");
                let registry = registry.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream, registry).await {
                        warn!(%e, "connection task ended with error");
                    }
                });
            }
            Err(e) => {
                error!(%e, "accept failed; continuing");
                continue;
            }
        }
    }
}

async fn handle_conn<DocCtx>(
    stream: TcpStream,
    registry: Arc<HubRegistry<DocCtx>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    DocCtx: Clone + Send + Sync + 'static,
{
    // Generate a connection id
    let conn_id = NEXT_ID.fetch_add(1, Ordering::Relaxed);

    // Capture config outside of non-async closure
    let handshake_auth = registry.config.handshake_auth.clone();
    let authenticate = registry.config.authenticate.clone();
    let default_permission = registry.config.default_permission;
    let close_connection = registry.config.on_close_connection.clone();
    let workspace_holder: Arc<std::sync::Mutex<Option<String>>> =
        Arc::new(std::sync::Mutex::new(None));
    let workspace_holder_c = workspace_holder.clone();

    let websocket_config = WebSocketConfig::default()
        .max_message_size(Some(protocol::MAX_MESSAGE_SIZE))
        .max_frame_size(Some(protocol::MAX_MESSAGE_SIZE));
    let mut ws = accept_hdr_async_with_config(
        stream,
        move |req: &tungstenite::handshake::server::Request,
              resp: tungstenite::handshake::server::Response| {
            // Parse and retain the workspace even when handshake auth is disabled;
            // persistence hooks must receive the same routing context.
            let uri = req.uri();
            let path = uri.path();
            let mut workspace_id = "";
            if let Some(rest) = path.strip_prefix('/') {
                if !rest.is_empty() {
                    workspace_id = rest.split('/').next().unwrap_or("");
                }
            }
            if let Ok(mut guard) = workspace_holder_c.lock() {
                *guard = Some(workspace_id.to_string());
            }

            if let Some(check) = &handshake_auth {
                // Parse query token parameter (no external deps)
                let token = uri.query().and_then(|q| {
                    for pair in q.split('&') {
                        let mut it = pair.splitn(2, '=');
                        let k = it.next().unwrap_or("");
                        let v = it.next();
                        if k == "token" {
                            return Some(v.unwrap_or(""));
                        }
                    }
                    None
                });

                let allowed = (check)(HandshakeAuthArgs {
                    workspace: workspace_id,
                    token,
                    request: req,
                    conn_id,
                });
                if !allowed {
                    warn!(workspace=%workspace_id, token=?token, "handshake auth denied");
                    // Build a 401 Unauthorized response
                    let builder = tungstenite::http::Response::builder()
                        .status(tungstenite::http::StatusCode::UNAUTHORIZED);
                    // Provide a small body for clarity
                    let response = builder
                        .body(Some("Unauthorized".to_string()))
                        .unwrap_or_else(|e| {
                            warn!(?e, "failed to build unauthorized response");
                            let mut fallback =
                                tungstenite::http::Response::new(Some("Unauthorized".to_string()));
                            *fallback.status_mut() = tungstenite::http::StatusCode::UNAUTHORIZED;
                            fallback
                        });
                    return Err(response);
                }
                debug!(workspace=%workspace_id, token=?token, "handshake auth accepted");
            }
            Ok(resp)
        },
        Some(websocket_config),
    )
    .await?;

    // Determine workspace id (default to empty string)
    let workspace_id = workspace_holder
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .unwrap_or_default();
    let Some(hub) = registry.get_or_create(&workspace_id).await else {
        warn!(workspace=%workspace_id, "workspace limit reached");
        ws.close(None).await?;
        return Ok(());
    };

    // writer task channel
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    let (mut sink, mut stream) = ws.split();
    // writer
    let sink_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sink.send(msg).await.is_err() {
                debug!("sink send error; writer task exiting");
                break;
            }
        }
    });

    let mut joined_rooms: HashSet<RoomKey> = HashSet::new();

    let receive_result = loop {
        let Some(msg) = stream.next().await else {
            break Ok(());
        };
        let msg = match msg {
            Ok(msg) => msg,
            Err(error) => {
                warn!(%error, "WebSocket receive error; closing connection");
                break Err(error);
            }
        };
        match msg {
            Message::Text(txt) => {
                if txt == "ping" {
                    let _ = tx.send(Message::Text("pong".into()));
                }
            }
            Message::Binary(data) => {
                if data.len() > protocol::MAX_MESSAGE_SIZE {
                    warn!(bytes = data.len(), "oversized protocol frame rejected");
                    continue;
                }
                if let Some(proto) = try_decode(data.as_ref()) {
                    match proto {
                        ProtocolMessage::JoinRequest {
                            crdt,
                            room_id,
                            auth,
                            version,
                        } => {
                            let room = RoomKey {
                                crdt,
                                room: room_id.clone(),
                            };
                            let send_room_limit_error = || {
                                let error = ProtocolMessage::JoinError {
                                    crdt,
                                    room_id: room.room.clone(),
                                    code: JoinErrorCode::Unknown,
                                    message: "workspace room limit reached".into(),
                                    receiver_version: None,
                                    app_code: None,
                                };
                                if let Ok(bytes) = loro_protocol::encode(&error) {
                                    let _ = tx.send(Message::Binary(bytes.into()));
                                }
                            };
                            // Reject impossible joins before invoking a potentially expensive
                            // authentication backend. Capacity is checked again after auth to
                            // handle concurrent room allocation without reserving state here.
                            if hub.lock().await.room_limit_reached(&room) {
                                send_room_limit_error();
                                continue;
                            }
                            // Authenticate before loading the room so denied joins cannot
                            // allocate persistent state or consume room capacity.
                            let auth_result = match &authenticate {
                                Some(auth_fn) => {
                                    (auth_fn)(AuthArgs {
                                        room: room.room.clone(),
                                        crdt: room.crdt,
                                        auth,
                                        conn_id,
                                    })
                                    .await
                                }
                                None => Ok(Some(default_permission)),
                            };
                            let permission = match auth_result {
                                Ok(Some(permission)) => permission,
                                Ok(None) => {
                                    let err = ProtocolMessage::JoinError {
                                        crdt,
                                        room_id: room.room.clone(),
                                        code: JoinErrorCode::AuthFailed,
                                        message: "Authentication failed".into(),
                                        receiver_version: None,
                                        app_code: None,
                                    };
                                    if let Ok(bytes) = loro_protocol::encode(&err) {
                                        let _ = tx.send(Message::Binary(bytes.into()));
                                    }
                                    warn!(room=?room.room, "join denied by authenticate() returning None");
                                    continue;
                                }
                                Err(message) => {
                                    let err = ProtocolMessage::JoinError {
                                        crdt,
                                        room_id: room.room.clone(),
                                        code: JoinErrorCode::Unknown,
                                        message,
                                        receiver_version: None,
                                        app_code: None,
                                    };
                                    if let Ok(bytes) = loro_protocol::encode(&err) {
                                        let _ = tx.send(Message::Binary(bytes.into()));
                                    }
                                    warn!(room=?room.room, "join denied due to authenticate() error");
                                    continue;
                                }
                            };
                            let mut h = hub.lock().await;
                            if h.room_limit_reached(&room) {
                                send_room_limit_error();
                                continue;
                            }
                            // ensure doc exists / load
                            if let Err(message) = h.ensure_room_loaded(&room).await {
                                let error = ProtocolMessage::JoinError {
                                    crdt,
                                    room_id: room.room.clone(),
                                    code: JoinErrorCode::Unknown,
                                    message,
                                    receiver_version: None,
                                    app_code: None,
                                };
                                if let Ok(bytes) = loro_protocol::encode(&error) {
                                    let _ = tx.send(Message::Binary(bytes.into()));
                                }
                                continue;
                            }
                            // register subscriber and record permission
                            h.join(conn_id, room.clone(), &tx);
                            h.perms.insert((conn_id, room.clone()), permission);
                            joined_rooms.insert(room.clone());
                            info!(workspace=%h.workspace, room=?room.room, ?permission, "join ok");
                            // respond ok with current version and empty extra
                            let current_version = h.current_version_bytes(&room);
                            let ok = ProtocolMessage::JoinResponseOk {
                                crdt,
                                room_id: room.room.clone(),
                                permission,
                                version: current_version,
                                extra: Some(Vec::new()),
                            };
                            if let Ok(bytes) = loro_protocol::encode(&ok) {
                                let _ = tx.send(Message::Binary(bytes.into()));
                            }
                            // ELO persistence exports are opaque indexes, not generic CRDT
                            // snapshots; ELO always uses version-filtered backfill below.
                            let initial_snapshot = (crdt != CrdtType::Elo)
                                .then(|| h.snapshot_bytes(&room))
                                .flatten();
                            if let Some(snapshot) = initial_snapshot {
                                match send_update(
                                    &tx,
                                    crdt,
                                    &room.room,
                                    snapshot,
                                    h.config.outbound_fragment_size,
                                ) {
                                    Ok(()) => {
                                        debug!(room=?room.room, "sent initial snapshot after join")
                                    }
                                    Err(error) => {
                                        warn!(room=?room.room, %error, "failed to send initial snapshot")
                                    }
                                }
                            } else {
                                // Otherwise, attempt backfill if other clients present or the CRDT allows
                                let others_in_room =
                                    h.subs.get(&room).map(|v| v.len()).unwrap_or(0) > 1;
                                let allow_when_empty = h
                                    .docs
                                    .get(&room)
                                    .map(|s| s.doc.allow_backfill_when_no_other_clients())
                                    .unwrap_or(false);
                                if others_in_room || allow_when_empty {
                                    let backfill = h
                                        .docs
                                        .get(&room)
                                        .map(|s| s.doc.compute_backfill(&version))
                                        .unwrap_or_default();
                                    let backfill_cnt = backfill.len();
                                    for update in backfill {
                                        if let Err(error) = send_update(
                                            &tx,
                                            crdt,
                                            &room.room,
                                            update,
                                            h.config.outbound_fragment_size,
                                        ) {
                                            warn!(room=?room.room, %error, "failed to send backfill");
                                            break;
                                        }
                                    }
                                    if backfill_cnt > 0 {
                                        debug!(room=?room.room, cnt=%backfill_cnt, "sent backfill after join");
                                    }
                                }
                            }
                        }
                        ProtocolMessage::DocUpdateFragmentHeader {
                            crdt,
                            room_id,
                            batch_id,
                            fragment_count,
                            total_size_bytes,
                        } => {
                            let room = RoomKey {
                                crdt,
                                room: room_id.clone(),
                            };
                            if !joined_rooms.contains(&room) {
                                send_ack(
                                    &tx,
                                    crdt,
                                    &room.room,
                                    batch_id,
                                    UpdateStatusCode::PermissionDenied,
                                );
                                continue;
                            }
                            // Permission check
                            let perm = hub
                                .lock()
                                .await
                                .perms
                                .get(&(conn_id, room.clone()))
                                .copied();
                            if !matches!(perm, Some(Permission::Write)) {
                                send_ack(
                                    &tx,
                                    crdt,
                                    &room.room,
                                    batch_id,
                                    UpdateStatusCode::PermissionDenied,
                                );
                                continue;
                            }
                            // Initialize batch (guard against hijack by another sender).
                            let mut h = hub.lock().await;
                            if fragment_count == 0
                                || fragment_count > h.config.max_fragments_per_batch
                                || total_size_bytes > h.config.max_fragment_batch_bytes
                            {
                                send_ack(
                                    &tx,
                                    crdt,
                                    &room.room,
                                    batch_id,
                                    UpdateStatusCode::PayloadTooLarge,
                                );
                                continue;
                            }
                            let key = (room.clone(), batch_id);
                            if let Some(existing) = h.fragments.get(&key) {
                                if existing.from_conn != conn_id {
                                    send_ack(
                                        &tx,
                                        crdt,
                                        &room.room,
                                        batch_id,
                                        UpdateStatusCode::InvalidUpdate,
                                    );
                                    continue;
                                }
                                // Duplicate header from the same sender is idempotent.
                                continue;
                            }
                            let (inflight, inflight_bytes) = h
                                .fragments
                                .values()
                                .filter(|batch| batch.from_conn == conn_id)
                                .fold((0usize, 0u64), |(count, bytes), batch| {
                                    (count + 1, bytes.saturating_add(batch.total_size))
                                });
                            let exceeds_byte_budget = inflight_bytes
                                .checked_add(total_size_bytes)
                                .is_none_or(|bytes| {
                                    bytes > h.config.max_inflight_fragment_bytes_per_connection
                                });
                            if inflight >= h.config.max_inflight_fragment_batches_per_connection
                                || exceeds_byte_budget
                            {
                                send_ack(
                                    &tx,
                                    crdt,
                                    &room.room,
                                    batch_id,
                                    UpdateStatusCode::RateLimited,
                                );
                                continue;
                            }
                            match h.start_fragment_batch(
                                &room,
                                conn_id,
                                batch_id,
                                fragment_count,
                                total_size_bytes,
                                &tx,
                            ) {
                                Ok(()) => {}
                                Err(_) => {
                                    send_ack(
                                        &tx,
                                        crdt,
                                        &room.room,
                                        batch_id,
                                        UpdateStatusCode::PayloadTooLarge,
                                    );
                                    continue;
                                }
                            }
                        }
                        ProtocolMessage::DocUpdateFragment {
                            crdt,
                            room_id,
                            batch_id,
                            index,
                            fragment,
                        } => {
                            let room = RoomKey {
                                crdt,
                                room: room_id.clone(),
                            };
                            if !joined_rooms.contains(&room) {
                                send_ack(
                                    &tx,
                                    crdt,
                                    &room.room,
                                    batch_id,
                                    UpdateStatusCode::PermissionDenied,
                                );
                                continue;
                            }
                            // Validate batch existence and sender binding; also index bounds
                            let mut h = hub.lock().await;
                            let key = (room.clone(), batch_id);
                            if let Some(b) = h.fragments.get(&key) {
                                if b.from_conn != conn_id {
                                    send_ack(
                                        &tx,
                                        crdt,
                                        &room.room,
                                        batch_id,
                                        UpdateStatusCode::InvalidUpdate,
                                    );
                                    // do not broadcast
                                    continue;
                                }
                                if !usize::try_from(index)
                                    .ok()
                                    .map(|i| i < b.chunks.len())
                                    .unwrap_or(false)
                                {
                                    send_ack(
                                        &tx,
                                        crdt,
                                        &room.room,
                                        batch_id,
                                        UpdateStatusCode::InvalidUpdate,
                                    );
                                    continue;
                                }
                            } else {
                                send_ack(
                                    &tx,
                                    crdt,
                                    &room.room,
                                    batch_id,
                                    UpdateStatusCode::FragmentTimeout,
                                );
                                continue;
                            }
                            // Accumulate and validate the complete update before any peer sees it.
                            let completed = match h
                                .add_fragment_and_maybe_finish(&room, batch_id, index, fragment)
                            {
                                Ok(Some(completed)) => completed,
                                Ok(None) => continue,
                                Err(error) => {
                                    let status = match error {
                                        FragmentBatchError::PayloadTooLarge => {
                                            UpdateStatusCode::PayloadTooLarge
                                        }
                                        FragmentBatchError::SizeMismatch => {
                                            UpdateStatusCode::InvalidUpdate
                                        }
                                    };
                                    send_ack(&tx, crdt, &room.room, batch_id, status);
                                    continue;
                                }
                            };
                            {
                                let apply_result = match crdt {
                                    CrdtType::Loro
                                    | CrdtType::LoroEphemeralStore
                                    | CrdtType::LoroEphemeralStorePersisted => {
                                        let start = std::time::Instant::now();
                                        let res = h.apply_updates(
                                            &room,
                                            std::slice::from_ref(&completed.payload),
                                        );
                                        let elapsed_ms = start.elapsed().as_millis();
                                        if res.is_ok() {
                                            debug!(room=?room.room, updates=1, ms=%elapsed_ms, "applied reassembled updates");
                                        }
                                        res
                                    }
                                    CrdtType::Elo => h.apply_updates(
                                        &room,
                                        std::slice::from_ref(&completed.payload),
                                    ),
                                    _ => Ok(()),
                                };

                                if apply_result.is_ok() {
                                    let header = ProtocolMessage::DocUpdateFragmentHeader {
                                        crdt,
                                        room_id: room.room.clone(),
                                        batch_id,
                                        fragment_count: completed.fragment_count,
                                        total_size_bytes: completed.total_size,
                                    };
                                    if let Ok(bytes) = loro_protocol::encode(&header) {
                                        h.broadcast(&room, conn_id, Message::Binary(bytes.into()));
                                    }
                                    let mut offset = 0;
                                    for (index, fragment_size) in
                                        completed.fragment_sizes.into_iter().enumerate()
                                    {
                                        let end = offset + fragment_size;
                                        let message = ProtocolMessage::DocUpdateFragment {
                                            crdt,
                                            room_id: room.room.clone(),
                                            batch_id,
                                            index: index as u64,
                                            fragment: completed.payload[offset..end].to_vec(),
                                        };
                                        offset = end;
                                        if let Ok(bytes) = loro_protocol::encode(&message) {
                                            h.broadcast(
                                                &room,
                                                conn_id,
                                                Message::Binary(bytes.into()),
                                            );
                                        }
                                    }
                                    send_ack(&tx, crdt, &room.room, batch_id, UpdateStatusCode::Ok);
                                } else {
                                    send_ack(
                                        &tx,
                                        crdt,
                                        &room.room,
                                        batch_id,
                                        UpdateStatusCode::InvalidUpdate,
                                    );
                                }
                            }
                        }
                        ProtocolMessage::DocUpdate {
                            crdt,
                            room_id,
                            updates,
                            batch_id,
                        } => {
                            let room = RoomKey {
                                crdt,
                                room: room_id.clone(),
                            };
                            let oversized =
                                updates.iter().any(|u| u.len() > protocol::MAX_MESSAGE_SIZE);
                            if oversized {
                                send_ack(
                                    &tx,
                                    crdt,
                                    &room.room,
                                    batch_id,
                                    UpdateStatusCode::PayloadTooLarge,
                                );
                                continue;
                            }
                            if !joined_rooms.contains(&room) {
                                send_ack(
                                    &tx,
                                    crdt,
                                    &room.room,
                                    batch_id,
                                    UpdateStatusCode::PermissionDenied,
                                );
                                warn!(room=?room.room, "update rejected: not joined");
                            } else {
                                // Check permission
                                let perm = hub
                                    .lock()
                                    .await
                                    .perms
                                    .get(&(conn_id, room.clone()))
                                    .copied();
                                if !matches!(perm, Some(Permission::Write)) {
                                    send_ack(
                                        &tx,
                                        crdt,
                                        &room.room,
                                        batch_id,
                                        UpdateStatusCode::PermissionDenied,
                                    );
                                    continue;
                                }
                                let mut h = hub.lock().await;
                                let apply_result = match crdt {
                                    CrdtType::Loro
                                    | CrdtType::LoroEphemeralStore
                                    | CrdtType::LoroEphemeralStorePersisted => {
                                        let start = std::time::Instant::now();
                                        let res = h.apply_updates(&room, &updates);
                                        let elapsed_ms = start.elapsed().as_millis();
                                        if res.is_ok() {
                                            debug!(room=?room.room, updates=%updates.len(), ms=%elapsed_ms, "applied and broadcast updates");
                                        }
                                        res
                                    }
                                    CrdtType::Elo => {
                                        // Index headers only; payload remains opaque to server.
                                        h.apply_updates(&room, &updates)
                                    }
                                    _ => Ok(()),
                                };

                                if apply_result.is_ok() {
                                    h.broadcast(&room, conn_id, Message::Binary(data));
                                    send_ack(&tx, crdt, &room.room, batch_id, UpdateStatusCode::Ok);
                                } else {
                                    send_ack(
                                        &tx,
                                        crdt,
                                        &room.room,
                                        batch_id,
                                        UpdateStatusCode::InvalidUpdate,
                                    );
                                }
                            }
                        }
                        _ => {
                            // For simplicity, ignore other messages in minimal server.
                        }
                    }
                } else {
                    // Invalid frame: close with Protocol error, but keep server running
                    warn!("invalid protocol frame; closing connection");
                    let _ = tx.send(Message::Close(Some(CloseFrame {
                        code: CloseCode::Protocol,
                        reason: "Protocol error".into(),
                    })));
                    break Ok(());
                }
            }
            Message::Close(frame) => {
                let _ = tx.send(Message::Close(frame.clone()));
                break Ok(());
            }
            Message::Ping(p) => {
                let _ = tx.send(Message::Pong(p));
                let _ = tx.send(Message::Text("pong".into()));
            }
            _ => {}
        }
    };

    let rooms_for_hook: Vec<(CrdtType, String)> = joined_rooms
        .into_iter()
        .map(|RoomKey { crdt, room }| (crdt, room))
        .collect();

    // cleanup
    {
        let mut h = hub.lock().await;
        h.leave_all(conn_id);
    }
    // drop tx to stop writer
    drop(tx);
    let _ = sink_task.await;

    if let Some(hook) = close_connection {
        let args = CloseConnectionArgs {
            workspace: workspace_id.clone(),
            conn_id,
            rooms: rooms_for_hook,
        };
        if let Err(e) = (hook)(args).await {
            warn!(conn_id, %e, "on_close_connection hook failed");
        }
    }

    debug!(conn_id, "connection closed and cleaned up");
    receive_result.map_err(Into::into)
}
