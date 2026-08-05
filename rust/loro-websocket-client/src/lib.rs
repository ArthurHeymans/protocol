//! Loro WebSocket Client
//!
//! Two layers are exposed:
//! - Low-level `Client` to send/receive raw `loro_protocol::ProtocolMessage`.
//! - High-level `LoroWebsocketClient` that joins rooms and applies incoming updates
//!   to a provided `loro::LoroDoc`. This mirrors the JS client's responsibilities.
//!
//! Low-level example (not run here):
//! ```no_run
//! use loro_websocket_client::Client;
//! use loro_protocol::{ProtocolMessage, CrdtType};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! #   let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
//! #   rt.block_on(async move {
//! let mut client = Client::connect("ws://127.0.0.1:9000").await?;
//! client.send(&ProtocolMessage::Leave { crdt: CrdtType::Loro, room_id: "room1".to_string() }).await?;
//! if let Some(msg) = client.next().await? {
//!     println!("got: {:?}", msg);
//! }
//! #   Ok(())
//! # })
//! # }
//! ```
//!
//! High-level example (not run here):
//! ```no_run
//! use std::sync::Arc;
//! use loro::{LoroDoc};
//! use loro_websocket_client::LoroWebsocketClient;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! #   let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
//! #   rt.block_on(async move {
//! let client = LoroWebsocketClient::connect("ws://127.0.0.1:9000").await?;
//! let doc = Arc::new(tokio::sync::Mutex::new(LoroDoc::new()));
//! let _room = client.join_loro("room1", doc.clone()).await?;
//! // mutate doc then commit; client auto-sends local updates to the room
//! { let mut d = doc.lock().await; d.get_text("text").insert(0, "hello").unwrap(); d.commit(); }
//! #   Ok(())
//! # })
//! # }
//! ```

use futures_util::{SinkExt, StreamExt};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    hash::{Hash, Hasher},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex as StdMutex,
    },
};
use tokio::{
    net::TcpStream,
    sync::{mpsc, oneshot, Mutex},
};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

use aes_gcm::aead::{Aead, KeyInit};
use loro::LoroDoc;
pub use loro_protocol as protocol;
use protocol::{encode, try_decode, CrdtType, ProtocolMessage, RoomErrorCode, UpdateStatusCode};

/// Errors that may occur in the client.
#[derive(Debug)]
pub enum ClientError {
    /// WebSocket handshake returned 401 Unauthorized.
    Unauthorized,
    /// Underlying WebSocket error.
    Ws(Box<tokio_tungstenite::tungstenite::Error>),
    /// Protocol encoding/decoding error.
    Protocol(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Unauthorized => write!(f, "unauthorized"),
            ClientError::Ws(e) => write!(f, "websocket error: {}", e),
            ClientError::Protocol(e) => write!(f, "protocol error: {}", e),
        }
    }
}
impl std::error::Error for ClientError {}
impl From<tokio_tungstenite::tungstenite::Error> for ClientError {
    fn from(e: tokio_tungstenite::tungstenite::Error) -> Self {
        ClientError::Ws(Box::new(e))
    }
}

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

const MAX_FRAGMENTS_PER_BATCH: usize = 64;
const MAX_FRAGMENT_BATCH_BYTES: usize = 8 * 1024 * 1024;
const MAX_INFLIGHT_FRAGMENT_BATCHES: usize = 8;
const MAX_INFLIGHT_FRAGMENT_BYTES: usize = 16 * 1024 * 1024;

/// Configuration knobs for the high-level client.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Timeout window for fragment reassembly before reporting FragmentTimeout.
    pub fragment_reassembly_timeout: std::time::Duration,
    /// Safety headroom subtracted from MAX_MESSAGE_SIZE when fragmenting.
    pub fragment_limit_headroom: usize,
    /// A soft per-fragment cap; final limit is min(soft_max, MAX-HEADROOM).
    pub fragment_limit_soft_max: usize,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            fragment_reassembly_timeout: std::time::Duration::from_secs(10),
            fragment_limit_headroom: 4096,
            fragment_limit_soft_max: 240 * 1024,
        }
    }
}

/// A minimal client wrapping a WebSocket stream.
pub struct Client {
    ws: Ws,
}

impl Client {
    /// Connect to a ws/wss URL.
    pub async fn connect(url: &str) -> Result<Self, ClientError> {
        match connect_async(url).await {
            Ok((ws, _resp)) => Ok(Self { ws }),
            Err(e) => {
                // Try to classify Unauthorized (401) specially
                if let tokio_tungstenite::tungstenite::Error::Http(resp) = &e {
                    if resp.status()
                        == tokio_tungstenite::tungstenite::http::StatusCode::UNAUTHORIZED
                    {
                        return Err(ClientError::Unauthorized);
                    }
                }
                let s = e.to_string().to_lowercase();
                if s.contains("401") || s.contains("unauthorized") {
                    return Err(ClientError::Unauthorized);
                }
                Err(ClientError::Ws(Box::new(e)))
            }
        }
    }

    /// Send a protocol message as a binary frame.
    pub async fn send(&mut self, msg: &ProtocolMessage) -> Result<(), ClientError> {
        let data = encode(msg).map_err(ClientError::Protocol)?;
        self.ws.send(Message::Binary(data.into())).await?;
        Ok(())
    }

    /// Send a keepalive ping (text frame "ping" per protocol.md).
    pub async fn ping(&mut self) -> Result<(), ClientError> {
        self.ws.send(Message::Text("ping".into())).await?;
        Ok(())
    }

    /// Receive the next protocol message.
    /// - Ignores non-binary frames.
    /// - Replies to text "ping" with text "pong".
    /// - Returns Ok(None) on clean close.
    pub async fn next(&mut self) -> Result<Option<ProtocolMessage>, ClientError> {
        loop {
            match self.ws.next().await {
                Some(Ok(Message::Binary(data))) => {
                    if let Some(msg) = try_decode(data.as_ref()) {
                        return Ok(Some(msg));
                    }
                    // Unknown/invalid payload -> skip.
                }
                Some(Ok(Message::Text(txt))) => {
                    if txt == "ping" {
                        self.ws.send(Message::Text("pong".into())).await?;
                    }
                    // Keepalive frames are connection-scoped; not forwarded to app.
                }
                Some(Ok(Message::Ping(_))) => {
                    // Let tungstenite handle pongs automatically, or reply with pong text for parity
                    // with protocol keepalive behavior.
                    self.ws.send(Message::Text("pong".into())).await?;
                }
                Some(Ok(Message::Close(_))) => return Ok(None),
                Some(Ok(_)) => { /* ignore other control frames */ }
                Some(Err(e)) => return Err(ClientError::Ws(Box::new(e))),
                None => return Ok(None),
            }
        }
    }

    /// Close the connection gracefully.
    pub async fn close(mut self) -> Result<(), ClientError> {
        self.ws.close(None).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_error_display() {
        let e = ClientError::Protocol("bad".into());
        assert!(format!("{}", e).contains("protocol error"));
    }

    #[test]
    fn elo_key_debug_is_redacted_and_conflicting_ids_are_rejected() {
        let key = EloResolvedKey {
            key_id: "kid".to_string(),
            key: [0xab; 32],
        };
        let debug = format!("{key:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("171"));

        let keyring = EloKeyring::new();
        keyring.add_key("kid", [1; 32]).expect("kid is new");
        keyring
            .add_key("kid", [1; 32])
            .expect("adding identical material is idempotent");
        assert!(keyring.add_key("kid", [2; 32]).is_err());
    }

    #[derive(Default)]
    struct RecordingAdaptor {
        updates: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    #[async_trait::async_trait]
    impl CrdtDocAdaptor for RecordingAdaptor {
        fn crdt_type(&self) -> CrdtType {
            CrdtType::Loro
        }

        async fn version(&self) -> Vec<u8> {
            Vec::new()
        }

        async fn set_ctx(&mut self, _ctx: CrdtAdaptorContext) {}

        async fn handle_join_ok(&mut self, _permission: protocol::Permission, _version: Vec<u8>) {}

        async fn apply_update(&mut self, updates: Vec<Vec<u8>>) {
            self.updates.lock().await.extend(updates);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_adaptor_join_preserves_auth_across_retries() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let address = listener
            .local_addr()
            .expect("test listener should have an address");
        let expected_auth = b"orgsync bootstrap claim".to_vec();
        let server_auth = expected_auth.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("client should connect");
            let mut websocket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("websocket handshake should succeed");
            for attempt in 0..3 {
                let Message::Binary(bytes) = websocket
                    .next()
                    .await
                    .expect("join request should arrive")
                    .expect("join frame should be readable")
                else {
                    panic!("join request should be binary");
                };
                let request = try_decode(bytes.as_ref()).expect("join request should decode");
                let ProtocolMessage::JoinRequest {
                    crdt,
                    room_id,
                    auth,
                    ..
                } = request
                else {
                    panic!("expected JoinRequest");
                };
                assert_eq!(auth, server_auth);

                let response = if attempt == 0 {
                    ProtocolMessage::JoinError {
                        crdt,
                        room_id: room_id.clone(),
                        code: protocol::JoinErrorCode::VersionUnknown,
                        message: "retry".to_string(),
                        receiver_version: Some(vec![1]),
                        app_code: None,
                    }
                } else {
                    ProtocolMessage::JoinResponseOk {
                        crdt,
                        room_id: room_id.clone(),
                        permission: protocol::Permission::Write,
                        version: Vec::new(),
                        extra: Some(Vec::new()),
                    }
                };
                websocket
                    .send(Message::Binary(
                        encode(&response).expect("response should encode").into(),
                    ))
                    .await
                    .expect("response should send");
                if attempt == 1 {
                    let rejoin = ProtocolMessage::RoomError {
                        crdt,
                        room_id,
                        code: RoomErrorCode::RejoinSuggested,
                        message: "refresh room state".to_string(),
                    };
                    websocket
                        .send(Message::Binary(
                            encode(&rejoin).expect("room error should encode").into(),
                        ))
                        .await
                        .expect("room error should send");
                }
            }
        });

        let client = LoroWebsocketClient::connect(&format!("ws://{address}"))
            .await
            .expect("client should connect");
        client
            .join_with_adaptor_and_auth(
                "room",
                expected_auth,
                Box::new(RecordingAdaptor::default()),
            )
            .await
            .expect("authenticated join should succeed");
        server.await.expect("test server should finish");
    }

    struct BlockingAdaptor {
        started: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    #[async_trait::async_trait]
    impl CrdtDocAdaptor for BlockingAdaptor {
        fn crdt_type(&self) -> CrdtType {
            CrdtType::Loro
        }

        async fn version(&self) -> Vec<u8> {
            Vec::new()
        }

        async fn set_ctx(&mut self, _ctx: CrdtAdaptorContext) {}

        async fn handle_join_ok(&mut self, _permission: protocol::Permission, _version: Vec<u8>) {}

        async fn apply_update(&mut self, _updates: Vec<Vec<u8>>) {
            self.started.notify_one();
            self.release.notified().await;
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn slow_adaptor_does_not_hold_the_global_registry_lock() {
        let (tx, _rx) = mpsc::unbounded_channel::<Message>();
        let adaptors: AdaptorRegistry = Arc::new(Mutex::new(HashMap::new()));
        let worker = ConnectionWorker::new(
            tx,
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(Mutex::new(HashMap::new())),
            adaptors.clone(),
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(AtomicU64::new(1)),
            Arc::new(StdMutex::new(HashMap::new())),
            Arc::new(ClientConfig::default()),
        );
        let slow_key = RoomKey {
            crdt: CrdtType::Loro,
            room: "slow".to_string(),
        };
        let fast_key = RoomKey {
            crdt: CrdtType::Loro,
            room: "fast".to_string(),
        };
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let fast_updates = Arc::new(Mutex::new(Vec::new()));
        {
            let mut adaptors = adaptors.lock().await;
            adaptors.insert(
                slow_key,
                RegisteredAdaptor {
                    adaptor: Arc::new(Mutex::new(Box::new(BlockingAdaptor {
                        started: started.clone(),
                        release: release.clone(),
                    }))),
                    auth: Vec::new(),
                },
            );
            adaptors.insert(
                fast_key,
                RegisteredAdaptor {
                    adaptor: Arc::new(Mutex::new(Box::new(RecordingAdaptor {
                        updates: fast_updates.clone(),
                    }))),
                    auth: Vec::new(),
                },
            );
        }

        let slow_worker = worker.clone();
        let slow = tokio::spawn(async move {
            slow_worker
                .handle_message(ProtocolMessage::DocUpdate {
                    crdt: CrdtType::Loro,
                    room_id: "slow".to_string(),
                    updates: vec![vec![1]],
                    batch_id: protocol::BatchId([1; 8]),
                })
                .await;
        });
        started.notified().await;
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            worker.handle_message(ProtocolMessage::DocUpdate {
                crdt: CrdtType::Loro,
                room_id: "fast".to_string(),
                updates: vec![vec![2]],
                batch_id: protocol::BatchId([2; 8]),
            }),
        )
        .await
        .expect("another room must not wait for the slow adaptor");
        release.notify_one();
        slow.await.expect("slow task should finish");
        assert_eq!(fast_updates.lock().await.as_slice(), &[vec![2]]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fragment_reassembly_delivers_updates_in_order() {
        let (tx, _rx) = mpsc::unbounded_channel::<Message>();
        let rooms = Arc::new(Mutex::new(HashMap::new()));
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let adaptors = Arc::new(Mutex::new(HashMap::new()));
        let pre_join_buf = Arc::new(Mutex::new(HashMap::new()));
        let frag_batches = Arc::new(Mutex::new(HashMap::new()));
        let batch_counter = Arc::new(AtomicU64::new(1));
        let sent_batches = Arc::new(StdMutex::new(HashMap::new()));
        let config = Arc::new(ClientConfig::default());

        let worker = ConnectionWorker::new(
            tx,
            rooms,
            pending,
            adaptors.clone(),
            pre_join_buf,
            frag_batches,
            batch_counter,
            sent_batches,
            config,
        );

        let room_id = "room-frag".to_string();
        let key = RoomKey {
            crdt: CrdtType::Loro,
            room: room_id.clone(),
        };
        let collected = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        adaptors.lock().await.insert(
            key.clone(),
            RegisteredAdaptor {
                adaptor: Arc::new(Mutex::new(Box::new(RecordingAdaptor {
                    updates: collected.clone(),
                }))),
                auth: Vec::new(),
            },
        );

        let batch_id = protocol::BatchId([1, 2, 3, 4, 5, 6, 7, 8]);
        worker
            .handle_message(ProtocolMessage::DocUpdateFragmentHeader {
                crdt: CrdtType::Loro,
                room_id: room_id.clone(),
                batch_id,
                fragment_count: 2,
                total_size_bytes: 10,
            })
            .await;
        // Send fragments out of order to ensure slot ordering is respected
        worker
            .handle_message(ProtocolMessage::DocUpdateFragment {
                crdt: CrdtType::Loro,
                room_id: room_id.clone(),
                batch_id,
                index: 1,
                fragment: b"world".to_vec(),
            })
            .await;
        worker
            .handle_message(ProtocolMessage::DocUpdateFragment {
                crdt: CrdtType::Loro,
                room_id,
                batch_id,
                index: 0,
                fragment: b"hello".to_vec(),
            })
            .await;

        let updates = collected.lock().await;
        assert_eq!(updates.as_slice(), &[b"helloworld".to_vec()]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fragment_reassembly_rejects_limits_and_duplicates() {
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        let frag_batches = Arc::new(Mutex::new(HashMap::new()));
        let config = ClientConfig::default();
        let worker = ConnectionWorker::new(
            tx,
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(Mutex::new(HashMap::new())),
            frag_batches.clone(),
            Arc::new(AtomicU64::new(1)),
            Arc::new(StdMutex::new(HashMap::new())),
            Arc::new(config),
        );
        let batch_id = protocol::BatchId([9; 8]);
        worker
            .handle_message(ProtocolMessage::DocUpdateFragmentHeader {
                crdt: CrdtType::Loro,
                room_id: "room".into(),
                batch_id,
                fragment_count: 65,
                total_size_bytes: 65,
            })
            .await;
        let Message::Binary(ack) = rx.recv().await.expect("limit ACK") else {
            panic!("expected binary ACK");
        };
        assert!(matches!(
            try_decode(ack.as_ref()),
            Some(ProtocolMessage::Ack {
                status: UpdateStatusCode::PayloadTooLarge,
                ..
            })
        ));
        assert!(frag_batches.lock().await.is_empty());

        worker
            .handle_message(ProtocolMessage::DocUpdateFragmentHeader {
                crdt: CrdtType::Loro,
                room_id: "room".into(),
                batch_id,
                fragment_count: 2,
                total_size_bytes: 2,
            })
            .await;
        let fragment = ProtocolMessage::DocUpdateFragment {
            crdt: CrdtType::Loro,
            room_id: "room".into(),
            batch_id,
            index: 0,
            fragment: vec![1],
        };
        worker.handle_message(fragment.clone()).await;
        worker.handle_message(fragment).await;
        let Message::Binary(ack) = rx.recv().await.expect("duplicate ACK") else {
            panic!("expected binary ACK");
        };
        assert!(matches!(
            try_decode(ack.as_ref()),
            Some(ProtocolMessage::Ack {
                status: UpdateStatusCode::InvalidUpdate,
                ..
            })
        ));
        assert!(frag_batches.lock().await.is_empty());
    }

    fn require_ok<T, E: std::fmt::Debug>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("{context}: {error:?}"),
        }
    }

    fn counter_u64(counter: loro::Counter) -> u64 {
        require_ok(
            u64::try_from(counter),
            "Loro counter should be non-negative",
        )
    }

    fn lock_unpoisoned<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
        mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    async fn wait_for_recorded_len<T>(items: &StdMutex<Vec<T>>, expected: usize) {
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if lock_unpoisoned(items).len() >= expected {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {expected} recorded items"));
    }

    fn encode_test_delta_container(
        peer: &[u8],
        start: u64,
        end: u64,
        key_id: &str,
        key: &[u8; 32],
        iv: [u8; ELO_IV_LENGTH],
        plaintext: &[u8],
    ) -> Vec<u8> {
        use protocol::bytes::BytesWriter;

        let mut header = BytesWriter::new();
        header.push_byte(protocol::elo::EloRecordKind::DeltaSpan as u8);
        header.push_var_bytes(peer);
        header.push_uleb128(start);
        header.push_uleb128(end);
        header.push_var_string(key_id);
        header.push_var_bytes(&iv);
        let record = require_ok(
            encrypt_elo_record(key, &iv, header.finalize(), plaintext),
            "test DeltaSpan should encrypt",
        );
        encode_elo_container(&[record])
    }

    #[tokio::test(flavor = "current_thread")]
    async fn elo_snapshot_container_roundtrips_plaintext() {
        let doc = Arc::new(Mutex::new(LoroDoc::new()));
        let key = [7u8; 32];
        let adaptor = EloDocAdaptor::new(doc, "kid", key)
            .with_iv_factory(Arc::new(|| [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]));
        let plaintext = b"hello-elo".to_vec();

        let container = require_ok(
            adaptor.encode_elo_snapshot_container(&plaintext),
            "deterministic IV generation should succeed",
        );
        let records = require_ok(
            protocol::elo::decode_elo_container(&container),
            "container should decode",
        );
        assert_eq!(records.len(), 1);
        let parsed = require_ok(
            protocol::elo::parse_elo_record_header(records[0]),
            "header should parse",
        );
        match parsed.header {
            protocol::elo::EloHeader::Snapshot(hdr) => {
                assert_eq!(hdr.key_id, "kid");
                assert_eq!(hdr.iv, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
                let cipher = aes_gcm::Aes256Gcm::new((&key).into());
                let decrypted = require_ok(
                    cipher.decrypt(
                        aes_gcm::Nonce::from_slice(&hdr.iv),
                        aes_gcm::aead::Payload {
                            msg: parsed.ct,
                            aad: parsed.aad,
                        },
                    ),
                    "ciphertext should decrypt",
                );
                assert_eq!(decrypted, plaintext);
            }
            _ => panic!("expected snapshot header"),
        }
        assert!(matches!(
            parsed.kind,
            protocol::elo::EloRecordKind::Snapshot
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn elo_local_update_is_canonical_delta_span_with_exact_metadata() {
        let doc = Arc::new(Mutex::new(LoroDoc::new()));
        let key = [7u8; 32];
        let base_snapshot = {
            let doc = doc.lock().await;
            require_ok(doc.set_peer_id(42), "peer id should be configurable");
            require_ok(
                doc.get_text("text").insert(0, "base"),
                "base edit should succeed",
            );
            doc.commit();
            require_ok(
                doc.export(loro::ExportMode::Snapshot),
                "base snapshot should export",
            )
        };
        let next_iv = Arc::new(AtomicU64::new(1));
        let mut adaptor =
            EloDocAdaptor::new(doc.clone(), "kid", key).with_iv_factory(Arc::new(move || {
                let mut iv = [3; ELO_IV_LENGTH];
                iv[..8].copy_from_slice(&next_iv.fetch_add(1, Ordering::Relaxed).to_be_bytes());
                iv
            }));
        let sent = Arc::new(StdMutex::new(Vec::new()));
        adaptor
            .set_ctx(CrdtAdaptorContext {
                send_update: {
                    let sent = sent.clone();
                    Arc::new(move |update| lock_unpoisoned(&sent).push(update))
                },
                on_join_failed: Arc::new(|_| {}),
                on_import_error: Arc::new(|error, _| panic!("unexpected packaging error: {error}")),
            })
            .await;
        adaptor
            .handle_join_ok(protocol::Permission::Write, Vec::new())
            .await;
        wait_for_recorded_len(&sent, 1).await;
        lock_unpoisoned(&sent).clear();

        let start = doc.lock().await.oplog_vv().get(&42).copied().unwrap_or(0);
        {
            let doc = doc.lock().await;
            require_ok(
                doc.get_text("text").insert(4, " + delta"),
                "local edit should succeed",
            );
            doc.commit();
        }
        let end = doc.lock().await.oplog_vv().get(&42).copied().unwrap_or(0);

        wait_for_recorded_len(&sent, 1).await;
        let sent = lock_unpoisoned(&sent);
        assert_eq!(sent.len(), 1);
        let records = require_ok(
            protocol::elo::decode_elo_container(&sent[0]),
            "delta container should decode",
        );
        assert_eq!(records.len(), 1);
        let parsed = require_ok(
            protocol::elo::parse_elo_record_header(records[0]),
            "delta header should parse",
        );
        let header = match parsed.header {
            protocol::elo::EloHeader::Delta(header) => header,
            _ => panic!("local update must use a DeltaSpan record"),
        };
        assert_eq!(header.peer_id, b"42");
        assert!(header.start > 0);
        assert_eq!(header.start, counter_u64(start));
        assert_eq!(header.end, counter_u64(end));

        let cipher = aes_gcm::Aes256Gcm::new((&key).into());
        let plaintext = require_ok(
            cipher.decrypt(
                aes_gcm::Nonce::from_slice(&header.iv),
                aes_gcm::aead::Payload {
                    msg: parsed.ct,
                    aad: parsed.aad,
                },
            ),
            "delta ciphertext should decrypt",
        );
        let blobs = require_ok(
            decode_canonical_delta_plaintext(&plaintext),
            "new DeltaSpan plaintext should use the canonical list encoding",
        );
        assert_eq!(blobs.len(), 1);
        let imported = LoroDoc::new();
        require_ok(
            imported.import(&base_snapshot),
            "base snapshot should import",
        );
        require_ok(imported.import(blobs[0]), "delta plaintext should import");
        assert_eq!(imported.get_text("text").to_string(), "base + delta");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn elo_rapid_local_updates_are_sent_in_callback_order_after_join() {
        let doc = Arc::new(Mutex::new(LoroDoc::new()));
        require_ok(
            doc.lock().await.set_peer_id(77),
            "peer id should be configurable",
        );
        let next_iv = Arc::new(AtomicU64::new(1));
        let mut adaptor =
            EloDocAdaptor::new(doc.clone(), "kid", [8; 32]).with_iv_factory(Arc::new(move || {
                let mut iv = [0; ELO_IV_LENGTH];
                iv[..8].copy_from_slice(&next_iv.fetch_add(1, Ordering::Relaxed).to_be_bytes());
                iv
            }));
        let sent = Arc::new(StdMutex::new(Vec::new()));
        adaptor
            .set_ctx(CrdtAdaptorContext {
                send_update: {
                    let sent = sent.clone();
                    Arc::new(move |update| lock_unpoisoned(&sent).push(update))
                },
                on_join_failed: Arc::new(|_| {}),
                on_import_error: Arc::new(|error, _| panic!("unexpected worker error: {error}")),
            })
            .await;

        {
            let doc = doc.lock().await;
            require_ok(doc.get_text("text").insert(0, "one"), "first edit");
            doc.commit();
        }
        let first_end = doc.lock().await.oplog_vv()[&77];
        {
            let doc = doc.lock().await;
            require_ok(doc.get_text("text").insert(3, "two"), "second edit");
            doc.commit();
        }
        let second_end = doc.lock().await.oplog_vv()[&77];
        assert!(lock_unpoisoned(&sent).is_empty());

        adaptor
            .handle_join_ok(protocol::Permission::Write, Vec::new())
            .await;
        wait_for_recorded_len(&sent, 3).await;
        let sent = lock_unpoisoned(&sent);
        let mut spans = Vec::new();
        let mut ivs = Vec::new();
        for container in sent.iter().take(2) {
            let records = require_ok(
                protocol::elo::decode_elo_container(container),
                "queued delta container should decode",
            );
            let parsed = require_ok(
                protocol::elo::parse_elo_record_header(records[0]),
                "queued delta header should parse",
            );
            match parsed.header {
                protocol::elo::EloHeader::Delta(header) => {
                    spans.push((header.start, header.end));
                    ivs.push(header.iv);
                }
                _ => panic!("queued local updates must precede the join snapshot"),
            }
        }
        assert_eq!(
            spans,
            vec![
                (0, counter_u64(first_end)),
                (counter_u64(first_end), counter_u64(second_end)),
            ]
        );
        assert_ne!(ivs[0], ivs[1]);
        let snapshot_records = require_ok(
            protocol::elo::decode_elo_container(&sent[2]),
            "join snapshot container should decode",
        );
        assert!(matches!(
            require_ok(
                protocol::elo::parse_elo_record_header(snapshot_records[0]),
                "join snapshot header should parse",
            )
            .kind,
            protocol::elo::EloRecordKind::Snapshot
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn elo_drop_cancels_queued_local_updates() {
        let doc = Arc::new(Mutex::new(LoroDoc::new()));
        let mut adaptor = EloDocAdaptor::new(doc.clone(), "kid", [8; 32]);
        let sent = Arc::new(StdMutex::new(Vec::new()));
        adaptor
            .set_ctx(CrdtAdaptorContext {
                send_update: {
                    let sent = sent.clone();
                    Arc::new(move |update| lock_unpoisoned(&sent).push(update))
                },
                on_join_failed: Arc::new(|_| {}),
                on_import_error: Arc::new(|_, _| {}),
            })
            .await;
        {
            let doc = doc.lock().await;
            require_ok(doc.get_text("text").insert(0, "queued"), "local edit");
            doc.commit();
        }
        drop(adaptor);
        tokio::task::yield_now().await;
        assert!(lock_unpoisoned(&sent).is_empty());
    }

    #[test]
    fn elo_multi_peer_blob_is_split_into_exact_delta_spans() {
        let source = LoroDoc::new();
        require_ok(
            source.set_peer_id(11),
            "first peer id should be configurable",
        );
        require_ok(
            source.get_text("text").insert(0, "left"),
            "first peer edit should succeed",
        );
        source.commit();
        require_ok(
            source.set_peer_id(22),
            "second peer id should be configurable",
        );
        require_ok(
            source.get_text("text").insert(4, "+right"),
            "second peer edit should succeed",
        );
        source.commit();
        let blob = require_ok(
            source.export(loro::ExportMode::all_updates()),
            "multi-peer update should export",
        );
        let key = [9u8; 32];
        let next_iv = Arc::new(AtomicU64::new(1));
        let iv_generator: EloIvGenerator = Arc::new(move || {
            let mut iv = [4; ELO_IV_LENGTH];
            iv[..8].copy_from_slice(&next_iv.fetch_add(1, Ordering::Relaxed).to_be_bytes());
            Ok(iv)
        });
        let used_ivs = Arc::new(StdMutex::new(HashSet::new()));
        let container = require_ok(
            encode_elo_delta_container_with(&source, "kid", &key, &iv_generator, &used_ivs, &blob),
            "multi-peer update should package",
        );

        let records = require_ok(
            protocol::elo::decode_elo_container(&container),
            "delta container should decode",
        );
        assert_eq!(records.len(), 2);
        let mut spans = Vec::new();
        let destination = LoroDoc::new();
        for record in records {
            let parsed = require_ok(
                protocol::elo::parse_elo_record_header(record),
                "delta header should parse",
            );
            let header = match parsed.header {
                protocol::elo::EloHeader::Delta(header) => header,
                _ => panic!("multi-peer update must contain only DeltaSpan records"),
            };
            spans.push((header.peer_id.clone(), header.start, header.end));
            let cipher = aes_gcm::Aes256Gcm::new((&key).into());
            let plaintext = require_ok(
                cipher.decrypt(
                    aes_gcm::Nonce::from_slice(&header.iv),
                    aes_gcm::aead::Payload {
                        msg: parsed.ct,
                        aad: parsed.aad,
                    },
                ),
                "delta ciphertext should decrypt",
            );
            let blobs = require_ok(
                decode_canonical_delta_plaintext(&plaintext),
                "DeltaSpan plaintext should decode",
            );
            assert_eq!(blobs.len(), 1);
            require_ok(destination.import(blobs[0]), "range update should import");
        }
        spans.sort();
        let vv = source.oplog_vv();
        assert_eq!(
            spans,
            vec![
                (b"11".to_vec(), 0, counter_u64(vv[&11])),
                (b"22".to_vec(), 0, counter_u64(vv[&22])),
            ]
        );
        assert_eq!(destination.get_text("text").to_string(), "left+right");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn elo_join_snapshot_has_real_sorted_version_and_importable_plaintext() {
        let doc = Arc::new(Mutex::new(LoroDoc::new()));
        {
            let doc = doc.lock().await;
            require_ok(doc.set_peer_id(9), "first peer id should be configurable");
            require_ok(
                doc.get_text("text").insert(0, "a"),
                "first edit should succeed",
            );
            doc.commit();
            require_ok(doc.set_peer_id(10), "second peer id should be configurable");
            require_ok(
                doc.get_text("text").insert(1, "b"),
                "second edit should succeed",
            );
            doc.commit();
        }
        let key = [5u8; 32];
        let mut adaptor = EloDocAdaptor::new(doc.clone(), "kid", key)
            .with_iv_factory(Arc::new(|| [6; ELO_IV_LENGTH]));
        let sent = Arc::new(StdMutex::new(Vec::new()));
        adaptor
            .set_ctx(CrdtAdaptorContext {
                send_update: {
                    let sent = sent.clone();
                    Arc::new(move |update| lock_unpoisoned(&sent).push(update))
                },
                on_join_failed: Arc::new(|_| {}),
                on_import_error: Arc::new(|error, _| panic!("unexpected snapshot error: {error}")),
            })
            .await;
        adaptor
            .handle_join_ok(protocol::Permission::Write, Vec::new())
            .await;
        wait_for_recorded_len(&sent, 1).await;

        let container = {
            let sent = lock_unpoisoned(&sent);
            assert_eq!(sent.len(), 1);
            sent[0].clone()
        };
        let records = require_ok(
            protocol::elo::decode_elo_container(&container),
            "snapshot container should decode",
        );
        let parsed = require_ok(
            protocol::elo::parse_elo_record_header(records[0]),
            "snapshot header should parse",
        );
        let header = match parsed.header {
            protocol::elo::EloHeader::Snapshot(header) => header,
            _ => panic!("join bootstrap must use a genuine snapshot record"),
        };
        let vv = doc.lock().await.oplog_vv();
        assert_eq!(
            header.vv,
            vec![
                (b"10".to_vec(), counter_u64(vv[&10])),
                (b"9".to_vec(), counter_u64(vv[&9])),
            ]
        );
        let cipher = aes_gcm::Aes256Gcm::new((&key).into());
        let snapshot = require_ok(
            cipher.decrypt(
                aes_gcm::Nonce::from_slice(&header.iv),
                aes_gcm::aead::Payload {
                    msg: parsed.ct,
                    aad: parsed.aad,
                },
            ),
            "snapshot ciphertext should decrypt",
        );
        let imported = LoroDoc::new();
        require_ok(
            imported.import(&snapshot),
            "snapshot plaintext should import",
        );
        assert_eq!(imported.get_text("text").to_string(), "ab");
        assert_eq!(imported.oplog_vv(), vv);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn elo_legacy_raw_delta_plaintext_remains_importable() {
        let source = LoroDoc::new();
        require_ok(source.set_peer_id(5), "peer id should be configurable");
        require_ok(
            source.get_text("text").insert(0, "legacy"),
            "legacy edit should succeed",
        );
        source.commit();
        let raw_delta = require_ok(
            source.export(loro::ExportMode::all_updates()),
            "legacy raw delta should export",
        );
        let end = counter_u64(source.oplog_vv()[&5]);
        let key = [4; 32];
        let container =
            encode_test_delta_container(b"5", 0, end, "kid", &key, [1; ELO_IV_LENGTH], &raw_delta);

        let destination = Arc::new(Mutex::new(LoroDoc::new()));
        let mut adaptor = EloDocAdaptor::new(destination.clone(), "kid", key);
        adaptor.apply_update(vec![container]).await;
        assert_eq!(
            destination.lock().await.get_text("text").to_string(),
            "legacy"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn elo_container_import_is_atomic_when_a_later_record_is_malformed() {
        let source = LoroDoc::new();
        require_ok(source.set_peer_id(5), "peer id should be configurable");
        require_ok(
            source.get_text("text").insert(0, "must stay absent"),
            "source edit should succeed",
        );
        source.commit();
        let valid_blob = require_ok(
            source.export(loro::ExportMode::all_updates()),
            "source update should export",
        );
        let key = [4; 32];
        let valid = encode_test_delta_container(
            b"5",
            0,
            counter_u64(source.oplog_vv()[&5]),
            "kid",
            &key,
            [1; ELO_IV_LENGTH],
            &valid_blob,
        );
        let invalid =
            encode_test_delta_container(b"6", 0, 1, "kid", &key, [2; ELO_IV_LENGTH], &[0xff]);
        let valid_records = require_ok(
            protocol::elo::decode_elo_container(&valid),
            "valid test container",
        );
        let invalid_records = require_ok(
            protocol::elo::decode_elo_container(&invalid),
            "invalid-plaintext test container",
        );
        let valid_record = valid_records[0].to_vec();
        let invalid_record = invalid_records[0].to_vec();
        let container = encode_elo_container(&[valid_record, invalid_record]);

        let destination = Arc::new(Mutex::new(LoroDoc::new()));
        let errors = Arc::new(StdMutex::new(Vec::new()));
        let mut adaptor = EloDocAdaptor::new(destination.clone(), "kid", key).with_error_handler({
            let errors = errors.clone();
            Arc::new(move |error| lock_unpoisoned(&errors).push(error))
        });
        adaptor.apply_update(vec![container]).await;

        assert_eq!(destination.lock().await.get_text("text").to_string(), "");
        assert!(lock_unpoisoned(&errors)
            .iter()
            .any(|error| error.kind == EloAdaptorErrorKind::ImportFailed));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn elo_fixed_key_adaptor_rejects_other_key_ids() {
        let source = LoroDoc::new();
        require_ok(source.set_peer_id(5), "peer id should be configurable");
        require_ok(
            source.get_text("text").insert(0, "secret"),
            "source edit should succeed",
        );
        source.commit();
        let raw_delta = require_ok(
            source.export(loro::ExportMode::all_updates()),
            "source delta should export",
        );
        let end = counter_u64(source.oplog_vv()[&5]);
        let key = [4; 32];
        let container = encode_test_delta_container(
            b"5",
            0,
            end,
            "other-kid",
            &key,
            [2; ELO_IV_LENGTH],
            &raw_delta,
        );

        let destination = Arc::new(Mutex::new(LoroDoc::new()));
        let mut adaptor = EloDocAdaptor::new(destination.clone(), "kid", key);
        let errors = Arc::new(StdMutex::new(Vec::new()));
        adaptor
            .set_ctx(CrdtAdaptorContext {
                send_update: Arc::new(|_| {}),
                on_join_failed: Arc::new(|_| {}),
                on_import_error: {
                    let errors = errors.clone();
                    Arc::new(move |error, _| lock_unpoisoned(&errors).push(error))
                },
            })
            .await;
        adaptor.apply_update(vec![container]).await;

        assert_eq!(destination.lock().await.get_text("text").to_string(), "");
        assert_eq!(
            lock_unpoisoned(&errors).as_slice(),
            &["unknown ELO key ID: other-kid"]
        );
    }

    struct WrongIdResolver;

    #[async_trait::async_trait]
    impl EloKeyResolver for WrongIdResolver {
        async fn resolve_key(
            &self,
            _key_id: Option<&str>,
        ) -> Result<Option<EloResolvedKey>, String> {
            Ok(Some(EloResolvedKey {
                key_id: "wrong".to_string(),
                key: [4; 32],
            }))
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn elo_resolver_mismatched_key_id_is_unknown_and_queued() {
        let source = LoroDoc::new();
        require_ok(source.set_peer_id(5), "peer id should be configurable");
        require_ok(source.get_text("text").insert(0, "secret"), "source edit");
        source.commit();
        let plaintext = require_ok(
            source.export(loro::ExportMode::all_updates()),
            "source update should export",
        );
        let container = encode_test_delta_container(
            b"5",
            0,
            counter_u64(source.oplog_vv()[&5]),
            "requested",
            &[4; 32],
            [2; ELO_IV_LENGTH],
            &plaintext,
        );
        let errors = Arc::new(StdMutex::new(Vec::new()));
        let mut adaptor = EloDocAdaptor::with_key_resolver(
            Arc::new(Mutex::new(LoroDoc::new())),
            Arc::new(WrongIdResolver),
        )
        .with_error_handler({
            let errors = errors.clone();
            Arc::new(move |error| lock_unpoisoned(&errors).push(error))
        });

        adaptor.apply_update(vec![container]).await;

        assert_eq!(adaptor.pending_encrypted_record_count(), 1);
        let errors = lock_unpoisoned(&errors);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].kind, EloAdaptorErrorKind::UnknownKey);
        assert!(errors[0].message.contains("returned key ID wrong"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn elo_unknown_keys_are_deduplicated_bounded_and_retryable() {
        let missing_key = [6; 32];
        let make_container = |peer: u64, text: &str, iv: [u8; ELO_IV_LENGTH]| {
            let source = LoroDoc::new();
            require_ok(source.set_peer_id(peer), "peer id should be configurable");
            require_ok(source.get_text("text").insert(0, text), "source edit");
            source.commit();
            let update = require_ok(
                source.export(loro::ExportMode::all_updates()),
                "source update should export",
            );
            encode_test_delta_container(
                peer.to_string().as_bytes(),
                0,
                counter_u64(source.oplog_vv()[&peer]),
                "k2",
                &missing_key,
                iv,
                &update,
            )
        };
        let evicted = make_container(1, "old", [1; ELO_IV_LENGTH]);
        let retained = make_container(2, "new", [2; ELO_IV_LENGTH]);
        let keyring = Arc::new(EloKeyring::new());
        keyring.add_key("k1", [1; 32]).expect("k1 is new");
        keyring.set_active_key("k1").expect("k1 should exist");
        let destination = Arc::new(Mutex::new(LoroDoc::new()));
        let errors = Arc::new(StdMutex::new(Vec::new()));
        let mut adaptor = EloDocAdaptor::with_key_resolver(destination.clone(), keyring.clone())
            .with_pending_limits(EloPendingLimits {
                max_records: 1,
                max_bytes: 1024 * 1024,
            })
            .with_error_handler({
                let errors = errors.clone();
                Arc::new(move |error| lock_unpoisoned(&errors).push(error))
            });

        adaptor
            .apply_update(vec![evicted.clone(), evicted, retained])
            .await;
        assert_eq!(adaptor.pending_encrypted_record_count(), 1);
        assert_eq!(
            lock_unpoisoned(&errors)
                .iter()
                .filter(|error| error.kind == EloAdaptorErrorKind::UnknownKey)
                .count(),
            2
        );
        assert!(lock_unpoisoned(&errors)
            .iter()
            .any(|error| error.kind == EloAdaptorErrorKind::PendingEvicted));

        keyring.add_key("k2", missing_key).expect("k2 is new");
        let retried = adaptor.retry_pending_encrypted_records().await;
        assert_eq!(
            retried,
            EloRetryResult {
                attempted: 1,
                imported: 1,
                remaining: 0,
            }
        );
        assert_eq!(destination.lock().await.get_text("text").to_string(), "new");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn elo_known_wrong_key_is_decrypt_failed_not_unknown_key() {
        let source = LoroDoc::new();
        require_ok(source.set_peer_id(3), "peer id should be configurable");
        require_ok(source.get_text("text").insert(0, "secret"), "source edit");
        source.commit();
        let plaintext = require_ok(
            source.export(loro::ExportMode::all_updates()),
            "source update should export",
        );
        let container = encode_test_delta_container(
            b"3",
            0,
            counter_u64(source.oplog_vv()[&3]),
            "k2",
            &[2; 32],
            [3; ELO_IV_LENGTH],
            &plaintext,
        );
        let keyring = Arc::new(EloKeyring::new());
        keyring.add_key("k2", [9; 32]).expect("k2 is new");
        keyring.set_active_key("k2").expect("k2 should exist");
        let errors = Arc::new(StdMutex::new(Vec::new()));
        let mut adaptor =
            EloDocAdaptor::with_key_resolver(Arc::new(Mutex::new(LoroDoc::new())), keyring)
                .with_error_handler({
                    let errors = errors.clone();
                    Arc::new(move |error| lock_unpoisoned(&errors).push(error))
                });

        adaptor.apply_update(vec![container]).await;

        assert_eq!(adaptor.pending_encrypted_record_count(), 0);
        assert_eq!(lock_unpoisoned(&errors).len(), 1);
        assert_eq!(
            lock_unpoisoned(&errors)[0].kind,
            EloAdaptorErrorKind::DecryptFailed
        );
        assert_eq!(
            lock_unpoisoned(&errors)[0].record.as_ref().unwrap().key_id,
            "k2"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn elo_rotation_retains_read_keys_and_new_key_snapshot_bootstraps() {
        let keyring = Arc::new(EloKeyring::new());
        keyring.add_key("k1", [1; 32]).expect("k1 is new");
        keyring.set_active_key("k1").expect("k1 should exist");
        let source = Arc::new(Mutex::new(LoroDoc::new()));
        let next_iv = Arc::new(AtomicU64::new(1));
        let mut adaptor = EloDocAdaptor::with_key_resolver(source.clone(), keyring.clone())
            .with_iv_factory(Arc::new(move || {
                let mut iv = [0; ELO_IV_LENGTH];
                iv[..8].copy_from_slice(&next_iv.fetch_add(1, Ordering::Relaxed).to_be_bytes());
                iv
            }));
        let sent = Arc::new(StdMutex::new(Vec::new()));
        adaptor
            .set_ctx(CrdtAdaptorContext {
                send_update: {
                    let sent = sent.clone();
                    Arc::new(move |update| lock_unpoisoned(&sent).push(update))
                },
                on_join_failed: Arc::new(|_| {}),
                on_import_error: Arc::new(|error, _| panic!("unexpected ELO error: {error}")),
            })
            .await;
        adaptor
            .handle_join_ok(protocol::Permission::Write, Vec::new())
            .await;
        wait_for_recorded_len(&sent, 1).await;

        keyring.add_key("k2", [2; 32]).expect("k2 is new");
        keyring.set_active_key("k2").expect("k2 should exist");
        assert_eq!(
            keyring
                .resolve_key(Some("k1"))
                .await
                .expect("key lookup should succeed")
                .expect("historical key should remain")
                .key,
            [1; 32]
        );
        {
            let doc = source.lock().await;
            require_ok(doc.set_peer_id(4), "peer id should be configurable");
            require_ok(doc.get_text("text").insert(0, "rotated"), "source edit");
            doc.commit();
        }
        assert!(adaptor.publish_snapshot().await);
        wait_for_recorded_len(&sent, 3).await;
        let snapshot = match lock_unpoisoned(&sent).last() {
            Some(snapshot) => snapshot.clone(),
            None => panic!("expected a published snapshot"),
        };
        let records = require_ok(
            protocol::elo::decode_elo_container(&snapshot),
            "snapshot container should decode",
        );
        let parsed = require_ok(
            protocol::elo::parse_elo_record_header(records[0]),
            "snapshot header should parse",
        );
        assert!(matches!(
            parsed.kind,
            protocol::elo::EloRecordKind::Snapshot
        ));
        let snapshot_key_id = match parsed.header {
            protocol::elo::EloHeader::Snapshot(header) => header.key_id,
            _ => panic!("expected snapshot header"),
        };
        assert_eq!(snapshot_key_id, "k2");

        let restarted = Arc::new(Mutex::new(LoroDoc::new()));
        let new_keyring = Arc::new(EloKeyring::new());
        new_keyring.add_key("k2", [2; 32]).expect("k2 is new");
        new_keyring.set_active_key("k2").expect("k2 should exist");
        let mut late_joiner = EloDocAdaptor::with_key_resolver(restarted.clone(), new_keyring);
        late_joiner.apply_update(vec![snapshot]).await;
        assert_eq!(
            restarted.lock().await.get_text("text").to_string(),
            "rotated"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn elo_default_iv_generation_is_random() {
        let doc = Arc::new(Mutex::new(LoroDoc::new()));
        let adaptor = EloDocAdaptor::new(doc, "kid", [7u8; 32]);

        let first = require_ok(
            adaptor.encode_elo_snapshot_container(b"first"),
            "OS randomness should be available",
        );
        let second = require_ok(
            adaptor.encode_elo_snapshot_container(b"second"),
            "OS randomness should be available",
        );

        let first_records = require_ok(
            protocol::elo::decode_elo_container(&first),
            "first container should decode",
        );
        let second_records = require_ok(
            protocol::elo::decode_elo_container(&second),
            "second container should decode",
        );
        let first_header = require_ok(
            protocol::elo::parse_elo_record_header(first_records[0]),
            "first header should parse",
        );
        let second_header = require_ok(
            protocol::elo::parse_elo_record_header(second_records[0]),
            "second header should parse",
        );
        let first_iv = match first_header.header {
            protocol::elo::EloHeader::Snapshot(header) => header.iv,
            _ => panic!("expected snapshot header"),
        };
        let second_iv = match second_header.header {
            protocol::elo::EloHeader::Snapshot(header) => header.iv,
            _ => panic!("expected snapshot header"),
        };

        assert_ne!(first_iv, [0; 12]);
        assert_ne!(second_iv, [0; 12]);
        assert_ne!(first_iv, second_iv);
    }

    #[test]
    fn elo_rejects_repeated_iv_from_compatibility_factory() {
        let doc = Arc::new(Mutex::new(LoroDoc::new()));
        let adaptor = EloDocAdaptor::new(doc, "kid", [7u8; 32])
            .with_iv_factory(Arc::new(|| [9; ELO_IV_LENGTH]));

        require_ok(
            adaptor.encode_elo_snapshot_container(b"first"),
            "first use of an IV should succeed",
        );
        let error = adaptor
            .encode_elo_snapshot_container(b"second")
            .expect_err("repeated IV must fail before encryption");
        assert_eq!(error, EloCryptoError::Encryption);
    }

    #[test]
    fn elo_iv_reuse_tracking_is_scoped_to_key_material() {
        let generator: EloIvGenerator = Arc::new(|| Ok([9; ELO_IV_LENGTH]));
        let used_ivs = Arc::new(StdMutex::new(HashSet::new()));
        require_ok(
            encode_elo_snapshot_container_with("k1", &[1; 32], &generator, &used_ivs, b"first"),
            "first key may use the IV",
        );
        require_ok(
            encode_elo_snapshot_container_with("k2", &[2; 32], &generator, &used_ivs, b"second"),
            "rotated key may independently use the IV",
        );
        assert_eq!(
            encode_elo_snapshot_container_with("k2", &[2; 32], &generator, &used_ivs, b"repeat",)
                .expect_err("the same key must not reuse an IV"),
            EloCryptoError::Encryption
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn elo_randomness_failure_is_reported_without_sending() {
        let doc = Arc::new(Mutex::new(LoroDoc::new()));
        let structured = Arc::new(StdMutex::new(Vec::new()));
        let mut adaptor = EloDocAdaptor::new(doc.clone(), "kid", [7u8; 32])
            .with_iv_generator(Arc::new(|| Err(getrandom::Error::UNSUPPORTED)))
            .with_error_handler({
                let structured = structured.clone();
                Arc::new(move |error| lock_unpoisoned(&structured).push(error))
            });

        let error = match adaptor.encode_elo_snapshot_container(b"plaintext") {
            Ok(_) => panic!("randomness failure must abort encryption"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            EloCryptoError::Randomness(error) if error == getrandom::Error::UNSUPPORTED
        ));

        let sent = Arc::new(StdMutex::new(Vec::new()));
        let reported = Arc::new(StdMutex::new(Vec::new()));
        adaptor
            .set_ctx(CrdtAdaptorContext {
                send_update: {
                    let sent = sent.clone();
                    Arc::new(move |update| lock_unpoisoned(&sent).push(update))
                },
                on_join_failed: Arc::new(|_| {}),
                on_import_error: {
                    let reported = reported.clone();
                    Arc::new(move |error, _| lock_unpoisoned(&reported).push(error))
                },
            })
            .await;
        {
            let doc = doc.lock().await;
            require_ok(
                doc.get_text("text").insert(0, "local update"),
                "local edit should succeed",
            );
            doc.commit();
        }
        adaptor
            .handle_join_ok(protocol::Permission::Write, Vec::new())
            .await;
        wait_for_recorded_len(&reported, 2).await;

        assert!(lock_unpoisoned(&sent).is_empty());
        let reported = lock_unpoisoned(&reported);
        assert_eq!(reported.len(), 2);
        assert!(reported
            .iter()
            .all(|error| error.contains("secure random IV generation failed")));
        let structured = lock_unpoisoned(&structured);
        assert_eq!(structured.len(), 2);
        assert!(structured
            .iter()
            .all(|error| error.kind == EloAdaptorErrorKind::EncryptFailed));
    }
}

type SharedAdaptor = Arc<Mutex<Box<dyn CrdtDocAdaptor + Send + Sync>>>;

#[derive(Clone)]
struct RegisteredAdaptor {
    adaptor: SharedAdaptor,
    auth: Vec<u8>,
}

type AdaptorRegistry = Arc<Mutex<HashMap<RoomKey, RegisteredAdaptor>>>;

#[derive(Clone)]
struct ConnectionWorker {
    tx: mpsc::UnboundedSender<Message>,
    rooms: Arc<Mutex<HashMap<RoomKey, RoomState>>>,
    pending: Arc<Mutex<PendingMap>>,
    adaptors: AdaptorRegistry,
    pre_join_buf: Arc<Mutex<HashMap<RoomKey, Vec<Vec<u8>>>>>,
    frag_batches: Arc<Mutex<HashMap<(RoomKey, protocol::BatchId), FragmentBatch>>>,
    next_batch_id: Arc<AtomicU64>,
    sent_batches: Arc<StdMutex<HashMap<(RoomKey, protocol::BatchId), Vec<Vec<u8>>>>>,
    config: Arc<ClientConfig>,
}

impl ConnectionWorker {
    fn new(
        tx: mpsc::UnboundedSender<Message>,
        rooms: Arc<Mutex<HashMap<RoomKey, RoomState>>>,
        pending: Arc<Mutex<PendingMap>>,
        adaptors: AdaptorRegistry,
        pre_join_buf: Arc<Mutex<HashMap<RoomKey, Vec<Vec<u8>>>>>,
        frag_batches: Arc<Mutex<HashMap<(RoomKey, protocol::BatchId), FragmentBatch>>>,
        next_batch_id: Arc<AtomicU64>,
        sent_batches: Arc<StdMutex<HashMap<(RoomKey, protocol::BatchId), Vec<Vec<u8>>>>>,
        config: Arc<ClientConfig>,
    ) -> Self {
        Self {
            tx,
            rooms,
            pending,
            adaptors,
            pre_join_buf,
            frag_batches,
            next_batch_id,
            sent_batches,
            config,
        }
    }

    fn spawn(self, mut stream: futures_util::stream::SplitStream<Ws>) {
        tokio::spawn(async move {
            while let Some(frame) = stream.next().await {
                match frame {
                    Ok(Message::Text(txt)) => {
                        self.handle_text(txt.to_string()).await;
                    }
                    Ok(Message::Binary(data)) => {
                        self.handle_binary(data.to_vec()).await;
                    }
                    Ok(Message::Ping(p)) => {
                        let _ = self.tx.send(Message::Pong(p));
                        let _ = self.tx.send(Message::Text("pong".into()));
                    }
                    Ok(Message::Close(_)) => break,
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("ws read error: {}", e);
                        break;
                    }
                }
            }
        });
    }

    async fn handle_text(&self, txt: String) {
        if txt == "ping" {
            let _ = self.tx.send(Message::Text("pong".into()));
        }
        // Ignore "pong" and any other text frames
    }

    async fn handle_binary(&self, data: Vec<u8>) {
        if let Some(msg) = try_decode(data.as_ref()) {
            self.handle_message(msg).await;
        }
    }

    async fn handle_message(&self, msg: ProtocolMessage) {
        let key = RoomKey {
            crdt: msg_crdt(&msg),
            room: msg_room_id(&msg),
        };
        match msg {
            ProtocolMessage::JoinResponseOk {
                permission,
                version,
                ..
            } => {
                let pending = { self.pending.lock().await.remove(&key) };
                if let Some(ch) = pending {
                    let _ = ch.send(JoinOutcome::Ok {
                        permission,
                        version,
                    });
                }
            }
            ProtocolMessage::JoinError {
                code,
                message,
                receiver_version,
                ..
            } => {
                let pending = { self.pending.lock().await.remove(&key) };
                if let Some(ch) = pending {
                    let _ = ch.send(JoinOutcome::Err {
                        code,
                        message: message.clone(),
                        receiver_version,
                    });
                }
                eprintln!("join error: {:?} - {}", code, message);
            }
            ProtocolMessage::DocUpdate { updates, .. } => {
                let adaptor = self
                    .adaptors
                    .lock()
                    .await
                    .get(&key)
                    .map(|registered| registered.adaptor.clone());
                if let Some(adaptor) = adaptor {
                    adaptor.lock().await.apply_update(updates).await;
                } else if let Some(doc) = self
                    .rooms
                    .lock()
                    .await
                    .get(&key)
                    .map(|state| state.doc.clone())
                {
                    let doc = doc.lock().await;
                    for u in updates {
                        let _ = doc.import(&u);
                    }
                } else {
                    let mut buf = self.pre_join_buf.lock().await;
                    buf.entry(key).or_default().extend(updates);
                }
            }
            ProtocolMessage::DocUpdateFragmentHeader {
                batch_id,
                fragment_count,
                total_size_bytes,
                ..
            } => {
                let declaration = usize::try_from(fragment_count)
                    .ok()
                    .zip(usize::try_from(total_size_bytes).ok())
                    .filter(|(count, total)| {
                        *count > 0
                            && *count <= MAX_FRAGMENTS_PER_BATCH
                            && *total > 0
                            && *total <= MAX_FRAGMENT_BATCH_BYTES
                    });
                let Some((fragment_count, total_size_bytes)) = declaration else {
                    self.send_fragment_ack(&key, batch_id, UpdateStatusCode::PayloadTooLarge);
                    return;
                };

                let mut map = self.frag_batches.lock().await;
                let batch_key = (key.clone(), batch_id);
                let existing_bytes = map
                    .get(&batch_key)
                    .map(|batch| batch.total_size_bytes)
                    .unwrap_or(0);
                let inflight_bytes = map
                    .values()
                    .map(|batch| batch.total_size_bytes)
                    .sum::<usize>();
                let next_count = map.len() + usize::from(!map.contains_key(&batch_key));
                let next_bytes = inflight_bytes
                    .saturating_sub(existing_bytes)
                    .saturating_add(total_size_bytes);
                if next_count > MAX_INFLIGHT_FRAGMENT_BATCHES
                    || next_bytes > MAX_INFLIGHT_FRAGMENT_BYTES
                {
                    drop(map);
                    self.send_fragment_ack(&key, batch_id, UpdateStatusCode::RateLimited);
                    return;
                }
                if let Some(existing) = map.remove(&batch_key) {
                    existing.timeout_active.store(false, Ordering::Release);
                }
                let timeout_active = Arc::new(AtomicBool::new(true));
                map.insert(
                    batch_key.clone(),
                    FragmentBatch {
                        fragment_count,
                        total_size_bytes,
                        slots: (0..fragment_count).map(|_| None).collect(),
                        received: 0,
                        received_bytes: 0,
                        timeout_active: timeout_active.clone(),
                    },
                );
                drop(map);

                let batches = self.frag_batches.clone();
                let key_clone = key.clone();
                let tx_timeout = self.tx.clone();
                let timeout = self.config.fragment_reassembly_timeout;
                tokio::spawn(async move {
                    tokio::time::sleep(timeout).await;
                    if !timeout_active.swap(false, Ordering::AcqRel) {
                        return;
                    }
                    let mut batches = batches.lock().await;
                    if batches.remove(&(key_clone.clone(), batch_id)).is_some() {
                        let ack = ProtocolMessage::Ack {
                            crdt: key_clone.crdt,
                            room_id: key_clone.room.clone(),
                            ref_id: batch_id,
                            status: UpdateStatusCode::FragmentTimeout,
                        };
                        if let Ok(data) = encode(&ack) {
                            let _ = tx_timeout.send(Message::Binary(data.into()));
                        }
                    }
                });
            }
            ProtocolMessage::DocUpdateFragment {
                batch_id,
                index,
                fragment,
                ..
            } => {
                let batch_key = (key.clone(), batch_id);
                let mut map = self.frag_batches.lock().await;
                let invalid = match map.get_mut(&batch_key) {
                    Some(batch) => match usize::try_from(index) {
                        Ok(index)
                            if index < batch.slots.len()
                                && batch.slots[index].is_none()
                                && fragment.len() <= protocol::MAX_MESSAGE_SIZE
                                && batch
                                    .received_bytes
                                    .checked_add(fragment.len())
                                    .is_some_and(|total| total <= batch.total_size_bytes) =>
                        {
                            batch.received_bytes += fragment.len();
                            batch.slots[index] = Some(fragment);
                            batch.received += 1;
                            false
                        }
                        _ => true,
                    },
                    None => {
                        drop(map);
                        self.send_fragment_ack(&key, batch_id, UpdateStatusCode::FragmentTimeout);
                        return;
                    }
                };
                if invalid {
                    if let Some(batch) = map.remove(&batch_key) {
                        batch.timeout_active.store(false, Ordering::Release);
                    }
                    drop(map);
                    self.send_fragment_ack(&key, batch_id, UpdateStatusCode::InvalidUpdate);
                    return;
                }

                let complete = map
                    .get(&batch_key)
                    .is_some_and(|batch| batch.received == batch.fragment_count);
                if !complete {
                    return;
                }
                let batch = map.remove(&batch_key).expect("completed batch exists");
                batch.timeout_active.store(false, Ordering::Release);
                if batch.received_bytes != batch.total_size_bytes {
                    drop(map);
                    self.send_fragment_ack(&key, batch_id, UpdateStatusCode::InvalidUpdate);
                    return;
                }
                let mut reassembled = Vec::with_capacity(batch.total_size_bytes);
                for slot in batch.slots {
                    let Some(fragment) = slot else {
                        drop(map);
                        self.send_fragment_ack(&key, batch_id, UpdateStatusCode::InvalidUpdate);
                        return;
                    };
                    reassembled.extend_from_slice(&fragment);
                }
                drop(map);
                let adaptor = self
                    .adaptors
                    .lock()
                    .await
                    .get(&key)
                    .map(|registered| registered.adaptor.clone());
                if let Some(adaptor) = adaptor {
                    adaptor.lock().await.apply_update(vec![reassembled]).await;
                } else if let Some(doc) = self
                    .rooms
                    .lock()
                    .await
                    .get(&key)
                    .map(|state| state.doc.clone())
                {
                    let doc = doc.lock().await;
                    let _ = doc.import(&reassembled);
                } else {
                    let mut buf = self.pre_join_buf.lock().await;
                    buf.entry(key).or_default().push(reassembled);
                }
            }
            ProtocolMessage::RoomError { code, message, .. } => {
                let registered = self.adaptors.lock().await.remove(&key);
                if let Some(registered) = &registered {
                    registered
                        .adaptor
                        .lock()
                        .await
                        .handle_room_error(code, &message)
                        .await;
                }

                // Always clear local state for this room; rejoin (if any) will register anew.
                self.cleanup_room(&key).await;
                eprintln!("room error {:?}: {}", code, message);

                if matches!(code, RoomErrorCode::RejoinSuggested) {
                    if let Some(RegisteredAdaptor { adaptor, auth }) = registered {
                        let room_name = key.room.clone();
                        let client = LoroWebsocketClient {
                            tx: self.tx.clone(),
                            rooms: self.rooms.clone(),
                            pending: self.pending.clone(),
                            adaptors: self.adaptors.clone(),
                            pre_join_buf: self.pre_join_buf.clone(),
                            next_batch_id: self.next_batch_id.clone(),
                            sent_batches: self.sent_batches.clone(),
                            config: self.config.clone(),
                        };
                        tokio::spawn(async move {
                            if let Err(err) = client
                                .join_with_shared_adaptor(&room_name, auth, adaptor)
                                .await
                            {
                                eprintln!("rejoin after RoomError failed: {}", err);
                            }
                        });
                    }
                }
            }
            ProtocolMessage::Ack { ref_id, status, .. } => {
                let sent_payloads = {
                    let mut map = self
                        .sent_batches
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    map.remove(&(key.clone(), ref_id))
                };

                let adaptor = self
                    .adaptors
                    .lock()
                    .await
                    .get(&key)
                    .map(|registered| registered.adaptor.clone());
                if let Some(adaptor) = adaptor {
                    let mut adaptor = adaptor.lock().await;
                    if status != UpdateStatusCode::Ok {
                        adaptor
                            .handle_update_error(
                                sent_payloads.clone().unwrap_or_default(),
                                status,
                                Some(format!("{:?}", status)),
                            )
                            .await;
                    }
                    adaptor.handle_ack(ref_id, status).await;
                } else if status != UpdateStatusCode::Ok {
                    eprintln!(
                        "ack status {:?} for {:?} ref {:?}",
                        status,
                        key.room,
                        ref_id.to_hex()
                    );
                }
            }
            ProtocolMessage::Leave { .. } | ProtocolMessage::JoinRequest { .. } => {}
        }
    }

    fn send_fragment_ack(
        &self,
        key: &RoomKey,
        batch_id: protocol::BatchId,
        status: UpdateStatusCode,
    ) {
        let ack = ProtocolMessage::Ack {
            crdt: key.crdt,
            room_id: key.room.clone(),
            ref_id: batch_id,
            status,
        };
        if let Ok(data) = encode(&ack) {
            let _ = self.tx.send(Message::Binary(data.into()));
        }
    }

    async fn cleanup_room(&self, key: &RoomKey) {
        if let Some(state) = self.rooms.lock().await.remove(key) {
            if let Some(sub) = state.sub {
                sub.unsubscribe();
            }
        }
        self.adaptors.lock().await.remove(key);
        self.pre_join_buf.lock().await.remove(key);
        self.pending.lock().await.remove(key);
        self.frag_batches
            .lock()
            .await
            .retain(|(room, _), _| room != key);
        self.sent_batches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|(room, _), _| room != key);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RoomKey {
    crdt: CrdtType,
    room: String,
}
impl Hash for RoomKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
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

struct RoomState {
    doc: Arc<Mutex<LoroDoc>>,
    sub: Option<loro::Subscription>,
}

enum JoinOutcome {
    Ok {
        permission: protocol::Permission,
        version: Vec<u8>,
    },
    Err {
        code: protocol::JoinErrorCode,
        message: String,
        receiver_version: Option<Vec<u8>>,
    },
}

type PendingMap = HashMap<RoomKey, oneshot::Sender<JoinOutcome>>;

/// A higher-level WebSocket client that manages rooms and applies updates to a LoroDoc.
#[derive(Clone)]
pub struct LoroWebsocketClient {
    tx: mpsc::UnboundedSender<Message>,
    rooms: Arc<Mutex<HashMap<RoomKey, RoomState>>>,
    // Join handshake results per room
    pending: Arc<Mutex<PendingMap>>,
    // Generic adaptor storage keyed by room
    adaptors: AdaptorRegistry,
    // Buffer updates received before room becomes active (mainly for %ELO)
    pre_join_buf: Arc<Mutex<HashMap<RoomKey, Vec<Vec<u8>>>>>,
    // For generating unique fragment batch ids
    next_batch_id: Arc<AtomicU64>,
    // Track outbound batches to surface update errors with original payloads
    sent_batches: Arc<StdMutex<HashMap<(RoomKey, protocol::BatchId), Vec<Vec<u8>>>>>,
    // Configurable knobs
    config: Arc<ClientConfig>,
}

impl LoroWebsocketClient {
    /// Connect and spawn reader/writer tasks with default config.
    pub async fn connect(url: &str) -> Result<Self, ClientError> {
        Self::connect_with_config(url, ClientConfig::default()).await
    }

    /// Connect and spawn reader/writer tasks with custom config.
    pub async fn connect_with_config(url: &str, config: ClientConfig) -> Result<Self, ClientError> {
        let (ws, _resp) = match connect_async(url).await {
            Ok(ok) => ok,
            Err(e) => {
                if let tokio_tungstenite::tungstenite::Error::Http(resp) = &e {
                    if resp.status()
                        == tokio_tungstenite::tungstenite::http::StatusCode::UNAUTHORIZED
                    {
                        return Err(ClientError::Unauthorized);
                    }
                }
                let s = e.to_string().to_lowercase();
                if s.contains("401") || s.contains("unauthorized") {
                    return Err(ClientError::Unauthorized);
                }
                return Err(ClientError::Ws(Box::new(e)));
            }
        };
        let (mut sink, stream) = ws.split();
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

        // Writer
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if sink.send(msg).await.is_err() {
                    break;
                }
            }
        });

        let rooms: Arc<Mutex<HashMap<RoomKey, RoomState>>> = Arc::new(Mutex::new(HashMap::new()));
        let pending: Arc<Mutex<PendingMap>> = Arc::new(Mutex::new(HashMap::new()));
        let adaptors_reader: AdaptorRegistry = Arc::new(Mutex::new(HashMap::new()));
        let pre_join_buf_reader: Arc<Mutex<HashMap<RoomKey, Vec<Vec<u8>>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let frag_batches_reader: Arc<Mutex<HashMap<(RoomKey, protocol::BatchId), FragmentBatch>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let batch_counter = Arc::new(AtomicU64::new(1));
        let sent_batches: Arc<StdMutex<HashMap<(RoomKey, protocol::BatchId), Vec<Vec<u8>>>>> =
            Arc::new(StdMutex::new(HashMap::new()));

        // Reader
        let cfg = Arc::new(config);
        ConnectionWorker::new(
            tx.clone(),
            rooms.clone(),
            pending.clone(),
            adaptors_reader.clone(),
            pre_join_buf_reader.clone(),
            frag_batches_reader,
            batch_counter.clone(),
            sent_batches.clone(),
            cfg.clone(),
        )
        .spawn(stream);

        Ok(Self {
            tx,
            rooms,
            pending,
            adaptors: adaptors_reader,
            pre_join_buf: pre_join_buf_reader,
            next_batch_id: batch_counter,
            sent_batches,
            config: cfg,
        })
    }

    /// Join a Loro room for the given document. Returns a handle for sending updates.
    pub async fn join_loro(
        &self,
        room_id: &str,
        doc: Arc<Mutex<LoroDoc>>,
    ) -> Result<LoroWebsocketClientRoom, ClientError> {
        let key = RoomKey {
            crdt: CrdtType::Loro,
            room: room_id.to_string(),
        };
        // Register room without subscription first
        self.rooms.lock().await.insert(
            key.clone(),
            RoomState {
                doc: doc.clone(),
                sub: None,
            },
        );

        let (tx_done, rx_done) = oneshot::channel::<JoinOutcome>();
        self.pending.lock().await.insert(key.clone(), tx_done);

        // Send join with local version/auth
        let local_version = doc.lock().await.oplog_vv().encode();
        let msg = ProtocolMessage::JoinRequest {
            crdt: CrdtType::Loro,
            room_id: key.room.clone(),
            auth: Vec::new(),
            version: local_version,
        };
        let data = encode(&msg).map_err(ClientError::Protocol)?;
        self.tx
            .send(Message::Binary(data.into()))
            .map_err(|_| ClientError::Protocol("send failed".into()))?;

        // Await join result
        match rx_done.await {
            Ok(JoinOutcome::Ok { permission, .. }) => {
                // Only subscribe to local updates if we have write permission
                if matches!(permission, protocol::Permission::Write) {
                    let tx2 = self.tx.clone();
                    let key2 = key.clone();
                    let batch_counter = self.next_batch_id.clone();
                    let sent_batches = self.sent_batches.clone();
                    let sub = {
                        let guard = doc.lock().await;
                        guard.subscribe_local_update(Box::new(move |bytes| {
                            let batch_id = protocol::BatchId(
                                batch_counter.fetch_add(1, Ordering::Relaxed).to_be_bytes(),
                            );
                            if let Ok(mut map) = sent_batches.lock() {
                                map.insert((key2.clone(), batch_id), vec![bytes.clone()]);
                            }
                            let msg = ProtocolMessage::DocUpdate {
                                crdt: key2.crdt,
                                room_id: key2.room.clone(),
                                updates: vec![bytes.clone()],
                                batch_id,
                            };
                            if let Ok(data) = encode(&msg) {
                                let _ = tx2.send(Message::Binary(data.into()));
                            }
                            true
                        }))
                    };
                    // Store subscription for cleanup
                    self.rooms.lock().await.insert(
                        key.clone(),
                        RoomState {
                            doc: doc.clone(),
                            sub: Some(sub),
                        },
                    );
                } else {
                    // Read-only: keep room without subscription
                    self.rooms.lock().await.insert(
                        key.clone(),
                        RoomState {
                            doc: doc.clone(),
                            sub: None,
                        },
                    );
                }
            }
            Ok(JoinOutcome::Err { code, message, .. }) => {
                // Remove room entry and return error
                self.rooms.lock().await.remove(&key);
                return Err(ClientError::Protocol(format!(
                    "join error: {:?} - {}",
                    code, message
                )));
            }
            Err(_) => {
                self.rooms.lock().await.remove(&key);
                return Err(ClientError::Protocol("join canceled".into()));
            }
        }

        Ok(LoroWebsocketClientRoom {
            inner: self.clone(),
            key,
        })
    }

    /// Send a keepalive ping.
    pub fn ping(&self) -> Result<(), ClientError> {
        self.tx
            .send(Message::Text("ping".into()))
            .map_err(|_| ClientError::Protocol("send failed".into()))
    }

    /// Generic join with a CRDT adaptor. Returns a room handle.
    pub async fn join_with_adaptor(
        &self,
        room_id: &str,
        adaptor: Box<dyn CrdtDocAdaptor + Send + Sync>,
    ) -> Result<LoroWebsocketClientRoom, ClientError> {
        self.join_with_adaptor_and_auth(room_id, Vec::new(), adaptor)
            .await
    }

    /// Generic join with a CRDT adaptor and application-defined join metadata.
    ///
    /// The authentication bytes are copied into every `JoinRequest`, including
    /// version-negotiation retries.
    pub async fn join_with_adaptor_and_auth(
        &self,
        room_id: &str,
        auth: Vec<u8>,
        adaptor: Box<dyn CrdtDocAdaptor + Send + Sync>,
    ) -> Result<LoroWebsocketClientRoom, ClientError> {
        self.join_with_shared_adaptor(room_id, auth, Arc::new(Mutex::new(adaptor)))
            .await
    }

    async fn join_with_shared_adaptor(
        &self,
        room_id: &str,
        auth: Vec<u8>,
        adaptor: SharedAdaptor,
    ) -> Result<LoroWebsocketClientRoom, ClientError> {
        let crdt_type = adaptor.lock().await.crdt_type();
        let key = RoomKey {
            crdt: crdt_type,
            room: room_id.to_string(),
        };

        // Register adaptor for this room, but not active until JoinResponseOk completes.
        // Construct adaptor context that sends updates (fragmenting if needed) and reports errors.
        let tx2 = self.tx.clone();
        let room_vec = key.room.clone();
        let crdt = key.crdt;
        let batch_counter = self.next_batch_id.clone();
        let cfg = self.config.clone();
        let sent_batches = self.sent_batches.clone();
        let room_key = key.clone();
        let send_update = move |upd: Vec<u8>| {
            // Leave headroom for envelope overhead using configured limits.
            let frag_limit = std::cmp::max(
                1usize,
                std::cmp::min(
                    cfg.fragment_limit_soft_max,
                    protocol::MAX_MESSAGE_SIZE.saturating_sub(cfg.fragment_limit_headroom),
                ),
            );

            let batch_id =
                protocol::BatchId(batch_counter.fetch_add(1, Ordering::Relaxed).to_be_bytes());

            if let Ok(mut map) = sent_batches.lock() {
                map.insert((room_key.clone(), batch_id), vec![upd.clone()]);
            }

            if upd.len() <= frag_limit {
                let msg = ProtocolMessage::DocUpdate {
                    crdt,
                    room_id: room_vec.clone(),
                    updates: vec![upd],
                    batch_id,
                };
                if let Ok(data) = encode(&msg) {
                    let _ = tx2.send(Message::Binary(data.into()));
                }
            } else {
                let total = upd.len();
                let n = total.div_ceil(frag_limit);
                // header
                let header = ProtocolMessage::DocUpdateFragmentHeader {
                    crdt,
                    room_id: room_vec.clone(),
                    batch_id,
                    fragment_count: n as u64,
                    total_size_bytes: total as u64,
                };
                if let Ok(data) = encode(&header) {
                    let _ = tx2.send(Message::Binary(data.into()));
                }
                // fragments
                for i in 0..n {
                    let start = i * frag_limit;
                    let end = ((i + 1) * frag_limit).min(total);
                    let frag = upd[start..end].to_vec();
                    let msg = ProtocolMessage::DocUpdateFragment {
                        crdt,
                        room_id: room_vec.clone(),
                        batch_id,
                        index: i as u64,
                        fragment: frag,
                    };
                    if let Ok(data) = encode(&msg) {
                        let _ = tx2.send(Message::Binary(data.into()));
                    }
                }
            }
        };

        let tx_err = self.tx.clone();
        let room_vec2 = key.room.clone();
        let crdt2 = key.crdt;
        let on_join_failed = move |reason: String| {
            let msg = ProtocolMessage::JoinError {
                crdt: crdt2,
                room_id: room_vec2.clone(),
                code: protocol::JoinErrorCode::AppError,
                message: reason,
                receiver_version: None,
                app_code: None,
            };
            if let Ok(data) = encode(&msg) {
                let _ = tx_err.send(Message::Binary(data.into()));
            }
        };
        let on_import_error = move |err: String, _data: Vec<Vec<u8>>| {
            eprintln!("import error in adaptor: {}", err);
        };

        adaptor
            .lock()
            .await
            .set_ctx(CrdtAdaptorContext {
                send_update: Arc::new(send_update),
                on_join_failed: Arc::new(on_join_failed),
                on_import_error: Arc::new(on_import_error),
            })
            .await;

        // Track to allow reader to route messages even before activation
        self.adaptors.lock().await.insert(
            key.clone(),
            RegisteredAdaptor {
                adaptor: adaptor.clone(),
                auth: auth.clone(),
            },
        );

        // Join with version negotiation on VersionUnknown
        let mut current_version = adaptor.lock().await.version().await;
        let mut tried_empty = false;
        loop {
            // Prepare pending and send JoinRequest
            let (tx_done, rx_done) = oneshot::channel::<JoinOutcome>();
            self.pending.lock().await.insert(key.clone(), tx_done);
            let msg = ProtocolMessage::JoinRequest {
                crdt: key.crdt,
                room_id: key.room.clone(),
                auth: auth.clone(),
                version: current_version.clone(),
            };
            let data = encode(&msg).map_err(ClientError::Protocol)?;
            self.tx
                .send(Message::Binary(data.into()))
                .map_err(|_| ClientError::Protocol("send failed".into()))?;

            match rx_done.await {
                Ok(JoinOutcome::Ok {
                    permission,
                    version: server_version,
                }) => {
                    let buffered = self.pre_join_buf.lock().await.remove(&key);
                    let mut adaptor = adaptor.lock().await;
                    if let Some(buf) = buffered {
                        adaptor.apply_update(buf).await;
                    }
                    adaptor.handle_join_ok(permission, server_version).await;
                    break;
                }
                Ok(JoinOutcome::Err {
                    code,
                    message,
                    receiver_version: _rv,
                }) => {
                    // Allow adaptor-specific error handling
                    let mut adaptor_guard = adaptor.lock().await;
                    adaptor_guard.handle_join_err(code, &message).await;
                    if code == protocol::JoinErrorCode::VersionUnknown {
                        if let Some(alt) = adaptor_guard
                            .get_alternative_version(&current_version)
                            .await
                        {
                            current_version = alt;
                            continue;
                        } else if !tried_empty {
                            current_version = Vec::new();
                            tried_empty = true;
                            continue;
                        }
                    }
                    self.adaptors.lock().await.remove(&key);
                    return Err(ClientError::Protocol(format!(
                        "join error: {:?} - {}",
                        code, message
                    )));
                }
                Err(_) => {
                    self.adaptors.lock().await.remove(&key);
                    return Err(ClientError::Protocol("join canceled".into()));
                }
            }
        }

        Ok(LoroWebsocketClientRoom {
            inner: self.clone(),
            key,
        })
    }

    /// Convenience: join a Loro room using LoroDocAdaptor.
    pub async fn join_loro_with_adaptor(
        &self,
        room_id: &str,
        doc: Arc<Mutex<LoroDoc>>,
    ) -> Result<LoroWebsocketClientRoom, ClientError> {
        let adaptor: Box<dyn CrdtDocAdaptor + Send + Sync> = Box::new(LoroDocAdaptor::new(doc));
        self.join_with_adaptor(room_id, adaptor).await
    }

    /// Join an %ELO room using an application-owned multi-key resolver.
    pub async fn join_elo_with_key_resolver(
        &self,
        room_id: &str,
        doc: Arc<Mutex<LoroDoc>>,
        key_resolver: Arc<dyn EloKeyResolver>,
    ) -> Result<LoroWebsocketClientRoom, ClientError> {
        let adaptor: Box<dyn CrdtDocAdaptor + Send + Sync> =
            Box::new(EloDocAdaptor::with_key_resolver(doc, key_resolver));
        self.join_with_adaptor(room_id, adaptor).await
    }

    /// Convenience: join an %ELO room using a fixed AES-256-GCM key.
    pub async fn join_elo_with_adaptor(
        &self,
        room_id: &str,
        doc: Arc<Mutex<LoroDoc>>,
        key_id: impl Into<String>,
        key: [u8; 32],
    ) -> Result<LoroWebsocketClientRoom, ClientError> {
        let adaptor: Box<dyn CrdtDocAdaptor + Send + Sync> =
            Box::new(EloDocAdaptor::new(doc, key_id, key));
        self.join_with_adaptor(room_id, adaptor).await
    }
}

/// Room handle providing helpers to send updates from a bound `LoroDoc`.
#[derive(Clone)]
pub struct LoroWebsocketClientRoom {
    inner: LoroWebsocketClient,
    key: RoomKey,
}

impl LoroWebsocketClientRoom {
    /// Retry ELO records retained because their key was unavailable.
    pub async fn retry_pending_encrypted_records(
        &self,
    ) -> Result<Option<EloRetryResult>, ClientError> {
        let adaptor = self
            .inner
            .adaptors
            .lock()
            .await
            .get(&self.key)
            .map(|registered| registered.adaptor.clone())
            .ok_or_else(|| ClientError::Protocol("room adaptor is unavailable".into()))?;
        let result = adaptor.lock().await.retry_pending_encrypted_records().await;
        Ok(result)
    }

    /// Publish a genuine ELO snapshot with the current active outbound key.
    pub async fn publish_elo_snapshot(&self) -> Result<bool, ClientError> {
        let adaptor = self
            .inner
            .adaptors
            .lock()
            .await
            .get(&self.key)
            .map(|registered| registered.adaptor.clone())
            .ok_or_else(|| ClientError::Protocol("room adaptor is unavailable".into()))?;
        let published = adaptor.lock().await.publish_elo_snapshot().await;
        Ok(published)
    }

    /// Send a `Leave` message for this room.
    pub async fn leave(&self) -> Result<(), ClientError> {
        let msg = ProtocolMessage::Leave {
            crdt: self.key.crdt,
            room_id: self.key.room.clone(),
        };
        let data = encode(&msg).map_err(ClientError::Protocol)?;
        self.inner
            .tx
            .send(Message::Binary(data.into()))
            .map_err(|_| ClientError::Protocol("send failed".into()))?;
        // Unsubscribe and remove room state
        if let Some(state) = self.inner.rooms.lock().await.remove(&self.key) {
            if let Some(sub) = state.sub {
                sub.unsubscribe();
            }
        }
        // Drop adaptor
        self.inner.adaptors.lock().await.remove(&self.key);
        if let Ok(mut map) = self.inner.sent_batches.lock() {
            map.retain(|(room, _), _| room != &self.key);
        }
        Ok(())
    }
}

fn msg_crdt(msg: &ProtocolMessage) -> CrdtType {
    match msg {
        ProtocolMessage::JoinRequest { crdt, .. }
        | ProtocolMessage::JoinResponseOk { crdt, .. }
        | ProtocolMessage::JoinError { crdt, .. }
        | ProtocolMessage::DocUpdate { crdt, .. }
        | ProtocolMessage::DocUpdateFragmentHeader { crdt, .. }
        | ProtocolMessage::DocUpdateFragment { crdt, .. }
        | ProtocolMessage::RoomError { crdt, .. }
        | ProtocolMessage::Ack { crdt, .. }
        | ProtocolMessage::Leave { crdt, .. } => *crdt,
    }
}

fn msg_room_id(msg: &ProtocolMessage) -> String {
    match msg {
        ProtocolMessage::JoinRequest { room_id, .. }
        | ProtocolMessage::JoinResponseOk { room_id, .. }
        | ProtocolMessage::JoinError { room_id, .. }
        | ProtocolMessage::DocUpdate { room_id, .. }
        | ProtocolMessage::DocUpdateFragmentHeader { room_id, .. }
        | ProtocolMessage::DocUpdateFragment { room_id, .. }
        | ProtocolMessage::RoomError { room_id, .. }
        | ProtocolMessage::Ack { room_id, .. }
        | ProtocolMessage::Leave { room_id, .. } => room_id.clone(),
    }
}

// --- Fragment reassembly holder ---
struct FragmentBatch {
    fragment_count: usize,
    total_size_bytes: usize,
    slots: Vec<Option<Vec<u8>>>,
    received: usize,
    received_bytes: usize,
    timeout_active: Arc<AtomicBool>,
}

// --- Generic CRDT adaptor trait and context ---
#[async_trait::async_trait]
pub trait CrdtDocAdaptor {
    fn crdt_type(&self) -> CrdtType;
    async fn version(&self) -> Vec<u8>;
    async fn set_ctx(&mut self, ctx: CrdtAdaptorContext);
    async fn handle_join_ok(&mut self, permission: protocol::Permission, version: Vec<u8>);
    async fn apply_update(&mut self, updates: Vec<Vec<u8>>);
    async fn handle_ack(&mut self, _ref_id: protocol::BatchId, _status: UpdateStatusCode) {}
    async fn handle_update_error(
        &mut self,
        _updates: Vec<Vec<u8>>,
        _status: UpdateStatusCode,
        _reason: Option<String>,
    ) {
    }
    async fn handle_room_error(&mut self, _code: RoomErrorCode, _message: &str) {}
    async fn handle_join_err(&mut self, _code: protocol::JoinErrorCode, _message: &str) {}
    async fn get_alternative_version(&mut self, _current: &[u8]) -> Option<Vec<u8>> {
        None
    }
    async fn retry_pending_encrypted_records(&mut self) -> Option<EloRetryResult> {
        None
    }
    async fn publish_elo_snapshot(&mut self) -> bool {
        false
    }
}

pub struct CrdtAdaptorContext {
    pub send_update: Arc<dyn Fn(Vec<u8>) + Send + Sync>,
    pub on_join_failed: Arc<dyn Fn(String) + Send + Sync>,
    pub on_import_error: Arc<dyn Fn(String, Vec<Vec<u8>>) + Send + Sync>,
}

// --- LoroDocAdaptor: plaintext Loro ---
pub struct LoroDocAdaptor {
    doc: Arc<Mutex<LoroDoc>>,
    sub: Option<loro::Subscription>,
    ctx: Option<CrdtAdaptorContext>,
}

impl LoroDocAdaptor {
    pub fn new(doc: Arc<Mutex<LoroDoc>>) -> Self {
        Self {
            doc,
            sub: None,
            ctx: None,
        }
    }
}

#[async_trait::async_trait]
impl CrdtDocAdaptor for LoroDocAdaptor {
    fn crdt_type(&self) -> CrdtType {
        CrdtType::Loro
    }

    async fn version(&self) -> Vec<u8> {
        self.doc.lock().await.oplog_vv().encode()
    }

    async fn set_ctx(&mut self, ctx: CrdtAdaptorContext) {
        self.ctx = Some(CrdtAdaptorContext {
            send_update: ctx.send_update.clone(),
            on_join_failed: ctx.on_join_failed.clone(),
            on_import_error: ctx.on_import_error.clone(),
        });
        let doc = self.doc.clone();
        let send = ctx.send_update.clone();
        // Subscribe to local updates and forward
        let sub = {
            let guard = doc.lock().await;
            guard.subscribe_local_update(Box::new(move |bytes| {
                (send)(bytes.clone());
                true
            }))
        };
        self.sub = Some(sub);
    }

    async fn handle_join_ok(&mut self, _permission: protocol::Permission, version: Vec<u8>) {
        // Minimal behavior: if server provides no version, send a snapshot
        if version.is_empty() {
            if let Ok(pt) = self.doc.lock().await.export(loro::ExportMode::Snapshot) {
                if let Some(ctx) = &self.ctx {
                    (ctx.send_update)(pt);
                }
            }
        }
    }

    async fn apply_update(&mut self, updates: Vec<Vec<u8>>) {
        let guard = self.doc.lock().await;
        for u in updates {
            let _ = guard.import(&u);
        }
    }
}

impl Drop for LoroDocAdaptor {
    fn drop(&mut self) {
        if let Some(sub) = self.sub.take() {
            sub.unsubscribe();
        }
    }
}

// --- EloDocAdaptor: E2EE Loro ---
const ELO_IV_LENGTH: usize = 12;

/// A key selected by the application for an ELO record.
#[derive(Clone, PartialEq, Eq)]
pub struct EloResolvedKey {
    pub key_id: String,
    pub key: [u8; 32],
}

impl std::fmt::Debug for EloResolvedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EloResolvedKey")
            .field("key_id", &self.key_id)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// Application-owned key lookup. `None` selects the active outbound key.
#[async_trait::async_trait]
pub trait EloKeyResolver: Send + Sync {
    async fn resolve_key(&self, key_id: Option<&str>) -> Result<Option<EloResolvedKey>, String>;
}

#[derive(Default)]
struct EloKeyringState {
    active_key_id: Option<String>,
    keys: HashMap<String, [u8; 32]>,
}

/// In-memory keyring that retains historical read keys when the active key changes.
#[derive(Clone, Default)]
pub struct EloKeyring {
    state: Arc<StdMutex<EloKeyringState>>,
}

impl EloKeyring {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_key(&self, key_id: impl Into<String>, key: [u8; 32]) -> Result<(), String> {
        let key_id = key_id.into();
        if key_id.len() > 64 {
            return Err("ELO key ID must be at most 64 UTF-8 bytes".to_string());
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(existing) = state.keys.get(&key_id) {
            return if existing == &key {
                Ok(())
            } else {
                Err(format!("ELO key ID already exists: {key_id}"))
            };
        }
        state.keys.insert(key_id, key);
        Ok(())
    }

    pub fn remove_key(&self, key_id: &str) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.active_key_id.as_deref() == Some(key_id) {
            state.active_key_id = None;
        }
        state.keys.remove(key_id).is_some()
    }

    pub fn set_active_key(&self, key_id: &str) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.keys.contains_key(key_id) {
            return Err(format!("unknown ELO key ID: {key_id}"));
        }
        state.active_key_id = Some(key_id.to_string());
        Ok(())
    }
}

#[async_trait::async_trait]
impl EloKeyResolver for EloKeyring {
    async fn resolve_key(&self, key_id: Option<&str>) -> Result<Option<EloResolvedKey>, String> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let selected = match key_id.or(state.active_key_id.as_deref()) {
            Some(selected) => selected,
            None => return Ok(None),
        };
        Ok(state.keys.get(selected).copied().map(|key| EloResolvedKey {
            key_id: selected.to_string(),
            key,
        }))
    }
}

struct FixedEloKeyResolver {
    key: EloResolvedKey,
}

#[async_trait::async_trait]
impl EloKeyResolver for FixedEloKeyResolver {
    async fn resolve_key(&self, key_id: Option<&str>) -> Result<Option<EloResolvedKey>, String> {
        if key_id.is_some_and(|requested| requested != self.key.key_id) {
            return Ok(None);
        }
        Ok(Some(self.key.clone()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EloAdaptorErrorKind {
    UnknownKey,
    DecryptFailed,
    MalformedRecord,
    ImportFailed,
    EncryptFailed,
    PendingEvicted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EloRecordMetadata {
    pub kind: protocol::elo::EloRecordKind,
    pub key_id: String,
    pub peer_id: Option<Vec<u8>>,
    pub start: Option<u64>,
    pub end: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EloAdaptorError {
    pub kind: EloAdaptorErrorKind,
    pub record: Option<EloRecordMetadata>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EloPendingLimits {
    pub max_records: usize,
    pub max_bytes: usize,
}

impl Default for EloPendingLimits {
    fn default() -> Self {
        Self {
            max_records: 128,
            max_bytes: 8 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EloRetryResult {
    pub attempted: usize,
    pub imported: usize,
    pub remaining: usize,
}

type EloIvGenerator = Arc<dyn Fn() -> Result<[u8; ELO_IV_LENGTH], getrandom::Error> + Send + Sync>;

/// A local failure that prevents an encrypted ELO record from being emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EloCryptoError {
    /// The operating system could not provide a fresh IV.
    Randomness(getrandom::Error),
    /// Record encryption could not safely proceed.
    Encryption,
}

impl std::fmt::Display for EloCryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EloCryptoError::Randomness(error) => {
                write!(f, "secure random IV generation failed: {error}")
            }
            EloCryptoError::Encryption => write!(f, "ELO record encryption failed"),
        }
    }
}

impl std::error::Error for EloCryptoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            EloCryptoError::Randomness(error) => Some(error),
            EloCryptoError::Encryption => None,
        }
    }
}

fn secure_random_iv() -> Result<[u8; ELO_IV_LENGTH], getrandom::Error> {
    let mut iv = [0; ELO_IV_LENGTH];
    getrandom::fill(&mut iv)?;
    Ok(iv)
}

type EloUsedIvs = Arc<StdMutex<HashSet<([u8; 32], [u8; ELO_IV_LENGTH])>>>;
type EloWorkerActivity = Arc<StdMutex<bool>>;

struct EloWorkerFailure {
    kind: EloAdaptorErrorKind,
    message: String,
}

fn emit_elo_worker_result(
    active: &EloWorkerActivity,
    send: &Arc<dyn Fn(Vec<u8>) + Send + Sync>,
    on_error: &Arc<dyn Fn(String, Vec<Vec<u8>>) + Send + Sync>,
    error_handler: &Arc<dyn Fn(EloAdaptorError) + Send + Sync>,
    result: Result<Vec<u8>, EloWorkerFailure>,
    _source: Vec<Vec<u8>>,
) -> bool {
    let active = active
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !*active {
        return false;
    }
    match result {
        Ok(container) => {
            (send)(container);
            true
        }
        Err(error) => {
            (error_handler)(EloAdaptorError {
                kind: error.kind,
                record: None,
                message: error.message.clone(),
            });
            (on_error)(error.message, Vec::new());
            false
        }
    }
}

fn next_unique_iv(
    key: &[u8; 32],
    iv_generator: &EloIvGenerator,
    used_ivs: &EloUsedIvs,
) -> Result<[u8; ELO_IV_LENGTH], EloCryptoError> {
    for _ in 0..4 {
        let iv = iv_generator().map_err(EloCryptoError::Randomness)?;
        if used_ivs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert((*key, iv))
        {
            return Ok(iv);
        }
    }
    Err(EloCryptoError::Encryption)
}

fn encrypt_elo_record(
    key: &[u8; 32],
    iv: &[u8; ELO_IV_LENGTH],
    header_bytes: Vec<u8>,
    plaintext: &[u8],
) -> Result<Vec<u8>, EloCryptoError> {
    use protocol::bytes::BytesWriter;

    let cipher = aes_gcm::Aes256Gcm::new(key.into());
    let ct = cipher
        .encrypt(
            aes_gcm::Nonce::from_slice(iv),
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: &header_bytes,
            },
        )
        .map_err(|_| EloCryptoError::Encryption)?;
    let mut record = BytesWriter::new();
    record.push_bytes(&header_bytes);
    record.push_var_bytes(&ct);
    Ok(record.finalize())
}

fn encode_elo_container(records: &[Vec<u8>]) -> Vec<u8> {
    use protocol::bytes::BytesWriter;

    let mut container = BytesWriter::new();
    container.push_uleb128(records.len() as u64);
    for record in records {
        container.push_var_bytes(record);
    }
    container.finalize()
}

fn encode_elo_snapshot_container_with_vv(
    key_id: &str,
    key: &[u8; 32],
    iv_generator: &EloIvGenerator,
    used_ivs: &EloUsedIvs,
    vv: &[(Vec<u8>, u64)],
    plaintext: &[u8],
) -> Result<Vec<u8>, EloCryptoError> {
    use protocol::bytes::BytesWriter;

    let iv = next_unique_iv(key, iv_generator, used_ivs)?;
    let mut header = BytesWriter::new();
    header.push_byte(protocol::elo::EloRecordKind::Snapshot as u8);
    header.push_uleb128(vv.len() as u64);
    for (peer_id, counter) in vv {
        header.push_var_bytes(peer_id);
        header.push_uleb128(*counter);
    }
    header.push_var_string(key_id);
    header.push_var_bytes(&iv);
    let record = encrypt_elo_record(key, &iv, header.finalize(), plaintext)?;
    Ok(encode_elo_container(&[record]))
}

#[cfg(test)]
fn encode_elo_snapshot_container_with(
    key_id: &str,
    key: &[u8; 32],
    iv_generator: &EloIvGenerator,
    used_ivs: &EloUsedIvs,
    plaintext: &[u8],
) -> Result<Vec<u8>, EloCryptoError> {
    encode_elo_snapshot_container_with_vv(key_id, key, iv_generator, used_ivs, &[], plaintext)
}

fn encode_canonical_delta_plaintext(blob: &[u8]) -> Vec<u8> {
    use protocol::bytes::BytesWriter;

    let mut plaintext = BytesWriter::new();
    plaintext.push_uleb128(1);
    plaintext.push_var_bytes(blob);
    plaintext.finalize()
}

fn decode_canonical_delta_plaintext(plaintext: &[u8]) -> Result<Vec<&[u8]>, String> {
    use protocol::bytes::BytesReader;

    const MAX_DELTA_BLOBS: usize = 1024;
    let mut reader = BytesReader::new(plaintext);
    let count = usize::try_from(reader.read_uleb128()?)
        .map_err(|_| "ELO DeltaSpan blob count is too large".to_string())?;
    if count > MAX_DELTA_BLOBS {
        return Err("ELO DeltaSpan blob count exceeds the supported limit".to_string());
    }
    let mut blobs = Vec::with_capacity(count);
    for _ in 0..count {
        blobs.push(reader.read_var_bytes()?);
    }
    if reader.remaining() != 0 {
        return Err("ELO DeltaSpan plaintext has trailing bytes".to_string());
    }
    Ok(blobs)
}

fn snapshot_version_entries(vv: &loro::VersionVector) -> Result<Vec<(Vec<u8>, u64)>, String> {
    let mut entries = vv
        .iter()
        .map(|(peer, counter)| {
            let counter = u64::try_from(*counter)
                .map_err(|_| format!("negative Loro counter for peer {peer}"))?;
            Ok((peer.to_string().into_bytes(), counter))
        })
        .collect::<Result<Vec<_>, String>>()?;
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(entries)
}

fn encode_elo_delta_container_with(
    doc: &LoroDoc,
    key_id: &str,
    key: &[u8; 32],
    iv_generator: &EloIvGenerator,
    used_ivs: &EloUsedIvs,
    local_blob: &[u8],
) -> Result<Vec<u8>, String> {
    use protocol::bytes::BytesWriter;

    let metadata = LoroDoc::decode_import_blob_meta(local_blob, true)
        .map_err(|error| format!("cannot inspect local Loro update metadata: {error}"))?;
    let mut spans = Vec::new();
    for (peer, end) in metadata.partial_end_vv.iter() {
        let start = metadata.partial_start_vv.get(peer).copied().unwrap_or(0);
        if *end > start {
            spans.push((*peer, start, *end));
        }
    }
    spans.sort_by_key(|(peer, _, _)| peer.to_string());
    if spans.is_empty() {
        return Err("local Loro update contains no forward peer interval".to_string());
    }

    let mut records = Vec::with_capacity(spans.len());
    for (peer, start, end) in spans {
        let start_u64 = u64::try_from(start)
            .map_err(|_| format!("negative Loro start counter for peer {peer}"))?;
        let end_u64 =
            u64::try_from(end).map_err(|_| format!("negative Loro end counter for peer {peer}"))?;
        let exact_update = doc
            .export(loro::ExportMode::updates_in_range(vec![loro::IdSpan::new(
                peer, start, end,
            )]))
            .map_err(|error| format!("cannot export Loro range {peer}[{start},{end}): {error}"))?;
        let plaintext = encode_canonical_delta_plaintext(&exact_update);
        let iv = next_unique_iv(key, iv_generator, used_ivs).map_err(|error| error.to_string())?;
        let mut header = BytesWriter::new();
        header.push_byte(protocol::elo::EloRecordKind::DeltaSpan as u8);
        header.push_var_bytes(peer.to_string().as_bytes());
        header.push_uleb128(start_u64);
        header.push_uleb128(end_u64);
        header.push_var_string(key_id);
        header.push_var_bytes(&iv);
        records.push(
            encrypt_elo_record(key, &iv, header.finalize(), &plaintext)
                .map_err(|error| error.to_string())?,
        );
    }
    Ok(encode_elo_container(&records))
}

enum EloWorkerCommand {
    LocalUpdate(Vec<u8>),
    Joined(protocol::Permission),
    PublishSnapshot(oneshot::Sender<bool>),
}

struct EloWorkerContext {
    doc: Arc<Mutex<LoroDoc>>,
    key_resolver: Arc<dyn EloKeyResolver>,
    iv_generator: EloIvGenerator,
    used_ivs: EloUsedIvs,
    active: EloWorkerActivity,
    send: Arc<dyn Fn(Vec<u8>) + Send + Sync>,
    on_error: Arc<dyn Fn(String, Vec<Vec<u8>>) + Send + Sync>,
    error_handler: Arc<dyn Fn(EloAdaptorError) + Send + Sync>,
}

impl EloWorkerContext {
    async fn resolve_outbound_key(&self) -> Result<EloResolvedKey, EloWorkerFailure> {
        let key = self
            .key_resolver
            .resolve_key(None)
            .await
            .map_err(|error| EloWorkerFailure {
                kind: EloAdaptorErrorKind::UnknownKey,
                message: format!("failed to resolve the active outbound ELO key: {error}"),
            })?
            .ok_or_else(|| EloWorkerFailure {
                kind: EloAdaptorErrorKind::UnknownKey,
                message: "no active outbound ELO key is available".to_string(),
            })?;
        if key.key_id.len() > 64 {
            return Err(EloWorkerFailure {
                kind: EloAdaptorErrorKind::EncryptFailed,
                message: "ELO key ID must be at most 64 UTF-8 bytes".to_string(),
            });
        }
        Ok(key)
    }

    async fn process_update(&self, blob: Vec<u8>) -> bool {
        let result = match self.resolve_outbound_key().await {
            Ok(key) => {
                let doc = self.doc.lock().await;
                encode_elo_delta_container_with(
                    &doc,
                    &key.key_id,
                    &key.key,
                    &self.iv_generator,
                    &self.used_ivs,
                    &blob,
                )
                .map_err(|message| EloWorkerFailure {
                    kind: EloAdaptorErrorKind::EncryptFailed,
                    message,
                })
            }
            Err(error) => Err(error),
        };
        emit_elo_worker_result(
            &self.active,
            &self.send,
            &self.on_error,
            &self.error_handler,
            result,
            vec![blob],
        )
    }

    async fn process_snapshot(&self) -> bool {
        let key = self.resolve_outbound_key().await;
        let snapshot = {
            let doc = self.doc.lock().await;
            doc.export(loro::ExportMode::Snapshot)
                .map(|plaintext| (doc.oplog_vv(), plaintext))
                .map_err(|error| EloWorkerFailure {
                    kind: EloAdaptorErrorKind::EncryptFailed,
                    message: format!("cannot export Loro join snapshot: {error}"),
                })
        };
        let result = key.and_then(|key| {
            snapshot.and_then(|(vv, plaintext)| {
                let entries =
                    snapshot_version_entries(&vv).map_err(|message| EloWorkerFailure {
                        kind: EloAdaptorErrorKind::EncryptFailed,
                        message,
                    })?;
                encode_elo_snapshot_container_with_vv(
                    &key.key_id,
                    &key.key,
                    &self.iv_generator,
                    &self.used_ivs,
                    &entries,
                    &plaintext,
                )
                .map_err(|error| EloWorkerFailure {
                    kind: EloAdaptorErrorKind::EncryptFailed,
                    message: error.to_string(),
                })
            })
        });
        emit_elo_worker_result(
            &self.active,
            &self.send,
            &self.on_error,
            &self.error_handler,
            result,
            Vec::new(),
        )
    }

    fn spawn(
        self,
        mut receiver: mpsc::UnboundedReceiver<EloWorkerCommand>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut permission = None;
            let mut pending = VecDeque::new();
            while let Some(command) = receiver.recv().await {
                match command {
                    EloWorkerCommand::LocalUpdate(blob) => match permission {
                        Some(protocol::Permission::Write) => {
                            self.process_update(blob).await;
                        }
                        Some(protocol::Permission::Read) => {}
                        None => pending.push_back(blob),
                    },
                    EloWorkerCommand::Joined(new_permission) => {
                        permission = Some(new_permission);
                        if matches!(new_permission, protocol::Permission::Write) {
                            while let Some(blob) = pending.pop_front() {
                                self.process_update(blob).await;
                            }
                            self.process_snapshot().await;
                        } else {
                            pending.clear();
                        }
                    }
                    EloWorkerCommand::PublishSnapshot(done) => {
                        let published = if matches!(permission, Some(protocol::Permission::Write)) {
                            self.process_snapshot().await
                        } else {
                            false
                        };
                        let _ = done.send(published);
                    }
                }
            }
        })
    }
}

struct PendingEloRecord {
    record: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EloImportOutcome {
    Imported,
    UnknownKey,
    Failed,
}

struct DecryptedEloRecord {
    metadata: EloRecordMetadata,
    blobs: Vec<Vec<u8>>,
    source: Vec<u8>,
}

enum EloDecryptOutcome {
    Decrypted(DecryptedEloRecord),
    UnknownKey,
    Failed,
}

fn elo_record_metadata(header: &protocol::elo::EloHeader) -> EloRecordMetadata {
    match header {
        protocol::elo::EloHeader::Delta(header) => EloRecordMetadata {
            kind: protocol::elo::EloRecordKind::DeltaSpan,
            key_id: header.key_id.clone(),
            peer_id: Some(header.peer_id.clone()),
            start: Some(header.start),
            end: Some(header.end),
        },
        protocol::elo::EloHeader::Snapshot(header) => EloRecordMetadata {
            kind: protocol::elo::EloRecordKind::Snapshot,
            key_id: header.key_id.clone(),
            peer_id: None,
            start: None,
            end: None,
        },
    }
}

/// Experimental %ELO adaptor with application key resolution and retryable imports.
pub struct EloDocAdaptor {
    doc: Arc<Mutex<LoroDoc>>,
    ctx: Option<CrdtAdaptorContext>,
    key_resolver: Arc<dyn EloKeyResolver>,
    #[cfg(test)]
    compatibility_key: Option<EloResolvedKey>,
    iv_generator: EloIvGenerator,
    used_ivs: EloUsedIvs,
    pending_limits: EloPendingLimits,
    pending_records: VecDeque<PendingEloRecord>,
    pending_bytes: usize,
    error_handler: Arc<dyn Fn(EloAdaptorError) + Send + Sync>,
    worker_active: EloWorkerActivity,
    worker_tx: Option<mpsc::UnboundedSender<EloWorkerCommand>>,
    worker: Option<tokio::task::JoinHandle<()>>,
    sub: Option<loro::Subscription>,
}

impl EloDocAdaptor {
    /// Fixed-key compatibility constructor. Incoming records with other key IDs are unknown.
    pub fn new(doc: Arc<Mutex<LoroDoc>>, key_id: impl Into<String>, key: [u8; 32]) -> Self {
        let key = EloResolvedKey {
            key_id: key_id.into(),
            key,
        };
        let resolver = Arc::new(FixedEloKeyResolver { key: key.clone() });
        Self::with_resolver_and_compatibility_key(doc, resolver, Some(key))
    }

    pub fn with_key_resolver(
        doc: Arc<Mutex<LoroDoc>>,
        key_resolver: Arc<dyn EloKeyResolver>,
    ) -> Self {
        Self::with_resolver_and_compatibility_key(doc, key_resolver, None)
    }

    fn with_resolver_and_compatibility_key(
        doc: Arc<Mutex<LoroDoc>>,
        key_resolver: Arc<dyn EloKeyResolver>,
        _compatibility_key: Option<EloResolvedKey>,
    ) -> Self {
        Self {
            doc,
            ctx: None,
            key_resolver,
            #[cfg(test)]
            compatibility_key: _compatibility_key,
            iv_generator: Arc::new(secure_random_iv),
            used_ivs: Arc::new(StdMutex::new(HashSet::new())),
            pending_limits: EloPendingLimits::default(),
            pending_records: VecDeque::new(),
            pending_bytes: 0,
            error_handler: Arc::new(|_| {}),
            worker_active: Arc::new(StdMutex::new(false)),
            worker_tx: None,
            worker: None,
            sub: None,
        }
    }

    pub fn with_pending_limits(mut self, limits: EloPendingLimits) -> Self {
        self.pending_limits = limits;
        self
    }

    pub fn with_error_handler(
        mut self,
        handler: Arc<dyn Fn(EloAdaptorError) + Send + Sync>,
    ) -> Self {
        self.error_handler = handler;
        self
    }

    pub fn pending_encrypted_record_count(&self) -> usize {
        self.pending_records.len()
    }

    pub async fn retry_pending_encrypted_records(&mut self) -> EloRetryResult {
        let pending = std::mem::take(&mut self.pending_records);
        let attempted = pending.len();
        self.pending_bytes = 0;
        let mut imported = 0;
        for pending_record in pending {
            match self.import_elo_record(&pending_record.record, false).await {
                EloImportOutcome::Imported => imported += 1,
                EloImportOutcome::UnknownKey => {
                    self.enqueue_pending_record(pending_record.record, false);
                }
                EloImportOutcome::Failed => {}
            }
        }
        EloRetryResult {
            attempted,
            imported,
            remaining: self.pending_records.len(),
        }
    }

    /// Queue a genuine snapshot using the currently active outbound key.
    pub async fn publish_snapshot(&mut self) -> bool {
        let (done_tx, done_rx) = oneshot::channel();
        let queued = self.worker_tx.as_ref().is_some_and(|worker| {
            worker
                .send(EloWorkerCommand::PublishSnapshot(done_tx))
                .is_ok()
        });
        if queued {
            done_rx.await.unwrap_or(false)
        } else {
            self.report_error(
                EloAdaptorErrorKind::EncryptFailed,
                None,
                "ELO update worker is unavailable".to_string(),
                Vec::new(),
            );
            false
        }
    }

    fn report_error(
        &self,
        kind: EloAdaptorErrorKind,
        record: Option<EloRecordMetadata>,
        message: String,
        _source: Vec<Vec<u8>>,
    ) {
        (self.error_handler)(EloAdaptorError {
            kind,
            record,
            message: message.clone(),
        });
        if let Some(ctx) = &self.ctx {
            (ctx.on_import_error)(message, Vec::new());
        }
    }

    fn enqueue_pending_record(&mut self, record: Vec<u8>, report_eviction: bool) -> bool {
        if self
            .pending_records
            .iter()
            .any(|pending| pending.record == record)
        {
            return false;
        }
        self.pending_bytes = self.pending_bytes.saturating_add(record.len());
        self.pending_records.push_back(PendingEloRecord { record });
        while self.pending_records.len() > self.pending_limits.max_records
            || self.pending_bytes > self.pending_limits.max_bytes
        {
            let Some(evicted) = self.pending_records.pop_front() else {
                break;
            };
            self.pending_bytes = self.pending_bytes.saturating_sub(evicted.record.len());
            if report_eviction {
                let metadata = protocol::elo::parse_elo_record_header(&evicted.record)
                    .ok()
                    .map(|parsed| elo_record_metadata(&parsed.header));
                self.report_error(
                    EloAdaptorErrorKind::PendingEvicted,
                    metadata,
                    "pending encrypted ELO record evicted by configured bounds".to_string(),
                    vec![evicted.record],
                );
            }
        }
        true
    }

    async fn import_elo_record(&mut self, record: &[u8], queue_unknown: bool) -> EloImportOutcome {
        match self.decrypt_elo_record(record, queue_unknown).await {
            EloDecryptOutcome::Decrypted(record) => {
                if self.import_decrypted_records(&[record]).await {
                    EloImportOutcome::Imported
                } else {
                    EloImportOutcome::Failed
                }
            }
            EloDecryptOutcome::UnknownKey => EloImportOutcome::UnknownKey,
            EloDecryptOutcome::Failed => EloImportOutcome::Failed,
        }
    }

    async fn decrypt_elo_record(
        &mut self,
        record: &[u8],
        queue_unknown: bool,
    ) -> EloDecryptOutcome {
        let parsed = match protocol::elo::parse_elo_record_header(record) {
            Ok(parsed) => parsed,
            Err(error) => {
                self.report_error(
                    EloAdaptorErrorKind::MalformedRecord,
                    None,
                    format!("malformed ELO record: {error}"),
                    vec![record.to_vec()],
                );
                return EloDecryptOutcome::Failed;
            }
        };
        let metadata = elo_record_metadata(&parsed.header);
        let (resolved, resolution_error) =
            match self.key_resolver.resolve_key(Some(&metadata.key_id)).await {
                Ok(Some(key)) if key.key_id == metadata.key_id => (Some(key), None),
                Ok(Some(key)) => (
                    None,
                    Some(format!(
                        "ELO resolver returned key ID {} for requested ID {}",
                        key.key_id, metadata.key_id
                    )),
                ),
                Ok(None) => (None, None),
                Err(error) => (
                    None,
                    Some(format!(
                        "failed to resolve ELO key ID {}: {error}",
                        metadata.key_id
                    )),
                ),
            };
        let Some(resolved) = resolved else {
            let added = if queue_unknown {
                self.enqueue_pending_record(record.to_vec(), true)
            } else {
                false
            };
            if added || resolution_error.is_some() {
                self.report_error(
                    EloAdaptorErrorKind::UnknownKey,
                    Some(metadata.clone()),
                    resolution_error
                        .unwrap_or_else(|| format!("unknown ELO key ID: {}", metadata.key_id)),
                    vec![record.to_vec()],
                );
            }
            return EloDecryptOutcome::UnknownKey;
        };
        let iv = match &parsed.header {
            protocol::elo::EloHeader::Delta(header) => header.iv,
            protocol::elo::EloHeader::Snapshot(header) => header.iv,
        };
        let cipher = aes_gcm::Aes256Gcm::new((&resolved.key).into());
        let plaintext = match cipher.decrypt(
            aes_gcm::Nonce::from_slice(&iv),
            aes_gcm::aead::Payload {
                msg: parsed.ct,
                aad: parsed.aad,
            },
        ) {
            Ok(plaintext) => plaintext,
            Err(_) => {
                self.report_error(
                    EloAdaptorErrorKind::DecryptFailed,
                    Some(metadata),
                    "decrypt_failed: ELO authentication failed".to_string(),
                    vec![record.to_vec()],
                );
                return EloDecryptOutcome::Failed;
            }
        };
        let blobs = if matches!(parsed.kind, protocol::elo::EloRecordKind::DeltaSpan) {
            decode_canonical_delta_plaintext(&plaintext)
                .unwrap_or_else(|_| vec![plaintext.as_slice()])
        } else {
            vec![plaintext.as_slice()]
        }
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();
        EloDecryptOutcome::Decrypted(DecryptedEloRecord {
            metadata,
            blobs,
            source: record.to_vec(),
        })
    }

    async fn import_decrypted_records(&self, records: &[DecryptedEloRecord]) -> bool {
        let blobs = records
            .iter()
            .flat_map(|record| record.blobs.iter().cloned())
            .collect::<Vec<_>>();
        if blobs.is_empty() {
            return true;
        }

        let current_snapshot = {
            let doc = self.doc.lock().await;
            match doc.export(loro::ExportMode::Snapshot) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    drop(doc);
                    self.report_error(
                        EloAdaptorErrorKind::ImportFailed,
                        records.first().map(|record| record.metadata.clone()),
                        format!("Loro snapshot export failed: {error}"),
                        records.iter().map(|record| record.source.clone()).collect(),
                    );
                    return false;
                }
            }
        };
        let candidate = LoroDoc::new();
        let validation = candidate
            .import(&current_snapshot)
            .and_then(|_| candidate.import_batch(&blobs));
        if let Err(error) = validation {
            self.report_error(
                EloAdaptorErrorKind::ImportFailed,
                records.first().map(|record| record.metadata.clone()),
                format!("Loro import failed: {error}"),
                records.iter().map(|record| record.source.clone()).collect(),
            );
            return false;
        }

        let doc = self.doc.lock().await;
        if let Err(error) = doc.import_batch(&blobs) {
            drop(doc);
            self.report_error(
                EloAdaptorErrorKind::ImportFailed,
                records.first().map(|record| record.metadata.clone()),
                format!("Loro import failed after validation: {error}"),
                records.iter().map(|record| record.source.clone()).collect(),
            );
            return false;
        }
        true
    }

    /// Overrides secure IV generation with a deterministic compatibility helper.
    ///
    /// The factory must return a fresh IV on every call. Repeated IVs are rejected
    /// before encryption to prevent AES-GCM nonce reuse under this adaptor's key.
    pub fn with_iv_factory(mut self, f: Arc<dyn Fn() -> [u8; 12] + Send + Sync>) -> Self {
        self.iv_generator = Arc::new(move || Ok(f()));
        self
    }

    #[cfg(test)]
    fn with_iv_generator(mut self, generator: EloIvGenerator) -> Self {
        self.iv_generator = generator;
        self
    }

    #[cfg(test)]
    fn encode_elo_snapshot_container(&self, plaintext: &[u8]) -> Result<Vec<u8>, EloCryptoError> {
        let key = self
            .compatibility_key
            .as_ref()
            .expect("snapshot compatibility helper requires EloDocAdaptor::new");
        encode_elo_snapshot_container_with(
            &key.key_id,
            &key.key,
            &self.iv_generator,
            &self.used_ivs,
            plaintext,
        )
    }
}

#[async_trait::async_trait]
impl CrdtDocAdaptor for EloDocAdaptor {
    fn crdt_type(&self) -> CrdtType {
        CrdtType::Elo
    }

    async fn version(&self) -> Vec<u8> {
        self.doc.lock().await.oplog_vv().encode()
    }

    async fn set_ctx(&mut self, ctx: CrdtAdaptorContext) {
        if let Some(sub) = self.sub.take() {
            sub.unsubscribe();
        }
        *self
            .worker_active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = false;
        if let Some(worker) = self.worker.take() {
            worker.abort();
        }
        self.worker_tx = None;
        self.worker_active = Arc::new(StdMutex::new(true));

        self.ctx = Some(CrdtAdaptorContext {
            send_update: ctx.send_update.clone(),
            on_join_failed: ctx.on_join_failed.clone(),
            on_import_error: ctx.on_import_error.clone(),
        });

        let (worker_tx, worker_rx) = mpsc::unbounded_channel();
        self.worker = Some(
            EloWorkerContext {
                doc: self.doc.clone(),
                key_resolver: self.key_resolver.clone(),
                iv_generator: self.iv_generator.clone(),
                used_ivs: self.used_ivs.clone(),
                active: self.worker_active.clone(),
                send: ctx.send_update.clone(),
                on_error: ctx.on_import_error.clone(),
                error_handler: self.error_handler.clone(),
            }
            .spawn(worker_rx),
        );
        self.worker_tx = Some(worker_tx.clone());

        let sub = {
            let doc = self.doc.lock().await;
            doc.subscribe_local_update(Box::new(move |bytes| {
                worker_tx
                    .send(EloWorkerCommand::LocalUpdate(bytes.clone()))
                    .is_ok()
            }))
        };
        self.sub = Some(sub);
    }

    async fn handle_join_ok(&mut self, permission: protocol::Permission, _version: Vec<u8>) {
        let queued = match &self.worker_tx {
            Some(worker) => worker.send(EloWorkerCommand::Joined(permission)).is_ok(),
            None => false,
        };
        if !queued {
            if let Some(ctx) = &self.ctx {
                (ctx.on_import_error)("ELO update worker is unavailable".to_string(), Vec::new());
            }
        }
    }

    async fn apply_update(&mut self, updates: Vec<Vec<u8>>) {
        for update in updates {
            let records = match protocol::elo::decode_elo_container(&update) {
                Ok(records) => records.into_iter().map(<[u8]>::to_vec).collect::<Vec<_>>(),
                Err(error) => {
                    self.report_error(
                        EloAdaptorErrorKind::MalformedRecord,
                        None,
                        format!("malformed ELO container: {error}"),
                        vec![update],
                    );
                    continue;
                }
            };
            let mut decrypted = Vec::new();
            let mut failed = false;
            for record in records {
                match self.decrypt_elo_record(&record, true).await {
                    EloDecryptOutcome::Decrypted(record) => decrypted.push(record),
                    EloDecryptOutcome::UnknownKey => {}
                    EloDecryptOutcome::Failed => failed = true,
                }
            }
            if !failed {
                self.import_decrypted_records(&decrypted).await;
            }
        }
    }

    async fn retry_pending_encrypted_records(&mut self) -> Option<EloRetryResult> {
        Some(EloDocAdaptor::retry_pending_encrypted_records(self).await)
    }

    async fn publish_elo_snapshot(&mut self) -> bool {
        EloDocAdaptor::publish_snapshot(self).await
    }
}

impl Drop for EloDocAdaptor {
    fn drop(&mut self) {
        if let Some(sub) = self.sub.take() {
            sub.unsubscribe();
        }
        self.worker_tx = None;
        *self
            .worker_active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = false;
        if let Some(worker) = self.worker.take() {
            worker.abort();
        }
    }
}

// Public adaptor re-exports for convenience
pub use CrdtDocAdaptor as DocAdaptor;
pub use EloDocAdaptor as EloAdaptor;
pub use LoroDocAdaptor as LoroAdaptor;
