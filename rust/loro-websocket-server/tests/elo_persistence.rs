use loro::VersionVector;
use loro_protocol::bytes::BytesWriter;
use loro_protocol::elo::{decode_elo_container, encode_elo_container};
use loro_websocket_client::Client;
use loro_websocket_server as server;
use loro_websocket_server::protocol::{self as proto, BatchId, CrdtType, UpdateStatusCode};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

#[derive(Default)]
struct PersistenceState {
    bytes: Option<Vec<u8>>,
    loads: Vec<(String, String, CrdtType)>,
    saves: Vec<(String, String, CrdtType, Option<String>)>,
}

#[tokio::test(flavor = "current_thread")]
async fn elo_callbacks_restore_version_filtered_late_join_after_restart() {
    let persistence = Arc::new(Mutex::new(PersistenceState::default()));
    let first_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first_addr = first_listener.local_addr().unwrap();
    let first_config = persistence_config(persistence.clone());
    let first_server = tokio::spawn(async move {
        server::serve_incoming_with_config(first_listener, first_config)
            .await
            .unwrap();
    });

    let mut writer = Client::connect(&format!("ws://{first_addr}/workspace"))
        .await
        .unwrap();
    join_elo(&mut writer, "persisted-room", Vec::new()).await;
    wait_for_join_ok(&mut writer).await;

    let snapshot = snapshot_record(b"7", 2, 1);
    let covered_delta = delta_record(b"7", 0, 2, 2);
    let later_delta = delta_record(b"7", 2, 3, 3);
    let update = encode_elo_container([
        snapshot.as_slice(),
        covered_delta.as_slice(),
        later_delta.as_slice(),
    ]);
    writer
        .send(&proto::ProtocolMessage::DocUpdate {
            crdt: CrdtType::Elo,
            room_id: "persisted-room".into(),
            updates: vec![update],
            batch_id: BatchId([9; 8]),
        })
        .await
        .unwrap();
    wait_for_ack(&mut writer, UpdateStatusCode::Ok).await;

    let persisted = wait_for_persisted_bytes(&persistence).await;
    let saved_records = decode_elo_container(&persisted).unwrap();
    assert_eq!(
        saved_records,
        vec![
            snapshot.as_slice(),
            covered_delta.as_slice(),
            later_delta.as_slice()
        ],
        "persistence must use the standard snapshot-first ELO container"
    );
    {
        let state = persistence.lock().unwrap();
        assert_eq!(
            state.loads,
            vec![("workspace".into(), "persisted-room".into(), CrdtType::Elo)]
        );
        assert_eq!(
            state.saves,
            vec![(
                "workspace".into(),
                "persisted-room".into(),
                CrdtType::Elo,
                Some("load-context".into())
            )]
        );
    }

    drop(writer);
    first_server.abort();
    let _ = first_server.await;

    let second_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second_addr = second_listener.local_addr().unwrap();
    let second_config = persistence_config(persistence.clone());
    let second_server = tokio::spawn(async move {
        server::serve_incoming_with_config(second_listener, second_config)
            .await
            .unwrap();
    });

    let mut late_joiner = Client::connect(&format!("ws://{second_addr}/workspace"))
        .await
        .unwrap();
    join_elo(&mut late_joiner, "persisted-room", Vec::new()).await;
    wait_for_join_ok(&mut late_joiner).await;
    let restored = wait_for_doc_update(&mut late_joiner).await;
    let restored_records = decode_elo_container(&restored).unwrap();
    assert_eq!(
        restored_records,
        vec![snapshot.as_slice(), later_delta.as_slice()],
        "late join must receive the retained snapshot before only uncovered deltas"
    );

    let mut current = VersionVector::default();
    current.insert(7, 3);
    let mut current_client = Client::connect(&format!("ws://{second_addr}/workspace"))
        .await
        .unwrap();
    join_elo(&mut current_client, "persisted-room", current.encode()).await;
    wait_for_join_ok(&mut current_client).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(150), current_client.next())
            .await
            .is_err(),
        "a current requester must not receive the persistence export blindly"
    );

    {
        let state = persistence.lock().unwrap();
        assert_eq!(
            state
                .loads
                .iter()
                .filter(|(_, _, crdt)| *crdt == CrdtType::Elo)
                .count(),
            2,
            "the restored room should be loaded only once"
        );
    }

    second_server.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn update_during_pending_save_remains_dirty_without_blocking_the_room() {
    let saved = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let save_calls = Arc::new(AtomicUsize::new(0));
    let save_started = Arc::new(tokio::sync::Notify::new());
    let release_save = Arc::new(tokio::sync::Notify::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config: server::ServerConfig<()> = server::ServerConfig {
        on_save_document: Some(Arc::new({
            let saved = saved.clone();
            let save_calls = save_calls.clone();
            let save_started = save_started.clone();
            let release_save = release_save.clone();
            move |args| {
                let saved = saved.clone();
                let call = save_calls.fetch_add(1, Ordering::SeqCst);
                let save_started = save_started.clone();
                let release_save = release_save.clone();
                Box::pin(async move {
                    saved.lock().unwrap().push(args.data);
                    if call == 0 {
                        save_started.notify_one();
                        release_save.notified().await;
                    }
                    Ok(())
                })
            }
        })),
        save_interval_ms: Some(10),
        ..Default::default()
    };
    let server_task = tokio::spawn(async move {
        server::serve_incoming_with_config(listener, config)
            .await
            .unwrap();
    });

    let mut writer = Client::connect(&format!("ws://{addr}/workspace"))
        .await
        .unwrap();
    join_elo(&mut writer, "save-race", Vec::new()).await;
    wait_for_join_ok(&mut writer).await;
    let first = delta_record(b"7", 0, 1, 1);
    writer
        .send(&proto::ProtocolMessage::DocUpdate {
            crdt: CrdtType::Elo,
            room_id: "save-race".into(),
            updates: vec![encode_elo_container([first.as_slice()])],
            batch_id: BatchId([1; 8]),
        })
        .await
        .unwrap();
    wait_for_ack(&mut writer, UpdateStatusCode::Ok).await;
    save_started.notified().await;

    let second = delta_record(b"7", 1, 2, 2);
    writer
        .send(&proto::ProtocolMessage::DocUpdate {
            crdt: CrdtType::Elo,
            room_id: "save-race".into(),
            updates: vec![encode_elo_container([second.as_slice()])],
            batch_id: BatchId([2; 8]),
        })
        .await
        .unwrap();
    tokio::time::timeout(
        Duration::from_millis(250),
        wait_for_ack(&mut writer, UpdateStatusCode::Ok),
    )
    .await
    .expect("pending persistence callback must not block room updates");
    release_save.notify_waiters();

    for _ in 0..100 {
        if saved.lock().unwrap().len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let saved = saved.lock().unwrap();
    assert!(saved.len() >= 2, "the racing update must remain dirty");
    assert_eq!(
        decode_elo_container(saved.last().unwrap()).unwrap(),
        vec![first.as_slice(), second.as_slice()]
    );

    server_task.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn corrupt_persisted_elo_state_rejects_join() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config: server::ServerConfig<()> = server::ServerConfig {
        on_load_document: Some(Arc::new(|_args| {
            Box::pin(async {
                Ok(server::LoadedDoc {
                    snapshot: Some(vec![0xff]),
                    ctx: None,
                })
            })
        })),
        ..Default::default()
    };
    let server_task = tokio::spawn(async move {
        server::serve_incoming_with_config(listener, config)
            .await
            .unwrap();
    });

    let mut client = Client::connect(&format!("ws://{addr}/workspace"))
        .await
        .unwrap();
    join_elo(&mut client, "corrupt-room", Vec::new()).await;
    let message = tokio::time::timeout(Duration::from_secs(2), client.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(
        message,
        proto::ProtocolMessage::JoinError {
            crdt: CrdtType::Elo,
            ..
        }
    ));

    server_task.abort();
}

fn persistence_config(persistence: Arc<Mutex<PersistenceState>>) -> server::ServerConfig<String> {
    let load_state = persistence.clone();
    let save_state = persistence;
    server::ServerConfig {
        on_load_document: Some(Arc::new(move |args| {
            let state = load_state.clone();
            Box::pin(async move {
                let mut state = state.lock().unwrap();
                state.loads.push((args.workspace, args.room, args.crdt));
                Ok(server::LoadedDoc {
                    snapshot: state.bytes.clone(),
                    ctx: Some("load-context".to_string()),
                })
            })
        })),
        on_save_document: Some(Arc::new(move |args| {
            let state = save_state.clone();
            Box::pin(async move {
                let mut state = state.lock().unwrap();
                state
                    .saves
                    .push((args.workspace, args.room, args.crdt, args.ctx));
                state.bytes = Some(args.data);
                Ok(())
            })
        })),
        save_interval_ms: Some(10),
        handshake_auth: Some(Arc::new(|_| true)),
        ..Default::default()
    }
}

async fn join_elo(client: &mut Client, room: &str, version: Vec<u8>) {
    client
        .send(&proto::ProtocolMessage::JoinRequest {
            crdt: CrdtType::Elo,
            room_id: room.into(),
            auth: Vec::new(),
            version,
        })
        .await
        .unwrap();
}

async fn wait_for_join_ok(client: &mut Client) {
    loop {
        let message = tokio::time::timeout(Duration::from_secs(2), client.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if matches!(
            message,
            proto::ProtocolMessage::JoinResponseOk {
                crdt: CrdtType::Elo,
                ..
            }
        ) {
            return;
        }
    }
}

async fn wait_for_ack(client: &mut Client, expected: UpdateStatusCode) {
    loop {
        let message = tokio::time::timeout(Duration::from_secs(2), client.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let proto::ProtocolMessage::Ack { status, .. } = message {
            assert_eq!(status, expected);
            return;
        }
    }
}

async fn wait_for_doc_update(client: &mut Client) -> Vec<u8> {
    loop {
        let message = tokio::time::timeout(Duration::from_secs(2), client.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let proto::ProtocolMessage::DocUpdate { mut updates, .. } = message {
            assert_eq!(updates.len(), 1);
            return updates.remove(0);
        }
    }
}

async fn wait_for_persisted_bytes(persistence: &Arc<Mutex<PersistenceState>>) -> Vec<u8> {
    for _ in 0..100 {
        if let Some(bytes) = persistence.lock().unwrap().bytes.clone() {
            return bytes;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("ELO room was not persisted");
}

fn snapshot_record(peer: &[u8], counter: u64, marker: u8) -> Vec<u8> {
    let mut record = BytesWriter::new();
    record.push_byte(0x01);
    record.push_uleb128(1);
    record.push_var_bytes(peer);
    record.push_uleb128(counter);
    record.push_var_string("key-1");
    record.push_var_bytes(&[marker; 12]);
    record.push_var_bytes(&[marker]);
    record.finalize()
}

fn delta_record(peer: &[u8], start: u64, end: u64, marker: u8) -> Vec<u8> {
    let mut record = BytesWriter::new();
    record.push_byte(0x00);
    record.push_var_bytes(peer);
    record.push_uleb128(start);
    record.push_uleb128(end);
    record.push_var_string("key-1");
    record.push_var_bytes(&[marker; 12]);
    record.push_var_bytes(&[marker]);
    record.finalize()
}
