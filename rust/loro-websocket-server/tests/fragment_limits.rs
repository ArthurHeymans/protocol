use loro_websocket_client::Client;
use loro_websocket_server as server;
use loro_websocket_server::protocol::{
    BatchId, CrdtType, ProtocolMessage, UpdateStatusCode, MAX_MESSAGE_SIZE,
};
use futures_util::{SinkExt, StreamExt};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;
use tokio::time::{timeout, Duration};
use tokio_tungstenite::tungstenite::Message;

async fn connect_and_join(
    config: server::ServerConfig<()>,
) -> (Client, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        server::serve_incoming_with_config(listener, config)
            .await
            .unwrap();
    });

    let url = format!("ws://{addr}/workspace?token=secret");
    let mut client = Client::connect(&url).await.unwrap();
    client
        .send(&ProtocolMessage::JoinRequest {
            crdt: CrdtType::Loro,
            room_id: "room".into(),
            auth: Vec::new(),
            version: Vec::new(),
        })
        .await
        .unwrap();

    let mut joined = false;
    let mut received_snapshot = false;
    while !joined || !received_snapshot {
        let message = timeout(Duration::from_secs(1), client.next())
            .await
            .expect("join response timed out")
            .unwrap()
            .expect("connection closed during join");
        match message {
            ProtocolMessage::JoinResponseOk { .. } => joined = true,
            ProtocolMessage::DocUpdate { .. } => received_snapshot = true,
            _ => {}
        }
    }

    (client, server_task)
}

async fn next_ack(client: &mut Client, batch_id: BatchId) -> UpdateStatusCode {
    loop {
        let message = timeout(Duration::from_secs(1), client.next())
            .await
            .expect("acknowledgement timed out")
            .unwrap()
            .expect("connection closed");
        if let ProtocolMessage::Ack { ref_id, status, .. } = message {
            if ref_id == batch_id {
                return status;
            }
        }
    }
}

fn config() -> server::ServerConfig<()> {
    server::ServerConfig {
        handshake_auth: Some(Arc::new(|args| args.token == Some("secret"))),
        ..Default::default()
    }
}

#[tokio::test(flavor = "current_thread")]
async fn oversized_binary_frame_closes_connection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let close_notified = Arc::new(Notify::new());
    let closed_rooms = Arc::new(Mutex::new(None));
    let mut server_config = config();
    server_config.on_close_connection = Some(Arc::new({
        let close_notified = close_notified.clone();
        let closed_rooms = closed_rooms.clone();
        move |args| {
            *closed_rooms.lock().unwrap() = Some(args.rooms);
            close_notified.notify_one();
            Box::pin(async { Ok(()) })
        }
    }));
    let server_task = tokio::spawn(async move {
        server::serve_incoming_with_config(listener, server_config)
            .await
            .unwrap();
    });
    let url = format!("ws://{addr}/workspace?token=secret");
    let (mut socket, _) = tokio_tungstenite::connect_async(&url).await.unwrap();

    let join = ProtocolMessage::JoinRequest {
        crdt: CrdtType::LoroEphemeralStore,
        room_id: "room-cleanup".into(),
        auth: Vec::new(),
        version: Vec::new(),
    };
    socket
        .send(Message::Binary(
            server::protocol::encode(&join).unwrap().into(),
        ))
        .await
        .unwrap();
    loop {
        let message = timeout(Duration::from_secs(1), socket.next())
            .await
            .expect("join response timed out")
            .expect("server closed before join response")
            .expect("server rejected join connection");
        if let Message::Binary(data) = message {
            if matches!(
                server::protocol::try_decode(data.as_ref()),
                Some(ProtocolMessage::JoinResponseOk { .. })
            ) {
                break;
            }
        }
    }

    socket
        .send(Message::Binary(vec![0; MAX_MESSAGE_SIZE + 1].into()))
        .await
        .unwrap();

    let result = timeout(Duration::from_secs(1), socket.next())
        .await
        .expect("server did not reject oversized frame");
    assert!(matches!(
        result,
        None | Some(Err(_)) | Some(Ok(Message::Close(_)))
    ));
    timeout(Duration::from_secs(1), close_notified.notified())
        .await
        .expect("on_close_connection was not called after receive error");
    assert_eq!(
        closed_rooms.lock().unwrap().as_deref(),
        Some(&[(CrdtType::LoroEphemeralStore, "room-cleanup".to_string())][..])
    );

    server_task.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn partial_fragment_batch_times_out() {
    let mut config = config();
    config.fragment_reassembly_timeout = Duration::from_millis(20);
    let (mut client, server_task) = connect_and_join(config).await;
    let batch_id = BatchId([1; 8]);

    client
        .send(&ProtocolMessage::DocUpdateFragmentHeader {
            crdt: CrdtType::Loro,
            room_id: "room".into(),
            batch_id,
            fragment_count: 2,
            total_size_bytes: 2,
        })
        .await
        .unwrap();

    assert_eq!(
        next_ack(&mut client, batch_id).await,
        UpdateStatusCode::FragmentTimeout
    );
    server_task.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn fragment_bytes_cannot_exceed_declared_total() {
    let (mut client, server_task) = connect_and_join(config()).await;
    let batch_id = BatchId([2; 8]);
    client
        .send(&ProtocolMessage::DocUpdateFragmentHeader {
            crdt: CrdtType::Loro,
            room_id: "room".into(),
            batch_id,
            fragment_count: 1,
            total_size_bytes: 2,
        })
        .await
        .unwrap();
    client
        .send(&ProtocolMessage::DocUpdateFragment {
            crdt: CrdtType::Loro,
            room_id: "room".into(),
            batch_id,
            index: 0,
            fragment: vec![1, 2, 3],
        })
        .await
        .unwrap();

    assert_eq!(
        next_ack(&mut client, batch_id).await,
        UpdateStatusCode::PayloadTooLarge
    );
    server_task.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn completed_batch_must_match_declared_total() {
    let (mut client, server_task) = connect_and_join(config()).await;
    let batch_id = BatchId([3; 8]);
    client
        .send(&ProtocolMessage::DocUpdateFragmentHeader {
            crdt: CrdtType::Loro,
            room_id: "room".into(),
            batch_id,
            fragment_count: 1,
            total_size_bytes: 4,
        })
        .await
        .unwrap();
    client
        .send(&ProtocolMessage::DocUpdateFragment {
            crdt: CrdtType::Loro,
            room_id: "room".into(),
            batch_id,
            index: 0,
            fragment: vec![1, 2, 3],
        })
        .await
        .unwrap();

    assert_eq!(
        next_ack(&mut client, batch_id).await,
        UpdateStatusCode::InvalidUpdate
    );
    server_task.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn reserved_fragment_bytes_are_limited_per_connection() {
    let mut config = config();
    config.max_inflight_fragment_bytes_per_connection = 3;
    let (mut client, server_task) = connect_and_join(config).await;
    let first = BatchId([4; 8]);
    let second = BatchId([5; 8]);

    for batch_id in [first, second] {
        client
            .send(&ProtocolMessage::DocUpdateFragmentHeader {
                crdt: CrdtType::Loro,
                room_id: "room".into(),
                batch_id,
                fragment_count: 2,
                total_size_bytes: 2,
            })
            .await
            .unwrap();
    }

    assert_eq!(
        next_ack(&mut client, second).await,
        UpdateStatusCode::RateLimited
    );
    server_task.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_fragment_batches_are_limited_per_connection() {
    let mut config = config();
    config.max_inflight_fragment_batches_per_connection = 1;
    let (mut client, server_task) = connect_and_join(config).await;
    let first = BatchId([6; 8]);
    let second = BatchId([7; 8]);

    for batch_id in [first, second] {
        client
            .send(&ProtocolMessage::DocUpdateFragmentHeader {
                crdt: CrdtType::Loro,
                room_id: "room".into(),
                batch_id,
                fragment_count: 2,
                total_size_bytes: 2,
            })
            .await
            .unwrap();
    }

    assert_eq!(
        next_ack(&mut client, second).await,
        UpdateStatusCode::RateLimited
    );
    server_task.abort();
}
