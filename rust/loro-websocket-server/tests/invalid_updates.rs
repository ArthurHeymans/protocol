use loro_websocket_client::Client;
use loro_websocket_server as server;
use loro_websocket_server::protocol::{
    BatchId, CrdtType, JoinErrorCode, ProtocolMessage, UpdateStatusCode,
};
use std::sync::Arc;
use tokio::time::{timeout, Duration};

async fn join(client: &mut Client, room: &str) {
    client
        .send(&ProtocolMessage::JoinRequest {
            crdt: CrdtType::Loro,
            room_id: room.to_string(),
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
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_loro_update_is_rejected_without_broadcast() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let config: server::ServerConfig<()> = server::ServerConfig {
            handshake_auth: Some(Arc::new(|args| args.token == Some("secret"))),
            ..Default::default()
        };
        server::serve_incoming_with_config(listener, config)
            .await
            .unwrap();
    });

    let url = format!("ws://{addr}/workspace?token=secret");
    let mut sender = Client::connect(&url).await.unwrap();
    let mut receiver = Client::connect(&url).await.unwrap();
    join(&mut sender, "room").await;
    join(&mut receiver, "room").await;

    let batch_id = BatchId([7; 8]);
    sender
        .send(&ProtocolMessage::DocUpdate {
            crdt: CrdtType::Loro,
            room_id: "room".into(),
            updates: vec![vec![1, 2, 3]],
            batch_id,
        })
        .await
        .unwrap();

    loop {
        let message = timeout(Duration::from_secs(1), sender.next())
            .await
            .expect("update acknowledgement timed out")
            .unwrap()
            .expect("sender connection closed");
        if let ProtocolMessage::Ack { ref_id, status, .. } = message {
            assert_eq!(ref_id, batch_id);
            assert_eq!(status, UpdateStatusCode::InvalidUpdate);
            break;
        }
    }

    if let Ok(result) = timeout(Duration::from_millis(100), receiver.next()).await {
        panic!("malformed update was broadcast: {result:?}");
    }

    server_task.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_loaded_loro_snapshot_rejects_join() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config: server::ServerConfig<()> = server::ServerConfig {
        on_load_document: Some(Arc::new(|_args| {
            Box::pin(async {
                Ok(server::LoadedDoc {
                    snapshot: Some(vec![1, 2, 3]),
                    ctx: None,
                })
            })
        })),
        handshake_auth: Some(Arc::new(|args| args.token == Some("secret"))),
        ..Default::default()
    };
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

    let message = timeout(Duration::from_secs(1), client.next())
        .await
        .expect("join response timed out")
        .unwrap()
        .expect("connection closed during join");
    match message {
        ProtocolMessage::JoinError { code, message, .. } => {
            assert_eq!(code, JoinErrorCode::Unknown);
            assert!(message.contains("load"), "unexpected message: {message}");
        }
        other => panic!("expected JoinError, got {other:?}"),
    }

    server_task.abort();
}
