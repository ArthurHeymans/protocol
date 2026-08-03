use loro::{ExportMode, LoroDoc};
use loro_websocket_client::Client;
use loro_websocket_server as server;
use loro_websocket_server::protocol::{BatchId, CrdtType, ProtocolMessage, UpdateStatusCode};
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
async fn validator_rejects_candidate_loro_snapshot() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config: server::ServerConfig<()> = server::ServerConfig {
        validate_loro_snapshot: Some(Arc::new(|args| {
            let document =
                LoroDoc::from_snapshot(args.snapshot).map_err(|error| error.to_string())?;
            if document.get_text("text").to_string().contains("forbidden") {
                return Err("forbidden text".into());
            }
            Ok(())
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
    let mut sender = Client::connect(&url).await.unwrap();
    let mut receiver = Client::connect(&url).await.unwrap();
    join(&mut sender, "room").await;
    join(&mut receiver, "room").await;

    let update = LoroDoc::new();
    update.get_text("text").insert(0, "forbidden").unwrap();
    let batch_id = BatchId([9; 8]);
    sender
        .send(&ProtocolMessage::DocUpdate {
            crdt: CrdtType::Loro,
            room_id: "room".into(),
            updates: vec![update.export(ExportMode::Snapshot).unwrap()],
            batch_id,
        })
        .await
        .unwrap();

    loop {
        let message = timeout(Duration::from_secs(1), sender.next())
            .await
            .expect("acknowledgement timed out")
            .unwrap()
            .expect("connection closed");
        if let ProtocolMessage::Ack { ref_id, status, .. } = message {
            assert_eq!(ref_id, batch_id);
            assert_eq!(status, UpdateStatusCode::InvalidUpdate);
            break;
        }
    }

    if let Ok(result) = timeout(Duration::from_millis(100), receiver.next()).await {
        panic!("rejected update was broadcast: {result:?}");
    }

    server_task.abort();
}
