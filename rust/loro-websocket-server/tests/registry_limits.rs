use loro_websocket_client::Client;
use loro_websocket_server as server;
use loro_websocket_server::protocol::{CrdtType, Permission, ProtocolMessage};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::time::{timeout, Duration};

fn config() -> server::ServerConfig<()> {
    server::ServerConfig {
        handshake_auth: Some(Arc::new(|args| args.token == Some("secret"))),
        ..Default::default()
    }
}

#[tokio::test(flavor = "current_thread")]
async fn workspace_limit_closes_new_workspace_connection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut config = config();
    config.max_workspaces = Some(1);
    let server_task = tokio::spawn(async move {
        server::serve_incoming_with_config(listener, config)
            .await
            .unwrap();
    });

    let first_url = format!("ws://{addr}/first?token=secret");
    let _first = Client::connect(&first_url).await.unwrap();
    let second_url = format!("ws://{addr}/second?token=secret");
    let mut second = Client::connect(&second_url).await.unwrap();

    assert!(timeout(Duration::from_secs(1), second.next())
        .await
        .expect("server did not close limited workspace")
        .unwrap()
        .is_none());
    server_task.abort();
}

async fn assert_room_limit(crdt: CrdtType) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut config = config();
    config.max_rooms_per_workspace = Some(1);
    let server_task = tokio::spawn(async move {
        server::serve_incoming_with_config(listener, config)
            .await
            .unwrap();
    });

    let url = format!("ws://{addr}/workspace?token=secret");
    let mut client = Client::connect(&url).await.unwrap();
    for room_id in ["first", "second"] {
        client
            .send(&ProtocolMessage::JoinRequest {
                crdt,
                room_id: room_id.into(),
                auth: Vec::new(),
                version: Vec::new(),
            })
            .await
            .unwrap();
        loop {
            let message = timeout(Duration::from_secs(1), client.next())
                .await
                .expect("join response timed out")
                .unwrap()
                .expect("connection closed during join");
            match message {
                ProtocolMessage::JoinResponseOk { room_id, .. } if room_id == "first" => break,
                ProtocolMessage::JoinError {
                    room_id, message, ..
                } if room_id == "second" => {
                    assert!(message.contains("room limit"));
                    server_task.abort();
                    return;
                }
                _ => {}
            }
        }
    }

    panic!("second room unexpectedly joined");
}

#[tokio::test(flavor = "current_thread")]
async fn room_limit_rejects_join_for_new_document_room() {
    assert_room_limit(CrdtType::Loro).await;
}

#[tokio::test(flavor = "current_thread")]
async fn room_limit_counts_relay_only_rooms() {
    for crdt in [CrdtType::Yjs, CrdtType::YjsAwareness, CrdtType::Flock] {
        assert_room_limit(crdt).await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn denied_joins_do_not_consume_room_capacity() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let authentication_calls = Arc::new(AtomicUsize::new(0));
    let config: server::ServerConfig<()> = server::ServerConfig {
        handshake_auth: Some(Arc::new(|args| args.token == Some("secret"))),
        authenticate: Some(Arc::new({
            let authentication_calls = authentication_calls.clone();
            move |args| {
                authentication_calls.fetch_add(1, Ordering::Relaxed);
                Box::pin(async move {
                    if args.auth.as_slice() == b"allow" {
                        Ok(Some(Permission::Write))
                    } else {
                        Ok(None)
                    }
                })
            }
        })),

        max_rooms_per_workspace: Some(1),
        ..Default::default()
    };
    let server_task = tokio::spawn(async move {
        server::serve_incoming_with_config(listener, config)
            .await
            .unwrap();
    });

    let url = format!("ws://{addr}/workspace?token=secret");
    let mut client = Client::connect(&url).await.unwrap();
    for room_id in ["denied-one", "denied-two", "denied-three"] {
        client
            .send(&ProtocolMessage::JoinRequest {
                crdt: CrdtType::Loro,
                room_id: room_id.into(),
                auth: Vec::new(),
                version: Vec::new(),
            })
            .await
            .unwrap();
        loop {
            let message = timeout(Duration::from_secs(1), client.next())
                .await
                .expect("denied join response timed out")
                .unwrap()
                .expect("connection closed during denied join");
            if let ProtocolMessage::JoinError {
                room_id: response_room,
                code,
                ..
            } = message
            {
                assert_eq!(response_room, room_id);
                assert_eq!(code, server::protocol::JoinErrorCode::AuthFailed);
                break;
            }
        }
    }

    client
        .send(&ProtocolMessage::JoinRequest {
            crdt: CrdtType::Loro,
            room_id: "authorized".into(),
            auth: b"allow".to_vec(),
            version: Vec::new(),
        })
        .await
        .unwrap();
    loop {
        let message = timeout(Duration::from_secs(1), client.next())
            .await
            .expect("authorized join response timed out")
            .unwrap()
            .expect("connection closed during authorized join");
        if let ProtocolMessage::JoinResponseOk { room_id, .. } = message {
            assert_eq!(room_id, "authorized");
            break;
        }
    }
    assert_eq!(authentication_calls.load(Ordering::Relaxed), 4);

    client
        .send(&ProtocolMessage::JoinRequest {
            crdt: CrdtType::Loro,
            room_id: "over-capacity".into(),
            auth: b"allow".to_vec(),
            version: Vec::new(),
        })
        .await
        .unwrap();
    loop {
        let message = timeout(Duration::from_secs(1), client.next())
            .await
            .expect("room limit response timed out")
            .unwrap()
            .expect("connection closed during room limit check");
        if let ProtocolMessage::JoinError {
            room_id, message, ..
        } = message
        {
            assert_eq!(room_id, "over-capacity");
            assert!(message.contains("room limit"));
            break;
        }
    }
    assert_eq!(
        authentication_calls.load(Ordering::Relaxed),
        4,
        "full workspaces should reject new rooms before authentication"
    );

    server_task.abort();
}
