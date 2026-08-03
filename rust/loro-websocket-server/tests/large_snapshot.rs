use loro::{ExportMode, LoroDoc};
use loro_websocket_client::LoroWebsocketClient;
use loro_websocket_server as server;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

fn large_text() -> String {
    let mut state = 0x1234_5678_u32;
    (0..600_000)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            char::from(b' ' + ((state >> 24) % 95) as u8)
        })
        .collect()
}

#[tokio::test(flavor = "current_thread")]
async fn join_fragments_large_loaded_snapshot() {
    let expected = large_text();
    let stored = LoroDoc::new();
    stored.get_text("text").insert(0, &expected).unwrap();
    let snapshot = stored.export(ExportMode::Snapshot).unwrap();
    assert!(snapshot.len() > loro_protocol::MAX_MESSAGE_SIZE);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config: server::ServerConfig<()> = server::ServerConfig {
        on_load_document: Some(Arc::new(move |_args| {
            let snapshot = snapshot.clone();
            Box::pin(async move {
                Ok(server::LoadedDoc {
                    snapshot: Some(snapshot),
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
    let client = LoroWebsocketClient::connect(&url).await.unwrap();
    let local = Arc::new(Mutex::new(LoroDoc::new()));
    let _room = client.join_loro("room", local.clone()).await.unwrap();

    timeout(Duration::from_secs(3), async {
        loop {
            if local.lock().await.get_text("text").to_string() == expected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("large snapshot was not delivered");

    server_task.abort();
}
