use loro::LoroDoc;
use loro_websocket_client::LoroWebsocketClient;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

// Test-only interoperability key. Production applications must provision keys
// through application key management.
const KEY: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Args: role receiver|sender, url, room alias.
    // The relay and TLS terminator can read and correlate the alias. Production
    // callers should generate a non-semantic alias from at least 16 bytes from
    // an OS CSPRNG, share it through an authenticated, confidential channel,
    // and still enforce authorization separately.
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() < 3 {
        eprintln!("usage: elo_index_client <receiver|sender> <ws_url> <room_alias>");
        std::process::exit(2);
    }
    let role = args.remove(0);
    let url = args.remove(0);
    let room = args.remove(0);

    let client = LoroWebsocketClient::connect(&url).await?;
    let doc = Arc::new(tokio::sync::Mutex::new(LoroDoc::new()));

    match role.as_str() {
        "sender" => {
            let _room = client
                .join_elo_with_adaptor(&room, doc.clone(), "k1".to_string(), KEY)
                .await?;
            // Edit after joining so this path exercises canonical DeltaSpan
            // interoperability rather than only initial snapshot import.
            {
                let d = doc.lock().await;
                d.get_text("t").insert(0, "hi").unwrap();
                d.commit();
            }
            // Allow the async writer, relay indexing, and late-join backfill to complete.
            sleep(Duration::from_millis(1_500)).await;
            Ok(())
        }
        "receiver" => {
            let _room = client
                .join_elo_with_adaptor(&room, doc.clone(), "k1".to_string(), KEY)
                .await?;
            // Poll document until expected content arrives
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            loop {
                {
                    let d = doc.lock().await;
                    let s = d.get_text("t").to_string();
                    if s == "hi" {
                        println!("INDEXED 1");
                        return Ok(());
                    }
                }
                if tokio::time::Instant::now() > deadline {
                    eprintln!("timeout waiting for content");
                    std::process::exit(1);
                }
                sleep(Duration::from_millis(50)).await;
            }
        }
        _ => {
            eprintln!("usage: elo_index_client <receiver|sender> <ws_url> <room_alias>");
            std::process::exit(2);
        }
    }
}
