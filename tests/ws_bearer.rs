//! The WebSocket bearer must carry real Hop link traffic: the Noise XX handshake
//! and an end-to-end message, with each link packet riding one WS binary frame.
//!
//! This stands up a genuine localhost WebSocket (server `tungstenite::accept`,
//! client `tungstenite::client`) and bridges a `Node` on each end, exactly what
//! `serve_ws` does in the daemon, then sends a message client → server and asserts
//! it arrives decrypted.

use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use hop_core::prelude::*;
use tungstenite::{Message, WebSocket};

/// One pump step: flush whatever the node wants to send as WS binary frames, then
/// read one frame (within the socket's read timeout) and feed it to the node.
fn pump<S: std::io::Read + std::io::Write>(node: &mut Node<MemoryStore>, ws: &mut WebSocket<S>) {
    for (_link, bytes) in node.drain_outgoing() {
        let _ = ws.write(Message::Binary(bytes.into()));
    }
    let _ = ws.flush();
    match ws.read() {
        Ok(Message::Binary(b)) => node.handle(BearerEvent::Data(1, b.to_vec())),
        Ok(_) => {}
        Err(tungstenite::Error::Io(e))
            if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
        Err(_) => {}
    }
    node.tick(0);
}

#[test]
fn message_round_trips_over_a_real_websocket() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();

    let server_id = Identity::generate();
    let server_addr = server_id.address();
    let client_id = Identity::generate();

    let (done_tx, done_rx) = mpsc::channel::<Vec<u8>>();

    // Server: accept the WS upgrade, play Responder, report the first message body.
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        stream.set_nodelay(true).ok();
        let mut ws = tungstenite::accept(stream).expect("ws accept");
        ws.get_mut()
            .set_read_timeout(Some(Duration::from_millis(50)))
            .ok();

        let mut node = Node::with_store(server_id, MemoryStore::new());
        // Publish our prekey so it gossips to the client on link-up, content is forward-secret
        // and defers until the recipient's prekey is known (DESIGN.md §25).
        node.publish_prekey().unwrap();
        node.handle(BearerEvent::Connected(1, Role::Responder));

        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            pump(&mut node, &mut ws);
            for bundle in node.take_inbox() {
                if let Ok(Some(read)) = node.read_message(&bundle) {
                    let _ = done_tx.send(read.body);
                    return;
                }
            }
        }
    });

    // Client: dial, play Initiator, send one message to the server's address.
    let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.set_nodelay(true).ok();
    let (mut ws, _) =
        tungstenite::client(format!("ws://127.0.0.1:{port}/"), stream).expect("ws client");
    ws.get_mut()
        .set_read_timeout(Some(Duration::from_millis(50)))
        .ok();

    let mut node = Node::with_store(client_id, MemoryStore::new());
    node.publish_prekey().unwrap();
    node.handle(BearerEvent::Connected(1, Role::Initiator));
    // Content defers until the server's prekey gossips in over the link, then flushes (§25).
    node.send_message(
        server_addr,
        "t".into(),
        b"hello over websocket".to_vec(),
        false,
    )
    .expect("send");

    let body = loop {
        pump(&mut node, &mut ws);
        if let Ok(body) = done_rx.try_recv() {
            break body;
        }
        // Give up if the server thread died.
        if server.is_finished() {
            break done_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap_or_default();
        }
    };

    assert_eq!(body, b"hello over websocket", "message delivered over WS");
    let _ = server.join();
}
