// Loopback-only WebSocket feed. Read-only: clients receive data and cannot send anything to the game.
use std::collections::HashSet;
use std::net::SocketAddr;

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::Message as WsMessage;

pub const SCHEMA_VERSION: u32 = 1;

/// One published item. `kind` is "event", "health", "message" or "status".
#[derive(Clone, Debug)]
pub struct Item {
    pub kind: &'static str,
    pub opcode: Option<u16>,
    pub json: Value,
}

#[derive(Default)]
struct Subscription {
    raw: bool,
    opcodes: Option<HashSet<u16>>,
}

impl Subscription {
    /// Parses `?raw=1&opcodes=1134,1135` from the request path.
    fn parse(uri: &str) -> Self {
        let mut s = Subscription::default();
        for pair in uri.split_once('?').map(|x| x.1).unwrap_or("").split('&') {
            match pair.split_once('=') {
                Some(("raw", v)) => s.raw = v == "1" || v == "true",
                Some(("opcodes", v)) => s.opcodes = Some(v.split(',').filter_map(|x| x.parse().ok()).collect()),
                _ => {}
            }
        }
        s
    }
    fn wants(&self, item: &Item) -> bool {
        if item.kind == "message" && !self.raw {
            return false;
        }
        match (&self.opcodes, item.opcode) {
            (Some(set), Some(op)) => set.contains(&op),
            (Some(_), None) => item.kind != "message",
            (None, _) => true,
        }
    }
}

/// Browsers send Origin; only pages served from this machine may connect.
fn origin_allowed(origin: Option<&str>) -> bool {
    let Some(o) = origin else { return true };
    let rest = o.strip_prefix("http://").or_else(|| o.strip_prefix("https://")).unwrap_or("");
    let host = rest.split(['/', ':']).next().unwrap_or("");
    matches!(host, "127.0.0.1" | "localhost")
        || rest.starts_with("[::1]")
}

pub async fn serve(port: u16, tx: broadcast::Sender<Item>) -> Result<()> {
    // Bind to loopback only; never expose the feed to the network.
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).await?;
    eprintln!("feed: ws://127.0.0.1:{port}/  (add ?raw=1 for decoded messages, ?opcodes=1134,1135 to filter)");
    loop {
        let (socket, _) = listener.accept().await?;
        let rx = tx.subscribe();
        tokio::spawn(async move {
            if let Err(e) = client(socket, rx).await {
                eprintln!("feed: client closed: {e}");
            }
        });
    }
}

async fn client(socket: TcpStream, mut rx: broadcast::Receiver<Item>) -> Result<()> {
    let mut sub = Subscription::default();
    let ws = tokio_tungstenite::accept_hdr_async(socket, |req: &Request, res: Response| -> Result<Response, ErrorResponse> {
        let origin = req.headers().get("origin").and_then(|v| v.to_str().ok());
        if !origin_allowed(origin) {
            let mut err = ErrorResponse::new(Some("Foreign origin rejected".into()));
            *err.status_mut() = StatusCode::FORBIDDEN;
            return Err(err);
        }
        sub = Subscription::parse(&req.uri().to_string());
        Ok(res)
    })
    .await?;
    let (mut sink, mut incoming) = ws.split();
    sink.send(WsMessage::text(json!({"kind":"hello","schema":SCHEMA_VERSION,"readOnly":true,"raw":sub.raw}).to_string())).await?;
    loop {
        tokio::select! {
            item = rx.recv() => match item {
                Ok(item) if sub.wants(&item) => sink.send(WsMessage::text(item.json.to_string())).await?,
                Ok(_) => {}
                // A slow client misses items; tell it explicitly rather than hiding the gap.
                Err(broadcast::error::RecvError::Lagged(n)) => sink.send(WsMessage::text(json!({"kind":"health","type":"feed_lagged","skipped":n}).to_string())).await?,
                Err(broadcast::error::RecvError::Closed) => return Ok(()),
            },
            // Incoming frames are ignored except close; the feed accepts no commands.
            msg = incoming.next() => match msg {
                Some(Ok(WsMessage::Close(_))) | None => return Ok(()),
                Some(Err(e)) => return Err(e.into()),
                _ => {}
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_filters_raw_messages_and_opcodes() {
        let item = |kind, opcode| Item { kind, opcode, json: Value::Null };
        let default = Subscription::parse("/");
        assert!(!default.wants(&item("message", Some(1134))));
        assert!(default.wants(&item("event", Some(1134))));
        let raw = Subscription::parse("/?raw=1&opcodes=1134,1135");
        assert!(raw.wants(&item("message", Some(1135))));
        assert!(!raw.wants(&item("message", Some(966))));
        assert!(raw.wants(&item("health", None)));
    }

    #[test]
    fn rejects_foreign_origins() {
        assert!(origin_allowed(None));
        assert!(origin_allowed(Some("http://localhost:3000")));
        assert!(!origin_allowed(Some("https://example.com")) && !origin_allowed(Some("http://localhost.evil.com")));
    }
}
