// game-feed: passive, read-only decoder that streams decoded game traffic over a loopback WebSocket.
// No injection, memory reads, packet sending/replay to the game, or input automation.
mod crypto;
mod events;
mod feed;
mod iv_table;
mod pcapng;
mod stream;
mod tcp;
#[cfg(windows)]
mod capture;

use std::collections::HashSet;
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{bail, Result};
use serde_json::json;
use tokio::sync::broadcast;

use events::EventDecoder;
use feed::Item;
use tcp::{Decoder, Output};

const USAGE: &str = "usage:
  game-feed live   [--port 4500] [--process MapleStory]   (run as administrator)
  game-feed replay <capture.pcapng> [--endpoint IP:PORT ...] [--port 4500] [--stdout]";

struct Pipeline {
    decoder: Decoder,
    events: EventDecoder,
    tx: broadcast::Sender<Item>,
    stdout: bool,
}

impl Pipeline {
    fn publish(&self, item: Item) {
        if self.stdout {
            println!("{}", item.json);
        }
        let _ = self.tx.send(item);
    }
    fn emit(&mut self, out: Vec<Output>) {
        for o in out {
            match o {
                Output::Health(h) => self.publish(Item { kind: "health", opcode: None, json: json!({"kind":"health", "health": h}) }),
                Output::Message(m) => {
                    for e in self.events.decode(&m) {
                        self.publish(Item { kind: "event", opcode: m.opcode, json: json!({"kind":"event","opcode":m.opcode,"ts":m.ts,"flow":m.flow,"serverPort":m.server_port,"event":e}) });
                    }
                    let mut v = serde_json::to_value(&m).unwrap_or_default();
                    v["kind"] = json!("message");
                    v["hex"] = json!(hex::encode(&m.data));
                    self.publish(Item { kind: "message", opcode: m.opcode, json: v });
                }
            }
        }
    }
    fn frame(&mut self, ts: f64, bytes: &[u8], endpoints: &HashSet<String>) {
        if let Some(seg) = tcp::ethernet_tcp(bytes, ts, endpoints) {
            let mut out = Vec::new();
            self.decoder.push(seg, &mut out);
            self.emit(out);
        }
    }
    fn tick(&mut self, force: bool) {
        let mut out = Vec::new();
        self.decoder.tick(force, &mut out);
        self.emit(out);
    }
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let port: u16 = flag(&args, "--port").map(|p| p.parse()).transpose()?.unwrap_or(4500);
    let (tx, _) = broadcast::channel::<Item>(8192);
    let mut pipe = Pipeline { decoder: Decoder::default(), events: EventDecoder::default(), tx: tx.clone(), stdout: args.iter().any(|a| a == "--stdout") };
    match args.first().map(String::as_str) {
        Some("replay") => {
            let Some(file) = args.get(1) else { bail!(USAGE) };
            let bytes = std::fs::read(file)?;
            if !pipe.stdout {
                tokio::spawn(feed::serve(port, tx.clone()));
                // Give dashboards a moment to connect before replaying.
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            // Server endpoints (ip:port); without them only the default game ports are decoded.
            let endpoints: HashSet<String> = args.windows(2).filter(|w| w[0] == "--endpoint").map(|w| w[1].clone()).collect();
            for (ts, frame) in pcapng::packets(&bytes)? {
                pipe.frame(ts, frame, &endpoints);
            }
            pipe.tick(true);
            eprintln!("replay: done (gaps {}, duplicates {})", pipe.decoder.gaps, pipe.decoder.duplicates);
            if !pipe.stdout {
                tokio::signal::ctrl_c().await?;
            }
            Ok(())
        }
        #[cfg(windows)]
        Some("live") => live(pipe, port, flag(&args, "--process").unwrap_or_else(|| "MapleStory".into())).await,
        _ => bail!(USAGE),
    }
}

#[cfg(windows)]
async fn live(mut pipe: Pipeline, port: u16, process: String) -> Result<()> {
    let pid = capture::find_process(&process)?;
    let (ftx, frx) = mpsc::channel::<(f64, Vec<u8>)>();
    let mut cap = capture::Capture::start(pid, ftx)?;
    let known = cap.known.clone();
    tokio::spawn(feed::serve(port, pipe.tx.clone()));
    pipe.publish(Item { kind: "status", opcode: None, json: json!({"kind":"status","state":"capturing","processId":pid}) });
    eprintln!("live: capturing process {pid}; Ctrl+C stops and removes this tool's pktmon filters");

    // Frames arrive from the ETW thread; decode them on a blocking worker to keep the feed responsive.
    let worker = tokio::task::spawn_blocking(move || {
        let mut last_tick = std::time::Instant::now();
        loop {
            match frx.recv_timeout(Duration::from_millis(100)) {
                Ok((ts, bytes)) => {
                    let eps = known.lock().unwrap().clone();
                    pipe.frame(ts, &bytes, &eps);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            if last_tick.elapsed() >= Duration::from_millis(100) {
                pipe.tick(false);
                last_tick = std::time::Instant::now();
            }
        }
        pipe.tick(true);
    });

    let mut refresh = tokio::time::interval(Duration::from_secs(10));
    refresh.tick().await;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = refresh.tick() => {
                if !capture::process_alive(pid) { eprintln!("live: game process exited"); break; }
                // Channel changes open new connections; follow only endpoints owned by the game.
                if let Ok(eps) = capture::endpoints(pid) {
                    for (ip, p) in eps {
                        match cap.add_endpoint(&ip, p) {
                            Ok(true) => eprintln!("live: following new endpoint {ip}:{p}"),
                            Ok(false) => {}
                            Err(e) => eprintln!("live: endpoint refresh: {e}"),
                        }
                    }
                }
            }
        }
    }
    drop(cap);
    let _ = tokio::time::timeout(Duration::from_secs(3), worker).await;
    eprintln!("live: stopped");
    Ok(())
}
