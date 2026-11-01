// Passive capture with Windows Packet Monitor (pktmon) and its ETW provider. Requires administrator.
// Ownership: refuses to start if pktmon is already running or has filters from another tool, and
// removes only the filters it added.
use std::collections::HashSet;
use std::process::Command;
use std::sync::{mpsc, Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{TraceTrait, UserTrace};
use ferrisetw::EventRecord;

const PKTMON_PROVIDER: &str = "4d4f80d9-c8bd-4d73-bb5b-19c90402c5ac";
const PACKET_EVENT: u16 = 160;
// FILETIME ticks between 1601-01-01 and the Unix epoch.
const EPOCH_TICKS: i64 = 116_444_736_000_000_000;

fn run(exe: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(exe).args(args).output().with_context(|| format!("cannot start {exe}"))?;
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    if !out.status.success() {
        bail!("{exe} {}: {}", args.join(" "), text.trim());
    }
    Ok(text)
}

fn powershell(script: &str) -> Result<String> {
    run("powershell.exe", &["-NoProfile", "-Command", script])
}

pub fn find_process(name: &str) -> Result<u32> {
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        bail!("invalid process name");
    }
    let out = powershell(&format!("Get-Process {name} -ErrorAction Stop | Select-Object -First 1 -ExpandProperty Id"))?;
    out.trim().parse().map_err(|_| anyhow!("{name} is not running; open the game and enter the world first"))
}

pub fn process_alive(pid: u32) -> bool {
    powershell(&format!("Get-Process -Id {pid} -ErrorAction Stop | Out-Null")).is_ok()
}

/// Established remote TCP endpoints owned by the game process, excluding HTTPS.
pub fn endpoints(pid: u32) -> Result<Vec<(String, u16)>> {
    let raw = powershell(&format!(
        "Get-NetTCPConnection -OwningProcess {pid} -State Established -ErrorAction SilentlyContinue | ForEach-Object {{ \"$($_.RemoteAddress) $($_.RemotePort)\" }}"
    ))?;
    Ok(raw
        .lines()
        .filter_map(|l| {
            let (ip, port) = l.trim().split_once(' ')?;
            let port: u16 = port.parse().ok()?;
            (port != 443 && ip.parse::<std::net::Ipv4Addr>().is_ok()).then(|| (ip.to_string(), port))
        })
        .collect())
}

pub struct Capture {
    filters: Vec<String>,
    owned: bool,
    trace: Option<UserTrace>,
    pub known: Arc<Mutex<HashSet<String>>>,
    prefix: String,
}

impl Capture {
    /// Starts capture and returns frames as (timestamp ms, ethernet bytes) on `tx`.
    pub fn start(pid: u32, tx: mpsc::Sender<(f64, Vec<u8>)>) -> Result<Self> {
        let status = run("pktmon.exe", &["status"]).context("Administrator permission is required for packet capture")?;
        if !status.to_lowercase().contains("not running") {
            bail!("Packet Monitor is already running. Stop its current owner first.");
        }
        let filters = run("pktmon.exe", &["filter", "list"])?;
        if !filters.contains("None") {
            bail!("Packet Monitor has filters from another tool. Clear them in that tool first.");
        }
        let mut cap = Capture { filters: Vec::new(), owned: false, trace: None, known: Arc::default(), prefix: format!("GameFeed-{}", std::process::id()) };
        let eps = endpoints(pid)?;
        if eps.is_empty() {
            bail!("No established game TCP connection. Enter the game world and retry.");
        }
        for (ip, port) in eps {
            cap.add_endpoint(&ip, port)?;
        }
        let provider = Provider::by_guid(PKTMON_PROVIDER)
            .any(0x10)
            .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
                if record.event_id() != PACKET_EVENT {
                    return;
                }
                let Ok(schema) = locator.event_schema(record) else { return };
                let parser = Parser::create(record, &schema);
                if let Ok(payload) = parser.try_parse::<Vec<u8>>("Payload") {
                    let ts = (record.raw_timestamp() - EPOCH_TICKS) as f64 / 10_000.0;
                    let _ = tx.send((ts, payload));
                }
            })
            .build();
        let (trace, handle) = UserTrace::new().named(cap.prefix.clone()).enable(provider).start().map_err(|e| anyhow!("ETW session: {e:?}"))?;
        std::thread::spawn(move || {
            let _ = UserTrace::process_from_handle(handle);
        });
        cap.trace = Some(trace);
        let log = std::env::temp_dir().join(format!("{}.etl", cap.prefix));
        run(
            "pktmon.exe",
            &["start", "--capture", "--comp", "nics", "--pkt-size", "0", "--flags", "0x10", "--log-mode", "memory", "--file-size", "64", "--file-name", &log.to_string_lossy()],
        )?;
        cap.owned = true;
        Ok(cap)
    }

    pub fn add_endpoint(&mut self, ip: &str, port: u16) -> Result<bool> {
        let key = format!("{ip}:{port}");
        if !self.known.lock().unwrap().insert(key) {
            return Ok(false);
        }
        let name = format!("{}-{}", self.prefix, self.filters.len());
        run("pktmon.exe", &["filter", "add", &name, "-i", ip, "-t", "TCP", "-p", &port.to_string()])?;
        self.filters.push(name);
        Ok(true)
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        if self.owned {
            let _ = run("pktmon.exe", &["stop"]);
        }
        if let Some(trace) = self.trace.take() {
            let _ = trace.stop();
        }
        for name in &self.filters {
            let _ = run("pktmon.exe", &["filter", "remove", name]);
        }
        let _ = std::fs::remove_file(std::env::temp_dir().join(format!("{}.etl", self.prefix)));
    }
}
