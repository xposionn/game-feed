// Minimal PCAPNG reader for offline replay (Enhanced Packet Blocks only).
use anyhow::{bail, Result};

/// Yields (timestamp ms, frame bytes) for each Enhanced Packet Block, assuming microsecond resolution.
pub fn packets(b: &[u8]) -> Result<Vec<(f64, &[u8])>> {
    let rd = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
    let (mut o, mut out) = (0usize, Vec::new());
    while o + 12 <= b.len() {
        let (kind, n) = (rd(o), rd(o + 4) as usize);
        if n < 12 || o + n > b.len() {
            bail!("Invalid or incomplete PCAPNG file");
        }
        if kind == 6 && n >= 32 {
            let cap = rd(o + 20) as usize;
            if cap > n - 32 {
                bail!("Invalid packet length");
            }
            let ts = (rd(o + 12) as f64 * 4294967296.0 + rd(o + 16) as f64) / 1000.0;
            out.push((ts, &b[o + 28..o + 28 + cap]));
        }
        o += n;
    }
    Ok(out)
}
