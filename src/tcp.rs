// Ethernet/IPv4/TCP parsing and per-flow reassembly, ported from Maple Scope's packets.mjs.
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Instant;

use crate::crypto::Direction;
use crate::stream::{Health, Message, ProtocolStream};

#[derive(Clone, Debug)]
pub struct Segment {
    pub direction: Direction,
    pub server_port: u16,
    pub flow: String,
    pub seq: u32,
    pub data: Vec<u8>,
    pub ts: f64,
}

/// Default game ports when no endpoint list is known.
const DEFAULT_PORTS: [u16; 2] = [8551, 8553];

pub fn ethernet_tcp(p: &[u8], ts: f64, endpoints: &HashSet<String>) -> Option<Segment> {
    if p.len() < 54 {
        return None;
    }
    let be16 = |o: usize| u16::from_be_bytes([p[o], p[o + 1]]);
    let (mut ip, mut kind) = (14usize, be16(12));
    if kind == 0x8100 && p.len() > 58 {
        kind = be16(16);
        ip = 18;
    }
    if kind != 0x800 || p[ip] >> 4 != 4 || p[ip + 9] != 6 {
        return None;
    }
    let tcp = ip + (p[ip] & 15) as usize * 4;
    if tcp + 20 > p.len() {
        return None;
    }
    let (sp, dp) = (be16(tcp), be16(tcp + 2));
    let addr = |o: usize| format!("{}.{}.{}.{}", p[o], p[o + 1], p[o + 2], p[o + 3]);
    let (src, dst) = (addr(ip + 12), addr(ip + 16));
    let known = |a: &str, port: u16| {
        if endpoints.is_empty() { DEFAULT_PORTS.contains(&port) } else { endpoints.contains(&format!("{a}:{port}")) }
    };
    let (source_known, dest_known) = (known(&src, sp), known(&dst, dp));
    if !source_known && !dest_known {
        return None;
    }
    let start = tcp + (p[tcp + 12] >> 4) as usize * 4;
    let end = p.len().min(ip + be16(ip + 2) as usize);
    if start >= end {
        return None;
    }
    Some(Segment {
        direction: if source_known { Direction::Server } else { Direction::Client },
        server_port: if source_known { sp } else { dp },
        flow: format!("{src}:{sp}>{dst}:{dp}"),
        seq: u32::from_be_bytes([p[tcp + 4], p[tcp + 5], p[tcp + 6], p[tcp + 7]]),
        data: p[start..end].to_vec(),
        ts,
    })
}

struct Flow {
    next: u64,
    pending: BTreeMap<u64, Segment>,
    stream: ProtocolStream,
    gap_at: Option<Instant>,
}

/// Reassembles TCP flows and reports gaps explicitly instead of guessing missing bytes.
#[derive(Default)]
pub struct Decoder {
    flows: HashMap<String, Flow>,
    pub gaps: u64,
    pub duplicates: u64,
}

pub enum Output {
    Message(Message),
    Health(Health),
}

impl Decoder {
    pub fn push(&mut self, p: Segment, out: &mut Vec<Output>) {
        let f = self.flows.entry(p.flow.clone()).or_insert_with(|| Flow {
            next: p.seq as u64,
            pending: BTreeMap::new(),
            stream: ProtocolStream::new(p.direction, p.flow.clone(), p.server_port),
            gap_at: None,
        });
        let mut seq = (f.next & !0xffff_ffff) | p.seq as u64;
        if seq > f.next && seq - f.next > 0x8000_0000 {
            seq = seq.wrapping_sub(1 << 32);
        } else if f.next > seq && f.next - seq > 0x8000_0000 {
            seq += 1 << 32;
        }
        let mut data = p.data.clone();
        if seq < f.next {
            let skip = (f.next - seq) as usize;
            if skip >= data.len() {
                self.duplicates += 1;
                return;
            }
            data.drain(..skip);
            seq = f.next;
        }
        if seq > f.next {
            f.pending.insert(seq, Segment { data, ..p });
            f.gap_at.get_or_insert_with(Instant::now);
            if f.pending.len() > 100 {
                Self::flush_gap(f, &mut self.gaps, out);
            }
            return;
        }
        Self::consume(f, &data, p.ts, out);
        Self::drain(f, out);
    }

    fn consume(f: &mut Flow, data: &[u8], ts: f64, out: &mut Vec<Output>) {
        f.stream.push(data, ts, out);
        f.next += data.len() as u64;
    }

    fn drain(f: &mut Flow, out: &mut Vec<Output>) {
        while let Some((&key, _)) = f.pending.first_key_value() {
            if key > f.next {
                break;
            }
            let p = f.pending.remove(&key).unwrap();
            let skip = (f.next - key) as usize;
            if skip < p.data.len() {
                Self::consume(f, &p.data[skip..], p.ts, out);
            }
        }
        if f.pending.is_empty() {
            f.gap_at = None;
        }
    }

    fn flush_gap(f: &mut Flow, gaps: &mut u64, out: &mut Vec<Output>) {
        let Some((&first, _)) = f.pending.first_key_value() else { return };
        *gaps += 1;
        out.push(Output::Health(Health {
            kind: "capture_gap",
            direction: f.stream.direction,
            flow: f.stream.flow.clone(),
            message: format!("Missing {} TCP bytes", first - f.next),
        }));
        f.stream.gap();
        f.next = first;
        f.gap_at = None;
        Self::drain(f, out);
    }

    /// Declares gaps for flows that waited too long for missing segments.
    pub fn tick(&mut self, force: bool, out: &mut Vec<Output>) {
        for f in self.flows.values_mut() {
            if !f.pending.is_empty() && (force || f.gap_at.is_some_and(|t| t.elapsed().as_millis() > 350)) {
                Self::flush_gap(f, &mut self.gaps, out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(sp: u16, dp: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 54];
        b[12..14].copy_from_slice(&0x800u16.to_be_bytes());
        b[14] = 0x45;
        b[23] = 6;
        b[16..18].copy_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
        b[26..30].copy_from_slice(&[10, 1, 1, 1]);
        b[30..34].copy_from_slice(&[10, 1, 1, 2]);
        b[34..36].copy_from_slice(&sp.to_be_bytes());
        b[36..38].copy_from_slice(&dp.to_be_bytes());
        b[38..42].copy_from_slice(&seq.to_be_bytes());
        b[46] = 0x50;
        b.extend_from_slice(payload);
        b
    }

    #[test]
    fn classifies_direction_by_known_port_or_endpoint() {
        let none = HashSet::new();
        assert_eq!(ethernet_tcp(&frame(8553, 40000, 1, b"x"), 0.0, &none).unwrap().direction, Direction::Server);
        assert_eq!(ethernet_tcp(&frame(40000, 8553, 1, b"x"), 0.0, &none).unwrap().direction, Direction::Client);
        assert!(ethernet_tcp(&frame(443, 40000, 1, b"x"), 0.0, &none).is_none());
        let eps: HashSet<String> = ["10.1.1.1:8666".to_string()].into();
        assert_eq!(ethernet_tcp(&frame(8666, 40000, 1, b"x"), 0.0, &eps).unwrap().server_port, 8666);
        assert!(ethernet_tcp(&frame(8553, 40000, 1, b"x"), 0.0, &eps).is_none());
    }

    #[test]
    fn out_of_order_segments_wait_and_duplicates_are_dropped() {
        let none = HashSet::new();
        let mut d = Decoder::default();
        let mut out = Vec::new();
        d.push(ethernet_tcp(&frame(8553, 40000, 100, b"ab"), 0.0, &none).unwrap(), &mut out);
        d.push(ethernet_tcp(&frame(8553, 40000, 104, b"ef"), 0.0, &none).unwrap(), &mut out);
        d.push(ethernet_tcp(&frame(8553, 40000, 100, b"ab"), 0.0, &none).unwrap(), &mut out);
        assert_eq!(d.duplicates, 1);
        d.tick(true, &mut out);
        assert_eq!(d.gaps, 1);
        assert!(out.iter().any(|o| matches!(o, Output::Health(h) if h.kind == "capture_gap")));
    }
}
