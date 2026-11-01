// Frame synchronization and decryption for one TCP direction, ported from Maple Scope's packets.mjs.
use serde::Serialize;

use crate::crypto::{next_iv, packet_length, recover_iv, transform, Direction};
use crate::tcp::Output;

#[derive(Clone, Debug, Serialize)]
pub struct Message {
    pub direction: Direction,
    pub opcode: Option<u16>,
    pub flow: String,
    #[serde(rename = "serverPort")]
    pub server_port: u16,
    pub ts: f64,
    #[serde(skip)]
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Health {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub direction: Direction,
    pub flow: String,
    pub message: String,
}

pub struct ProtocolStream {
    pub direction: Direction,
    pub flow: String,
    server_port: u16,
    buffer: Vec<u8>,
    iv: Option<u32>,
    last_time: f64,
}

const MAX_FRAME: usize = 1_000_000;

impl ProtocolStream {
    pub fn new(direction: Direction, flow: String, server_port: u16) -> Self {
        Self { direction, flow, server_port, buffer: Vec::new(), iv: None, last_time: 0.0 }
    }

    pub fn gap(&mut self) {
        self.buffer.clear();
        self.iv = None;
    }

    fn health(&self, kind: &'static str, message: &str) -> Output {
        Output::Health(Health { kind, direction: self.direction, flow: self.flow.clone(), message: message.into() })
    }

    pub fn push(&mut self, data: &[u8], ts: f64, out: &mut Vec<Output>) {
        self.last_time = ts;
        self.buffer.extend_from_slice(data);
        if self.buffer.len() > 2_000_000 {
            self.gap();
            out.push(self.health("decoder_reset", "Decoder buffer limit reached"));
            return;
        }
        self.drain(out);
    }

    fn sync(&mut self, out: &mut Vec<Output>) -> bool {
        let limit = self.buffer.len().min(4096);
        for start in 0..limit {
            let (mut offset, mut headers) = (start, Vec::new());
            while offset + 4 <= self.buffer.len() && headers.len() < 5 {
                match packet_length(&self.buffer, offset) {
                    Some(n) if n > 0 && n <= MAX_FRAME && offset + 4 + n <= self.buffer.len() => {
                        headers.push(u16::from_le_bytes([self.buffer[offset], self.buffer[offset + 1]]));
                        offset += 4 + n;
                    }
                    _ => break,
                }
            }
            if headers.len() < 3 {
                continue;
            }
            if let Some(iv) = recover_iv(&headers, self.direction) {
                self.buffer.drain(..start);
                self.iv = Some(iv);
                out.push(self.health("decoder_sync", "Cipher synchronized"));
                return true;
            }
        }
        false
    }

    fn drain(&mut self, out: &mut Vec<Output>) {
        loop {
            if self.iv.is_none() && !self.sync(out) {
                return;
            }
            let mask = self.direction.mask();
            while self.buffer.len() >= 4 {
                let iv = self.iv.unwrap();
                let header = u16::from_le_bytes([self.buffer[0], self.buffer[1]]);
                let n = packet_length(&self.buffer, 0).unwrap_or(0);
                if n == 0 || n > MAX_FRAME || iv >> 16 != (header ^ mask) as u32 {
                    self.iv = None;
                    self.buffer.drain(..1);
                    out.push(self.health("decoder_desync", "Cipher resynchronizing"));
                    break;
                }
                if self.buffer.len() < n + 4 {
                    return;
                }
                let body = transform(&self.buffer[4..4 + n], iv, self.direction);
                out.push(Output::Message(Message {
                    direction: self.direction,
                    opcode: (body.len() >= 2).then(|| u16::from_le_bytes([body[0], body[1]])),
                    flow: self.flow.clone(),
                    server_port: self.server_port,
                    ts: self.last_time,
                    data: body,
                }));
                self.buffer.drain(..n + 4);
                self.iv = Some(next_iv(iv));
            }
            if self.iv.is_some() || self.buffer.len() < 4 {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SERVER_MASK;

    /// Builds synthetic encrypted server frames with the documented header layout.
    fn encode(frames: &[&[u8]], mut iv: u32) -> Vec<u8> {
        let mut out = Vec::new();
        for body in frames {
            let header = ((iv >> 16) as u16) ^ SERVER_MASK;
            out.extend_from_slice(&header.to_le_bytes());
            out.extend_from_slice(&(header ^ body.len() as u16).to_le_bytes());
            out.extend(body.iter().map(|x| x.wrapping_add(iv as u8)));
            iv = next_iv(iv);
        }
        out
    }

    #[test]
    fn synchronizes_and_decodes_synthetic_frames() {
        let bodies: Vec<Vec<u8>> = (0..6u16).map(|i| [(1134 + i).to_le_bytes().to_vec(), vec![i as u8; 10]].concat()).collect();
        let refs: Vec<&[u8]> = bodies.iter().map(|b| b.as_slice()).collect();
        let wire = encode(&refs, 0x5c21_9e07);
        let mut s = ProtocolStream::new(Direction::Server, "f".into(), 8553);
        let mut out = Vec::new();
        s.push(&wire, 1.0, &mut out);
        let messages: Vec<&Message> = out.iter().filter_map(|o| if let Output::Message(m) = o { Some(m) } else { None }).collect();
        assert_eq!(messages.len(), 6);
        assert_eq!(messages[0].opcode, Some(1134));
        assert_eq!(messages[5].data, bodies[5]);
    }
}
