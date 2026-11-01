// Packet transforms, ported from Maple Scope's crypto.mjs (based on MapleLib and MapleSniffer, see THIRD_PARTY.md).
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes256;

use crate::iv_table::SHUFFLE;

pub const CLIENT_MASK: u16 = 223;
pub const SERVER_MASK: u16 = 65534;
const KEY: [u8; 32] = [
    0x0f, 0, 0, 0, 0x1b, 0, 0, 0, 0xc5, 0, 0, 0, 0x46, 0, 0, 0, 0xf3, 0, 0, 0, 0xbe, 0, 0, 0, 0xff, 0, 0, 0, 0x75, 0, 0, 0,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Client,
    Server,
}

impl Direction {
    pub fn mask(self) -> u16 {
        match self {
            Direction::Client => CLIENT_MASK,
            Direction::Server => SERVER_MASK,
        }
    }
}

pub fn next_iv(old: u32) -> u32 {
    let mut state: u32 = 0xc65053f2;
    for j in 0..4 {
        let v = ((old >> (j * 8)) & 255) as u8;
        let (mut a, mut b, mut c, mut d) = (state as u8, (state >> 8) as u8, (state >> 16) as u8, (state >> 24) as u8);
        a = a.wrapping_add(SHUFFLE[b as usize]).wrapping_sub(v);
        b = b.wrapping_sub(c ^ SHUFFLE[v as usize]);
        c = SHUFFLE[d as usize].wrapping_add(v) ^ c;
        d = d.wrapping_sub(a).wrapping_add(SHUFFLE[v as usize]);
        state = a as u32 | (b as u32) << 8 | (c as u32) << 16 | (d as u32) << 24;
        state = state.rotate_left(3);
    }
    state
}

pub fn transform(data: &[u8], iv: u32, direction: Direction) -> Vec<u8> {
    if direction == Direction::Server {
        let k = iv as u8;
        return data.iter().map(|x| x.wrapping_sub(k)).collect();
    }
    let cipher = Aes256::new(GenericArray::from_slice(&KEY));
    let mut out = data.to_vec();
    let (mut offset, mut chunk) = (0usize, 1456usize);
    while offset < out.len() {
        let mut stream = [0u8; 16];
        for i in 0..4 {
            stream[i * 4..i * 4 + 4].copy_from_slice(&iv.to_le_bytes());
        }
        let end = out.len().min(offset + chunk);
        for j in offset..end {
            if (j - offset) % 16 == 0 {
                let mut block = GenericArray::clone_from_slice(&stream);
                cipher.encrypt_block(&mut block);
                stream.copy_from_slice(&block);
            }
            out[j] ^= stream[(j - offset) % 16];
        }
        offset = end;
        chunk = 1460;
    }
    out
}

pub fn packet_length(b: &[u8], o: usize) -> Option<usize> {
    if b.len() < o + 4 {
        return None;
    }
    let a = u16::from_le_bytes([b[o], b[o + 1]]);
    let c = u16::from_le_bytes([b[o + 2], b[o + 3]]);
    Some((a ^ c) as usize)
}

/// Recovers the IV from at least three consecutive frame headers; ambiguous matches return None.
pub fn recover_iv(headers: &[u16], direction: Direction) -> Option<u32> {
    if headers.len() < 3 {
        return None;
    }
    let mask = direction.mask();
    let hi = ((headers[0] ^ mask) as u32) << 16;
    let mut candidate = None;
    for low in 0..65536u32 {
        let initial = hi | low;
        let mut iv = initial;
        let ok = headers.iter().take(5).all(|h| {
            let m = iv >> 16 == (h ^ mask) as u32;
            iv = next_iv(iv);
            m
        });
        if ok {
            if candidate.is_some() {
                return None;
            }
            candidate = Some(initial);
        }
    }
    candidate
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_transform_is_reversible_subtraction() {
        let plain = [1u8, 2, 3, 250];
        let iv = 0x1234_5605;
        let enc: Vec<u8> = plain.iter().map(|x| x.wrapping_add(5)).collect();
        assert_eq!(transform(&enc, iv, Direction::Server), plain);
    }

    #[test]
    fn client_transform_is_an_involution() {
        let plain: Vec<u8> = (0..3000u32).map(|i| (i * 7) as u8).collect();
        let enc = transform(&plain, 0xdeadbeef, Direction::Client);
        assert_ne!(enc, plain);
        assert_eq!(transform(&enc, 0xdeadbeef, Direction::Client), plain);
    }

    #[test]
    fn recovers_iv_from_synthetic_headers() {
        let start = 0x3a7c_19e2u32;
        let mut iv = start;
        let headers: Vec<u16> = (0..5)
            .map(|_| {
                let h = ((iv >> 16) as u16) ^ SERVER_MASK;
                iv = next_iv(iv);
                h
            })
            .collect();
        let got = recover_iv(&headers, Direction::Server).expect("iv");
        // Different low halves can share the same header chain; any match must reproduce it.
        let mut v = got;
        for h in &headers {
            assert_eq!(v >> 16, (h ^ SERVER_MASK) as u32);
            v = next_iv(v);
        }
        assert!(recover_iv(&headers[..2], Direction::Server).is_none());
    }
}
