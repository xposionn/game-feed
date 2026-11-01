// Typed events for observed messages, ported from Maple Scope's engine. Partial reverse engineering:
// layouts are guarded and fail closed; unknown fields stay unknown or are passed as raw hex.
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use serde_json::{json, Map, Value};

use crate::crypto::Direction;
use crate::stream::Message;

/// Monster species IDs and names, used to reject unrelated 966/978 layouts.
fn monsters() -> &'static HashMap<u32, Value> {
    static M: OnceLock<HashMap<u32, Value>> = OnceLock::new();
    M.get_or_init(|| {
        let raw: HashMap<String, Value> = serde_json::from_str(include_str!("../data/monsters.json")).unwrap_or_default();
        raw.into_iter().filter_map(|(k, v)| Some((k.parse().ok()?, v))).collect()
    })
}

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn i16le(b: &[u8], o: usize) -> i16 {
    i16::from_le_bytes([b[o], b[o + 1]])
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u64le(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn point(b: &[u8], o: usize) -> Value {
    json!({"x": i16le(b, o), "y": i16le(b, o + 2)})
}
/// Length-prefixed UTF-8 string; rejects control characters and invalid text.
fn string_at(b: &[u8], at: usize, max: usize) -> Option<(String, usize)> {
    if at + 2 > b.len() {
        return None;
    }
    let n = u16le(b, at) as usize;
    if n == 0 || n > max || at + 2 + n > b.len() {
        return None;
    }
    let s = std::str::from_utf8(&b[at + 2..at + 2 + n]).ok()?;
    if s.chars().any(|c| (c as u32) < 9) {
        return None;
    }
    Some((s.to_string(), at + 2 + n))
}
fn event(kind: &str, fields: Value) -> Value {
    let mut m = Map::new();
    m.insert("type".into(), json!(kind));
    if let Value::Object(f) = fields {
        m.extend(f);
    }
    Value::Object(m)
}

/// Client pickup request: opcode rotates, structure is stable. Byte 6 varies per connection.
pub fn is_pickup_request(b: &[u8]) -> bool {
    (b.len() == 31 || b.len() == 43) && u32le(b, 2) == 0 && [5000001, 5000004].contains(&u32le(b, 27)) && u32le(b, 19) > 0
}

/// Exact observed short map-load layout; other 422 variants carry full character state.
fn map_announcement(b: &[u8]) -> bool {
    b.len() == 103 && u16le(b, 46) == 2 && u32le(b, 48) == 100 && b[53] == 1 && b[67] == 1 && u32le(b, 68) == 0xffff_ffff
        && u32le(b, 80) == 999_999_999 && u32le(b, 84) == 999_999_999
}

// Movement profiles: fragment type -> width, per opcode.
fn movement_width(opcode: u16, kind: u8) -> Option<usize> {
    let base = match kind { 0 => Some(21), 1 => Some(9), 10 => Some(2), 12 => Some(11), 13 => Some(23), _ => None };
    let extra = match (opcode, kind) {
        (639, 3) => Some(9), (639, 8) => Some(21),
        (666, 2) => Some(9), (666, 3 | 6 | 9 | 11) => Some(15), (666, 28) => Some(5),
        (985, 2) => Some(9),
        _ => None,
    };
    base.or(extra)
}

fn movement(b: &[u8], opcode: u16) -> Option<Value> {
    let (count_at, start, footer, at) = match opcode { 639 => (22, 24, 0, 14), 666 => (18, 20, 0, 10), 985 => (38, 40, 1, 30), _ => return None };
    if b.len() < start + footer {
        return None;
    }
    let (count, end) = (b[count_at] as usize, b.len() - footer);
    let (mut offset, mut fragments) = (start, Vec::new());
    for _ in 0..count {
        let kind = *b.get(offset)?;
        let width = movement_width(opcode, kind)?;
        if offset >= end || offset + width > end {
            return None;
        }
        // Position is supported only for absolute fragments 0 and 13.
        let mut f = json!({"fragmentType": kind});
        if kind == 0 || kind == 13 {
            f["position"] = point(b, offset + 1);
        }
        fragments.push(f);
        offset += width;
    }
    if offset != end {
        return None;
    }
    let subject = match opcode { 985 => "monster", 639 => "pet-owner", _ => "actor" };
    Some(event("movement", json!({"subjectId": u32le(b, 2), "subjectKind": subject, "position": point(b, at), "fragments": fragments, "partial": true})))
}

/// Target structure of 677-679; hit values are raw (not named damage).
fn attack_targets(b: &[u8]) -> Option<Value> {
    if b.len() < 63 {
        return None;
    }
    let count = u32le(b, 51) as usize;
    if count > 32 {
        return None;
    }
    let (mut offset, mut targets) = (63usize, Vec::new());
    for _ in 0..count {
        if offset + 6 > b.len() {
            return None;
        }
        let (object_id, hits) = (u32le(b, offset), u16le(b, offset + 4) as usize);
        let width = 14 + 10 * hits;
        if hits > 32 || offset + width > b.len() {
            return None;
        }
        let raw: Vec<String> = (0..hits).map(|j| u64le(b, offset + 8 + j * 10).to_string()).collect();
        targets.push(json!({"objectId": object_id, "hitCount": hits, "rawHitValues": raw}));
        offset += width;
    }
    (offset == b.len()).then(|| json!(targets))
}

fn npc_catalog(b: &[u8]) -> Option<Value> {
    if b.len() < 23 || b[6..21].iter().any(|&x| x != 0) {
        return None;
    }
    let (npc_id, count) = (u32le(b, 2), u16le(b, 21) as usize);
    if npc_id == 0 || !(1..=256).contains(&count) {
        return None;
    }
    let (mut at, mut ordinal, mut buybacks, mut listings) = (23usize, 0u32, 0, Vec::new());
    for _ in 0..count {
        if at + 157 > b.len() {
            return None;
        }
        let (stock, index, item_id) = (u32le(b, at), u32le(b, at + 4), u32le(b, at + 8));
        let category = item_id / 10000;
        if !(1_000_000..=9_999_999).contains(&item_id) {
            return None;
        }
        // Personal buyback rows have a distinct layout and are never stock.
        if stock == 0 {
            if index != 0 || at + 198 > b.len() {
                return None;
            }
            buybacks += 1;
            at += 198;
            continue;
        }
        if buybacks > 0 || stock > 100_000 || index != ordinal || u32le(b, at + 16) != 100_000 {
            return None;
        }
        ordinal += 1;
        let size = if category == 207 { 163 } else { 157 };
        if ![200, 201, 203, 206, 207, 212, 400].contains(&category) || at + size > b.len() {
            return None;
        }
        let price = u64le(b, at + 36);
        // A zero price is not "free"; it is an unsupported recharge/unknown row.
        if price > 0 {
            listings.push(json!({"slot": index, "itemId": item_id, "price": price.to_string()}));
        }
        at += size;
    }
    (at == b.len()).then(|| event("npc_catalog", json!({"npcId": npc_id, "listings": listings, "excludedBuybackRows": buybacks})))
}

fn shop_listings(b: &[u8]) -> Option<Vec<Value>> {
    if b.len() < 8 || u32le(b, 2) != 0 {
        return None;
    }
    let count = u16le(b, 6) as usize;
    if count > 128 || (count == 0 && b.len() != 8) {
        return None;
    }
    let mut rows: Vec<(usize, Value, (u32, u16))> = Vec::new();
    let mut i = 30;
    while i + 20 <= b.len() {
        let item_id = u32le(b, i);
        let category = item_id / 1_000_000;
        let start = i - 22;
        if (1..=4).contains(&category) && b[i - 2] == 1 && b[i - 1] == if category == 1 { 1 } else { 2 } && b[i + 4] == 0 && u32le(b, i + 13) == 0xffff_ffff {
            let slot = u16le(b, start + 2);
            if u16le(b, start) as u32 == category && (1..=128).contains(&slot) {
                rows.push((start, json!({"itemId": item_id, "slot": slot, "available": u32le(b, start + 4), "bundle": u32le(b, start + 8), "price": u64le(b, start + 12).to_string()}), (category, slot)));
            }
        }
        i += 1;
    }
    let unique: HashSet<_> = rows.iter().map(|r| r.2).collect();
    if rows.len() != count || (count > 0 && rows[0].0 != 8) || unique.len() != count {
        return None;
    }
    Some(rows.into_iter().map(|r| r.1).collect())
}

fn shop_opening(b: &[u8]) -> Option<Value> {
    if b.len() < 70 || b.len() > 65536 || u32le(b, 2) != 2 || u32le(b, 10) != 3 {
        return None;
    }
    let (title, end) = string_at(b, 18, 120)?;
    if end + 14 > b.len() || u32le(b, end) != 2 {
        return None;
    }
    let actor_id = u32le(b, end + 4);
    let (owner, oend) = string_at(b, end + 12, 32)?;
    if oend + 4 > b.len() || u32le(b, oend) / 10000 != 514 {
        return None;
    }
    // Accept only one complete guarded listing section; several candidates are ambiguous.
    let mut found = Vec::new();
    for at in oend + 4..b.len().saturating_sub(2) {
        let count = u16le(b, at);
        if count == 0 || count > 128 {
            continue;
        }
        let mut data = vec![0x78, 5, 0, 0, 0, 0];
        data.extend_from_slice(&b[at..]);
        if let Some(rows) = shop_listings(&data) {
            found.push(rows);
        }
    }
    if found.len() != 1 {
        return None;
    }
    Some(event("player_shop_opened", json!({"shopObjectId": u32le(b, 14), "actorId": actor_id, "owner": owner, "title": title, "permitItemId": u32le(b, oend), "listings": found.pop()})))
}

fn shop_presence(b: &[u8]) -> Option<Value> {
    if b.len() < 100 {
        return None;
    }
    let (owner, oend) = string_at(b, 18, 32)?;
    let mut p = oend.max(b.len().saturating_sub(180));
    while p + 16 < b.len() {
        if u32le(b, p) == 3 && u32le(b, p + 8) == 2 {
            if let Some((title, tend)) = string_at(b, p + 12, 120) {
                if tend + 43 == b.len() && u32le(b, tend) / 10000 == 514 {
                    return Some(event("player_shop_seen", json!({"actorId": u32le(b, 6), "owner": owner, "title": title, "shopObjectId": u32le(b, p + 4), "permitItemId": u32le(b, tend)})));
                }
            }
        }
        p += 1;
    }
    None
}

#[derive(Default)]
pub struct EventDecoder {
    seen_drops: HashSet<(String, u32)>,
    spawned: HashSet<(String, u32)>,
    kill_candidates: HashMap<u32, (u32, u32, f64)>,
    deaths: HashMap<u32, f64>,
    killed: HashSet<u32>,
}

impl EventDecoder {
    /// Decodes one message into zero or more events.
    pub fn decode(&mut self, m: &Message) -> Vec<Value> {
        let Some(op) = m.opcode else { return vec![] };
        let b = &m.data;
        if m.direction == Direction::Client {
            return self.client(op, b).into_iter().collect();
        }
        let mut out = Vec::new();
        match op {
            422 if map_announcement(b) => {
                // u32@10 equals server port - 8540 in every observed sample; the displayed number is unconfirmed.
                out.push(event("map_loaded", json!({"mapId": u32le(b, 36), "channelIndex": u32le(b, 10), "channelEvidence": "port-correlated-unconfirmed"})));
            }
            167 if b.len() >= 569 => out.push(event("map_candidate", json!({"mapId": u32le(b, 565), "evidence": "needs-422-agreement"}))),
            554 if b.len() >= 20 => {
                let len = u16le(b, 18) as usize;
                if (2..=32).contains(&len) && 20 + len <= b.len() {
                    if let Ok(name) = std::str::from_utf8(&b[20..20 + len]) {
                        if name.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') && (2..=24).contains(&name.chars().count()) {
                            out.push(event("player_seen", json!({"actorId": u32le(b, 6), "name": name, "scope": "client-visibility"})));
                        }
                    }
                }
                out.extend(shop_presence(b));
            }
            555 if b.len() == 6 => out.push(event("player_left", json!({"actorId": u32le(b, 2), "scope": "client-visibility"}))),
            677..=679 if b.len() >= 12 && u32le(b, 2) != 0 => {
                let mut e = event("skill_observed", json!({"actorId": u32le(b, 2), "skillId": u32le(b, 8), "partial": true}));
                if let Some(t) = attack_targets(b) {
                    e["targets"] = t;
                }
                out.push(e);
            }
            966 | 978 if b.len() >= 12 => {
                let (object_id, species) = (u32le(b, 3), u32le(b, 8));
                if let Some(mob) = monsters().get(&species) {
                    if self.spawned.insert((m.flow.clone(), object_id)) {
                        out.push(event("monster_spawn", json!({"objectId": object_id, "speciesId": species, "name": mob["name"], "level": mob["level"]})));
                    }
                }
            }
            1098 if b.len() >= 14 => {
                let (object_id, actor, job) = (u32le(b, 2), u32le(b, 6), u32le(b, 10));
                self.kill_candidates.insert(object_id, (actor, job, m.ts));
                out.extend(self.match_kill(object_id));
            }
            977 if b.len() >= 6 => {
                let object_id = u32le(b, 2);
                self.deaths.insert(object_id, m.ts);
                self.spawned.remove(&(m.flow.clone(), object_id));
                out.push(event("monster_removed", json!({"objectId": object_id})));
                out.extend(self.match_kill(object_id));
            }
            985 | 639 | 666 => out.extend(movement(b, op)),
            996 if b.len() == 28 => out.push(event("object_counter", json!({"objectId": u32le(b, 2), "counter": u16le(b, 6), "partial": true}))),
            1134 if b.len() >= 46 => {
                let drop_id = u32le(b, 4);
                // The server repeats a definition (spawn animation, then landed); report the first.
                if self.seen_drops.insert((m.flow.clone(), drop_id)) {
                    let value = u32le(b, 21);
                    let currency = b[8] == 1 && value < 1_000_000;
                    // Byte 29 follows a 4-byte owner field; owner types 0 and 1 both carry landing coordinates.
                    let position = ((b.len() == 115 || b.len() == 123) && b[2] == 0 && b[29] <= 1).then(|| point(b, 30));
                    out.push(event("drop", json!({"dropId": drop_id, "itemId": (!currency).then_some(value), "amount": currency.then_some(value), "currency": currency, "sourceObject": u32le(b, 42), "position": position})));
                }
            }
            1135 if b.len() >= 7 => {
                let drop_id = u32le(b, 2);
                self.seen_drops.remove(&(m.flow.clone(), drop_id));
                if b[6] == 5 && b.len() >= 11 {
                    out.push(event("pickup", json!({"dropId": drop_id, "actorId": u32le(b, 7)})));
                } else {
                    // A removal without mode 5 is not proof of collection.
                    out.push(event("drop_removed", json!({"dropId": drop_id, "mode": b[6]})));
                }
            }
            126 if b.len() >= 13 => {
                let mask = u32le(b, 5);
                let values = match mask {
                    1024 => Some(json!({"hp": u32le(b, 9)})),
                    4096 => Some(json!({"mp": u32le(b, 9)})),
                    5120 if b.len() >= 17 => Some(json!({"hp": u32le(b, 9), "mp": u32le(b, 13)})),
                    65536 if b.len() >= 17 => Some(json!({"exp": u64le(b, 9)})),
                    262144 if b.len() >= 17 => Some(json!({"mesos": u64le(b, 9)})),
                    // Unknown or zero masks do not invent stats.
                    _ => None,
                };
                out.extend(values.map(|v| event("stat", json!({"mask": mask, "values": v}))));
            }
            114 => out.push(event("inventory_changed", json!({"operationCount": (b.len() >= 9).then(|| u32le(b, 4)), "partial": true, "hex": hex::encode(&b[2..])}))),
            174 if b.len() >= 5 => {
                let n = u16le(b, 3) as usize;
                if n <= b.len() - 5 {
                    out.push(event("chat", json!({"chatType": b[2], "message": String::from_utf8_lossy(&b[5..5 + n])})));
                }
            }
            1103 if b.len() == 66 && b[14..22].iter().all(|&x| x == 255) => {
                let (object_id, npc_id) = (u32le(b, 2), u32le(b, 6));
                if object_id != 0 && npc_id != 0 && npc_id <= 99_999_999 {
                    out.push(event("npc_spawn", json!({"objectId": object_id, "npcId": npc_id, "position": point(b, 10)})));
                }
            }
            1373 => out.extend(npc_catalog(b)),
            1399 => out.extend(shop_opening(b)),
            // Changed 1400 lists are not bound to a shop yet; listings are reported unattributed.
            1400 => out.extend(shop_listings(b).map(|rows| event("player_shop_listings", json!({"listings": rows, "shopBinding": "unattributed"})))),
            _ => {}
        }
        out
    }

    fn client(&mut self, op: u16, b: &[u8]) -> Option<Value> {
        if (op == 45093 && b.len() >= 23) || is_pickup_request(b) {
            return Some(event("pickup_request", json!({"dropId": u32le(b, 19), "layout": if op == 45093 { "legacy" } else { "structure" }})));
        }
        match op {
            59331 if b.len() >= 9 => Some(event("attack", json!({"skillId": u32le(b, 4), "rank": b[8], "targetId": (b.len() >= 142).then(|| u32le(b, 138))}))),
            8404 if b.len() >= 6 => Some(event("skill_use", json!({"skillId": u32le(b, 2)}))),
            39594 if b.len() >= 12 => Some(event("item_use", json!({"itemId": u32le(b, 8), "slot": u16le(b, 6)}))),
            _ => None,
        }
    }

    /// A kill needs both the attribution (1098) and the removal (977) within one second.
    fn match_kill(&mut self, object_id: u32) -> Option<Value> {
        let (actor, job, ts) = *self.kill_candidates.get(&object_id)?;
        let death = *self.deaths.get(&object_id)?;
        if (ts - death).abs() > 1000.0 || !self.killed.insert(object_id) {
            return None;
        }
        // Bound memory on long sessions.
        if self.killed.len() > 100_000 {
            self.killed.clear();
            self.kill_candidates.clear();
            self.deaths.clear();
        }
        Some(event("kill", json!({"objectId": object_id, "actorId": actor, "jobId": job, "evidence": "1098+977"})))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(direction: Direction, opcode: u16, data: Vec<u8>, ts: f64) -> Message {
        Message { direction, opcode: Some(opcode), flow: "f".into(), server_port: 8553, ts, data }
    }
    fn server(opcode: u16, len: usize) -> Vec<u8> {
        let mut b = vec![0u8; len];
        b[0..2].copy_from_slice(&opcode.to_le_bytes());
        b
    }
    fn types(v: &[Value]) -> Vec<&str> {
        v.iter().map(|e| e["type"].as_str().unwrap()).collect()
    }

    #[test]
    fn drop_reported_once_with_position_then_confirmed_pickup() {
        let mut b = server(1134, 115);
        b[4..8].copy_from_slice(&77u32.to_le_bytes());
        b[21..25].copy_from_slice(&4000015u32.to_le_bytes());
        b[30..32].copy_from_slice(&(-491i16).to_le_bytes());
        b[32..34].copy_from_slice(&1459i16.to_le_bytes());
        let mut d = EventDecoder::default();
        let first = d.decode(&msg(Direction::Server, 1134, b.clone(), 0.0));
        assert_eq!(first[0]["itemId"], 4000015);
        assert_eq!(first[0]["position"], json!({"x": -491, "y": 1459}));
        assert!(d.decode(&msg(Direction::Server, 1134, b, 0.0)).is_empty());
        let mut p = server(1135, 15);
        p[2..6].copy_from_slice(&77u32.to_le_bytes());
        p[6] = 5;
        p[7..11].copy_from_slice(&46756u32.to_le_bytes());
        assert_eq!(d.decode(&msg(Direction::Server, 1135, p, 0.0))[0], json!({"type": "pickup", "dropId": 77, "actorId": 46756}));
    }

    #[test]
    fn unobserved_owner_type_keeps_position_unknown() {
        let mut b = server(1134, 123);
        b[29] = 6;
        assert_eq!(EventDecoder::default().decode(&msg(Direction::Server, 1134, b, 0.0))[0]["position"], Value::Null);
    }

    #[test]
    fn kill_requires_attribution_and_removal_within_one_second() {
        let mut d = EventDecoder::default();
        let mut a = server(1098, 14);
        a[2..6].copy_from_slice(&9u32.to_le_bytes());
        a[6..10].copy_from_slice(&111u32.to_le_bytes());
        assert!(types(&d.decode(&msg(Direction::Server, 1098, a.clone(), 1000.0))).is_empty());
        let mut r = server(977, 6);
        r[2..6].copy_from_slice(&9u32.to_le_bytes());
        assert_eq!(types(&d.decode(&msg(Direction::Server, 977, r.clone(), 1500.0))), ["monster_removed", "kill"]);
        let mut late = EventDecoder::default();
        late.decode(&msg(Direction::Server, 1098, a, 1000.0));
        assert_eq!(types(&late.decode(&msg(Direction::Server, 977, r, 3000.0))), ["monster_removed"]);
    }

    #[test]
    fn stats_decode_known_masks_only() {
        let mut d = EventDecoder::default();
        let mut b = server(126, 17);
        b[5..9].copy_from_slice(&5120u32.to_le_bytes());
        b[9..13].copy_from_slice(&500u32.to_le_bytes());
        b[13..17].copy_from_slice(&300u32.to_le_bytes());
        assert_eq!(d.decode(&msg(Direction::Server, 126, b.clone(), 0.0))[0]["values"], json!({"hp": 500, "mp": 300}));
        b[5..9].copy_from_slice(&7u32.to_le_bytes());
        assert!(d.decode(&msg(Direction::Server, 126, b, 0.0)).is_empty());
    }

    #[test]
    fn map_load_requires_exact_layout() {
        let mut b = server(422, 103);
        b[10..14].copy_from_slice(&12u32.to_le_bytes());
        b[36..40].copy_from_slice(&10004113u32.to_le_bytes());
        b[46..48].copy_from_slice(&2u16.to_le_bytes());
        b[48..52].copy_from_slice(&100u32.to_le_bytes());
        b[53] = 1;
        b[67] = 1;
        b[68..72].copy_from_slice(&u32::MAX.to_le_bytes());
        b[80..84].copy_from_slice(&999_999_999u32.to_le_bytes());
        b[84..88].copy_from_slice(&999_999_999u32.to_le_bytes());
        let mut d = EventDecoder::default();
        let e = d.decode(&msg(Direction::Server, 422, b.clone(), 0.0));
        assert_eq!((e[0]["mapId"].as_u64(), e[0]["channelIndex"].as_u64()), (Some(10004113), Some(12)));
        b[53] = 0;
        assert!(d.decode(&msg(Direction::Server, 422, b, 0.0)).is_empty());
    }

    #[test]
    fn players_and_chat() {
        let mut d = EventDecoder::default();
        let mut b = server(554, 26);
        b[6..10].copy_from_slice(&222u32.to_le_bytes());
        b[18..20].copy_from_slice(&6u16.to_le_bytes());
        b[20..26].copy_from_slice(b"Hunter");
        assert_eq!(d.decode(&msg(Direction::Server, 554, b, 0.0))[0]["name"], "Hunter");
        let mut c = server(174, 7);
        c[3..5].copy_from_slice(&2u16.to_le_bytes());
        c[5..7].copy_from_slice(b"hi");
        assert_eq!(d.decode(&msg(Direction::Server, 174, c, 0.0))[0]["message"], "hi");
    }

    #[test]
    fn client_pickup_request_and_unknown_marker() {
        let mut d = EventDecoder::default();
        let mut b = vec![0u8; 31];
        b[6] = 21;
        b[19..23].copy_from_slice(&7u32.to_le_bytes());
        b[27..31].copy_from_slice(&5000001u32.to_le_bytes());
        assert_eq!(d.decode(&msg(Direction::Client, 60067, b.clone(), 0.0))[0]["dropId"], 7);
        b[27..31].copy_from_slice(&5000002u32.to_le_bytes());
        assert!(d.decode(&msg(Direction::Client, 60067, b, 0.0)).is_empty());
    }
}
