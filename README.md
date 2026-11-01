# game-feed

Passive, read-only decoder for MapleStory Classic World traffic. It streams decoded messages and typed events over a WebSocket on `127.0.0.1`, for local dashboards.

It does not inject into the game, read its memory, send or replay packets, or automate input. The WebSocket accepts no commands.

## Build

Requires Windows, Rust (MSVC toolchain) and Visual Studio Build Tools with the C++ workload.

```powershell
cargo build --release
cargo test
```

## Run

Live capture uses Windows Packet Monitor and needs an elevated terminal:

```powershell
target\release\game-feed.exe live --port 4500
```

It refuses to start if `pktmon` is already running or holds filters from another tool. It filters only the established, non-HTTPS TCP endpoints of the game process, follows new endpoints every 10 seconds (channel changes), and on Ctrl+C or game exit stops `pktmon` and removes only its own filters.

Offline replay of a pcapng file (no administrator needed):

```powershell
target\release\game-feed.exe replay capture.pcapng --endpoint 203.0.113.10:8547 --stdout
```

Pass each game server endpoint with `--endpoint`; without it only ports 8551 and 8553 are decoded.

## Feed

Connect to `ws://127.0.0.1:4500/`. Browser origins other than `localhost`/`127.0.0.1` are rejected.

| Query | Effect |
|---|---|
| `raw=1` | Also send every decoded message as hex |
| `opcodes=1134,1135` | Only items for these opcodes (health and status still pass) |

Every frame is JSON with a `kind`:

- `hello`: `{schema, readOnly, raw}` on connect.
- `status`: capture state.
- `health`: `decoder_sync`, `decoder_desync`, `decoder_reset`, `capture_gap` (missing TCP bytes are reported, never guessed), `feed_lagged` (this client was too slow and skipped items).
- `event`: `{opcode, ts, flow, serverPort, event}` with the typed event below.
- `message`: `{direction, opcode, flow, serverPort, ts, hex}` with `raw=1`.

| Event | Source | Notes |
|---|---|---|
| `map_loaded` | server 422 (103-byte layout) | `mapId`; `channelIndex` equals server port - 8540 in all samples, displayed channel number unconfirmed |
| `map_candidate` | server 167 | `mapId` at 565; trust only when it agrees with 422 |
| `player_seen` / `player_left` | server 554 / 555 | Client visibility only, not a map census |
| `player_shop_seen` | server 554 | Owner, title, shop object, permit |
| `player_shop_opened` / `player_shop_listings` | server 1399 / 1400 | Row prefixes; 1400 is not bound to a shop |
| `skill_observed` | server 677-679 | Actor and skill; `targets` with raw hit values when the structure is exact. No damage or kills derived |
| `monster_spawn` | server 966 / 978 | Known species only; name and level |
| `monster_removed` | server 977 | Removal is not death by itself |
| `kill` | server 1098 + 977 within 1s | `actorId`, `jobId` (job is not damage) |
| `movement` | server 639 / 666 / 985 | Pet owner / actor / monster; position on absolute fragments |
| `object_counter` | server 996 | Partial |
| `drop` | server 1134 | `itemId` or `amount` (Mesos), `sourceObject`, `position` or `null` |
| `pickup` | server 1135 mode 5 | Confirmed collection by `actorId` |
| `drop_removed` | server 1135 other modes | Not proof of collection |
| `stat` | server 126 | HP, MP, HP+MP, EXP, Mesos masks only |
| `inventory_changed` | server 114 | Operation count and raw hex; operations unresolved |
| `chat` | server 174 | `chatType`, `message` |
| `npc_spawn` / `npc_catalog` | server 1103 / 1373 | NPC position; shop listings (zero-price and buyback rows excluded) |
| `pickup_request` | client, rotating opcode | Structure-matched; `dropId` |
| `attack` / `skill_use` / `item_use` | client 59331 / 8404 / 39594 | Skill or item IDs |

The protocol knowledge is partial reverse engineering, not an official specification. Unknown fields stay unknown; extend `src/events.rs` only after checking new decoders against real recordings, including counterexamples.

## Privacy

Captured traffic can contain chat, player names and identifiers. Keep recordings and dashboards local, and never commit captures.

## License

GPL-3.0-or-later; see `LICENSE` and `THIRD_PARTY.md`.
