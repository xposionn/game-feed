# Third-party notices

The packet transform, IV shuffle table and framing are ported from Maple Scope (GPL-3.0-or-later), which adapted them from:

- MapleLib (Snow and haha01haha01), GPL version 3 or later: https://github.com/hadeutscher/MapleLib/tree/master/MapleCryptoLib
- MapleSniffer public key-table/profile cross-check: https://github.com/taida957789/MapleSniffer/blob/main/src/protocol/maple_aes.cpp

Public algorithm constants are not account or recorded-session credentials. Preserve the GPL text in `LICENSE` and this attribution when distributing derivatives.

Rust crates keep their own licenses (aes, anyhow, futures-util, hex, serde, serde_json, tokio, tokio-tungstenite, ferrisetw). `data/monsters.json` holds a minimal list of monster IDs, names and levels taken from Maple Scope's reference data. Game names and content remain the property of their respective rights holders.
