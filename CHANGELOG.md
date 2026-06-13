# Changelog

## 0.1.0 — 2026-06-13

Initial release. `audit_bytes` carves OLE/CFB ([MS-CFB]) compound files for
orphaned directory entries (deleted-stream recovery), free-sector + slack
residue, structure/marker tamper anomalies, and root CLSID/timestamps —
happy-path reading via the `cfb` crate, constants from `forensicnomicon::olecf`.
Panic-free, `forbid(unsafe_code)`, fuzzed.
