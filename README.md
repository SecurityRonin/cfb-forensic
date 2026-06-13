# cfb-forensic

[![cfb-forensic](https://img.shields.io/crates/v/cfb-forensic.svg)](https://crates.io/crates/cfb-forensic)
[![Docs.rs](https://img.shields.io/docsrs/cfb-forensic)](https://docs.rs/cfb-forensic)
[![Rust 1.81+](https://img.shields.io/badge/rust-1.81%2B-blue.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/cfb-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/cfb-forensic/actions)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Carve OLE Compound File Binary ([MS-CFB]) files for what a happy-path reader hides — orphaned (deleted) directory entries, free-sector and slack residue, and structural tamper tells.**

CFB (a.k.a. OLE2 / COM Structured Storage) is the container behind JumpLists (`.automaticDestinations-ms`), legacy Office `.doc`/`.xls`/`.ppt`, `.msi`, `.msg`, thumbcache, and sticky notes. The mature [`cfb`](https://crates.io/crates/cfb) crate reads the *live* streams and storages perfectly; it does **not** expose the deleted-stream metadata, unallocated sectors, or marker violations that matter to an examiner. `cfb-forensic` adds exactly that carving layer on top — the CFB analogue of `sqlite-forensic` over `rusqlite`.

## Audit a compound file in 30 seconds

```toml
[dependencies]
cfb-forensic = "0.1"
```

```rust
use cfb_forensic::audit_bytes;

for finding in audit_bytes(compound_file_bytes) {
    println!("{finding:?}");   // OLECF-ORPHANED-DIR-ENTRY, OLECF-FREE-SECTOR-RESIDUE, ...
}
```

`audit_bytes` does a minimal raw walk of the header, FAT/mini-FAT and directory — independent of `cfb`'s logical view — so it can see sectors and directory entries the navigation layer has already discarded.

## What it observes

| Code | What it observes |
|---|---|
| `OLECF-ORPHANED-DIR-ENTRY` | a directory entry unreachable from the root red-black tree — recoverable **deleted-stream** name, size and content pointer |
| `OLECF-FREE-SECTOR-RESIDUE` | a FAT/mini-FAT sector marked free (`FREESECT`) that still holds non-zero bytes — deleted-stream remnants |
| `OLECF-SLACK-RESIDUE` | non-zero bytes past a stream's declared size, in its final allocated sector |
| `OLECF-STRUCTURE-ANOMALY` | a marker / DIFAT / red-black violation, or a stream entry carrying a non-zero CLSID or timestamps ([MS-CFB] says those MUST be zero for a stream — a tamper tell) |
| `OLECF-ROOT-CLSID` | the root-storage CLSID and the only creation/modification timestamps CFB records |

Every finding is a `forensicnomicon::report` observation — **"consistent with", never a verdict**; the analyst concludes. Format constants (signature, sector markers, directory-entry offsets, `ObjectType`/`Color` enums) come from [`forensicnomicon::olecf`](https://crates.io/crates/forensicnomicon).

## Trust but verify

Panic-free on untrusted input — every offset, sector index and length field is range-checked before use, allocations are capped, and the raw walk never indexes a slice unchecked. `#![forbid(unsafe_code)]`, fuzzed over `audit_bytes`, validated against real compound files (JumpLists and `.msi`/`.msg` samples). The happy-path read path is the battle-hardened `cfb` crate (40M+ downloads since 2017); we add only the carving walk.

---

[Privacy Policy](https://securityronin.github.io/cfb-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/cfb-forensic/terms/) · © 2026 Security Ronin Ltd
