# 1. Carve as a layer over the mature `cfb` crate

Date: 2026-07-24
Status: Accepted

## Context

OLE Compound File Binary (`[MS-CFB]`, a.k.a. OLE2 / COM Structured Storage) is
the container behind JumpLists (`.automaticDestinations-ms`), legacy Office
`.doc`/`.xls`/`.ppt`, `.msi`, `.msg`, thumbcache, and sticky notes. A
production-grade reader already exists: the [`cfb`](https://crates.io/crates/cfb)
crate — battle-hardened since 2017, tens of millions of downloads — reads the
*live* storages and streams correctly, including sector/mini-sector chains, the
red-black directory tree, and clean-file metadata.

What `cfb` deliberately does **not** expose is exactly what an examiner needs:
directory entries the live tree no longer reaches (deleted streams), sectors the
FAT/mini-FAT marks free but still hold bytes, slack past a stream's declared
size, and `[MS-CFB]` marker/field violations. A spec-faithful reader hides these
because they are not part of the live view.

The fleet's Research-First / build-vs-reuse discipline says: when a correct,
maintained, better-scoped library exists, reuse it and add only the missing
layer. Reimplementing a full CFB reader to add carving would duplicate a large,
well-tested surface for no benefit.

## Decision

1. **Depend on `cfb = "0.14"`** (Cargo.toml) for all happy-path reading. The
   crate's live view is treated as the trusted oracle for "what is reachable".
2. **`cfb-forensic` adds only the carving/anomaly layer** — the CFB analogue of
   `sqlite-forensic` over `rusqlite`. It does not reimplement live navigation,
   clean metadata extraction, or stream reading.
3. **Expose thin `cfb`-backed helpers** — `live_entry_names(&[u8])` and
   `read_live_stream(&[u8], path)` (src/lib.rs) — so consumers and tests get
   clean-file content and a cross-check oracle without opening a second reader.

## Consequences

- The audited surface is small: the carving walk in `src/lib.rs` + the raw
  decode in `src/raw.rs`, with the mature `cfb` crate carrying the read path.
- `live_entry_names` doubles as a sanity oracle: the set of names `cfb` reaches
  must be disjoint from the orphan set the carver reports, a differential check
  tests exercise (tests/audit.rs).
- This inverts the fleet's usual "prefer our own crates" default, which is
  correct here: no SecurityRonin CFB reader exists, and the mature third-party
  reader is the better-scoped, lower-risk choice per the build-vs-reuse rule.
- If a future SecurityRonin `cfb-core` reader is ever published, the happy-path
  dependency can migrate; the carving layer (which reads raw bytes directly,
  see ADR 0002) is unaffected.
