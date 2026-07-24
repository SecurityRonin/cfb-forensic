# 3. Format constants come from `forensicnomicon::olecf`, nothing hardcoded

Date: 2026-07-24
Status: Accepted

## Context

The raw decode (ADR 0002) needs every `[MS-CFB]` constant: the 8-byte signature,
header field offsets (major version, sector/mini-sector shift, mini-stream
cutoff, first DIR/mini-FAT/DIFAT sector), the 128-byte directory-entry field
offsets (name, object type, colour, siblings, CLSID, state bits, FILETIMEs,
start sector, stream size), the DIFAT header layout, and the sector sentinels
(`FREESECT`, `ENDOFCHAIN`, `MAXREGSECT`, `NOSTREAM`).

The fleet's KNOWLEDGE-leaf discipline puts format facts — magic bytes, field
offsets, enums, invariants — in `forensicnomicon`, a zero-dependency
compile-time constants crate every analyzer depends *down* onto. Baking the same
offsets into each analyzer would duplicate a published contract and let copies
drift.

## Decision

1. **Depend on `forensicnomicon = "1"`** (Cargo.toml) and import
   `forensicnomicon::olecf as k` in both `src/raw.rs` and `src/lib.rs`.
2. **Every offset, size, and sentinel is `k::*`** — `k::OLECF_SIGNATURE`,
   `k::HEADER_SIZE`, `k::DIR_ENTRY_SIZE`, `k::FREESECT`, `k::ENDOFCHAIN`,
   `k::MAXREGSECT`, `k::MINI_SECTOR_SIZE`, `k::SECTOR_SHIFT_V3`, the `DIFAT_*`
   layout, the directory field offsets, and so on. The module docs of both files
   state constants come from `forensicnomicon::olecf` and are never hardcoded
   here.
3. **Severity thresholds reuse format facts too** — e.g. the slack severity
   cutoff compares against `k::MINI_SECTOR_SIZE` rather than a literal
   (`OlecfAnomaly::severity`, src/lib.rs).

## Consequences

- A `[MS-CFB]` layout correction lands once in `forensicnomicon` and every
  consumer inherits it; this crate holds zero magic offsets.
- `cfb-forensic` gains a transitive dependency on the KNOWLEDGE leaf, matching
  the fleet's downward dependency direction (analyzer → KNOWLEDGE, never the
  reverse).
- The forensicnomicon `1.x` line is required (git log: forensicnomicon
  `0.5 → 0.11 → 1`); the API used is the stable `olecf` constant surface plus the
  `report` model (ADR 0004).
