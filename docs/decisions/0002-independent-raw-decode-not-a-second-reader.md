# 2. An independent raw decode layer, not a second reader

Date: 2026-07-24
Status: Accepted

## Context

ADR 0001 delegates live reading to the `cfb` crate. But the anomalies this crate
hunts — orphaned (live-tree-unreachable) directory entries, free-sector residue,
slack — are precisely the structures a happy-path reader normalizes away or
refuses. `cfb`'s API surfaces the *reachable* tree; it never hands back the full
128-byte directory array including entries the red-black tree abandoned, nor the
raw contents of sectors the FAT marks free.

This is the fleet's binding `-forensic`-may-go-lower principle: a `-core` reader
is built to read *valid* data robustly, so it abstracts away exactly the detail a
forensic auditor must see. Contorting the audit through the reader's happy-path
API would hide the very anomalies it exists to find.

## Decision

1. **`src/raw.rs` performs a thin, self-contained raw decode** of the header,
   FAT, mini-FAT, and the *full* directory-entry array — including orphaned
   entries — over the input `&[u8]`. It is explicitly **not** a second CFB
   reader: its module doc states live navigation and stream extraction stay with
   `cfb`; raw decode exists only so the analyzer can see residue.
2. **The carver walks the raw structure directly.** `audit_bytes` computes the
   reachable-SID set (`raw::reachable_sids`, a loop-guarded red-black walk that
   mirrors what `cfb` exposes), then treats every allocated-but-unreached
   `0x01`/`0x02` entry as an orphan and carves its still-resident FAT/mini-FAT
   chain (`carve_fat` / `carve_mini` in src/lib.rs).
3. **Endianness and layout follow `[MS-CFB]`.** All multi-byte fields are
   little-endian; the CLSID is rendered as a `[MS-DTYP]` GUID (first three groups
   little-endian, last two big-endian — `format_clsid`, src/lib.rs). Offsets and
   sentinels are never hardcoded (see ADR 0003).

## Consequences

- The analyzer sees deleted-stream metadata (name, size, timestamps,
  start-sector) and carves the bytes because the FAT chain is still resident
  after a logical delete — content `cfb` never returns.
- Two independent views of the same file (`cfb`'s live tree vs the raw decode)
  let the crate report exactly the delta, which is the forensic product.
- The raw decoder carries its own robustness burden (ADR 0005): it degrades to
  safe defaults on truncation rather than trusting `cfb` to have validated the
  bytes first.
- There is no `-core` crate to depend on: the reader half of the fleet's
  `core/`+`forensic/` split is the third-party `cfb` crate, and the low-level
  structural view the audit needs is this in-crate raw module (see ADR 0006).
