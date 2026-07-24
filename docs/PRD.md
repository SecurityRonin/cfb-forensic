# cfb-forensic — Design, Purpose & Scope

`cfb-forensic` is a **library** (not a runnable product): forensic carving over
OLE Compound File Binary (`[MS-CFB]`) files. This document records why the crate
exists and where its boundaries lie. Load-bearing design decisions are captured
as ADRs under [`docs/decisions/`](decisions/).

## Purpose

CFB (a.k.a. OLE2 / COM Structured Storage) is the container behind JumpLists
(`.automaticDestinations-ms`), legacy Office `.doc`/`.xls`/`.ppt`, `.msi`,
`.msg`, thumbcache, and sticky notes. A mature reader — the
[`cfb`](https://crates.io/crates/cfb) crate — reads the *live* streams and
storages perfectly. It does **not** expose the deleted-stream metadata,
unallocated sectors, or marker violations that matter to an examiner.

`cfb-forensic` adds exactly that carving layer: the CFB analogue of
`sqlite-forensic` over `rusqlite`. It is consumed by fleet orchestration (Issen,
disk4n6) and by any Rust developer who needs to see what a happy-path CFB reader
discards.

## What it does

A single entry point, `audit_bytes(&[u8]) -> Vec<OlecfAnomaly>`, does a minimal
raw walk of the header, FAT/mini-FAT, and directory — independent of `cfb`'s
logical view — and reports:

| Code | Observation |
|---|---|
| `OLECF-ORPHANED-DIR-ENTRY` | a directory entry unreachable from the live red-black tree — recoverable deleted-stream name/size/timestamps/start-sector, with stream bytes carved from the still-resident FAT chain |
| `OLECF-FREE-SECTOR-RESIDUE` | a FAT/mini-FAT slot marked free that still holds non-zero bytes |
| `OLECF-SLACK-RESIDUE` | non-zero bytes past a stream's declared size in its final allocated (mini-)sector |
| `OLECF-STRUCTURE-ANOMALY` | a byte-order marker or DIFAT-off-file violation, or a stream entry carrying a non-zero CLSID / state bits / FILETIME (`[MS-CFB]` §2.6.3 requires them zero — a tamper tell) |
| `OLECF-ROOT-CLSID` | provenance: the root-storage CLSID and the create/modify FILETIMEs CFB records |

`audit_findings(&[u8], Scope)` returns the same information as canonical
`forensicnomicon::report::Finding`s tagged with the producing `Source`.
`live_entry_names` and `read_live_stream` expose the `cfb`-backed happy-path view
for cross-checking and clean-file extraction.

## Scope

- **In scope:** carving orphaned/deleted directory entries and their resident
  stream bytes; free-sector and slack residue detection; `[MS-CFB]` structural /
  tamper anomalies; root provenance; emitting all of it as hedged, canonical
  observations.
- **Delegated, not in scope:** live storage/stream navigation and clean-file
  metadata — provided by the `cfb` crate (ADR 0001). Format constants and the
  report vocabulary — provided by `forensicnomicon` (ADRs 0003, 0004).

## Non-goals

- **Not a general-purpose CFB reader.** The in-crate `raw` module is a forensic
  structural view, not a reusable reader; live reading stays with `cfb`
  (ADR 0002).
- **Not a semantic decoder of the contained application formats.** It carves the
  CFB container; interpreting a carved `.msg` / `.doc` / JumpList payload is a
  higher-layer concern.
- **No verdicts.** Every finding is an observation, hedged "consistent with";
  MITRE techniques are consistencies, never assertions. The analyst/tribunal
  concludes (ADR 0004).
- **No binary.** It ships no CLI/GUI/MCP surface — only a fixture-minting example
  and a fuzz target — so it is library tier: its intent lives in this lighter
  Purpose & Scope doc (`docs/PRD.md`, the fleet-standard filename) plus the ADRs
  under `docs/decisions/`, rather than a full product PRD (ADR 0006).

## Validation approach

- **Panic-free on untrusted input**, `forbid(unsafe)`, bounds-checked reads,
  capped allocations, loop-guarded chain walks (ADR 0005).
- **Fuzzed** over the full `audit_bytes` pipeline (`fuzz/fuzz_targets/audit.rs`).
- **Cross-checked against `cfb`**: the set of live names `cfb` reaches is a sanity
  oracle against the orphan set (`live_entry_names`).
- **Real compound files**: a real JumpList
  (`tests/data/jumplist.automaticDestinations-ms`); the clean / deleted-stream /
  orphaned-entry `.cfb` fixtures are minted reproducibly by `examples/gen_cfb.rs`
  (privacy-safe, no real user data).
