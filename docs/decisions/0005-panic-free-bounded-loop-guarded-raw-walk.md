# 5. `forbid(unsafe)` + a panic-free, bounded, loop-guarded raw walk

Date: 2026-07-24
Status: Accepted

## Context

`audit_bytes` parses **untrusted, attacker-controllable** compound files: length
and count fields, chain pointers, and directory offsets all come from the input
and may be hostile — a length that overflows, a FAT chain that loops, a DIFAT
slot pointing off the end of the file, a directory chain that cycles. The fleet's
Paranoid Gatekeeper standard for parsing crates is: never panic, never read out
of bounds, never trust a length field, cap allocations against alloc bombs.

This crate does no memory-mapping — it operates on an in-memory `&[u8]` slice —
so it has no reason to take the mmap `unsafe` exception that `ewf`/`memory-forensic`
carry.

## Decision

1. **`unsafe_code = "forbid"`** (Cargo.toml `[lints.rust]`), earning the
   `unsafe forbidden` badge, with no per-site allow anywhere.
2. **Panic-free lints:** `unwrap_used` and `expect_used` are `deny`
   (Cargo.toml `[lints.clippy]`); `clippy.toml` allows unwrap/expect only inside
   tests. `audit_bytes` returns an empty `Vec` on any non-CFB or malformed input
   rather than erroring or panicking.
3. **Bounds-checked reads:** every multi-byte field goes through `le_u16`/
   `le_u32`/`le_u64` (src/raw.rs) which read `0` when the slice range is absent;
   every sector/mini-sector access is a checked `data.get(range)`; `sector_offset`
   uses `checked_add`/`checked_shl`.
4. **Allocation caps against hostile counts:** `MAX_SECTORS` (16 Mi),
   `MAX_DIR_ENTRIES` (4 Mi), `MAX_CHAIN_STEPS` (32 Mi) in `src/raw.rs`, and
   `MAX_MINI_STREAM` (16 MiB) in `src/lib.rs` bound the FAT, directory, chain
   walks, and mini-stream materialization.
5. **Loop guards on every chain walk:** the FAT-chain, mini-FAT-chain, directory
   read, and red-black reachability walks each carry a `visited` bitmap or step
   counter so a crafted cycle terminates. Genuinely unreachable defensive arms
   are annotated `// cov:unreachable: <invariant>` rather than deleted.
6. **A `fuzz_target` drives the full `audit_bytes` pipeline** over arbitrary
   bytes (`fuzz/fuzz_targets/audit.rs`, run on nightly per `fuzz.yml`) — the
   empirical partner to the static panic-free lints.

## Consequences

- The crate is `forbid(unsafe)` and panic-free by lint, verified by fuzzing —
  matching the fleet's untrusted-input posture without an mmap exception.
- Robustness wording follows the fleet standard: the headline claim is
  "input-fuzzed"; "panic-free" appears only as the qualified static half.
- **Deviation from the fleet `safe-read` standard (rationale not recovered):**
  the bounds-checked integer readers are hand-rolled (`le_u16`/`le_u32`/`le_u64`
  in `src/raw.rs`) rather than routed through the published `safe-read` crate,
  which the fleet mandates as the single audited implementation. The hand-rolled
  versions use `data.get(off..off+N)` with a fixed `N`, so they do not overflow,
  but they duplicate a solved primitive. Original intent not recovered in
  available history; a migration to `safe-read` is the obvious follow-up.
