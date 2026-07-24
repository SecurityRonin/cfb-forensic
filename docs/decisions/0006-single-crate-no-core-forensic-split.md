# 6. A single `cfb-forensic` crate — no in-house `core/`+`forensic/` split

Date: 2026-07-24
Status: Accepted

## Context

The fleet's crate-structure standard for a single-format repo (Pattern A) is two
crates: `<x>-core` (the reader) + `<x>-forensic` (the analyzer). The reader half
robustly reads valid data; the analyzer half audits for anomalies and depends
*down* onto the reader (or lower).

For CFB, the reader half already exists and is third-party: the `cfb` crate
(ADR 0001). Publishing a redundant SecurityRonin `cfb-core` reader purely to
satisfy the split would duplicate a mature, well-tested library for no benefit.
The only in-house work is the analyzer plus the thin raw structural view it needs
(ADR 0002), which is not a general-purpose reader.

## Decision

1. **Ship one crate, `cfb-forensic`** (Cargo.toml `name = "cfb-forensic"`), a
   plain library — no workspace, no `core/` member.
2. **The reader role is filled by the third-party `cfb` crate**; the
   `-forensic` analyzer stands alone atop it, exactly as the naming grammar
   allows when the reader is not an in-house `-core`.
3. **The low-level structural view lives in-crate** as the private-ish
   `pub mod raw` (src/raw.rs), not a separately published `-core`, because it is
   the analyzer's forensic view (full directory array, free sectors), not a
   happy-path reader others would reuse.
4. **Import path is `cfb_forensic`** (the crate name), distinct from the
   third-party `cfb` import, so the two coexist without collision.

## Consequences

- The repo is library tier: it ships no binary an examiner runs (only a fixture
  generator `examples/gen_cfb.rs` and a fuzz target). It therefore gets ADRs plus
  a lighter Purpose & Scope doc at `docs/PRD.md` (the fleet-standard filename),
  rather than a full product PRD.
- If a first-party CFB reader is ever warranted, it would be published as its own
  `cfb-core`/reader crate and this analyzer would depend on it; nothing in the
  public API (`audit_bytes`, `audit_findings`, `OlecfAnomaly`) would change.
- `Cargo.toml` `exclude`s test data, fuzz, docs, examples, and CI config from the
  published package, keeping the crate lean for `cargo add` consumers.
