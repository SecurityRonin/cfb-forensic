# 7. Declare a low CI-verified MSRV (1.81), decoupled from the pinned toolchain

Date: 2026-07-24
Status: Accepted

## Context

The fleet MSRV policy separates the **dev toolchain** (what contributors and CI
build with) from the **declared MSRV** (`rust-version` — a downstream-facing
promise). Apps declare MSRV = the pinned toolchain; **published libraries keep a
low, CI-verified MSRV** so their crates.io audience stays wide, and raising it is
treated as a near-breaking change.

`cfb-forensic` is a published library (ADR 0006): third-party developers `cargo
add` it. It pins the current fleet stable for development but must not force that
version on consumers.

## Decision

1. **`rust-version = "1.81"`** in Cargo.toml — the declared, downstream-facing
   floor.
2. **`rust-toolchain.toml` pins the current fleet stable (`1.96.0`)** with
   `clippy` + `rustfmt` components — the single source of truth for the *dev*
   toolchain (git log: "pin toolchain to 1.96.0 (fleet toolchain policy)"), kept
   deliberately distinct from the declared MSRV.
3. **The README advertises `Rust 1.81+`** as a build-compat go/no-go badge,
   consistent with the declared floor.

## Consequences

- Consumers on Rust 1.81 or newer can use the crate; the crate is not silently
  raised to 1.96 just because the fleet develops on it.
- The 1.81 floor is the level compatible with the crate's dependency graph
  (`cfb 0.14`, `forensicnomicon 1`) and its own language use; the *precise*
  reason 1.81 was chosen over a lower floor (e.g. 1.75/1.80) is not recovered
  from available history — treat it as the verified floor, raised only with an
  explicit reason and a CI check.
- A dedicated low-MSRV CI job verifies the 1.81 promise: `.github/workflows/ci.yml`
  carries an `msrv` job ("MSRV (1.81)") pinning `dtolnay/rust-toolchain@1.81`, so
  the badge is a real guarantee, not an aspiration.
