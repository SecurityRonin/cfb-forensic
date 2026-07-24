# 4. Emit findings as hedged observations through `forensicnomicon::report`

Date: 2026-07-24
Status: Accepted

## Context

Every analyzer in the fleet emits its findings as one normalized reporting model
(`forensicnomicon::report`) so orchestration (Issen, disk4n6) and a future GUI
render them uniformly instead of N bespoke `XxxAnalysis` types. The model
distinguishes observed facts from conclusions: findings are **observations**,
hedged "consistent with", never verdicts — the analyst/tribunal concludes.

`cfb-forensic`'s anomalies carry runtime detail (recovered names, sizes, byte
offsets, carved lengths, MITRE techniques), so their `code`s are effectively
dynamic payloads. The fleet's producer pattern says: keep the typed domain enum
(the analyzer's knowledge), and convert to canonical `Finding`s — using the
`report` builder directly for dynamic codes rather than a static `Observation`
impl.

## Decision

1. **Keep a typed `OlecfAnomaly` enum** (src/lib.rs) as the domain vocabulary,
   with a stable scheme-prefixed `code()` per variant —
   `OLECF-ORPHANED-DIR-ENTRY`, `OLECF-FREE-SECTOR-RESIDUE`, `OLECF-SLACK-RESIDUE`,
   `OLECF-STRUCTURE-ANOMALY`, `OLECF-ROOT-CLSID` — the published contract.
2. **Convert via the builder** in `OlecfAnomaly::to_finding(Source)`, attaching
   severity, category, hedged note, subject ref, evidence rows (with `Location`),
   and MITRE techniques. `audit_findings(&[u8], Scope)` returns canonical
   `Finding`s tagged with the producing `Source`.
3. **All narration is hedged.** Notes say "consistent with a deleted stream",
   "consistent with tampering or timestomping", etc.; `mitre()` returns
   techniques the anomaly is *consistent with* (`T1070`, `T1564`, `T1027`), never
   an assertion. The lib doc states findings are observations, never verdicts.
4. **Severity mapping is the 5-level identity** (the fleet's canonical mapping
   for a 5-level native scale): `Info/Low/Medium/High/Critical` map straight
   through; slack is re-graded per-size against `k::MINI_SECTOR_SIZE`, and
   `OLECF-ROOT-CLSID` is `Info` provenance.
5. **Categories use the analytical lens** — `Residue` (orphans/free/slack),
   `Integrity` (structure/tamper), `Provenance` (root CLSID).

## Consequences

- Output slots straight into the fleet `Report` aggregate; no bespoke type for
  Issen to special-case.
- The `code` strings are a stable API: they must never change once shipped; new
  variants get new codes.
- Because the enum is retained alongside the `Finding` conversion, consumers who
  want typed access (e.g. `OrphanDetail` fields) keep it, while the canonical
  path stays uniform.
