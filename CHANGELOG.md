# Changelog

## [0.2.1](https://github.com/SecurityRonin/cfb-forensic/compare/cfb-forensic-v0.2.0...cfb-forensic-v0.2.1) - 2026-07-25

### Documentation

- use verbatim Apache-2.0 license text

### Fixed

- *(vet)* declare own crates first-party so version bumps don't break supply-chain audit
- *(ci)* restore the coverage and fuzz gates (were never functional)

## 0.1.0 — 2026-06-13

Initial release. `audit_bytes` carves OLE/CFB ([MS-CFB]) compound files for
orphaned directory entries (deleted-stream recovery), free-sector + slack
residue, structure/marker tamper anomalies, and root CLSID/timestamps —
happy-path reading via the `cfb` crate, constants from `forensicnomicon::olecf`.
Panic-free, `forbid(unsafe_code)`, fuzzed.
