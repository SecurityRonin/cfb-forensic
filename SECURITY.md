# Security Policy

`cfb-forensic` is designed to parse **untrusted Windows Shell Link (`.lnk`)
files** — including those acquired from compromised or actively hostile systems.
Hostile input is the expected case, not an edge case. Robustness against crafted
links, malformed structures, and garbled encodings is a core design goal, and we
take reports of crashes, hangs, or memory-safety issues seriously.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x   | ✅ — current release line, receives security fixes |
| < 0.1   | ❌ — pre-release, unsupported |

Security fixes are released against the latest published `0.1.x` line.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Report privately, by either:

- **GitHub Security Advisories** — open a private advisory on the
  [`cfb-forensic` repository](https://github.com/SecurityRonin/cfb-forensic/security/advisories/new), or
- **Email** — [albert@securityronin.com](mailto:albert@securityronin.com).

Please include:

- the affected version and target triple,
- a minimal reproducing `.lnk` file or byte buffer (a fuzz corpus entry is ideal),
- the observed behaviour (panic, hang, excessive allocation, mis-parse) and the
  expected behaviour.

We aim to acknowledge a report within a few business days and to coordinate
disclosure once a fix is available.

## Security posture

`cfb-forensic` is hardened against adversarial input by construction:

- **`#![forbid(unsafe_code)]`** across both crates — no `unsafe`, no C bindings,
  no FFI, anywhere.
- **No panics on malicious input** — every integer / length / offset read is
  bounds-checked; no length field is trusted. A truncated or garbled link yields
  absent sub-structures or `None` rather than crashing. Arithmetic is checked or
  saturating.
- **Bounded walks** — the ExtraData block chain is bounded by the buffer length
  and terminates on an under-size block; the reader refuses to spin.
- **Fail loud where it matters** — a genuine error surfaces with context rather
  than as a silent default or a silently-wrong parse.

### Fuzzing

Continuous fuzzing with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz)
backs the hardening above. Two targets cover the surfaces that consume
attacker-controlled bytes:

| Target | Surface |
|---|---|
| `shelllink` | the `[MS-SHLLINK]` header / LinkInfo / StringData / ExtraData parse |
| `forensic`  | the full parse → audit pipeline |

Panics found by fuzzing are fixed and pinned as regression tests.

For how to run the targets yourself, see
[CONTRIBUTING.md](CONTRIBUTING.md#quality-gates).
