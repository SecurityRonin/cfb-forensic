# cfb-forensic

Forensic carving over OLE Compound File Binary ([MS-CFB]) files — the analyzer
layer the general-purpose `cfb` reader doesn't provide.

Happy-path navigation comes from the mature [`cfb`](https://crates.io/crates/cfb)
crate; `cfb-forensic` adds a thin raw parse of the header + FAT/mini-FAT +
directory to recover what `cfb` hides:

| Code | What it observes |
|---|---|
| `OLECF-ORPHANED-DIR-ENTRY` | a directory entry unreachable from the root tree — recoverable **deleted-stream** metadata + content |
| `OLECF-FREE-SECTOR-RESIDUE` | a free FAT/mini-FAT sector still holding non-zero data — deleted-stream remnants |
| `OLECF-SLACK-RESIDUE` | non-zero bytes past a stream's declared size, in its final sector |
| `OLECF-STRUCTURE-ANOMALY` | red-black / DIFAT / marker violation, or a stream entry with non-zero CLSID/timestamps ([MS-CFB] says they MUST be zero — a tamper tell) |
| `OLECF-ROOT-CLSID` | the root/storage CLSID + the only timestamps CFB carries |

```rust
let findings = cfb_forensic::audit_bytes(compound_file_bytes);
```

CFB (= OLE2 / COM Structured Storage) underpins JumpLists, legacy Office, `.msi`,
`.msg`, thumbcache. Every finding is an observation ("consistent with"), never a
verdict. Constants come from `forensicnomicon::olecf`.

---

[Privacy Policy](https://securityronin.github.io/cfb-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/cfb-forensic/terms/) · © 2026 Security Ronin Ltd
