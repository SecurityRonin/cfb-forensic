//! `cfb-forensic` — forensic carving over OLE Compound File Binary (`[MS-CFB]`)
//! files.
//!
//! Happy-path reading — live storages/streams, clean-file metadata (CLSID,
//! FILETIMEs, sizes) — is delegated to the mature [`cfb`] crate. This crate adds
//! the **carving and anomaly layer** `cfb` deliberately hides: the directory
//! entries, sectors, and slack space a spec-faithful reader skips because they
//! are no longer part of the live tree.
//!
//! ```no_run
//! let bytes: &[u8] = b"...";
//! for anomaly in cfb_forensic::audit_bytes(bytes) {
//!     println!("{} — {}", anomaly.code(), anomaly.note());
//! }
//! ```
//!
//! All findings are **observations**, hedged "consistent with", never verdicts —
//! the analyst/tribunal concludes. Format constants come from
//! [`forensicnomicon::olecf`]; nothing is hardcoded here.
//!
//! # Anomaly classes
//!
//! - [`OLECF-ORPHANED-DIR-ENTRY`](OlecfAnomaly::OrphanedDirEntry) — a stream/storage
//!   directory entry that the live red-black tree no longer reaches: deleted-stream
//!   metadata that survived, with name/size/timestamps/start-sector recovered and
//!   the stream bytes carved from the still-resident FAT chain.
//! - [`OLECF-FREE-SECTOR-RESIDUE`](OlecfAnomaly::FreeSectorResidue) — a FAT/mini-FAT
//!   slot marked free whose backing sector still holds non-zero bytes.
//! - [`OLECF-SLACK-RESIDUE`](OlecfAnomaly::SlackResidue) — non-zero bytes past a
//!   stream's declared size in its final (mini-)sector.
//! - [`OLECF-STRUCTURE-ANOMALY`](OlecfAnomaly::StructureAnomaly) — a red-black /
//!   sibling-cycle / chain-loop / off-file-DIFAT structural violation, or a stream
//!   entry whose CLSID / state-bits / FILETIMEs are non-zero (`[MS-CFB]` §2.6.3
//!   requires them zero) — a tamper tell.
//! - [`OLECF-ROOT-CLSID`](OlecfAnomaly::RootClsid) — provenance: the root/storage
//!   CLSID and the create/modify FILETIMEs CFB carries.

use std::io::{Cursor, Read};

use forensicnomicon::olecf as k;
use forensicnomicon::report::{Category, Finding, Location, Severity, Source, SubjectRef};

pub mod raw;

use raw::{DirEntry, RawCfb};

/// Cap on bytes materialized when resolving the root mini-stream for slack and
/// mini-FAT residue analysis (16 MiB) — defends against a hostile root size.
const MAX_MINI_STREAM: usize = 1 << 24;

/// How much of the file the audit covered, surfaced on the [`Source`] scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The whole file was decoded.
    Whole,
}

impl Scope {
    fn label(self) -> &'static str {
        match self {
            Scope::Whole => "whole file",
        }
    }
}

/// The producing [`Source`] for a `cfb-forensic` finding.
#[must_use]
pub fn source(scope: Scope) -> Source {
    Source {
        analyzer: "cfb-forensic".to_string(),
        scope: scope.label().to_string(),
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    }
}

/// Recovered detail for an orphaned (live-tree-unreachable) directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrphanDetail {
    /// The entry's stream id (index in the directory array).
    pub sid: u32,
    /// The recovered name (lossy UTF-16LE).
    pub name: String,
    /// `0x01` storage / `0x02` stream.
    pub object_type: u8,
    /// Declared stream size in bytes.
    pub stream_size: u64,
    /// Starting sector id of the (still-resident) stream chain.
    pub start_sector: u32,
    /// Creation FILETIME (raw `u64`, `0` if absent).
    pub create_time: u64,
    /// Modification FILETIME (raw `u64`, `0` if absent).
    pub modify_time: u64,
    /// Number of stream bytes carved from the resident FAT chain (`0` if none
    /// could be recovered).
    pub carved_len: usize,
}

/// Which structural rule a [`OlecfAnomaly::StructureAnomaly`] flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StructureIssue {
    /// A stream entry carries a non-zero CLSID (`[MS-CFB]` §2.6.3 requires zero).
    StreamNonZeroClsid { sid: u32, name: String },
    /// A stream entry carries non-zero state bits (`[MS-CFB]` §2.6.3 requires zero).
    StreamNonZeroStateBits {
        sid: u32,
        name: String,
        state_bits: u32,
    },
    /// A stream entry carries a non-zero create/modify FILETIME
    /// (`[MS-CFB]` §2.6.3 requires zero).
    StreamNonZeroFiletime { sid: u32, name: String },
    /// The directory or a FAT/mini-FAT chain looped back on itself.
    ChainLoop { space: &'static str },
    /// A DIFAT slot referenced a FAT sector beyond the end of the file.
    DifatOffFile { sid: u32 },
    /// The byte-order mark was not the required little-endian `0xFFFE`.
    BadByteOrder { value: u16 },
}

/// A forensic anomaly observed in an OLE Compound File. Each variant maps to a
/// stable, scheme-prefixed `code` (the published contract).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OlecfAnomaly {
    /// `OLECF-ORPHANED-DIR-ENTRY` — a stream/storage entry unreachable from the
    /// live root tree: deleted-stream metadata that survived.
    OrphanedDirEntry(OrphanDetail),
    /// `OLECF-FREE-SECTOR-RESIDUE` — a free FAT/mini-FAT slot whose backing
    /// sector still holds non-zero bytes.
    FreeSectorResidue {
        /// The (mini-)sector id marked free.
        sid: u32,
        /// `"FAT"` or `"mini-FAT"`.
        space: &'static str,
        /// Byte offset in the file of the residual sector.
        offset: u64,
        /// Count of non-zero bytes recovered.
        residue_len: usize,
    },
    /// `OLECF-SLACK-RESIDUE` — non-zero bytes past a stream's declared size in
    /// its final allocated (mini-)sector.
    SlackResidue {
        /// The owning entry's SID.
        sid: u32,
        /// The owning entry's name.
        name: String,
        /// `"FAT"` or `"mini-FAT"`.
        space: &'static str,
        /// Number of non-zero slack bytes.
        slack_len: usize,
    },
    /// `OLECF-STRUCTURE-ANOMALY` — a structural / tamper violation.
    StructureAnomaly(StructureIssue),
    /// `OLECF-ROOT-CLSID` — the root/storage CLSID and the FILETIMEs CFB carries.
    RootClsid {
        /// The entry's SID (`0` for the root storage).
        sid: u32,
        /// The entry's name.
        name: String,
        /// CLSID rendered as a canonical upper-case GUID string.
        clsid: String,
        /// Creation FILETIME (raw `u64`).
        create_time: u64,
        /// Modification FILETIME (raw `u64`).
        modify_time: u64,
    },
}

impl OlecfAnomaly {
    /// The stable, scheme-prefixed machine code for this anomaly.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            OlecfAnomaly::OrphanedDirEntry(_) => "OLECF-ORPHANED-DIR-ENTRY",
            OlecfAnomaly::FreeSectorResidue { .. } => "OLECF-FREE-SECTOR-RESIDUE",
            OlecfAnomaly::SlackResidue { .. } => "OLECF-SLACK-RESIDUE",
            OlecfAnomaly::StructureAnomaly(_) => "OLECF-STRUCTURE-ANOMALY",
            OlecfAnomaly::RootClsid { .. } => "OLECF-ROOT-CLSID",
        }
    }

    /// Severity of this anomaly.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            OlecfAnomaly::OrphanedDirEntry(_) => Severity::High,
            OlecfAnomaly::FreeSectorResidue { .. } => Severity::Medium,
            OlecfAnomaly::SlackResidue { slack_len, .. } => {
                if *slack_len >= k::MINI_SECTOR_SIZE {
                    Severity::Medium
                } else {
                    Severity::Low
                }
            }
            OlecfAnomaly::StructureAnomaly(issue) => match issue {
                StructureIssue::StreamNonZeroClsid { .. }
                | StructureIssue::StreamNonZeroStateBits { .. }
                | StructureIssue::StreamNonZeroFiletime { .. }
                | StructureIssue::ChainLoop { .. }
                | StructureIssue::DifatOffFile { .. } => Severity::High,
                StructureIssue::BadByteOrder { .. } => Severity::Medium,
            },
            OlecfAnomaly::RootClsid { .. } => Severity::Info,
        }
    }

    /// Analytical lens for this anomaly.
    #[must_use]
    pub fn category(&self) -> Category {
        match self {
            OlecfAnomaly::OrphanedDirEntry(_)
            | OlecfAnomaly::FreeSectorResidue { .. }
            | OlecfAnomaly::SlackResidue { .. } => Category::Residue,
            OlecfAnomaly::StructureAnomaly(_) => Category::Integrity,
            OlecfAnomaly::RootClsid { .. } => Category::Provenance,
        }
    }

    /// MITRE ATT&CK techniques this anomaly is **consistent with** (never a verdict).
    #[must_use]
    pub fn mitre(&self) -> &'static [&'static str] {
        match self {
            OlecfAnomaly::OrphanedDirEntry(_) => &["T1070", "T1564"],
            OlecfAnomaly::FreeSectorResidue { .. } | OlecfAnomaly::SlackResidue { .. } => {
                &["T1564"]
            }
            OlecfAnomaly::StructureAnomaly(_) => &["T1070", "T1027"],
            OlecfAnomaly::RootClsid { .. } => &[],
        }
    }

    /// Human-readable, hedged note.
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            OlecfAnomaly::OrphanedDirEntry(d) => format!(
                "Directory entry '{}' (sid {}) is not reachable from the live root tree; \
                 consistent with a deleted stream whose metadata survived. {} byte(s) carved \
                 from the resident FAT chain.",
                d.name, d.sid, d.carved_len
            ),
            OlecfAnomaly::FreeSectorResidue {
                sid,
                space,
                offset,
                residue_len,
            } => format!(
                "{space} sector {sid} is marked free but holds {residue_len} non-zero byte(s) at \
                 offset {offset}; consistent with deleted-stream remnant."
            ),
            OlecfAnomaly::SlackResidue {
                name,
                space,
                slack_len,
                ..
            } => format!(
                "Stream '{name}' leaves {slack_len} non-zero {space} slack byte(s) past its \
                 declared size; consistent with residue from a prior, larger allocation."
            ),
            OlecfAnomaly::StructureAnomaly(issue) => issue.note(),
            OlecfAnomaly::RootClsid {
                name,
                clsid,
                create_time,
                modify_time,
                ..
            } => format!(
                "{name} CLSID {clsid}; create FILETIME {create_time}, modify FILETIME {modify_time}."
            ),
        }
    }

    /// Build the subject reference, if this anomaly is about a named object.
    fn subject(&self) -> Option<SubjectRef> {
        let (sid, name) = match self {
            OlecfAnomaly::OrphanedDirEntry(d) => (d.sid, d.name.clone()),
            OlecfAnomaly::SlackResidue { sid, name, .. }
            | OlecfAnomaly::RootClsid { sid, name, .. } => (*sid, name.clone()),
            OlecfAnomaly::StructureAnomaly(issue) => return issue.subject(),
            OlecfAnomaly::FreeSectorResidue { .. } => return None,
        };
        Some(SubjectRef {
            scheme: "olecf".to_string(),
            kind: "directory_entry".to_string(),
            id: format!("sid:{sid}"),
            label: Some(name),
        })
    }

    /// Convert to a canonical [`Finding`]. Dynamic codes carry runtime detail, so
    /// this uses the [`forensicnomicon::report`] builder directly.
    #[must_use]
    pub fn to_finding(&self, src: Source) -> Finding {
        let mut builder = Finding::observation(self.severity(), self.category(), self.code())
            .note(self.note())
            .source(src);

        if let Some(subject) = self.subject() {
            builder = builder.subject(subject);
        }
        for technique in self.mitre() {
            builder = builder.mitre(*technique);
        }
        for (field, value, loc) in self.evidence() {
            builder = match loc {
                Some(location) => builder.evidence_at(field, value, location),
                None => builder.evidence(field, value),
            };
        }
        builder.build()
    }

    /// Evidence rows for this anomaly.
    fn evidence(&self) -> Vec<(String, String, Option<Location>)> {
        match self {
            OlecfAnomaly::OrphanedDirEntry(d) => vec![
                ("name".into(), d.name.clone(), None),
                (
                    "object_type".into(),
                    format!("0x{:02x}", d.object_type),
                    None,
                ),
                (
                    "stream_size".into(),
                    d.stream_size.to_string(),
                    Some(Location::RecordId(u64::from(d.sid))),
                ),
                ("start_sector".into(), d.start_sector.to_string(), None),
                ("carved_len".into(), d.carved_len.to_string(), None),
                ("create_time".into(), d.create_time.to_string(), None),
                ("modify_time".into(), d.modify_time.to_string(), None),
            ],
            OlecfAnomaly::FreeSectorResidue {
                space,
                residue_len,
                offset,
                ..
            } => vec![
                ("space".into(), (*space).to_string(), None),
                (
                    "residue_len".into(),
                    residue_len.to_string(),
                    Some(Location::ByteOffset(*offset)),
                ),
            ],
            OlecfAnomaly::SlackResidue {
                space, slack_len, ..
            } => vec![
                ("space".into(), (*space).to_string(), None),
                ("slack_len".into(), slack_len.to_string(), None),
            ],
            OlecfAnomaly::StructureAnomaly(issue) => issue.evidence(),
            OlecfAnomaly::RootClsid {
                clsid,
                create_time,
                modify_time,
                ..
            } => vec![
                ("clsid".into(), clsid.clone(), None),
                ("create_time".into(), create_time.to_string(), None),
                ("modify_time".into(), modify_time.to_string(), None),
            ],
        }
    }
}

impl StructureIssue {
    fn note(&self) -> String {
        match self {
            StructureIssue::StreamNonZeroClsid { name, sid } => format!(
                "Stream entry '{name}' (sid {sid}) carries a non-zero CLSID; [MS-CFB] §2.6.3 \
                 requires it zero — consistent with tampering or a non-conformant writer."
            ),
            StructureIssue::StreamNonZeroStateBits {
                name,
                sid,
                state_bits,
            } => format!(
                "Stream entry '{name}' (sid {sid}) carries non-zero state bits 0x{state_bits:08x}; \
                 [MS-CFB] §2.6.3 requires them zero — consistent with tampering."
            ),
            StructureIssue::StreamNonZeroFiletime { name, sid } => format!(
                "Stream entry '{name}' (sid {sid}) carries a non-zero create/modify FILETIME; \
                 [MS-CFB] §2.6.3 requires it zero — consistent with tampering or timestomping."
            ),
            StructureIssue::ChainLoop { space } => format!(
                "The {space} chain loops back on itself; consistent with structural corruption \
                 or a crafted file."
            ),
            StructureIssue::DifatOffFile { sid } => format!(
                "A DIFAT slot references FAT sector {sid} beyond the end of the file; consistent \
                 with structural corruption or a crafted file."
            ),
            StructureIssue::BadByteOrder { value } => format!(
                "Header byte-order mark is 0x{value:04x}, not the required little-endian 0xFFFE."
            ),
        }
    }

    fn subject(&self) -> Option<SubjectRef> {
        let (sid, name) = match self {
            StructureIssue::StreamNonZeroClsid { sid, name }
            | StructureIssue::StreamNonZeroStateBits { sid, name, .. }
            | StructureIssue::StreamNonZeroFiletime { sid, name } => (*sid, name.clone()),
            StructureIssue::ChainLoop { .. }
            | StructureIssue::DifatOffFile { .. }
            | StructureIssue::BadByteOrder { .. } => return None,
        };
        Some(SubjectRef {
            scheme: "olecf".to_string(),
            kind: "directory_entry".to_string(),
            id: format!("sid:{sid}"),
            label: Some(name),
        })
    }

    fn evidence(&self) -> Vec<(String, String, Option<Location>)> {
        match self {
            StructureIssue::StreamNonZeroStateBits { state_bits, .. } => {
                vec![("state_bits".into(), format!("0x{state_bits:08x}"), None)]
            }
            StructureIssue::DifatOffFile { sid } => {
                vec![("fat_sector".into(), sid.to_string(), None)]
            }
            StructureIssue::BadByteOrder { value } => {
                vec![("byte_order".into(), format!("0x{value:04x}"), None)]
            }
            _ => Vec::new(),
        }
    }
}

/// Audit a compound file's bytes, returning every anomaly observed. Never panics
/// on malformed or hostile input; a buffer that is not a CFB yields an empty
/// list.
#[must_use]
pub fn audit_bytes(data: &[u8]) -> Vec<OlecfAnomaly> {
    let Some(raw) = raw::decode(data) else {
        return Vec::new();
    };

    let mut anomalies = Vec::new();

    // Header sanity (structure).
    if raw.byte_order != k::BYTE_ORDER_LE {
        anomalies.push(OlecfAnomaly::StructureAnomaly(
            StructureIssue::BadByteOrder {
                value: raw.byte_order,
            },
        ));
    }

    detect_orphans(data, &raw, &mut anomalies);
    detect_structure(data, &raw, &mut anomalies);
    detect_free_residue(data, &raw, &mut anomalies);
    detect_slack(data, &raw, &mut anomalies);
    surface_root_clsid(&raw, &mut anomalies);

    anomalies
}

/// Audit and return canonical [`Finding`]s, tagged with the producing [`Source`].
#[must_use]
pub fn audit_findings(data: &[u8], scope: Scope) -> Vec<Finding> {
    let src = source(scope);
    audit_bytes(data)
        .into_iter()
        .map(|a| a.to_finding(src.clone()))
        .collect()
}

/// The headline carving pass: every allocated stream/storage entry not reachable
/// from the live root tree is an orphan; recover its metadata and carve its
/// resident stream bytes.
fn detect_orphans(data: &[u8], raw: &RawCfb, out: &mut Vec<OlecfAnomaly>) {
    let reachable = raw::reachable_sids(&raw.dir_entries);
    for (idx, entry) in raw.dir_entries.iter().enumerate() {
        if reachable.get(idx).copied().unwrap_or(false) {
            continue;
        }
        // Only allocated stream/storage entries are forensically meaningful
        // orphans; an unallocated 0x00 slot is just empty directory space.
        if !matches!(entry.object_type, 0x01 | 0x02) {
            continue;
        }
        let carved = carve_stream(data, raw, entry);
        out.push(OlecfAnomaly::OrphanedDirEntry(OrphanDetail {
            sid: entry.sid,
            name: entry.name.clone(),
            object_type: entry.object_type,
            stream_size: entry.stream_size,
            start_sector: entry.start_sector,
            create_time: entry.create_time,
            modify_time: entry.modify_time,
            carved_len: carved.len(),
        }));
    }
}

/// Carve a stream's bytes by following its still-resident FAT (or mini-FAT)
/// chain. Returns the recovered bytes truncated to the declared size; loop- and
/// length-guarded. Streams below the mini-stream cutoff live in the mini-FAT,
/// which we resolve through the root entry's mini-stream.
fn carve_stream(data: &[u8], raw: &RawCfb, entry: &DirEntry) -> Vec<u8> {
    if entry.object_type != 0x02 || entry.stream_size == 0 {
        return Vec::new();
    }
    let size = usize::try_from(entry.stream_size).unwrap_or(usize::MAX);

    if entry.stream_size < u64::from(raw.mini_stream_cutoff) {
        carve_mini(data, raw, entry.start_sector, size)
    } else {
        carve_fat(data, raw, entry.start_sector, size)
    }
}

/// Carve from the regular FAT chain.
fn carve_fat(data: &[u8], raw: &RawCfb, start: u32, size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(size.min(1 << 20));
    let mut sid = start;
    let mut visited = vec![false; raw.fat.len()];
    while sid <= k::MAXREGSECT && out.len() < size {
        if let Some(slot) = visited.get_mut(sid as usize) {
            if *slot {
                break;
            }
            *slot = true;
        } else {
            break;
        }
        let start_off = (u64::from(sid) + 1).saturating_mul(raw.sector_size as u64);
        if let Ok(off) = usize::try_from(start_off) {
            if let Some(s) = data.get(off..off.saturating_add(raw.sector_size)) {
                out.extend_from_slice(s);
            }
        }
        sid = raw.fat.get(sid as usize).copied().unwrap_or(k::ENDOFCHAIN);
    }
    out.truncate(size);
    out
}

/// Carve from the mini-FAT chain via the root entry's mini-stream.
fn carve_mini(data: &[u8], raw: &RawCfb, start: u32, size: usize) -> Vec<u8> {
    // The mini-stream is the root entry's own (regular-FAT) stream.
    let Some(root) = raw.dir_entries.first() else {
        return Vec::new();
    };
    let mini_stream = carve_fat(data, raw, root.start_sector, MAX_MINI_STREAM);
    let mini_size = 1usize << raw.mini_sector_shift.clamp(1, 16);

    let mut out = Vec::with_capacity(size.min(1 << 20));
    let mut msid = start;
    let mut visited = vec![false; raw.mini_fat.len()];
    while msid <= k::MAXREGSECT && out.len() < size {
        if let Some(slot) = visited.get_mut(msid as usize) {
            if *slot {
                break;
            }
            *slot = true;
        } else {
            break;
        }
        let off = (msid as usize).saturating_mul(mini_size);
        if let Some(s) = mini_stream.get(off..off.saturating_add(mini_size)) {
            out.extend_from_slice(s);
        }
        msid = raw
            .mini_fat
            .get(msid as usize)
            .copied()
            .unwrap_or(k::ENDOFCHAIN);
    }
    out.truncate(size);
    out
}

/// Detect the `[MS-CFB]` §2.6.3 "must be zero on a stream" tamper tells and the
/// off-file DIFAT structural violation.
fn detect_structure(data: &[u8], raw: &RawCfb, out: &mut Vec<OlecfAnomaly>) {
    for entry in &raw.dir_entries {
        if !entry.is_stream() {
            continue;
        }
        if entry.clsid != [0u8; 16] {
            out.push(OlecfAnomaly::StructureAnomaly(
                StructureIssue::StreamNonZeroClsid {
                    sid: entry.sid,
                    name: entry.name.clone(),
                },
            ));
        }
        if entry.state_bits != 0 {
            out.push(OlecfAnomaly::StructureAnomaly(
                StructureIssue::StreamNonZeroStateBits {
                    sid: entry.sid,
                    name: entry.name.clone(),
                    state_bits: entry.state_bits,
                },
            ));
        }
        if entry.create_time != 0 || entry.modify_time != 0 {
            out.push(OlecfAnomaly::StructureAnomaly(
                StructureIssue::StreamNonZeroFiletime {
                    sid: entry.sid,
                    name: entry.name.clone(),
                },
            ));
        }
    }

    // A DIFAT FAT-sector pointer beyond the file is an off-file reference.
    let max_sid = (data.len() / raw.sector_size.max(1)) as u64;
    for i in 0..k::DIFAT_HEADER_COUNT {
        let off = k::DIFAT_HEADER_OFFSET + i * 4;
        let mut b = [0u8; 4];
        if let Some(s) = data.get(off..off + 4) {
            b.copy_from_slice(s);
        }
        let sid = u32::from_le_bytes(b);
        if sid <= k::MAXREGSECT && u64::from(sid) >= max_sid {
            out.push(OlecfAnomaly::StructureAnomaly(
                StructureIssue::DifatOffFile { sid },
            ));
        }
    }
}

/// Detect free FAT/mini-FAT slots whose backing sector still holds non-zero bytes.
fn detect_free_residue(data: &[u8], raw: &RawCfb, out: &mut Vec<OlecfAnomaly>) {
    // Regular FAT: a FREESECT slot at index `sid` ⇒ sector (sid+1)<<sector_shift.
    for (sid, &slot) in raw.fat.iter().enumerate() {
        if slot != k::FREESECT {
            continue;
        }
        let sid = sid as u32;
        let off = (u64::from(sid) + 1).saturating_mul(raw.sector_size as u64);
        let Ok(start) = usize::try_from(off) else {
            continue;
        };
        let Some(sector) = data.get(start..start.saturating_add(raw.sector_size)) else {
            continue;
        };
        let residue = sector.iter().filter(|&&b| b != 0).count();
        if residue > 0 {
            out.push(OlecfAnomaly::FreeSectorResidue {
                sid,
                space: "FAT",
                offset: off,
                residue_len: residue,
            });
        }
    }

    // Mini-FAT: free mini-sectors with non-zero residue inside the mini-stream.
    let mini_size = 1usize << raw.mini_sector_shift.clamp(1, 16);
    if let Some(root) = raw.dir_entries.first() {
        let mini_stream = carve_fat(data, raw, root.start_sector, MAX_MINI_STREAM);
        for (msid, &slot) in raw.mini_fat.iter().enumerate() {
            if slot != k::FREESECT {
                continue;
            }
            let off = msid.saturating_mul(mini_size);
            let Some(sector) = mini_stream.get(off..off.saturating_add(mini_size)) else {
                continue;
            };
            let residue = sector.iter().filter(|&&b| b != 0).count();
            if residue > 0 {
                out.push(OlecfAnomaly::FreeSectorResidue {
                    sid: msid as u32,
                    space: "mini-FAT",
                    offset: off as u64,
                    residue_len: residue,
                });
            }
        }
    }
}

/// Detect non-zero slack past a live stream's declared size in its final sector.
fn detect_slack(data: &[u8], raw: &RawCfb, out: &mut Vec<OlecfAnomaly>) {
    let reachable = raw::reachable_sids(&raw.dir_entries);
    let mini_size = 1usize << raw.mini_sector_shift.clamp(1, 16);

    for (idx, entry) in raw.dir_entries.iter().enumerate() {
        if !entry.is_stream() || entry.stream_size == 0 {
            continue;
        }
        if !reachable.get(idx).copied().unwrap_or(false) {
            continue; // orphans carve their own bytes; slack is for live streams
        }
        let size = usize::try_from(entry.stream_size).unwrap_or(usize::MAX);
        let in_mini = entry.stream_size < u64::from(raw.mini_stream_cutoff);
        let (unit, space, bytes) = if in_mini {
            (
                mini_size,
                "mini-FAT",
                carve_mini(data, raw, entry.start_sector, MAX_MINI_STREAM),
            )
        } else {
            (
                raw.sector_size,
                "FAT",
                carve_fat(data, raw, entry.start_sector, MAX_MINI_STREAM),
            )
        };
        if unit == 0 || size % unit == 0 {
            continue; // exact multiple ⇒ no slack region
        }
        let slack_start = size;
        let slack_end = bytes.len();
        if slack_end > slack_start {
            let slack = &bytes[slack_start..slack_end];
            let nonzero = slack.iter().filter(|&&b| b != 0).count();
            if nonzero > 0 {
                out.push(OlecfAnomaly::SlackResidue {
                    sid: entry.sid,
                    name: entry.name.clone(),
                    space,
                    slack_len: nonzero,
                });
            }
        }
    }
}

/// Surface the root storage's CLSID and FILETIMEs as a provenance breadcrumb.
fn surface_root_clsid(raw: &RawCfb, out: &mut Vec<OlecfAnomaly>) {
    if let Some(root) = raw.dir_entries.first() {
        out.push(OlecfAnomaly::RootClsid {
            sid: root.sid,
            name: if root.name.is_empty() {
                "Root Entry".to_string()
            } else {
                root.name.clone()
            },
            clsid: format_clsid(&root.clsid),
            create_time: root.create_time,
            modify_time: root.modify_time,
        });
    }
}

/// Render a 16-byte CLSID as a canonical upper-case GUID string. The first three
/// groups are little-endian; the last two are big-endian (`[MS-DTYP]` GUID).
fn format_clsid(b: &[u8; 16]) -> String {
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// Cross-check helper: the set of live stream/storage names the `cfb` crate
/// reaches, used by tests/consumers as a sanity oracle against our orphan set.
/// Returns `None` if `cfb` cannot open the bytes at all.
#[must_use]
pub fn live_entry_names(data: &[u8]) -> Option<Vec<String>> {
    let cursor = Cursor::new(data.to_vec());
    let comp = cfb::CompoundFile::open(cursor).ok()?;
    let mut names = Vec::new();
    for entry in comp.walk() {
        names.push(entry.name().to_string());
    }
    Some(names)
}

/// Read a live stream's bytes via the `cfb` crate (happy-path extraction), for
/// consumers that want clean-file stream content rather than carved residue.
#[must_use]
pub fn read_live_stream(data: &[u8], path: &str) -> Option<Vec<u8>> {
    let cursor = Cursor::new(data.to_vec());
    let mut comp = cfb::CompoundFile::open(cursor).ok()?;
    let mut stream = comp.open_stream(path).ok()?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).ok()?;
    Some(buf)
}
