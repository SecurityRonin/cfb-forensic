//! Exhaustive coverage of every [`OlecfAnomaly`] / [`StructureIssue`] variant's
//! canonical output — `code`, `severity`, `category`, `mitre`, `note`, and the
//! `to_finding` builder path (which drives the private `subject`/`evidence`
//! arms). These methods emit forensic evidence values, so each variant is
//! exercised against its documented `[MS-CFB]`-derived contract.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use cfb_forensic::raw::DirEntry;
use cfb_forensic::{read_live_stream, source, OlecfAnomaly, OrphanDetail, Scope, StructureIssue};
use forensicnomicon::olecf as k;
use forensicnomicon::report::{Category, Severity};

const CLEAN: &[u8] = include_bytes!("data/clean.cfb");

#[test]
fn read_live_stream_extracts_a_present_stream_and_none_for_a_missing_one() {
    // clean.cfb holds a live "/payload" stream of 5000 0x41 bytes.
    let payload = read_live_stream(CLEAN, "/payload").expect("payload stream present");
    assert_eq!(payload.len(), 5000);
    assert!(payload.iter().all(|&b| b == 0x41));
    // A path that does not exist yields None, not a panic.
    assert!(read_live_stream(CLEAN, "/does-not-exist").is_none());
}

fn orphan() -> OlecfAnomaly {
    OlecfAnomaly::OrphanedDirEntry(OrphanDetail {
        sid: 4,
        name: "payload".to_string(),
        object_type: 0x02,
        stream_size: 5000,
        start_sector: 4,
        create_time: 0,
        modify_time: 0,
        carved_len: 5000,
    })
}

fn all_variants() -> Vec<OlecfAnomaly> {
    vec![
        orphan(),
        OlecfAnomaly::FreeSectorResidue {
            sid: 7,
            space: "FAT",
            offset: 4096,
            residue_len: 128,
        },
        OlecfAnomaly::FreeSectorResidue {
            sid: 3,
            space: "mini-FAT",
            offset: 384,
            residue_len: 40,
        },
        // slack_len >= MINI_SECTOR_SIZE ⇒ Medium
        OlecfAnomaly::SlackResidue {
            sid: 2,
            name: "note".to_string(),
            space: "mini-FAT",
            slack_len: k::MINI_SECTOR_SIZE,
        },
        // slack_len < MINI_SECTOR_SIZE ⇒ Low
        OlecfAnomaly::SlackResidue {
            sid: 2,
            name: "note".to_string(),
            space: "mini-FAT",
            slack_len: 3,
        },
        OlecfAnomaly::StructureAnomaly(StructureIssue::StreamNonZeroClsid {
            sid: 2,
            name: "note".to_string(),
        }),
        OlecfAnomaly::StructureAnomaly(StructureIssue::StreamNonZeroStateBits {
            sid: 2,
            name: "note".to_string(),
            state_bits: 0x0000_0001,
        }),
        OlecfAnomaly::StructureAnomaly(StructureIssue::StreamNonZeroFiletime {
            sid: 2,
            name: "note".to_string(),
        }),
        OlecfAnomaly::StructureAnomaly(StructureIssue::ChainLoop { space: "FAT" }),
        OlecfAnomaly::StructureAnomaly(StructureIssue::DifatOffFile { sid: 999 }),
        OlecfAnomaly::StructureAnomaly(StructureIssue::BadByteOrder { value: 0xFEFF }),
        OlecfAnomaly::RootClsid {
            sid: 0,
            name: "Root Entry".to_string(),
            clsid: "00000000-0000-0000-0000-000000000000".to_string(),
            create_time: 0,
            modify_time: 0,
        },
    ]
}

#[test]
fn every_variant_emits_code_severity_category_note_and_finding() {
    let src = source(Scope::Whole);
    for a in all_variants() {
        // Every metadata accessor must produce non-empty, contract-shaped output.
        assert!(a.code().starts_with("OLECF-"), "code prefix: {}", a.code());
        let _ = a.severity();
        let _ = a.category();
        let _ = a.mitre();
        assert!(!a.note().is_empty(), "note for {}", a.code());

        // to_finding drives the private subject()/evidence() arms too.
        let finding = a.to_finding(src.clone());
        assert_eq!(finding.code, a.code());
        assert_eq!(finding.severity, Some(a.severity()));
        assert_eq!(finding.category, a.category());
    }
}

#[test]
fn severity_and_category_match_the_spec_mapping() {
    assert_eq!(orphan().severity(), Severity::High);
    assert_eq!(orphan().category(), Category::Residue);

    let free = OlecfAnomaly::FreeSectorResidue {
        sid: 1,
        space: "FAT",
        offset: 512,
        residue_len: 10,
    };
    assert_eq!(free.severity(), Severity::Medium);
    assert_eq!(free.category(), Category::Residue);

    let big_slack = OlecfAnomaly::SlackResidue {
        sid: 2,
        name: "n".into(),
        space: "FAT",
        slack_len: k::MINI_SECTOR_SIZE,
    };
    assert_eq!(big_slack.severity(), Severity::Medium);
    let small_slack = OlecfAnomaly::SlackResidue {
        sid: 2,
        name: "n".into(),
        space: "FAT",
        slack_len: 1,
    };
    assert_eq!(small_slack.severity(), Severity::Low);

    let bad_bom = OlecfAnomaly::StructureAnomaly(StructureIssue::BadByteOrder { value: 0x1234 });
    assert_eq!(bad_bom.severity(), Severity::Medium);
    assert_eq!(bad_bom.category(), Category::Integrity);

    let tamper = OlecfAnomaly::StructureAnomaly(StructureIssue::StreamNonZeroClsid {
        sid: 2,
        name: "n".into(),
    });
    assert_eq!(tamper.severity(), Severity::High);

    let root = OlecfAnomaly::RootClsid {
        sid: 0,
        name: "Root Entry".into(),
        clsid: "x".into(),
        create_time: 1,
        modify_time: 2,
    };
    assert_eq!(root.severity(), Severity::Info);
    assert_eq!(root.category(), Category::Provenance);
    assert!(root.mitre().is_empty());
}

#[test]
fn structure_issue_evidence_and_subject_populate_findings() {
    let src = source(Scope::Whole);

    // StreamNonZeroStateBits carries a state_bits evidence row + a subject.
    let f = OlecfAnomaly::StructureAnomaly(StructureIssue::StreamNonZeroStateBits {
        sid: 2,
        name: "note".into(),
        state_bits: 0xDEAD_BEEF,
    })
    .to_finding(src.clone());
    assert!(f.context.external_refs.iter().any(|r| r.id == "T1070"));
    assert!(f
        .evidence
        .iter()
        .any(|e| e.field == "state_bits" && e.value.contains("deadbeef")));
    assert!(f.subjects.iter().any(|s| s.id == "sid:2"));

    // DifatOffFile: fat_sector evidence, no subject.
    let f = OlecfAnomaly::StructureAnomaly(StructureIssue::DifatOffFile { sid: 42 })
        .to_finding(src.clone());
    assert!(f.evidence.iter().any(|e| e.field == "fat_sector"));
    assert!(f.subjects.is_empty());

    // BadByteOrder: byte_order evidence, no subject.
    let f = OlecfAnomaly::StructureAnomaly(StructureIssue::BadByteOrder { value: 0x1234 })
        .to_finding(src);
    assert!(f.evidence.iter().any(|e| e.field == "byte_order"));
    assert!(f.subjects.is_empty());
}

#[test]
fn free_sector_residue_has_no_subject_but_carries_evidence() {
    let f = OlecfAnomaly::FreeSectorResidue {
        sid: 9,
        space: "FAT",
        offset: 8192,
        residue_len: 64,
    }
    .to_finding(source(Scope::Whole));
    assert!(f.subjects.is_empty());
    assert!(f.evidence.iter().any(|e| e.field == "residue_len"));
    assert!(f.evidence.iter().any(|e| e.field == "space"));
}

#[test]
fn dir_entry_object_type_predicates() {
    let mut e = DirEntry {
        sid: 1,
        name: "s".into(),
        object_type: 0x02,
        color: 1,
        left: k::NOSTREAM,
        right: k::NOSTREAM,
        child: k::NOSTREAM,
        clsid: [0u8; 16],
        state_bits: 0,
        create_time: 0,
        modify_time: 0,
        start_sector: 0,
        stream_size: 0,
    };
    assert!(e.is_stream());
    assert!(e.is_allocated());

    e.object_type = 0x05; // root storage
    assert!(!e.is_stream());
    assert!(e.is_allocated());

    e.object_type = 0x00; // unallocated slot
    assert!(!e.is_stream());
    assert!(!e.is_allocated());
}

#[test]
fn sector_offset_formula_and_overflow() {
    // (sid + 1) << sector_shift.
    assert_eq!(cfb_forensic::raw::sector_offset(0, 9), Some(512));
    assert_eq!(cfb_forensic::raw::sector_offset(1, 9), Some(1024));
    assert_eq!(cfb_forensic::raw::sector_offset(3, 12), Some(4 * 4096));
    // A shift amount >= 64 returns None rather than panicking.
    assert_eq!(cfb_forensic::raw::sector_offset(1, 64), None);
}
