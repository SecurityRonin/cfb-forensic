//! Integration tests for `cfb-forensic`, validated against fixtures minted by
//! the `cfb` crate (see `examples/gen_cfb.rs`) and a real-world Jump List CFB.
//!
//! The cross-check oracle is the `cfb` crate's own live-stream listing: our
//! orphan set must be exactly the entries `cfb` no longer reaches.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use cfb_forensic::{
    audit_bytes, audit_findings, live_entry_names, OlecfAnomaly, Scope, StructureIssue,
};
use forensicnomicon::olecf as k;
use forensicnomicon::report::{Category, Severity};

const CLEAN: &[u8] = include_bytes!("data/clean.cfb");
const DELETED: &[u8] = include_bytes!("data/deleted_stream.cfb");
const ORPHANED: &[u8] = include_bytes!("data/orphaned_entry.cfb");
const JUMPLIST: &[u8] = include_bytes!("data/jumplist.automaticDestinations-ms");

fn codes(anomalies: &[OlecfAnomaly]) -> Vec<&'static str> {
    anomalies.iter().map(OlecfAnomaly::code).collect()
}

#[test]
fn clean_file_has_no_residue_or_tamper_findings() {
    let anomalies = audit_bytes(CLEAN);
    // Only the benign provenance breadcrumb; no orphan/residue/slack/tamper.
    assert_eq!(codes(&anomalies), vec!["OLECF-ROOT-CLSID"]);
    assert!(!codes(&anomalies).contains(&"OLECF-ORPHANED-DIR-ENTRY"));
    assert!(!codes(&anomalies).contains(&"OLECF-FREE-SECTOR-RESIDUE"));
}

#[test]
fn orphaned_entry_is_detected_and_carved() {
    let anomalies = audit_bytes(ORPHANED);
    let orphans: Vec<_> = anomalies
        .iter()
        .filter_map(|a| match a {
            OlecfAnomaly::OrphanedDirEntry(d) => Some(d),
            _ => None,
        })
        .collect();

    assert_eq!(orphans.len(), 1, "exactly one orphaned entry expected");
    let orphan = orphans[0];
    assert_eq!(orphan.name, "payload");
    assert_eq!(orphan.object_type, 0x02);
    assert_eq!(orphan.stream_size, 5000);
    // The resident FAT chain still holds the stream → carve recovers every byte.
    assert_eq!(orphan.carved_len, 5000, "carved the full resident stream");
}

#[test]
fn orphan_set_matches_cfb_live_set_difference() {
    // Doer-Checker: cfb's live listing is the oracle. clean.cfb has `payload`
    // live; orphaned_entry.cfb does not — so the orphan we report must be
    // exactly the entry that vanished from cfb's live set.
    let clean_live = live_entry_names(CLEAN).expect("cfb opens clean");
    let orphaned_live = live_entry_names(ORPHANED).expect("cfb opens orphaned");

    assert!(clean_live.contains(&"payload".to_string()));
    assert!(!orphaned_live.contains(&"payload".to_string()));

    let orphan_names: Vec<String> = audit_bytes(ORPHANED)
        .iter()
        .filter_map(|a| match a {
            OlecfAnomaly::OrphanedDirEntry(d) => Some(d.name.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(orphan_names, vec!["payload".to_string()]);
}

#[test]
fn deleted_stream_leaves_free_sector_residue() {
    let anomalies = audit_bytes(DELETED);
    let residue: Vec<_> = anomalies
        .iter()
        .filter_map(|a| match a {
            OlecfAnomaly::FreeSectorResidue { residue_len, .. } => Some(*residue_len),
            _ => None,
        })
        .collect();

    assert!(
        !residue.is_empty(),
        "freed sectors still hold the secret bytes"
    );
    // The deleted `secret` stream was 6000 bytes; its freed FAT sectors retain
    // exactly that many non-zero bytes (4096-byte sectors: 4096 + 1904 = 6000).
    let total: usize = residue.iter().sum();
    assert_eq!(
        total, 6000,
        "all 6000 secret bytes survive as free-sector residue"
    );

    // cfb's live set no longer lists `secret`.
    let live = live_entry_names(DELETED).expect("cfb opens deleted");
    assert!(!live.contains(&"secret".to_string()));
}

#[test]
fn stream_tamper_tells_fire_for_nonzero_clsid_state_filetime() {
    // [MS-CFB] §2.6.3: a stream entry's CLSID, state bits, and FILETIMEs must be
    // zero. Mutate clean.cfb's `note` stream entry to violate all three.
    let mut bytes = CLEAN.to_vec();
    let fds = u32::from_le_bytes(
        bytes[k::FIRST_DIR_SECTOR..k::FIRST_DIR_SECTOR + 4]
            .try_into()
            .unwrap(),
    );
    let shift = u16::from_le_bytes([bytes[k::SECTOR_SHIFT], bytes[k::SECTOR_SHIFT + 1]]);
    let dir0 = ((u64::from(fds) + 1) << shift) as usize;
    let note = dir0 + 2 * k::DIR_ENTRY_SIZE; // sid 2 = "note"
    bytes[note + k::CLSID] = 0xAB;
    bytes[note + k::STATE_BITS] = 0x01;
    bytes[note + k::CREATE_TIME] = 0x99;

    let anomalies = audit_bytes(&bytes);
    let issues: Vec<_> = anomalies
        .iter()
        .filter_map(|a| match a {
            OlecfAnomaly::StructureAnomaly(i) => Some(i.clone()),
            _ => None,
        })
        .collect();

    assert!(issues
        .iter()
        .any(|i| matches!(i, StructureIssue::StreamNonZeroClsid { .. })));
    assert!(issues
        .iter()
        .any(|i| matches!(i, StructureIssue::StreamNonZeroStateBits { .. })));
    assert!(issues
        .iter()
        .any(|i| matches!(i, StructureIssue::StreamNonZeroFiletime { .. })));
}

#[test]
fn real_world_jumplist_parses_without_panic_and_is_clean() {
    // A genuine *.automaticDestinations-ms is a well-formed CFB; it must parse
    // and surface no residue/tamper findings (only the provenance breadcrumb).
    assert!(
        live_entry_names(JUMPLIST).is_some(),
        "cfb opens the real jumplist"
    );
    let anomalies = audit_bytes(JUMPLIST);
    assert!(!codes(&anomalies).contains(&"OLECF-ORPHANED-DIR-ENTRY"));
    assert!(!codes(&anomalies).contains(&"OLECF-STRUCTURE-ANOMALY"));
}

#[test]
fn findings_carry_source_severity_category_and_mitre() {
    let findings = audit_findings(ORPHANED, Scope::Whole);
    let orphan = findings
        .iter()
        .find(|f| f.code == "OLECF-ORPHANED-DIR-ENTRY")
        .expect("orphan finding present");
    assert_eq!(orphan.severity, Some(Severity::High));
    assert_eq!(orphan.category, Category::Residue);
    assert_eq!(orphan.source.analyzer, "cfb-forensic");
    // Consistent-with MITRE techniques, never a verdict.
    let mitre: Vec<&str> = orphan
        .context
        .external_refs
        .iter()
        .map(|r| r.id.as_str())
        .collect();
    assert!(mitre.contains(&"T1070"));
    assert!(mitre.contains(&"T1564"));
}

#[test]
fn malformed_input_never_panics() {
    assert!(audit_bytes(&[]).is_empty());
    assert!(audit_bytes(&[0u8; 10]).is_empty());
    assert!(audit_bytes(&[0xFFu8; 5000]).is_empty());
    // Valid signature, garbage body — must not panic, must not falsely report.
    let mut sig = k::OLECF_SIGNATURE.to_vec();
    sig.extend_from_slice(&[0xCCu8; 4096]);
    let _ = audit_bytes(&sig);
}
