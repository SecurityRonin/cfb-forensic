//! `cfb-forensic` — forensic carving over OLE Compound File Binary (`[MS-CFB]`)
//! files. RED stub: the public surface exists so the tests compile; the carving
//! and anomaly detection are implemented in the GREEN commit.

use forensicnomicon::report::{Category, Finding, Severity, Source};

/// Audit scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The whole file.
    Whole,
}

/// Producing source.
#[must_use]
pub fn source(_scope: Scope) -> Source {
    Source {
        analyzer: "cfb-forensic".to_string(),
        scope: "whole file".to_string(),
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    }
}

/// Recovered orphan detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrphanDetail {
    pub sid: u32,
    pub name: String,
    pub object_type: u8,
    pub stream_size: u64,
    pub start_sector: u32,
    pub create_time: u64,
    pub modify_time: u64,
    pub carved_len: usize,
}

/// Structural issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StructureIssue {
    StreamNonZeroClsid { sid: u32, name: String },
    StreamNonZeroStateBits { sid: u32, name: String, state_bits: u32 },
    StreamNonZeroFiletime { sid: u32, name: String },
    ChainLoop { space: &'static str },
    DifatOffFile { sid: u32 },
    BadByteOrder { value: u16 },
}

/// Anomaly kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OlecfAnomaly {
    OrphanedDirEntry(OrphanDetail),
    FreeSectorResidue { sid: u32, space: &'static str, offset: u64, residue_len: usize },
    SlackResidue { sid: u32, name: String, space: &'static str, slack_len: usize },
    StructureAnomaly(StructureIssue),
    RootClsid { sid: u32, name: String, clsid: String, create_time: u64, modify_time: u64 },
}

impl OlecfAnomaly {
    #[must_use]
    pub fn code(&self) -> &'static str {
        "OLECF-UNIMPLEMENTED"
    }
    #[must_use]
    pub fn severity(&self) -> Severity {
        Severity::Info
    }
    #[must_use]
    pub fn category(&self) -> Category {
        Category::Residue
    }
    #[must_use]
    pub fn note(&self) -> String {
        String::new()
    }
}

/// Audit bytes — RED stub returns nothing.
#[must_use]
pub fn audit_bytes(_data: &[u8]) -> Vec<OlecfAnomaly> {
    Vec::new()
}

/// Audit to findings — RED stub.
#[must_use]
pub fn audit_findings(_data: &[u8], _scope: Scope) -> Vec<Finding> {
    Vec::new()
}

/// Live entry names via the cfb crate — RED stub.
#[must_use]
pub fn live_entry_names(_data: &[u8]) -> Option<Vec<String>> {
    None
}

/// Live stream read via the cfb crate — RED stub.
#[must_use]
pub fn read_live_stream(_data: &[u8], _path: &str) -> Option<Vec<u8>> {
    None
}
