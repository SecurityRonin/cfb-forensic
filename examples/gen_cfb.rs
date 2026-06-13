//! Mint the privacy-safe CFB test fixtures with the `cfb` crate, so the corpus
//! is reproducible from the recorded command and contains no real user data.
//!
//! Run from the repo root:
//!
//! ```text
//! cargo run --example gen_cfb
//! ```
//!
//! Produces, under `tests/data/`:
//!
//! - `clean.cfb`        — a root storage with one sub-storage and three streams
//!                        of varied sizes (one mini-stream, one large stream).
//! - `deleted_stream.cfb` — the same file with one stream removed *after* it was
//!                        written, so its directory entry is detached from the
//!                        live tree (orphan) and its sectors are freed but the
//!                        bytes remain (free-sector residue). The exact mutation
//!                        is: create streams `keep_a`, `secret`, `keep_b`, write
//!                        recognizable payloads, then `remove_stream("/secret")`.

use std::fs;
use std::io::{Cursor, Write};
use std::path::Path;

fn main() -> std::io::Result<()> {
    let out_dir = Path::new("tests/data");
    fs::create_dir_all(out_dir)?;

    write_clean(out_dir)?;
    write_deleted_stream(out_dir)?;
    write_orphaned_entry(out_dir)?;

    println!(
        "wrote clean.cfb, deleted_stream.cfb, orphaned_entry.cfb to {}",
        out_dir.display()
    );
    Ok(())
}

/// A clean compound file: root + one sub-storage + three streams.
fn write_clean(out_dir: &Path) -> std::io::Result<()> {
    let cursor = Cursor::new(Vec::new());
    let mut comp = cfb::CompoundFile::create(cursor)?;

    comp.create_storage("/docs")?;

    // Small stream → lives in the mini-FAT (< 4096 bytes).
    {
        let mut s = comp.create_stream("/docs/note")?;
        s.write_all(b"a short note that lives in the mini-stream")?;
    }
    // Another small stream.
    {
        let mut s = comp.create_stream("/summary")?;
        s.write_all(b"summary stream contents")?;
    }
    // Large stream → lives in the regular FAT (>= 4096 bytes).
    {
        let mut s = comp.create_stream("/payload")?;
        s.write_all(&vec![0x41u8; 5000])?;
    }

    comp.flush()?;
    let bytes = comp.into_inner().into_inner();
    fs::write(out_dir.join("clean.cfb"), bytes)?;
    Ok(())
}

/// A deleted-stream fixture: write three streams, then remove the middle one so
/// its directory entry is orphaned and its sectors are freed (residue survives).
fn write_deleted_stream(out_dir: &Path) -> std::io::Result<()> {
    let cursor = Cursor::new(Vec::new());
    let mut comp = cfb::CompoundFile::create(cursor)?;

    {
        let mut s = comp.create_stream("/keep_a")?;
        s.write_all(b"keep_a payload that should remain reachable")?;
    }
    {
        // The secret stream: a large, recognizable payload so the carve is
        // verifiable. >= 4096 bytes ⇒ regular-FAT sectors, easy to free-carve.
        let mut s = comp.create_stream("/secret")?;
        s.write_all(&recognizable_secret())?;
    }
    {
        let mut s = comp.create_stream("/keep_b")?;
        s.write_all(b"keep_b payload that should remain reachable")?;
    }

    comp.flush()?;
    // The mutation that produces the residue: remove the middle stream. `cfb`
    // detaches its directory entry from the red-black tree and frees its FAT
    // sectors, but does not zero the freed sector bytes.
    comp.remove_stream("/secret")?;
    comp.flush()?;

    let bytes = comp.into_inner().into_inner();
    fs::write(out_dir.join("deleted_stream.cfb"), bytes)?;
    Ok(())
}

/// An orphaned-directory-entry fixture.
///
/// The `cfb` crate is a tidy writer: `remove_stream` fully zeroes the deleted
/// directory entry, so a `cfb`-only deletion leaves free-sector residue but no
/// *orphaned entry* (the headline carve). Real-world deletions — and tools that
/// only unlink an entry from the red-black tree without scrubbing it — leave the
/// 128-byte entry (type, name, start sector, size, timestamps) intact while the
/// parent's child/sibling pointer is cleared.
///
/// We model that faithfully with a single, documented byte-level mutation of
/// `clean.cfb`: in the first directory sector, the `summary` entry (sid 3) points
/// to `payload` (sid 4) through its left-sibling field. We set that left-sibling
/// pointer to `NOSTREAM` (0xFFFFFFFF). The `payload` entry itself is left
/// untouched — type 0x02 (stream), name "payload", start sector 4, size 5000 — so
/// it becomes allocated-but-unreachable, and its FAT chain still holds the 5000
/// `0x41` bytes for the carve.
///
/// Mutation: at file offset `dir_sector0 + 3*128 + LEFT_SIBLING`, overwrite the
/// 4-byte left-sibling SID of entry 3 with 0xFFFFFFFF.
fn write_orphaned_entry(out_dir: &Path) -> std::io::Result<()> {
    use forensicnomicon::olecf as k;

    let mut bytes = fs::read(out_dir.join("clean.cfb"))?;

    // Resolve the directory's first sector offset from the header.
    let first_dir_sector =
        u32::from_le_bytes(read4(&bytes, k::FIRST_DIR_SECTOR)) as u64;
    let sector_shift = u16::from_le_bytes([bytes[k::SECTOR_SHIFT], bytes[k::SECTOR_SHIFT + 1]]);
    let sector_size = 1u64 << sector_shift;
    let dir_sector0 = (first_dir_sector + 1) * sector_size;

    // Entry 3 ("summary") left-sibling field → NOSTREAM, detaching entry 4
    // ("payload") from the live tree without scrubbing it.
    let target = (dir_sector0 as usize) + 3 * k::DIR_ENTRY_SIZE + k::LEFT_SIBLING;
    bytes[target..target + 4].copy_from_slice(&k::NOSTREAM.to_le_bytes());

    fs::write(out_dir.join("orphaned_entry.cfb"), bytes)?;
    Ok(())
}

fn read4(data: &[u8], off: usize) -> [u8; 4] {
    let mut b = [0u8; 4];
    b.copy_from_slice(&data[off..off + 4]);
    b
}

/// A recognizable 6000-byte payload: the marker string repeated. Easy to confirm
/// in a carve and large enough to span several FAT sectors.
fn recognizable_secret() -> Vec<u8> {
    let marker = b"SECRET-CARVE-MARKER-0123456789-";
    let mut out = Vec::with_capacity(6000);
    while out.len() < 6000 {
        out.extend_from_slice(marker);
    }
    out.truncate(6000);
    out
}
