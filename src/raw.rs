//! Thin, panic-free raw decode of the parts of an OLE Compound File the `cfb`
//! crate hides: the header, the FAT and mini-FAT sector chains, and the full
//! 128-byte directory-entry array (including entries the live red-black tree no
//! longer reaches). Offsets and sentinels come from
//! [`forensicnomicon::olecf`] — never hardcoded here.
//!
//! This is **not** a second CFB reader: live navigation, clean metadata, and
//! stream extraction stay with `cfb`. This module exists only so the analyzer
//! can see deleted/orphaned residue that a spec-faithful reader skips.

use forensicnomicon::olecf as k;

/// A decoded 128-byte directory entry. Every field is read with bounds checks;
/// a truncated entry yields zeroed / empty fields rather than a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// Index of this entry in the directory array (its stream id / SID).
    pub sid: u32,
    /// UTF-16LE name, lossily decoded and trimmed at the declared name length.
    pub name: String,
    /// Raw object-type byte (`0x00`/`0x01`/`0x02`/`0x05`).
    pub object_type: u8,
    /// Raw colour byte (`0x00` red / `0x01` black).
    pub color: u8,
    /// Left-sibling SID, or [`forensicnomicon::olecf::NOSTREAM`].
    pub left: u32,
    /// Right-sibling SID, or `NOSTREAM`.
    pub right: u32,
    /// Child SID (storages only), or `NOSTREAM`.
    pub child: u32,
    /// 16-byte class id, verbatim.
    pub clsid: [u8; 16],
    /// User-defined state bits.
    pub state_bits: u32,
    /// Creation FILETIME (raw `u64`).
    pub create_time: u64,
    /// Modification FILETIME (raw `u64`).
    pub modify_time: u64,
    /// Starting sector id of the entry's stream (or mini-stream for the root).
    pub start_sector: u32,
    /// Declared stream size in bytes.
    pub stream_size: u64,
}

impl DirEntry {
    /// True if this entry's object type marks it as a live stream or storage
    /// (`0x01`/`0x02`/`0x05`) rather than an unallocated `0x00` slot.
    #[must_use]
    pub fn is_allocated(&self) -> bool {
        matches!(self.object_type, 0x01 | 0x02 | 0x05)
    }

    /// True for a stream object (`0x02`).
    #[must_use]
    pub fn is_stream(&self) -> bool {
        self.object_type == 0x02
    }
}

/// The decoded shape of a compound file, carrying everything the analyzer needs
/// that `cfb` does not surface.
#[derive(Debug, Clone)]
pub struct RawCfb {
    /// Major version (3 or 4) as read from the header.
    pub major_version: u16,
    /// `log2(sector size)` from the header.
    pub sector_shift: u16,
    /// `log2(mini-sector size)` from the header (normally 6).
    pub mini_sector_shift: u16,
    /// Mini-stream size cutoff (normally 4096).
    pub mini_stream_cutoff: u32,
    /// Byte-order mark as read (normally `0xFFFE`).
    pub byte_order: u16,
    /// Resolved sector size in bytes (`1 << sector_shift`, clamped to a sane range).
    pub sector_size: usize,
    /// First DIFAT sector id from the header.
    pub first_difat_sector: u32,
    /// Declared DIFAT sector count from the header.
    pub num_difat_sectors: u32,
    /// The full FAT: one next-SID slot per sector in the file.
    pub fat: Vec<u32>,
    /// The mini-FAT: one next-mini-SID slot per mini-sector.
    pub mini_fat: Vec<u32>,
    /// Every directory entry, in array order (live and orphaned alike).
    pub dir_entries: Vec<DirEntry>,
    /// Total file length in bytes.
    pub file_len: u64,
}

/// Hard caps so a hostile length/count field cannot drive an allocation bomb or
/// an unbounded walk. A real CFB never approaches these.
const MAX_SECTORS: usize = 16 * 1024 * 1024;
const MAX_DIR_ENTRIES: usize = 4 * 1024 * 1024;
const MAX_CHAIN_STEPS: usize = 32 * 1024 * 1024;

#[inline]
fn le_u16(data: &[u8], off: usize) -> u16 {
    let mut b = [0u8; 2];
    if let Some(s) = data.get(off..off + 2) {
        b.copy_from_slice(s);
    }
    u16::from_le_bytes(b)
}

#[inline]
fn le_u32(data: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    if let Some(s) = data.get(off..off + 4) {
        b.copy_from_slice(s);
    }
    u32::from_le_bytes(b)
}

#[inline]
fn le_u64(data: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    if let Some(s) = data.get(off..off + 8) {
        b.copy_from_slice(s);
    }
    u64::from_le_bytes(b)
}

/// Byte offset of regular sector `sid`: `(sid + 1) << sector_shift`
/// ([`forensicnomicon::olecf`] formula). Returns `None` on overflow.
#[must_use]
pub fn sector_offset(sid: u32, sector_shift: u16) -> Option<u64> {
    (u64::from(sid)).checked_add(1)?.checked_shl(u32::from(sector_shift))
}

/// Decode a compound file's header, FAT, mini-FAT, and directory array.
///
/// Returns `None` only when the buffer is too small to hold a header or lacks
/// the OLECF signature; every field beyond that degrades to a safe default
/// rather than failing, so partially-corrupt images still yield residue.
#[must_use]
pub fn decode(data: &[u8]) -> Option<RawCfb> {
    if data.len() < k::HEADER_SIZE {
        return None;
    }
    if data.get(0..8) != Some(&k::OLECF_SIGNATURE) {
        return None;
    }

    let major_version = le_u16(data, k::MAJOR_VERSION);
    let sector_shift = le_u16(data, k::SECTOR_SHIFT);
    let mini_sector_shift = le_u16(data, k::MINI_SECTOR_SHIFT);
    let mini_stream_cutoff = le_u32(data, k::MINI_STREAM_CUTOFF);
    let byte_order = le_u16(data, k::BYTE_ORDER);

    // Clamp the sector shift to the spec range (9..=12 covers v3/v4); an absurd
    // shift would otherwise produce a meaningless sector size. Default to v3.
    let effective_shift = if (9..=20).contains(&sector_shift) {
        sector_shift
    } else {
        u16::from(k::SECTOR_SHIFT_V3)
    };
    let sector_size = 1usize << effective_shift;

    let first_dir_sector = le_u32(data, k::FIRST_DIR_SECTOR);
    let first_minifat_sector = le_u32(data, k::FIRST_MINIFAT_SECTOR);
    let first_difat_sector = le_u32(data, k::FIRST_DIFAT_SECTOR);
    let num_difat_sectors = le_u32(data, k::NUM_DIFAT_SECTORS);

    let file_len = data.len() as u64;

    let fat = read_fat(data, sector_size, first_difat_sector, num_difat_sectors);
    let mini_fat = read_chain_table(data, sector_size, &fat, first_minifat_sector);
    let dir_entries = read_directory(data, sector_size, &fat, first_dir_sector);

    Some(RawCfb {
        major_version,
        sector_shift,
        mini_sector_shift,
        mini_stream_cutoff,
        byte_order,
        sector_size,
        first_difat_sector,
        num_difat_sectors,
        fat,
        mini_fat,
        dir_entries,
        file_len,
    })
}

/// Read the slice of bytes for regular sector `sid`, or `None` if out of range.
fn sector_slice(data: &[u8], sector_size: usize, sid: u32) -> Option<&[u8]> {
    let start = (u64::from(sid) + 1).checked_mul(sector_size as u64)?;
    let start = usize::try_from(start).ok()?;
    let end = start.checked_add(sector_size)?;
    data.get(start..end)
}

/// Assemble the FAT by following the DIFAT: the 109 in-header slots, then any
/// DIFAT-sector chain. Each referenced FAT sector contributes `sector_size/4`
/// next-pointers. Bounded by [`MAX_SECTORS`] and [`MAX_CHAIN_STEPS`].
fn read_fat(
    data: &[u8],
    sector_size: usize,
    first_difat_sector: u32,
    num_difat_sectors: u32,
) -> Vec<u32> {
    let entries_per_sector = sector_size / 4;
    let mut fat_sector_ids: Vec<u32> = Vec::new();

    // 109 in-header DIFAT entries.
    for i in 0..k::DIFAT_HEADER_COUNT {
        let sid = le_u32(data, k::DIFAT_HEADER_OFFSET + i * 4);
        if sid <= k::MAXREGSECT {
            fat_sector_ids.push(sid);
        }
    }

    // DIFAT-sector chain: each DIFAT sector holds (entries_per_sector - 1) FAT
    // sector ids plus a trailing next-DIFAT-sector pointer.
    let mut difat_sid = first_difat_sector;
    let mut steps = 0usize;
    let difat_cap = (num_difat_sectors as usize).saturating_add(MAX_SECTORS).min(MAX_SECTORS);
    while difat_sid <= k::MAXREGSECT && steps < difat_cap && steps < MAX_CHAIN_STEPS {
        let Some(sector) = sector_slice(data, sector_size, difat_sid) else {
            break;
        };
        if entries_per_sector == 0 {
            break; // cov:unreachable: sector_size>=512 so entries_per_sector>=128
        }
        for i in 0..(entries_per_sector - 1) {
            let sid = le_u32(sector, i * 4);
            if sid <= k::MAXREGSECT {
                fat_sector_ids.push(sid);
            }
        }
        difat_sid = le_u32(sector, (entries_per_sector - 1) * 4);
        steps += 1;
        if fat_sector_ids.len() > MAX_SECTORS {
            break;
        }
    }

    // Concatenate the FAT sectors into the full next-pointer table.
    let mut fat: Vec<u32> = Vec::new();
    for sid in fat_sector_ids {
        let Some(sector) = sector_slice(data, sector_size, sid) else {
            continue;
        };
        for i in 0..entries_per_sector {
            fat.push(le_u32(sector, i * 4));
            if fat.len() >= MAX_SECTORS {
                return fat;
            }
        }
    }
    fat
}

/// Follow a FAT sector chain from `first_sid`, concatenating each sector's
/// `u32` slots into a flat table (used for the mini-FAT). Loop-guarded.
fn read_chain_table(data: &[u8], sector_size: usize, fat: &[u32], first_sid: u32) -> Vec<u32> {
    let entries_per_sector = sector_size / 4;
    let mut out: Vec<u32> = Vec::new();
    let mut sid = first_sid;
    let mut seen = 0usize;
    let mut visited = vec![false; fat.len()];
    while sid <= k::MAXREGSECT && seen < MAX_CHAIN_STEPS {
        if let Some(slot) = visited.get_mut(sid as usize) {
            if *slot {
                break; // chain loop
            }
            *slot = true;
        }
        let Some(sector) = sector_slice(data, sector_size, sid) else {
            break;
        };
        for i in 0..entries_per_sector {
            out.push(le_u32(sector, i * 4));
            if out.len() >= MAX_SECTORS {
                return out;
            }
        }
        sid = next_in_fat(fat, sid);
        seen += 1;
    }
    out
}

/// Read every directory entry by following the directory-sector chain from
/// `first_dir_sector` and slicing each sector into 128-byte entries. Bounded by
/// [`MAX_DIR_ENTRIES`]; loop-guarded against a cyclic directory chain.
fn read_directory(data: &[u8], sector_size: usize, fat: &[u32], first_dir_sector: u32) -> Vec<DirEntry> {
    let entries_per_sector = sector_size / k::DIR_ENTRY_SIZE;
    let mut entries: Vec<DirEntry> = Vec::new();
    let mut sid = first_dir_sector;
    let mut seen = 0usize;
    let mut visited = vec![false; fat.len()];
    while sid <= k::MAXREGSECT && seen < MAX_CHAIN_STEPS {
        if let Some(slot) = visited.get_mut(sid as usize) {
            if *slot {
                break; // directory-chain loop
            }
            *slot = true;
        }
        let Some(sector) = sector_slice(data, sector_size, sid) else {
            break;
        };
        for i in 0..entries_per_sector {
            let base = i * k::DIR_ENTRY_SIZE;
            let Some(raw) = sector.get(base..base + k::DIR_ENTRY_SIZE) else {
                break; // cov:unreachable: entries_per_sector bounds i within the sector
            };
            let sid_index = entries.len() as u32;
            entries.push(parse_dir_entry(raw, sid_index));
            if entries.len() >= MAX_DIR_ENTRIES {
                return entries;
            }
        }
        sid = next_in_fat(fat, sid);
        seen += 1;
    }
    entries
}

/// FAT next-pointer for `sid`, or [`forensicnomicon::olecf::ENDOFCHAIN`] when
/// the sid is past the table (treat an out-of-range pointer as chain end).
fn next_in_fat(fat: &[u32], sid: u32) -> u32 {
    fat.get(sid as usize).copied().unwrap_or(k::ENDOFCHAIN)
}

/// Decode one 128-byte directory entry. `raw` is guaranteed 128 bytes by the
/// caller; every field read still goes through a bounds-checked helper.
fn parse_dir_entry(raw: &[u8], sid: u32) -> DirEntry {
    let name_len = le_u16(raw, k::NAME_LEN) as usize;
    let name = decode_entry_name(raw, name_len);

    let mut clsid = [0u8; 16];
    if let Some(s) = raw.get(k::CLSID..k::CLSID + 16) {
        clsid.copy_from_slice(s);
    }

    DirEntry {
        sid,
        name,
        object_type: raw.get(k::OBJECT_TYPE).copied().unwrap_or(0),
        color: raw.get(k::COLOR).copied().unwrap_or(0),
        left: le_u32(raw, k::LEFT_SIBLING),
        right: le_u32(raw, k::RIGHT_SIBLING),
        child: le_u32(raw, k::CHILD),
        clsid,
        state_bits: le_u32(raw, k::STATE_BITS),
        create_time: le_u64(raw, k::CREATE_TIME),
        modify_time: le_u64(raw, k::MODIFY_TIME),
        start_sector: le_u32(raw, k::START_SECTOR),
        stream_size: le_u64(raw, k::STREAM_SIZE),
    }
}

/// Lossily decode an entry's UTF-16LE name, honoring the declared byte length
/// (which includes the terminating NUL) but never trusting it past 64 bytes.
fn decode_entry_name(raw: &[u8], declared_len: usize) -> String {
    // `declared_len` counts bytes including the trailing UTF-16 NUL; clamp to the
    // 64-byte field and drop the terminator before decoding.
    let byte_len = declared_len.min(k::NAME_LEN);
    let chars = byte_len / 2;
    let chars = chars.saturating_sub(if chars > 0 { 1 } else { 0 });
    let mut units: Vec<u16> = Vec::with_capacity(chars);
    for i in 0..chars {
        units.push(le_u16(raw, k::NAME + i * 2));
    }
    String::from_utf16_lossy(&units)
}

/// Walk the live red-black directory tree from the root entry, returning the set
/// of SIDs reachable through child/left/right pointers. Mirrors what the `cfb`
/// crate exposes; everything allocated-but-unreached is an orphan.
///
/// Loop-guarded by a visited set, so a corrupt sibling cycle terminates.
#[must_use]
pub fn reachable_sids(entries: &[DirEntry]) -> Vec<bool> {
    let mut reachable = vec![false; entries.len()];
    if entries.is_empty() {
        return reachable;
    }
    // The root storage is always entry 0 (`[MS-CFB]` §2.6.2).
    let mut stack: Vec<u32> = vec![0];
    let mut steps = 0usize;
    while let Some(sid) = stack.pop() {
        steps += 1;
        if steps > MAX_DIR_ENTRIES {
            break; // cov:unreachable: each SID is marked once, so steps <= entries.len()
        }
        let idx = sid as usize;
        let Some(slot) = reachable.get_mut(idx) else {
            continue;
        };
        if *slot {
            continue;
        }
        *slot = true;
        let Some(entry) = entries.get(idx) else {
            continue; // cov:unreachable: reachable and entries share a length
        };
        for next in [entry.child, entry.left, entry.right] {
            if next <= k::MAXREGSECT && (next as usize) < entries.len() {
                stack.push(next);
            }
        }
    }
    reachable
}
