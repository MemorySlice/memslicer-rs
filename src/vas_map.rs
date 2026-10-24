//! VAS Map (0x1001) entries covering the whole enumerated address space.
//!
//! One entry is produced per enumerated range, whether its bytes were
//! captured or the range was skipped by pre-filtering or the user's filters,
//! so a consumer can tell "not stored" from "did not exist". Names come from
//! the live enumeration (`NameSource` 1).

use libmsl::{VasEntry, VasNameSource};

use crate::acquire::classify_region;
use crate::backend::RangeInfo;
use crate::protection::parse_protection;

/// Build the VAS Map entries for `ranges`, ordered by base address.
pub fn build_vas_entries(ranges: &[RangeInfo]) -> Vec<VasEntry> {
    let mut entries: Vec<VasEntry> = ranges.iter().map(vas_entry).collect();
    entries.sort_by_key(|entry| entry.base_addr);
    entries
}

fn vas_entry(range: &RangeInfo) -> VasEntry {
    VasEntry {
        base_addr: range.base_addr,
        region_size: range.size,
        protection: parse_protection(&range.protection),
        region_type: classify_region(&range.file_path),
        name_source: VasNameSource::Live,
        mapped_path: range.file_path.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libmsl::RegionType;

    fn range(base_addr: u64, protection: &str, file_path: &str, readable: bool) -> RangeInfo {
        RangeInfo {
            base_addr,
            size: 0x1000,
            protection: protection.to_string(),
            file_path: file_path.to_string(),
            readable,
            skip_reason: (!readable).then(|| "test skip".to_string()),
            pages_resident: -1,
        }
    }

    #[test]
    fn captured_and_skipped_ranges_both_get_entries() {
        let ranges = vec![
            range(0x2000, "r--", "/dev/binder", false),
            range(0x1000, "rw-", "[heap]", true),
        ];
        let entries = build_vas_entries(&ranges);
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|e| e.name_source == VasNameSource::Live));
        assert_eq!(
            entries[0].base_addr, 0x1000,
            "entries are sorted by address"
        );
        assert_eq!(entries[1].base_addr, 0x2000);
    }

    #[test]
    fn entry_carries_size_protection_type_and_path() {
        let entries = build_vas_entries(&[range(0x7000, "r-x", "/system/lib64/libc.so", true)]);
        let entry = &entries[0];
        assert_eq!(entry.region_size, 0x1000);
        assert_eq!(entry.protection, 0b101);
        assert_eq!(entry.region_type, RegionType::Image);
        assert_eq!(entry.mapped_path, "/system/lib64/libc.so");
    }

    #[test]
    fn anonymous_range_has_empty_path_and_anon_type() {
        let entries = build_vas_entries(&[range(0x9000, "rw-", "", true)]);
        assert_eq!(entries[0].mapped_path, "");
        assert_eq!(entries[0].region_type, RegionType::Anon);
    }

    #[test]
    fn pseudo_names_are_kept_as_reported() {
        let entries = build_vas_entries(&[
            range(0x1000, "rw-", "[stack]", true),
            range(0x2000, "r--", "[vdso]", true),
        ]);
        assert_eq!(entries[0].mapped_path, "[stack]");
        assert_eq!(entries[0].region_type, RegionType::Stack);
        assert_eq!(entries[1].mapped_path, "[vdso]");
        assert_eq!(entries[1].region_type, RegionType::Unknown);
    }

    #[test]
    fn empty_enumeration_gives_empty_map() {
        assert!(build_vas_entries(&[]).is_empty());
    }
}
