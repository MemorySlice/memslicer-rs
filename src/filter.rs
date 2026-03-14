use regex::Regex;

/// Decides whether a memory region should be included based on address ranges,
/// protection bits, and file path patterns. All non-empty conditions use AND logic.
pub struct RegionFilter {
    /// Only include regions overlapping at least one of these address ranges.
    pub addr_ranges: Vec<(u64, u64)>,
    /// Minimum protection bits required (bitwise AND check).
    pub min_prot: u8,
    /// If non-empty, the region's file_path must match at least one regex.
    pub include_paths: Vec<Regex>,
    /// Exclude the region if its file_path matches any of these regexes.
    pub exclude_paths: Vec<Regex>,
}

impl RegionFilter {
    /// Create an empty filter that accepts every region.
    pub fn new() -> Self {
        Self {
            addr_ranges: Vec::new(),
            min_prot: 0,
            include_paths: Vec::new(),
            exclude_paths: Vec::new(),
        }
    }

    /// Return `true` if the region passes all configured filter conditions.
    ///
    /// - Address range check: the region `[base_addr, base_addr + size)` must
    ///   overlap at least one entry in `addr_ranges` (if non-empty).
    /// - Protection check: `(protection & min_prot) == min_prot` (if `min_prot != 0`).
    /// - Include paths: `file_path` must match at least one regex (if non-empty).
    /// - Exclude paths: `file_path` must NOT match any regex (if non-empty).
    pub fn matches(
        &self,
        base_addr: u64,
        size: u64,
        protection: u8,
        file_path: &str,
    ) -> bool {
        if !self.check_addr_ranges(base_addr, size) {
            return false;
        }
        if !self.check_protection(protection) {
            return false;
        }
        if !self.check_include_paths(file_path) {
            return false;
        }
        if !self.check_exclude_paths(file_path) {
            return false;
        }
        true
    }

    fn check_addr_ranges(&self, base_addr: u64, size: u64) -> bool {
        if self.addr_ranges.is_empty() {
            return true;
        }
        let region_end = base_addr.saturating_add(size);
        self.addr_ranges
            .iter()
            .any(|&(start, end)| base_addr < end && region_end > start)
    }

    fn check_protection(&self, protection: u8) -> bool {
        if self.min_prot == 0 {
            return true;
        }
        (protection & self.min_prot) == self.min_prot
    }

    fn check_include_paths(&self, file_path: &str) -> bool {
        if self.include_paths.is_empty() {
            return true;
        }
        self.include_paths.iter().any(|re| re.is_match(file_path))
    }

    fn check_exclude_paths(&self, file_path: &str) -> bool {
        if self.exclude_paths.is_empty() {
            return true;
        }
        !self.exclude_paths.iter().any(|re| re.is_match(file_path))
    }
}

impl Default for RegionFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn re(pattern: &str) -> Regex {
        Regex::new(pattern).unwrap()
    }

    // --- empty filter accepts everything ---

    #[test]
    fn test_empty_filter_accepts_all() {
        let f = RegionFilter::new();
        assert!(f.matches(0x1000, 0x1000, 7, "/usr/lib/libc.so"));
        assert!(f.matches(0, 0, 0, ""));
    }

    // --- address range tests ---

    #[test]
    fn test_addr_range_overlap() {
        let mut f = RegionFilter::new();
        f.addr_ranges.push((0x2000, 0x4000));

        // fully inside
        assert!(f.matches(0x2500, 0x500, 7, ""));
        // overlaps start
        assert!(f.matches(0x1000, 0x2000, 7, ""));
        // overlaps end
        assert!(f.matches(0x3000, 0x2000, 7, ""));
        // fully contains the range
        assert!(f.matches(0x1000, 0x5000, 7, ""));
    }

    #[test]
    fn test_addr_range_no_overlap() {
        let mut f = RegionFilter::new();
        f.addr_ranges.push((0x2000, 0x4000));

        // before
        assert!(!f.matches(0x0, 0x1000, 7, ""));
        // exactly adjacent (no overlap)
        assert!(!f.matches(0x0, 0x2000, 7, ""));
        // after
        assert!(!f.matches(0x4000, 0x1000, 7, ""));
    }

    #[test]
    fn test_multiple_addr_ranges() {
        let mut f = RegionFilter::new();
        f.addr_ranges.push((0x1000, 0x2000));
        f.addr_ranges.push((0x5000, 0x6000));

        assert!(f.matches(0x1500, 0x100, 7, ""));
        assert!(f.matches(0x5500, 0x100, 7, ""));
        assert!(!f.matches(0x3000, 0x100, 7, ""));
    }

    // --- protection tests ---

    #[test]
    fn test_min_prot_read() {
        let mut f = RegionFilter::new();
        f.min_prot = 1; // require read

        assert!(f.matches(0, 0x1000, 1, ""));  // r--
        assert!(f.matches(0, 0x1000, 7, ""));  // rwx
        assert!(!f.matches(0, 0x1000, 2, "")); // -w-
        assert!(!f.matches(0, 0x1000, 0, "")); // ---
    }

    #[test]
    fn test_min_prot_read_write() {
        let mut f = RegionFilter::new();
        f.min_prot = 3; // require rw

        assert!(f.matches(0, 0x1000, 3, ""));  // rw-
        assert!(f.matches(0, 0x1000, 7, ""));  // rwx
        assert!(!f.matches(0, 0x1000, 1, "")); // r--
        assert!(!f.matches(0, 0x1000, 5, "")); // r-x
    }

    // --- include path tests ---

    #[test]
    fn test_include_paths_match() {
        let mut f = RegionFilter::new();
        f.include_paths.push(re(r"libc"));

        assert!(f.matches(0, 0x1000, 7, "/usr/lib/libc.so"));
        assert!(!f.matches(0, 0x1000, 7, "/usr/lib/libm.so"));
    }

    #[test]
    fn test_include_paths_any() {
        let mut f = RegionFilter::new();
        f.include_paths.push(re(r"libc"));
        f.include_paths.push(re(r"libm"));

        assert!(f.matches(0, 0x1000, 7, "/usr/lib/libc.so"));
        assert!(f.matches(0, 0x1000, 7, "/usr/lib/libm.so"));
        assert!(!f.matches(0, 0x1000, 7, "/usr/lib/libz.so"));
    }

    // --- exclude path tests ---

    #[test]
    fn test_exclude_paths() {
        let mut f = RegionFilter::new();
        f.exclude_paths.push(re(r"\.so$"));

        assert!(!f.matches(0, 0x1000, 7, "/usr/lib/libc.so"));
        assert!(f.matches(0, 0x1000, 7, "/usr/bin/app"));
        assert!(f.matches(0, 0x1000, 7, ""));
    }

    // --- combined conditions (AND logic) ---

    #[test]
    fn test_combined_conditions() {
        let mut f = RegionFilter::new();
        f.addr_ranges.push((0x1000, 0x3000));
        f.min_prot = 1;
        f.include_paths.push(re(r"libc"));
        f.exclude_paths.push(re(r"debug"));

        // all conditions pass
        assert!(f.matches(0x1500, 0x500, 5, "/usr/lib/libc.so"));

        // addr out of range
        assert!(!f.matches(0x5000, 0x500, 5, "/usr/lib/libc.so"));

        // insufficient protection
        assert!(!f.matches(0x1500, 0x500, 0, "/usr/lib/libc.so"));

        // path not in include list
        assert!(!f.matches(0x1500, 0x500, 5, "/usr/lib/libz.so"));

        // path matches exclude
        assert!(!f.matches(0x1500, 0x500, 5, "/usr/lib/libc-debug.so"));
    }

    #[test]
    fn test_default_trait() {
        let f = RegionFilter::default();
        assert!(f.matches(0x1000, 0x1000, 7, "/anything"));
    }
}
