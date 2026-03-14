/// Parse a protection string like "rwx", "r-x", "rw-", "---" into a bitfield.
/// R = bit 0 (1), W = bit 1 (2), X = bit 2 (4).
/// A dash or missing character means the corresponding bit is not set.
pub fn parse_protection(s: &str) -> u8 {
    let mut bits: u8 = 0;
    let b = s.as_bytes();
    if b.first() == Some(&b'r') {
        bits |= 1;
    }
    if b.get(1) == Some(&b'w') {
        bits |= 2;
    }
    if b.get(2) == Some(&b'x') {
        bits |= 4;
    }
    bits
}

/// Convert a protection bitfield back to a string.
/// 7 -> "rwx", 5 -> "r-x", 0 -> "---", etc.
#[allow(dead_code)]
pub fn protection_to_string(bits: u8) -> String {
    let r = if bits & 1 != 0 { 'r' } else { '-' };
    let w = if bits & 2 != 0 { 'w' } else { '-' };
    let x = if bits & 4 != 0 { 'x' } else { '-' };
    format!("{}{}{}", r, w, x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rwx() {
        assert_eq!(parse_protection("rwx"), 7);
    }

    #[test]
    fn test_parse_read_only() {
        assert_eq!(parse_protection("r--"), 1);
    }

    #[test]
    fn test_parse_read_write() {
        assert_eq!(parse_protection("rw-"), 3);
    }

    #[test]
    fn test_parse_read_execute() {
        assert_eq!(parse_protection("r-x"), 5);
    }

    #[test]
    fn test_parse_none() {
        assert_eq!(parse_protection("---"), 0);
    }

    #[test]
    fn test_parse_write_only() {
        assert_eq!(parse_protection("-w-"), 2);
    }

    #[test]
    fn test_parse_execute_only() {
        assert_eq!(parse_protection("--x"), 4);
    }

    #[test]
    fn test_parse_empty_string() {
        assert_eq!(parse_protection(""), 0);
    }

    #[test]
    fn test_parse_partial_string() {
        assert_eq!(parse_protection("r"), 1);
        assert_eq!(parse_protection("rw"), 3);
    }

    #[test]
    fn test_to_string_all() {
        assert_eq!(protection_to_string(7), "rwx");
    }

    #[test]
    fn test_to_string_none() {
        assert_eq!(protection_to_string(0), "---");
    }

    #[test]
    fn test_to_string_read_execute() {
        assert_eq!(protection_to_string(5), "r-x");
    }

    #[test]
    fn test_to_string_write_execute() {
        assert_eq!(protection_to_string(6), "-wx");
    }

    #[test]
    fn test_roundtrip() {
        for bits in 0u8..8 {
            let s = protection_to_string(bits);
            assert_eq!(parse_protection(&s), bits, "roundtrip failed for bits={bits}");
        }
    }

    #[test]
    fn test_roundtrip_strings() {
        let cases = ["rwx", "r--", "rw-", "r-x", "---", "-w-", "--x", "-wx"];
        for s in cases {
            let bits = parse_protection(s);
            assert_eq!(protection_to_string(bits), s, "roundtrip failed for \"{s}\"");
        }
    }
}
