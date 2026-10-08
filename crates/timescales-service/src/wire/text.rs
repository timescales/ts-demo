//! Bounded UTF-8 strings inside binary messages.

use timescales_core::{DecodeError, Reader};

/// A `u32`-prefixed UTF-8 string of at most `max` bytes.
pub(crate) fn read_utf8(
    r: &mut Reader<'_>,
    max: usize,
    what: &'static str,
) -> Result<String, DecodeError> {
    String::from_utf8(r.bytes(max)?).map_err(|_| DecodeError::InvalidValue(what))
}

/// The longest prefix of `s` that fits in `max` bytes and ends on a
/// character boundary.
pub(crate) fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use timescales_core::encoding::put_bytes;

    use super::*;

    #[test]
    fn truncation_stops_on_a_character_boundary() {
        assert_eq!(truncate_utf8("abc", 3), "abc");
        assert_eq!(truncate_utf8("abc", 2), "ab");
        assert_eq!(truncate_utf8("aé", 2), "a");
        assert_eq!(truncate_utf8("€€", 4), "€");
        assert_eq!(truncate_utf8("€", 0), "");
    }

    #[test]
    fn strings_are_bounded_and_utf8() {
        let mut b = Vec::new();
        put_bytes(&mut b, "héllo".as_bytes());
        assert_eq!(read_utf8(&mut Reader::new(&b), 6, "s"), Ok("héllo".into()));
        assert!(matches!(
            read_utf8(&mut Reader::new(&b), 5, "s"),
            Err(DecodeError::LengthExceeded { len: 6, max: 5 })
        ));
        let mut bad = Vec::new();
        put_bytes(&mut bad, &[0xc3, 0x28]);
        assert_eq!(
            read_utf8(&mut Reader::new(&bad), 8, "s"),
            Err(DecodeError::InvalidValue("s"))
        );
    }
}
