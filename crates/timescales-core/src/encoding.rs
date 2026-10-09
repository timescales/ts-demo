//! Canonical binary encoding.
//!
//! Every protocol object that is hashed, signed or committed to goes through
//! this encoding. The rules are deliberately boring:
//!
//! * Integers are fixed-width little-endian.
//! * Enums are a single tag byte and unknown tags are rejected.
//! * Byte arrays of static length are written verbatim.
//! * variable-length sequences carry a `u32` length prefix and a caller-supplied
//!   upper bound that is checked *before* any allocation.
//! * Decoding must consume the whole input (`decode_exact`), so two distinct
//!   byte strings never decode to the same value.
//!
//! There is no self-description and no schema evolution here. Versioning is
//! done explicitly with version fields in the outer objects.

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DecodeError {
    #[error("unexpected end of input: needed {needed} bytes, {remaining} remaining")]
    UnexpectedEof { needed: usize, remaining: usize },
    #[error("invalid tag {tag} for {ty}")]
    InvalidTag { ty: &'static str, tag: u8 },
    #[error("sequence length {len} exceeds bound {max}")]
    LengthExceeded { len: usize, max: usize },
    #[error("{0} trailing bytes after value")]
    TrailingBytes(usize),
    #[error("invalid value for {0}")]
    InvalidValue(&'static str),
}

/// Write side of the canonical encoding.
pub trait Encode {
    fn encode(&self, out: &mut Vec<u8>);

    /// Encoded size when it is known up front, so `to_bytes` allocates once.
    /// A hint only: the encoding never depends on it.
    fn encoded_len(&self) -> usize {
        0
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode(&mut out);
        out
    }
}

/// Read side of the canonical encoding.
pub trait Decode: Sized {
    /// Fewest bytes any value of this type encodes to. [`Reader::seq`]
    /// divides the input left by it to cap what a length prefix can make it
    /// reserve. The default of 1 is always sound. Types with a fixed or
    /// known minimum size override it. A value that is too large only costs
    /// reallocations, never correctness.
    const MIN_ENCODED_LEN: usize = 1;

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError>;

    /// Decode a value and require that `bytes` contains nothing else.
    fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish()?;
        Ok(v)
    }
}

/// Bounds-checked cursor over a byte slice.
#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.remaining() < n {
            return Err(DecodeError::UnexpectedEof {
                needed: n,
                remaining: self.remaining(),
            });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let s = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    pub fn i64(&mut self) -> Result<i64, DecodeError> {
        Ok(i64::from_le_bytes(self.array()?))
    }

    pub fn bool(&mut self) -> Result<bool, DecodeError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            tag => Err(DecodeError::InvalidTag { ty: "bool", tag }),
        }
    }

    /// Read a length prefix and check it against `max` before the caller
    /// allocates anything.
    pub fn len_prefix(&mut self, max: usize) -> Result<usize, DecodeError> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(DecodeError::LengthExceeded { len, max });
        }
        Ok(len)
    }

    pub fn bytes(&mut self, max: usize) -> Result<Vec<u8>, DecodeError> {
        let len = self.len_prefix(max)?;
        Ok(self.take(len)?.to_vec())
    }

    pub fn seq<T: Decode>(&mut self, max: usize) -> Result<Vec<T>, DecodeError> {
        let len = self.len_prefix(max)?;
        let mut v = Vec::with_capacity(self.seq_capacity::<T>(len));
        for _ in 0..len {
            v.push(T::decode(self)?);
        }
        Ok(v)
    }

    /// Elements [`Self::seq`] reserves for a length prefix of `len`. Each
    /// element takes at least `MIN_ENCODED_LEN` bytes, so a hostile length
    /// cannot reserve room for more elements than the rest of the input
    /// could describe.
    fn seq_capacity<T: Decode>(&self, len: usize) -> usize {
        len.min(self.remaining() / T::MIN_ENCODED_LEN.max(1))
    }

    pub fn finish(&self) -> Result<(), DecodeError> {
        match self.remaining() {
            0 => Ok(()),
            n => Err(DecodeError::TrailingBytes(n)),
        }
    }
}

pub fn put_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}

pub fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn put_i64(out: &mut Vec<u8>, v: i64) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn put_bool(out: &mut Vec<u8>, v: bool) {
    out.push(u8::from(v));
}

/// Length-prefixed byte string.
///
/// # Panics
/// If `bytes` is longer than `u32::MAX`. Protocol objects are bounded far
/// below that, so hitting this is a programming error.
pub fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_len(out, bytes.len());
    out.extend_from_slice(bytes);
}

pub fn put_seq<T: Encode>(out: &mut Vec<u8>, items: &[T]) {
    put_len(out, items.len());
    for item in items {
        item.encode(out);
    }
}

fn put_len(out: &mut Vec<u8>, len: usize) {
    let len = u32::try_from(len).expect("sequence longer than u32::MAX");
    put_u32(out, len);
}

impl Encode for u64 {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u64(out, *self);
    }
}

impl Decode for u64 {
    const MIN_ENCODED_LEN: usize = 8;

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.u64()
    }
}

impl<const N: usize> Encode for [u8; N] {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}

impl<const N: usize> Decode for [u8; N] {
    const MIN_ENCODED_LEN: usize = N;

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.array()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_trailing_bytes() {
        let mut b = 7u64.to_bytes();
        b.push(0);
        assert_eq!(u64::decode_exact(&b), Err(DecodeError::TrailingBytes(1)));
    }

    #[test]
    fn length_bound_checked_before_allocation() {
        let mut b = Vec::new();
        put_u32(&mut b, u32::MAX);
        let mut r = Reader::new(&b);
        assert!(matches!(
            r.seq::<u64>(16),
            Err(DecodeError::LengthExceeded { .. })
        ));
    }

    #[test]
    fn bool_is_strict() {
        let mut r = Reader::new(&[2]);
        assert!(r.bool().is_err());
    }

    #[test]
    fn every_decode_error_is_produced() {
        // Exhaustive on purpose: a new variant must be produced here.
        fn variant(e: &DecodeError) -> usize {
            match e {
                DecodeError::UnexpectedEof { .. } => 0,
                DecodeError::InvalidTag { .. } => 1,
                DecodeError::LengthExceeded { .. } => 2,
                DecodeError::TrailingBytes(_) => 3,
                DecodeError::InvalidValue(_) => 4,
            }
        }
        let mut long = Vec::new();
        put_u32(&mut long, 17);
        // A band whose low tick lies above its high tick.
        let inverted: Vec<u8> = [5u64, 4, 5].iter().flat_map(|t| t.to_le_bytes()).collect();
        let errors = [
            u64::decode_exact(&[0; 7]).map(|_| ()),
            Reader::new(&[2]).bool().map(|_| ()),
            Reader::new(&long).seq::<u64>(16).map(|_| ()),
            u64::decode_exact(&[0; 9]).map(|_| ()),
            crate::PriceBand::decode_exact(&inverted).map(|_| ()),
        ];
        let seen: Vec<usize> = errors
            .iter()
            .map(|e| variant(e.as_ref().unwrap_err()))
            .collect();
        assert_eq!(seen, [0, 1, 2, 3, 4]);
    }

    struct Wide;

    impl Decode for Wide {
        const MIN_ENCODED_LEN: usize = 289;

        fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
            r.take(289).map(|_| Wide)
        }
    }

    #[test]
    fn reservation_is_bounded_by_the_input_left() {
        let input = [0u8; 600];
        let r = Reader::new(&input);
        // A prefix claiming a million elements reserves only what 600 bytes
        // could hold: two 289-byte elements, 75 u64s, 600 one-byte items.
        assert_eq!(r.seq_capacity::<Wide>(1 << 20), 2);
        assert_eq!(r.seq_capacity::<u64>(1 << 20), 75);
        assert_eq!(r.seq_capacity::<[u8; 1]>(1 << 20), 600);
        // A zero-sized element never divides by zero.
        assert_eq!(r.seq_capacity::<[u8; 0]>(1 << 20), 600);
        // An honest prefix gets exactly what it asks for.
        assert_eq!(r.seq_capacity::<Wide>(2), 2);
        assert_eq!(r.seq_capacity::<u64>(3), 3);
    }

    #[test]
    fn hostile_length_fails_at_end_of_input() {
        let mut b = Vec::new();
        put_u32(&mut b, 1 << 20);
        b.extend_from_slice(&[0u8; 16]);
        let mut r = Reader::new(&b);
        assert!(matches!(
            r.seq::<u64>(1 << 24),
            Err(DecodeError::UnexpectedEof { .. })
        ));
    }

    #[test]
    fn min_encoded_len_of_primitives() {
        assert_eq!(<u64 as Decode>::MIN_ENCODED_LEN, 7u64.to_bytes().len());
        assert_eq!(<[u8; 32] as Decode>::MIN_ENCODED_LEN, 32);
        assert_eq!(<Wide as Decode>::MIN_ENCODED_LEN, 289);
    }
}
