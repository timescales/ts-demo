//! Edwards point checks shared by the committee and epoch-key messages.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::traits::IsIdentity;

/// Decompresses canonical encodings only (`y < p`, and no sign bit when
/// `x = 0`): the point must re-encode to the same bytes. This is RFC 8032
/// strict decoding, as the SDK's `decompress` does it.
pub(crate) fn decompress_canonical(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    let point = CompressedEdwardsY(*bytes).decompress()?;
    (point.compress().as_bytes() == bytes).then_some(point)
}

/// A point of the prime-order subgroup other than the identity.
pub(crate) fn is_prime_order(point: &EdwardsPoint) -> bool {
    !point.is_identity() && point.is_torsion_free()
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
    use curve25519_dalek::scalar::Scalar;

    use super::*;

    #[test]
    fn multiples_of_the_base_point_are_prime_order() {
        let p = Scalar::from(123_456_789u64) * ED25519_BASEPOINT_POINT;
        let decoded = decompress_canonical(p.compress().as_bytes()).unwrap();
        assert_eq!(decoded, p);
        assert!(is_prime_order(&decoded));
    }

    #[test]
    fn identity_and_torsion_are_not_prime_order() {
        let identity = EdwardsPoint::default();
        assert!(decompress_canonical(identity.compress().as_bytes()).is_some());
        assert!(!is_prime_order(&identity));
        for t in &EIGHT_TORSION[1..] {
            assert!(!is_prime_order(t));
        }
        let mixed = ED25519_BASEPOINT_POINT + EIGHT_TORSION[1];
        assert!(decompress_canonical(mixed.compress().as_bytes()).is_some());
        assert!(!is_prime_order(&mixed));
    }

    #[test]
    fn non_canonical_encodings_are_refused() {
        // y = p + 1 reduces to the identity's y = 1.
        let mut y_above_p = [0xff; 32];
        y_above_p[0] = 0xee;
        y_above_p[31] = 0x7f;
        assert!(CompressedEdwardsY(y_above_p).decompress().is_some());
        assert!(decompress_canonical(&y_above_p).is_none());
        // x = 0 with the sign bit set.
        let mut negative_zero = [0u8; 32];
        negative_zero[0] = 1;
        negative_zero[31] = 0x80;
        assert!(decompress_canonical(&negative_zero).is_none());
    }

    #[test]
    fn bytes_off_the_curve_are_refused() {
        // y = 2 has no x on the curve.
        let mut y2 = [0u8; 32];
        y2[0] = 2;
        assert!(CompressedEdwardsY(y2).decompress().is_none());
        assert!(decompress_canonical(&y2).is_none());
    }
}
