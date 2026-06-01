//! `egoc-sl2` — SL(2,Fq) group element and operations.
//!
//! # Design
//! `SL2<const Q: u64>` is a 2×2 matrix [[a,b],[c,d]] with det=1 over Fq.
//! The field prime Q is encoded in the type, matching `Fp<Q>`.
//! Group multiplication, inverse, identity, constant-time equality.

use egoc_field::{random_fp, Fp};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

pub use egoc_field::FieldError;

// ---------------------------------------------------------------------------
// SL2<Q> — 2×2 matrix over Fq with det = 1
// ---------------------------------------------------------------------------

/// A group element g ∈ SL(2,Fq): [[a,b],[c,d]], det(g) = ad−bc ≡ 1 (mod Q).
#[derive(Clone, Copy, Debug, Zeroize)]
pub struct SL2<const Q: u64> {
    pub a: Fp<Q>,
    pub b: Fp<Q>,
    pub c: Fp<Q>,
    pub d: Fp<Q>,
}

impl<const Q: u64> SL2<Q> {
    /// Construct and verify det = 1.
    pub fn new(a: Fp<Q>, b: Fp<Q>, c: Fp<Q>, d: Fp<Q>) -> Result<Self, SL2Error> {
        let det = a.mul(d).sub(b.mul(c));
        if det != Fp::<Q>::one() {
            return Err(SL2Error::InvalidDeterminant(det.val()));
        }
        Ok(Self { a, b, c, d })
    }

    /// Identity element: [[1,0],[0,1]].
    pub fn identity() -> Self {
        Self {
            a: Fp::one(), b: Fp::zero(),
            c: Fp::zero(), d: Fp::one(),
        }
    }

    /// Determinant — always 1 for valid elements.
    pub fn det(&self) -> Fp<Q> { self.a.mul(self.d).sub(self.b.mul(self.c)) }

    /// Group multiplication: self * rhs.
    pub fn mul(&self, rhs: &Self) -> Self {
        let result = Self {
            a: self.a.mul(rhs.a).add(self.b.mul(rhs.c)),
            b: self.a.mul(rhs.b).add(self.b.mul(rhs.d)),
            c: self.c.mul(rhs.a).add(self.d.mul(rhs.c)),
            d: self.c.mul(rhs.b).add(self.d.mul(rhs.d)),
        };
        debug_assert_eq!(
            result.det(), Fp::<Q>::one(),
            "SL2::mul produced det ≠ 1 — group invariant violated"
        );
        result
    }

    /// Group inverse: [[d,-b],[-c,a]] (since det=1).
    pub fn inverse(&self) -> Self {
        Self { a: self.d, b: self.b.neg(), c: self.c.neg(), d: self.a }
    }

    /// Negate all entries: −g. Note det(−g) = det(g) for 2×2.
    pub fn neg(&self) -> Self {
        Self { a: self.a.neg(), b: self.b.neg(), c: self.c.neg(), d: self.d.neg() }
    }

    /// Encode as 4 little-endian u64 values (32 bytes) for hashing.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&self.a.val().to_le_bytes());
        out[8..16].copy_from_slice(&self.b.val().to_le_bytes());
        out[16..24].copy_from_slice(&self.c.val().to_le_bytes());
        out[24..32].copy_from_slice(&self.d.val().to_le_bytes());
        out
    }
}

impl<const Q: u64> ConstantTimeEq for SL2<Q> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.a.ct_eq(&other.a)
            & self.b.ct_eq(&other.b)
            & self.c.ct_eq(&other.c)
            & self.d.ct_eq(&other.d)
    }
}

impl<const Q: u64> PartialEq for SL2<Q> {
    fn eq(&self, other: &Self) -> bool { bool::from(self.ct_eq(other)) }
}
impl<const Q: u64> Eq for SL2<Q> {}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Error from SL2 construction.
#[derive(Debug, thiserror::Error)]
pub enum SL2Error {
    /// The matrix has determinant ≠ 1.
    #[error("determinant is {0}, expected 1")]
    InvalidDeterminant(u64),
}

// ---------------------------------------------------------------------------
// Random SL(2,Fq) sampling
// ---------------------------------------------------------------------------

/// Sample a uniformly random g ∈ SL(2,Fq).
///
/// Method: sample a ≠ 0, then b, c uniformly; set d = (1 + b·c) · a⁻¹.
/// Expected retries: 1/(1 − 1/Q) ≈ 1 + 1/Q.
pub fn random_sl2<const Q: u64>(rng: &mut impl rand::RngCore) -> SL2<Q> {
    loop {
        let a: Fp<Q> = random_fp(rng);
        if bool::from(a.is_zero()) { continue; }
        let b: Fp<Q> = random_fp(rng);
        let c: Fp<Q> = random_fp(rng);
        let num = Fp::<Q>::one().add(b.mul(c));
        let d   = num.mul(a.inv_public());
        let det = a.mul(d).sub(b.mul(c));
        if det == Fp::<Q>::one() {
            return SL2 { a, b, c, d };
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    type G = SL2<101>;

    #[test]
    fn identity_det_one() {
        assert_eq!(G::identity().det(), Fp::<101>::one());
    }

    #[test]
    fn mul_inverse_is_identity() {
        let mut rng = StdRng::seed_from_u64(7);
        let g: G = random_sl2(&mut rng);
        assert_eq!(g.mul(&g.inverse()), G::identity());
    }

    #[test]
    fn det_preserved_under_mul() {
        let mut rng = StdRng::seed_from_u64(13);
        let g: G = random_sl2(&mut rng);
        let h: G = random_sl2(&mut rng);
        assert_eq!(g.mul(&h).det(), Fp::<101>::one());
    }

    #[test]
    fn neg_det_preserved() {
        let mut rng = StdRng::seed_from_u64(17);
        let g: G = random_sl2(&mut rng);
        assert_eq!(g.neg().det(), g.det());
    }

    #[test]
    fn neg_ne_g() {
        // Proves gauge_hash_neg_distinct is a theorem, not just an axiom:
        // g = -g => 2g = 0 => g = 0 (Q odd prime), but det(0) = 0 ≠ 1.
        // Therefore g ≠ -g always holds in SL(2,Fq), making H(g) ≠ H(-g)
        // provable from BLAKE3 collision resistance alone (no empirical assumption).
        let mut rng = StdRng::seed_from_u64(99);
        for _ in 0..1000 {
            let g: G = random_sl2(&mut rng);
            assert_ne!(g, g.neg(),
                "g = -g would require det(g) = 0, impossible in SL(2,Fq)");
        }
    }

    #[test]
    fn non_abelian() {
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..100 {
            let g: G = random_sl2(&mut rng);
            let h: G = random_sl2(&mut rng);
            if g.mul(&h) != h.mul(&g) { return; }
        }
        panic!("All 100 pairs commuted — SL(2,Fq) should be non-abelian for Q>3");
    }
}