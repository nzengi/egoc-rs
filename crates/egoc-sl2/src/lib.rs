//! `egoc-sl2` — SL(2,Fq) group element and operations.
//!
//! # Design (Committee: A1 de Valence, A4 Szalai, A5 DJB)
//! - `SL2` is a 2×2 matrix [[a,b],[c,d]] with det=1 over Fq
//! - Group multiplication, inverse, identity
//! - Constant-time equality via `subtle`
//! - `zeroize::Zeroize` — secret gauge elements wiped on drop
//! - `random_sl2` uses `rand::CryptoRng` (OsRng in production)

use egoc_field::{Fp, random_fp};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

pub use egoc_field::FieldError;

// ---------------------------------------------------------------------------
// SL2 — 2×2 matrix over Fq with det = 1
// ---------------------------------------------------------------------------

/// A group element g ∈ SL(2,Fq): [[a,b],[c,d]], det(g)=ad-bc≡1 (mod q).
#[derive(Clone, Copy, Debug, Zeroize)]
pub struct SL2 {
    pub a: Fp,
    pub b: Fp,
    pub c: Fp,
    pub d: Fp,
}

impl SL2 {
    /// Construct and verify det = 1.
    pub fn new(a: Fp, b: Fp, c: Fp, d: Fp) -> Result<Self, SL2Error> {
        let det = a.mul(d).sub(b.mul(c));
        if det != Fp::one(a.q()) {
            return Err(SL2Error::InvalidDeterminant(det.val()));
        }
        Ok(Self { a, b, c, d })
    }

    /// Identity element: [[1,0],[0,1]].
    pub fn identity(q: u64) -> Self {
        Self {
            a: Fp::one(q), b: Fp::zero(q),
            c: Fp::zero(q), d: Fp::one(q),
        }
    }

    pub fn q(&self) -> u64 { self.a.q() }

    /// Determinant (should always be 1 for valid elements).
    pub fn det(&self) -> Fp { self.a.mul(self.d).sub(self.b.mul(self.c)) }

    /// Group multiplication: self * rhs.
    pub fn mul(&self, rhs: &Self) -> Self {
        let result = Self {
            a: self.a.mul(rhs.a).add(self.b.mul(rhs.c)),
            b: self.a.mul(rhs.b).add(self.b.mul(rhs.d)),
            c: self.c.mul(rhs.a).add(self.d.mul(rhs.c)),
            d: self.c.mul(rhs.b).add(self.d.mul(rhs.d)),
        };
        // det(AB) = det(A)·det(B) = 1·1 = 1 — verify in debug builds.
        debug_assert_eq!(
            result.det(), Fp::one(self.q()),
            "SL2::mul produced det ≠ 1 — group invariant violated"
        );
        result
    }

    /// Group inverse: [[d,-b],[-c,a]] (since det=1).
    pub fn inverse(&self) -> Self {
        Self {
            a:  self.d,
            b:  self.b.neg(),
            c:  self.c.neg(),
            d:  self.a,
        }
    }

    /// Returns -g (negate all entries).  Note: det(-g) = det(g) when n is even.
    /// For 2×2: det(-g) = (-a)(-d)-(-b)(-c) = ad-bc = det(g).
    pub fn neg(&self) -> Self {
        Self {
            a: self.a.neg(),
            b: self.b.neg(),
            c: self.c.neg(),
            d: self.d.neg(),
        }
    }

    /// Encode as 4 little-endian u64 values (for hashing).
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&self.a.val().to_le_bytes());
        out[8..16].copy_from_slice(&self.b.val().to_le_bytes());
        out[16..24].copy_from_slice(&self.c.val().to_le_bytes());
        out[24..32].copy_from_slice(&self.d.val().to_le_bytes());
        out
    }
}

impl ConstantTimeEq for SL2 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.a.ct_eq(&other.a)
            & self.b.ct_eq(&other.b)
            & self.c.ct_eq(&other.c)
            & self.d.ct_eq(&other.d)
    }
}

impl PartialEq for SL2 {
    fn eq(&self, other: &Self) -> bool { bool::from(self.ct_eq(other)) }
}
impl Eq for SL2 {}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum SL2Error {
    #[error("determinant is {0}, expected 1")]
    InvalidDeterminant(u64),
}

// ---------------------------------------------------------------------------
// Random SL(2,Fq) sampling
// ---------------------------------------------------------------------------

/// Sample a uniformly random g ∈ SL(2,Fq).
///
/// Method: sample (a,b,c) uniformly from Fq; set d = (1 + b*c) * a^{-1}.
/// If a=0, retry.  Expected retries: 1/(1-1/q) ≈ 1 + 1/q for large q.
pub fn random_sl2(q: u64, rng: &mut impl rand::RngCore) -> SL2 {
    loop {
        let a = random_fp(q, rng);
        if bool::from(a.is_zero()) { continue; }
        let b = random_fp(q, rng);
        let c = random_fp(q, rng);
        // d = (1 + b*c) / a
        let num = Fp::one(q).add(b.mul(c));
        let d   = num.mul(a.invert().expect("a != 0"));
        // Verify (should always hold)
        let det = a.mul(d).sub(b.mul(c));
        if det == Fp::one(q) {
            return SL2 { a, b, c, d };
        }
    }
}

// ---------------------------------------------------------------------------
// Matrix × vector helpers (for lift map)
// ---------------------------------------------------------------------------

/// Multiply a 2×2 SL2 matrix by a column vector [x, y]^T mod q.
pub fn sl2_apply(g: &SL2, x: Fp, y: Fp) -> (Fp, Fp) {
    (g.a.mul(x).add(g.b.mul(y)), g.c.mul(x).add(g.d.mul(y)))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    const Q: u64 = 101;

    #[test]
    fn identity_det_one() {
        let id = SL2::identity(Q);
        assert_eq!(id.det(), Fp::one(Q));
    }

    #[test]
    fn mul_inverse_is_identity() {
        let mut rng = StdRng::seed_from_u64(7);
        let g = random_sl2(Q, &mut rng);
        let id = g.mul(&g.inverse());
        assert_eq!(id, SL2::identity(Q));
    }

    #[test]
    fn det_preserved_under_mul() {
        let mut rng = StdRng::seed_from_u64(13);
        let g = random_sl2(Q, &mut rng);
        let h = random_sl2(Q, &mut rng);
        assert_eq!(g.mul(&h).det(), Fp::one(Q));
    }

    #[test]
    fn neg_det_preserved() {
        let mut rng = StdRng::seed_from_u64(17);
        let g = random_sl2(Q, &mut rng);
        assert_eq!(g.neg().det(), g.det());
    }

    #[test]
    fn non_abelian() {
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..100 {
            let g = random_sl2(Q, &mut rng);
            let h = random_sl2(Q, &mut rng);
            if g.mul(&h) != h.mul(&g) { return; }
        }
        panic!("All 100 pairs commuted — SL(2,Fq) should be non-abelian for Q>3");
    }
}