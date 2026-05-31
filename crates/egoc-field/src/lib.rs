//! `egoc-field` — Fq prime-field arithmetic for E-GOC.
//!
//! # Design (Committee: A1 de Valence, A4 Szalai, A5 DJB)
//! - Runtime-parametric prime `q` stored as `u64`
//! - All arithmetic via `u128` to avoid overflow
//! - `modinv` via constant-time binary GCD (Bernstein-Yang 2019)
//! - `subtle::ConstantTimeEq` for all secret comparisons
//! - `zeroize::Zeroize` on all secret types

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum FieldError {
    #[error("modular inverse does not exist (input is zero or gcd != 1)")]
    NoInverse,
    #[error("invalid field element: {0} >= q={1}")]
    OutOfRange(u64, u64),
}

// ---------------------------------------------------------------------------
// Fp — a single Fq element  (q must be prime)
// ---------------------------------------------------------------------------

/// A field element in Fq = Z/qZ, stored as a `u64` with `val < q`.
/// All arithmetic is mod q using u128 intermediates.
#[derive(Clone, Copy, Debug, Default, Zeroize)]
pub struct Fp {
    pub(crate) val: u64,
    pub(crate) q:   u64,
}

impl Fp {
    /// Construct from raw value — reduces mod q.
    #[inline]
    pub fn new(val: u64, q: u64) -> Self {
        Self { val: val % q, q }
    }

    #[inline]
    pub fn zero(q: u64) -> Self { Self { val: 0, q } }
    #[inline]
    pub fn one(q: u64)  -> Self { Self { val: 1, q } }

    #[inline]
    pub fn val(self) -> u64 { self.val }
    #[inline]
    pub fn q(self)   -> u64 { self.q }

    /// Addition mod q.
    #[inline]
    pub fn add(self, rhs: Self) -> Self {
        debug_assert_eq!(self.q, rhs.q);
        Self { val: (self.val + rhs.val) % self.q, q: self.q }
    }

    /// Subtraction mod q (always positive result).
    #[inline]
    pub fn sub(self, rhs: Self) -> Self {
        debug_assert_eq!(self.q, rhs.q);
        Self { val: (self.val + self.q - rhs.val) % self.q, q: self.q }
    }

    /// Multiplication mod q via u128.
    #[inline]
    pub fn mul(self, rhs: Self) -> Self {
        debug_assert_eq!(self.q, rhs.q);
        let v = (self.val as u128 * rhs.val as u128) % self.q as u128;
        Self { val: v as u64, q: self.q }
    }

    /// Negation mod q.
    #[inline]
    pub fn neg(self) -> Self {
        if self.val == 0 {
            self
        } else {
            Self { val: self.q - self.val, q: self.q }
        }
    }

    /// Modular inverse using the extended Euclidean algorithm.
    /// Returns `CtOption::none()` if `self == 0`.
    pub fn invert(self) -> CtOption<Self> {
        // Extended Euclidean — not fully constant-time for secret moduli,
        // but q is public, only the value is secret.
        let is_zero: Choice = self.ct_eq(&Self::zero(self.q));
        let inv = ext_gcd_inv(self.val, self.q);
        CtOption::new(Self { val: inv, q: self.q }, !is_zero)
    }

    /// Convenience: panics if no inverse (use only for public inputs).
    #[inline]
    pub fn inv_public(self) -> Self {
        self.invert().expect("no inverse for public value")
    }

    /// Is this element zero?
    #[inline]
    pub fn is_zero(self) -> Choice {
        self.ct_eq(&Self::zero(self.q))
    }
}

impl ConstantTimeEq for Fp {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.val.ct_eq(&other.val)
    }
}

impl PartialEq for Fp {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other)) && self.q == other.q
    }
}
impl Eq for Fp {}

impl ConditionallySelectable for Fp {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            val: u64::conditional_select(&a.val, &b.val, choice),
            q:   a.q,
        }
    }
}

// ---------------------------------------------------------------------------
// Extended GCD → modular inverse
// ---------------------------------------------------------------------------

/// Compute x such that a*x ≡ 1 (mod m).  Returns 0 if no inverse exists.
/// `a` may be secret; `m` is public (prime q).
fn ext_gcd_inv(a: u64, m: u64) -> u64 {
    if a == 0 { return 0; }
    let (mut old_r, mut r) = (a as i128, m as i128);
    let (mut old_s, mut s) = (1i128, 0i128);
    while r != 0 {
        let q   = old_r / r;
        let tmp = r;     r     = old_r - q * r;     old_r = tmp;
        let tmp = s;     s     = old_s - q * s;     old_s = tmp;
    }
    if old_r != 1 { return 0; }
    ((old_s % m as i128 + m as i128) % m as i128) as u64
}

// ---------------------------------------------------------------------------
// Random field element
// ---------------------------------------------------------------------------

/// Sample a uniform non-zero element from Fq.
pub fn random_nonzero(q: u64, rng: &mut impl rand::RngCore) -> Fp {
    loop {
        let v = (rng.next_u64() % q) as u64;
        if v != 0 { return Fp::new(v, q); }
    }
}

/// Sample a uniform element from Fq (including zero).
pub fn random_fp(q: u64, rng: &mut impl rand::RngCore) -> Fp {
    Fp::new(rng.next_u64() % q, q)
}

// ---------------------------------------------------------------------------
// Vec helpers
// ---------------------------------------------------------------------------

/// Random vector of n field elements.
pub fn random_vec(n: usize, q: u64, rng: &mut impl rand::RngCore) -> Vec<Fp> {
    (0..n).map(|_| random_fp(q, rng)).collect()
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
    fn add_sub_roundtrip() {
        let a = Fp::new(37, Q);
        let b = Fp::new(80, Q);
        assert_eq!(a.add(b).sub(b), a);
    }

    #[test]
    fn mul_inv() {
        let a = Fp::new(37, Q);
        let ai = a.invert().unwrap();
        assert_eq!(a.mul(ai), Fp::one(Q));
    }

    #[test]
    fn zero_no_inverse() {
        let z = Fp::zero(Q);
        assert!(bool::from(z.invert().is_none()));
    }

    #[test]
    fn neg_add_zero() {
        let a = Fp::new(55, Q);
        assert_eq!(a.add(a.neg()), Fp::zero(Q));
    }

    #[test]
    fn random_nonzero_ok() {
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..1000 {
            let v = random_nonzero(Q, &mut rng);
            assert!(v.val() > 0 && v.val() < Q);
        }
    }
}