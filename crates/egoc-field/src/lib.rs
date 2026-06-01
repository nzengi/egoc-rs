//! `egoc-field` — Fq prime-field arithmetic for E-GOC.
//!
//! # Design (Committee: A1 de Valence, A4 Szalai, A5 DJB)
//! - Runtime-parametric prime `q` stored as `u64`
//! - All arithmetic via `u128` to avoid overflow
//! - `modinv` via Fermat's little theorem: a^(q-2) mod q
//!   Exponent q-2 is derived from the *public* prime, so loop count is
//!   fixed at 64 bits independent of secret `a` → constant-time in `a`.
//! - `subtle::ConstantTimeEq` for all secret comparisons
//! - `zeroize::Zeroize` on all secret types
//! - Unbiased random sampling via 128-bit reduction (bias ≈ 2^{-64})

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Error from field arithmetic.
#[derive(Debug, thiserror::Error)]
pub enum FieldError {
    #[error("modular inverse does not exist (input is zero or gcd != 1)")]
    NoInverse,
    #[error("invalid field element: {0} >= q={1}")]
    OutOfRange(u64, u64),
}

/// Unified top-level error type for all E-GOC operations.
#[derive(Debug, thiserror::Error)]
pub enum EgocError {
    /// Security parameter validation failure.
    #[error("parameter error: {0}")]
    Param(#[from] ParamError),
    /// Field arithmetic error.
    #[error("field error: {0}")]
    Field(#[from] FieldError),
    /// Witness construction error.
    #[error("witness error: {0}")]
    Witness(String),
    /// Proof serialization / deserialization error.
    #[error("proof error: {0}")]
    Proof(String),
    /// IVC fold compatibility error.
    #[error("fold error: {0}")]
    Fold(String),
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

    /// Modular inverse via Fermat's little theorem: a^(q-2) mod q.
    ///
    /// Since q is the *public* prime, the exponent (q-2) is fixed and public.
    /// The square-and-multiply loop always runs exactly 64 iterations with
    /// constant-time conditional multiplies → no timing leak from secret `a`.
    /// Returns `CtOption::none()` if `self == 0`.
    pub fn invert(self) -> CtOption<Self> {
        let is_zero: Choice = self.ct_eq(&Self::zero(self.q));
        let inv = ct_pow(self.val, self.q - 2, self.q);
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
// Constant-time modular exponentiation (Fermat inverse)
// ---------------------------------------------------------------------------

/// Constant-time square-and-multiply: base^exp mod m.
///
/// The loop runs a fixed 64 iterations regardless of `base` or `exp`.
/// Bit selection and conditional multiply use only data-independent branches,
/// so no secret value leaks through timing.  `exp` is always the public
/// constant (q-2), so even the per-bit branch is safe.
#[inline]
fn ct_pow(base: u64, exp: u64, m: u64) -> u64 {
    let mut result: u128 = 1;
    let mut b: u128 = base as u128 % m as u128;
    let mut e = exp;
    // Fixed 64 iterations — e is a public constant (q-2).
    for _ in 0..64 {
        // If low bit is set, multiply result by b.
        let mask = (e & 1).wrapping_neg(); // 0xFFFF… if bit set, else 0
        let candidate = (result * b) % m as u128;
        // Constant-time select: result = mask ? candidate : result
        result = (candidate & mask as u128) | (result & !mask as u128);
        b = (b * b) % m as u128;
        e >>= 1;
    }
    result as u64
}

// ---------------------------------------------------------------------------
// Random field element
// ---------------------------------------------------------------------------

/// Sample a uniform element from Fq (including zero).
///
/// Uses 128-bit reduction: bias ≤ 2^64 / q^2 < 2^{-64} for q ≤ 2^32.
/// This is negligible for all practical field sizes.
pub fn random_fp(q: u64, rng: &mut impl rand::RngCore) -> Fp {
    let hi = rng.next_u64() as u128;
    let lo = rng.next_u64() as u128;
    let wide = (hi << 64) | lo;
    Fp::new((wide % q as u128) as u64, q)
}

/// Sample a uniform non-zero element from Fq.
///
/// Rejection sampling over `random_fp`; expected iterations: q/(q-1) ≈ 1.
pub fn random_nonzero(q: u64, rng: &mut impl rand::RngCore) -> Fp {
    loop {
        let v = random_fp(q, rng);
        if !bool::from(v.is_zero()) { return v; }
    }
}

// ---------------------------------------------------------------------------
// Vec helpers
// ---------------------------------------------------------------------------

/// Random vector of n field elements.
pub fn random_vec(n: usize, q: u64, rng: &mut impl rand::RngCore) -> Vec<Fp> {
    (0..n).map(|_| random_fp(q, rng)).collect()
}

// ---------------------------------------------------------------------------
// EgocParams — security parameter set with validation  (A5 Bernstein)
// ---------------------------------------------------------------------------

/// Security parameter set for E-GOC.
///
/// # Security level
/// Paper §8: `(2n - 3) · ⌊log₂q⌋ ≥ λ` bits.
/// For NIST Level I (λ=128): n=10, q=257 → (17)·8 = 136 bits ✓
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgocParams {
    /// Number of message/randomness elements (n ≥ 2).
    pub n: usize,
    /// Field prime (q ≥ 5, q prime).
    pub q: u64,
}

/// Error returned by `EgocParams::validate`.
#[derive(Debug, thiserror::Error)]
pub enum ParamError {
    #[error("n must be ≥ 2, got {0}")]
    NTooSmall(usize),
    #[error("q must be ≥ 5, got {0}")]
    QTooSmall(u64),
    #[error("security level {got} bits < required {need} bits")]
    InsufficientSecurity { got: u32, need: u32 },
}

impl EgocParams {
    /// Construct and validate parameters.
    pub fn new(n: usize, q: u64) -> Result<Self, ParamError> {
        let p = Self { n, q };
        p.validate()?;
        Ok(p)
    }

    /// Security level in bits: `(2n - 3) · ⌊log₂q⌋`.
    ///
    /// Derived from the SSP hardness bound in paper §8.
    pub fn security_bits(&self) -> u32 {
        let factor = (2 * self.n).saturating_sub(3) as u32;
        factor * self.q.ilog2()
    }

    /// Validate parameters against paper §8 requirements.
    ///
    /// - n ≥ 2
    /// - q ≥ 5
    /// - security_bits() ≥ 128 (NIST Level I minimum)
    pub fn validate(&self) -> Result<(), ParamError> {
        if self.n < 2 {
            return Err(ParamError::NTooSmall(self.n));
        }
        if self.q < 5 {
            return Err(ParamError::QTooSmall(self.q));
        }
        let bits = self.security_bits();
        if bits < 128 {
            return Err(ParamError::InsufficientSecurity { got: bits, need: 128 });
        }
        Ok(())
    }

    /// Returns `true` if these parameters meet NIST Level I (128-bit security).
    pub fn is_nist_level1(&self) -> bool { self.security_bits() >= 128 }

    /// Returns `true` if these parameters meet NIST Level III (192-bit security).
    pub fn is_nist_level3(&self) -> bool { self.security_bits() >= 192 }

    /// Returns `true` if these parameters meet NIST Level V (256-bit security).
    pub fn is_nist_level5(&self) -> bool { self.security_bits() >= 256 }

    /// Byte length of a commitment matrix (2n × 2 × 8 bytes).
    pub fn commit_bytes(&self) -> usize { 2 * self.n * 2 * 8 }

    /// Byte length of a proof: header(16) + a_rows(32n) + z_m(8n) + z_r(8n).
    pub fn proof_bytes(&self) -> usize { 16 + 48 * self.n }
}

/// Recommended parameter sets (paper Table 1).
impl EgocParams {
    /// NIST Level I — 136-bit security: n=10, q=257.
    pub const LEVEL1: Self = Self { n: 10, q: 257 };
    /// NIST Level III — 204-bit security: n=16, q=257.
    pub const LEVEL3: Self = Self { n: 16, q: 257 };
    /// NIST Level V — 272-bit security: n=22, q=257.
    pub const LEVEL5: Self = Self { n: 22, q: 257 };
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

    // EgocParams tests
    #[test]
    fn params_level1_valid() {
        assert!(EgocParams::LEVEL1.validate().is_ok());
        assert!(EgocParams::LEVEL1.is_nist_level1());
        assert_eq!(EgocParams::LEVEL1.security_bits(), 136); // (2*10-3)*8
    }

    #[test]
    fn params_level3_valid() {
        assert!(EgocParams::LEVEL3.validate().is_ok());
        assert!(EgocParams::LEVEL3.is_nist_level3());
        assert_eq!(EgocParams::LEVEL3.security_bits(), 232); // (2*16-3)*8 = 29*8
    }

    #[test]
    fn params_level5_valid() {
        assert!(EgocParams::LEVEL5.validate().is_ok());
        assert!(EgocParams::LEVEL5.is_nist_level5());
        assert_eq!(EgocParams::LEVEL5.security_bits(), 328); // (2*22-3)*8 = 41*8
    }

    #[test]
    fn params_n_too_small() {
        let p = EgocParams { n: 1, q: 257 };
        assert!(matches!(p.validate(), Err(ParamError::NTooSmall(1))));
    }

    #[test]
    fn params_q_too_small() {
        let p = EgocParams { n: 10, q: 3 };
        assert!(matches!(p.validate(), Err(ParamError::QTooSmall(3))));
    }

    #[test]
    fn params_insufficient_security() {
        // n=3, q=101: (6-3)*6 = 18 bits — way below 128
        let p = EgocParams { n: 3, q: 101 };
        assert!(matches!(p.validate(), Err(ParamError::InsufficientSecurity { .. })));
    }

    #[test]
    fn params_proof_bytes() {
        // proof_bytes = 16 + 48*n
        assert_eq!(EgocParams::LEVEL1.proof_bytes(), 16 + 48 * 10);
    }

    #[test]
    fn params_new_rejects_bad() {
        assert!(EgocParams::new(1, 257).is_err());
        assert!(EgocParams::new(10, 257).is_ok());
    }
}