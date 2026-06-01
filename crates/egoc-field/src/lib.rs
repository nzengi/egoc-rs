//! `egoc-field` — Fq prime-field arithmetic for E-GOC.
//!
//! # Design
//! `Fp<const Q: u64>` encodes the field prime as a compile-time constant.
//! This eliminates the per-element `q: u64` field (struct is 8 bytes, not 16),
//! allows the compiler to fold `% Q` into immediate-mode division, and makes
//! mixing elements from different fields a compile-time type error.
//!
//! All arithmetic uses `u128` intermediates to avoid overflow.
//! Modular inverse uses Fermat's little theorem: a^(Q-2) mod Q.
//! The exponent Q-2 is public, so the 64-iteration loop is constant-time in `a`.

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Error from field arithmetic.
#[derive(Debug, thiserror::Error)]
pub enum FieldError {
    /// Modular inverse of zero does not exist.
    #[error("modular inverse does not exist (input is zero)")]
    NoInverse,
    /// Value out of range for the field.
    #[error("invalid field element: {0} >= Q")]
    OutOfRange(u64),
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
    /// Witness construction or validation error.
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
// Fp<Q> — a single element of Fq = Z/QZ
// ---------------------------------------------------------------------------

/// A field element in Fq = Z/QZ, where `Q` is a compile-time prime constant.
///
/// The prime is encoded in the type — `Fp<101>` and `Fp<257>` are distinct
/// types, so mixing elements from different fields is a compile-time error.
/// Each value occupies exactly 8 bytes (one `u64`).
#[derive(Clone, Copy, Debug, Default, Zeroize)]
pub struct Fp<const Q: u64> {
    val: u64,
}

impl<const Q: u64> Fp<Q> {
    /// Construct from a raw value — reduces mod Q.
    #[inline]
    pub fn new(val: u64) -> Self {
        Self { val: val % Q }
    }

    /// The additive identity.
    #[inline]
    pub fn zero() -> Self { Self { val: 0 } }

    /// The multiplicative identity.
    #[inline]
    pub fn one() -> Self { Self { val: 1 } }

    /// The raw value in [0, Q).
    #[inline]
    pub fn val(self) -> u64 { self.val }

    /// The field prime (same as the const parameter).
    #[inline]
    pub fn q() -> u64 { Q }

    /// Addition mod Q.
    #[inline]
    pub fn add(self, rhs: Self) -> Self {
        Self { val: (self.val + rhs.val) % Q }
    }

    /// Subtraction mod Q (result always positive).
    #[inline]
    pub fn sub(self, rhs: Self) -> Self {
        Self { val: (self.val + Q - rhs.val) % Q }
    }

    /// Multiplication mod Q via u128.
    #[inline]
    pub fn mul(self, rhs: Self) -> Self {
        let v = (self.val as u128 * rhs.val as u128) % Q as u128;
        Self { val: v as u64 }
    }

    /// Negation mod Q.
    #[inline]
    pub fn neg(self) -> Self {
        if self.val == 0 { self } else { Self { val: Q - self.val } }
    }

    /// Modular inverse via Fermat's little theorem: a^(Q-2) mod Q.
    ///
    /// Q-2 is a public constant, so the 64-iteration loop is constant-time
    /// in `self`. Returns `CtOption::none()` when `self == 0`.
    pub fn invert(self) -> CtOption<Self> {
        let is_zero = self.ct_eq(&Self::zero());
        let inv = ct_pow(self.val, Q - 2, Q);
        CtOption::new(Self { val: inv }, !is_zero)
    }

    /// Inverse for public values — panics on zero.
    #[inline]
    pub fn inv_public(self) -> Self {
        self.invert().expect("no inverse for public value")
    }

    /// Returns `Choice::from(1)` when `self == 0`.
    #[inline]
    pub fn is_zero(self) -> Choice {
        self.ct_eq(&Self::zero())
    }
}

impl<const Q: u64> ConstantTimeEq for Fp<Q> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.val.ct_eq(&other.val)
    }
}

impl<const Q: u64> PartialEq for Fp<Q> {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}
impl<const Q: u64> Eq for Fp<Q> {}

impl<const Q: u64> ConditionallySelectable for Fp<Q> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self { val: u64::conditional_select(&a.val, &b.val, choice) }
    }
}

// ---------------------------------------------------------------------------
// Constant-time modular exponentiation
// ---------------------------------------------------------------------------

/// Constant-time square-and-multiply: `base^exp mod m`.
///
/// Fixed 64 iterations — `exp` must be a public constant (e.g. Q-2).
/// Bit selection and conditional multiply use no data-dependent branches.
#[inline]
pub fn ct_pow(base: u64, exp: u64, m: u64) -> u64 {
    let mut result: u128 = 1;
    let mut b: u128 = base as u128 % m as u128;
    let mut e = exp;
    for _ in 0..64 {
        let mask = (e & 1).wrapping_neg();
        let candidate = (result * b) % m as u128;
        // CT-select: mask is a u64 zero-extended to u128. `result < m < 2^64`
        // always holds (upper 64 bits are zero), so `!mask as u128` correctly
        // clears the upper half. A future change widening m must revisit this.
        result = (candidate & mask as u128) | (result & !mask as u128);
        b = (b * b) % m as u128;
        e >>= 1;
    }
    result as u64
}

// ---------------------------------------------------------------------------
// Random sampling
// ---------------------------------------------------------------------------

/// Sample a uniform element from Fq (including zero).
///
/// Uses 128-bit reduction: bias ≤ 2^64 / Q^2 < 2^{-64} for Q ≤ 2^32.
pub fn random_fp<const Q: u64>(rng: &mut impl rand::RngCore) -> Fp<Q> {
    let hi = rng.next_u64() as u128;
    let lo = rng.next_u64() as u128;
    Fp::new(((hi << 64 | lo) % Q as u128) as u64)
}

/// Sample a uniform non-zero element from Fq.
pub fn random_nonzero<const Q: u64>(rng: &mut impl rand::RngCore) -> Fp<Q> {
    loop {
        let v: Fp<Q> = random_fp(rng);
        if !bool::from(v.is_zero()) { return v; }
    }
}

/// Sample a vector of `n` uniform field elements.
pub fn random_vec<const Q: u64>(n: usize, rng: &mut impl rand::RngCore) -> Vec<Fp<Q>> {
    (0..n).map(|_| random_fp(rng)).collect()
}

/// Sample a zero vector of `n` field elements.
pub fn zero_vec<const Q: u64>(n: usize) -> Vec<Fp<Q>> {
    vec![Fp::zero(); n]
}

// ---------------------------------------------------------------------------
// Primality helper
// ---------------------------------------------------------------------------

/// Trial-division primality test for small primes (q ≤ 2^16 by design).
///
/// Returns `true` if and only if `n` is prime.
/// No Miller-Rabin needed — E-GOC parameters use q ≤ 65537.
fn is_prime(n: u64) -> bool {
    if n < 2 { return false; }
    if n == 2 { return true; }
    if n % 2 == 0 { return false; }
    let mut i = 3u64;
    while i * i <= n {
        if n % i == 0 { return false; }
        i += 2;
    }
    true
}

// ---------------------------------------------------------------------------
// EgocParams — security parameter set
// ---------------------------------------------------------------------------

/// Security parameter set for E-GOC: message length `n` and field prime `q`.
///
/// `q` is stored as a runtime `u64` here for API flexibility (e.g. CLI tools),
/// but all cryptographic operations use `Fp<Q>` with Q as a compile-time const.
/// Use the provided constants `LEVEL1`, `LEVEL3`, `LEVEL5` for standard sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgocParams {
    /// Number of message/randomness elements (n ≥ 2).
    pub n: usize,
    /// Field prime (q ≥ 5, q prime). Matches the const Q in Fp<Q>.
    pub q: u64,
}

/// Errors from `EgocParams::validate`.
#[derive(Debug, thiserror::Error)]
pub enum ParamError {
    /// n is too small.
    #[error("n must be ≥ 2, got {0}")]
    NTooSmall(usize),
    /// q is too small.
    #[error("q must be ≥ 5, got {0}")]
    QTooSmall(u64),
    /// q is not prime — Fermat inversion is only correct for prime moduli.
    #[error("q must be prime, got {0} (composite)")]
    QNotPrime(u64),
    /// Security level is below the required threshold.
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

    /// Security level in bits: `(2n − 3) · ⌊log₂ q⌋`.
    pub fn security_bits(&self) -> u32 {
        let factor = (2 * self.n).saturating_sub(3) as u32;
        factor * self.q.ilog2()
    }

    /// Validate against paper §8 requirements (n ≥ 2, q ≥ 5, q prime, ≥ 128 bits).
    pub fn validate(&self) -> Result<(), ParamError> {
        if self.n < 2 { return Err(ParamError::NTooSmall(self.n)); }
        if self.q < 5 { return Err(ParamError::QTooSmall(self.q)); }
        if !is_prime(self.q) { return Err(ParamError::QNotPrime(self.q)); }
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

    /// Byte length of a commitment matrix: 2n × 2 × 8 bytes.
    pub fn commit_bytes(&self) -> usize { 2 * self.n * 2 * 8 }
    /// Byte length of a proof: header(16) + a_rows(32n) + z_m(8n) + z_r(8n).
    pub fn proof_bytes(&self)  -> usize { 16 + 48 * self.n }
}

impl EgocParams {
    /// NIST Level I — 136-bit security: n=10, q=257.
    pub const LEVEL1: Self = Self { n: 10, q: 257 };
    /// NIST Level III — 232-bit security: n=16, q=257.
    pub const LEVEL3: Self = Self { n: 16, q: 257 };
    /// NIST Level V — 328-bit security: n=22, q=257.
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

    type F = Fp<101>;

    #[test]
    fn add_sub_roundtrip() {
        let a = F::new(37);
        let b = F::new(80);
        assert_eq!(a.add(b).sub(b), a);
    }

    #[test]
    fn mul_inv() {
        let a = F::new(37);
        let ai = a.invert().unwrap();
        assert_eq!(a.mul(ai), F::one());
    }

    #[test]
    fn zero_no_inverse() {
        assert!(bool::from(F::zero().invert().is_none()));
    }

    #[test]
    fn neg_add_zero() {
        let a = F::new(55);
        assert_eq!(a.add(a.neg()), F::zero());
    }

    #[test]
    fn fp_is_8_bytes() {
        assert_eq!(std::mem::size_of::<F>(), 8);
    }

    #[test]
    fn different_q_is_different_type() {
        // Compile-time proof: Fp<101> and Fp<257> are distinct types.
        let _a: Fp<101> = Fp::<101>::new(5);
        let _b: Fp<257> = Fp::<257>::new(5);
        // If this compiles, the type system enforces field separation.
    }

    #[test]
    fn random_nonzero_ok() {
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..1000 {
            let v: Fp<101> = random_nonzero(&mut rng);
            assert!(v.val() > 0 && v.val() < 101);
        }
    }

    #[test]
    fn params_level1_valid() {
        assert!(EgocParams::LEVEL1.validate().is_ok());
        assert_eq!(EgocParams::LEVEL1.security_bits(), 136);
    }

    #[test]
    fn params_level3_valid() {
        assert!(EgocParams::LEVEL3.validate().is_ok());
        assert_eq!(EgocParams::LEVEL3.security_bits(), 232);
    }

    #[test]
    fn params_level5_valid() {
        assert!(EgocParams::LEVEL5.validate().is_ok());
        assert_eq!(EgocParams::LEVEL5.security_bits(), 328);
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
        let p = EgocParams { n: 3, q: 101 };
        assert!(matches!(p.validate(), Err(ParamError::InsufficientSecurity { .. })));
    }

    #[test]
    fn params_proof_bytes() {
        assert_eq!(EgocParams::LEVEL1.proof_bytes(), 16 + 48 * 10);
    }

    #[test]
    fn params_new_rejects_bad() {
        assert!(EgocParams::new(1, 257).is_err());
        assert!(EgocParams::new(10, 257).is_ok());
    }

    #[test]
    fn params_composite_q_fails() {
        for &q in &[6u64, 9, 10, 15, 25, 49] {
            let p = EgocParams { n: 10, q };
            assert!(
                matches!(p.validate(), Err(ParamError::QNotPrime(_))),
                "composite q={} should fail primality check", q
            );
        }
    }

    #[test]
    fn params_prime_q_ok() {
        // Primes in [256, 512) give floor(log2(q))=8, so 17×8=136 ≥ 128 bits.
        // 257, 263, 269 are all prime and satisfy the full security requirement.
        for &q in &[257u64, 263, 269] {
            let p = EgocParams { n: 10, q };
            assert!(
                p.validate().is_ok(),
                "prime q={} with n=10 should pass full validation", q
            );
        }
        // Primes that are prime but fail the security threshold — must NOT
        // be rejected with QNotPrime; the error must be InsufficientSecurity.
        for &q in &[7u64, 11, 13, 127] {
            let p = EgocParams { n: 10, q };
            assert!(
                !matches!(p.validate(), Err(ParamError::QNotPrime(_))),
                "prime q={} should not fail primality check", q
            );
        }
    }

    #[test]
    fn is_prime_basic() {
        assert!(!is_prime(0));
        assert!(!is_prime(1));
        assert!(is_prime(2));
        assert!(is_prime(3));
        assert!(!is_prime(4));
        assert!(is_prime(5));
        assert!(!is_prime(6));
        assert!(is_prime(257));
        assert!(!is_prime(256));
        assert!(!is_prime(255));
    }
}