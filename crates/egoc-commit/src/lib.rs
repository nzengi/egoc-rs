//! `egoc-commit` — E-GOC commitment scheme.
//!
//! # Design
//! - `Witness<Q>` holds (m, r) ∈ Fq^n × Fq^n — zeroized on drop
//! - `lift(w)` → L(m,r) ∈ Fq^{2n×2}
//! - `commit(w,g)` → (C_mat, H(g)) where C_mat = L(m,r)·g
//! - `verify(w,g,cmt)` → Result<(), EgocError> (constant-time comparison)
//! - `gauge_hash(g)` → [u8;32] — BLAKE3(g.to_bytes())
//!
//! # Cross-gauge binding
//! The commitment includes H(g) so that the attack L(−m,−r)·(−g) = L(m,r)·g
//! is blocked: H(−g) ≠ H(g) by BLAKE3 collision resistance.

use egoc_field::{random_vec, EgocError, EgocParams, Fp};
use egoc_sl2::SL2;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Witness
// ---------------------------------------------------------------------------

/// Secret witness (m, r) ∈ Fq^n × Fq^n.
///
/// Zeroized on drop — secret values are wiped when the witness is dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Witness<const Q: u64> {
    pub m: Vec<Fp<Q>>,
    pub r: Vec<Fp<Q>>,
    /// Message length n (= m.len() = r.len()).
    pub n: usize,
}

impl<const Q: u64> Witness<Q> {
    /// Construct from raw vectors.
    ///
    /// Panics in debug mode if `m` is empty or `m.len() != r.len()`.
    /// For validated construction, prefer [`Witness::from_params`].
    ///
    /// # Security — randomness requirement
    ///
    /// **`r` must be chosen uniformly at random for hiding to hold.**
    ///
    /// If `r = [0, …, 0]`, hiding is completely broken: any observer can
    /// recover `m[i]` from the commitment as `m[i] = C[2i][0] · g.a⁻¹ mod q`.
    /// Zero randomness is only safe for deterministic test vectors (KAT).
    ///
    /// Use [`Witness::random`] or [`Witness::random_from_params`] for
    /// production witnesses — these always sample uniform `r`.
    pub fn new(m: Vec<Fp<Q>>, r: Vec<Fp<Q>>) -> Self {
        debug_assert!(!m.is_empty(), "witness m must be non-empty");
        debug_assert_eq!(m.len(), r.len(), "m and r must have equal length");
        // Warn in debug builds when all randomness is zero — hiding is broken.
        debug_assert!(
            r.iter().any(|x| x.val() != 0),
            "Witness r=[0..0]: hiding is completely broken — use random r in production. \
             For test vectors only."
        );
        let n = m.len();
        Self { m, r, n }
    }

    /// Construct and validate against `EgocParams`.
    ///
    /// Returns `Err` if `m.len() != params.n`, `r.len() != params.n`,
    /// or `params.q != Q`.
    pub fn from_params(
        params: &EgocParams,
        m: Vec<Fp<Q>>,
        r: Vec<Fp<Q>>,
    ) -> Result<Self, EgocError> {
        if params.q != Q {
            return Err(EgocError::Witness(format!(
                "params.q={} does not match type parameter Q={}", params.q, Q
            )));
        }
        if m.len() != params.n {
            return Err(EgocError::Witness(format!(
                "m.len()={} != params.n={}", m.len(), params.n
            )));
        }
        if r.len() != params.n {
            return Err(EgocError::Witness(format!(
                "r.len()={} != params.n={}", r.len(), params.n
            )));
        }
        Ok(Self::new(m, r))
    }

    /// Validate this witness against `EgocParams`.
    pub fn validate(&self, params: &EgocParams) -> Result<(), EgocError> {
        if params.q != Q {
            return Err(EgocError::Witness(format!(
                "params.q={} does not match type parameter Q={}", params.q, Q
            )));
        }
        if self.n != params.n {
            return Err(EgocError::Witness(format!(
                "witness n={} != params.n={}", self.n, params.n
            )));
        }
        Ok(())
    }

    /// Sample a random witness for the given length `n`.
    pub fn random(n: usize, rng: &mut impl rand::RngCore) -> Self {
        let m = random_vec(n, rng);
        let r = random_vec(n, rng);
        Self::new(m, r)
    }

    /// Sample a random witness for the given `EgocParams`.
    ///
    /// Panics if `params.q != Q`.
    pub fn random_from_params(params: &EgocParams, rng: &mut impl rand::RngCore) -> Self {
        assert_eq!(params.q, Q, "params.q does not match type parameter Q");
        Self::random(params.n, rng)
    }
}

impl<const Q: u64> std::fmt::Debug for Witness<Q> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Witness<{}> {{ n={}, [REDACTED] }}", Q, self.n)
    }
}

// ---------------------------------------------------------------------------
// CommitMatrix
// ---------------------------------------------------------------------------

/// Commitment matrix C_mat = L(m,r)·g ∈ Fq^{2n×2}.
#[derive(Clone, Debug, PartialEq, Eq, Zeroize)]
pub struct CommitMatrix<const Q: u64> {
    rows: Vec<[Fp<Q>; 2]>,
}

impl<const Q: u64> CommitMatrix<Q> {
    /// Construct from a pre-computed row slice.
    ///
    /// Used by `egoc-proof` to wrap `a_rows` (commitment to prover randomness)
    /// in the algebraically correct type without re-running the commit pipeline.
    pub fn from_rows(rows: Vec<[Fp<Q>; 2]>) -> Self {
        Self { rows }
    }

    /// Number of message/randomness pairs (n = row_count / 2).
    pub fn n(&self) -> usize { self.rows.len() / 2 }

    /// Read-only view of the matrix rows.
    pub fn rows(&self) -> &[[Fp<Q>; 2]] { &self.rows }

    /// Consume and return the inner row vector.
    pub fn into_rows(self) -> Vec<[Fp<Q>; 2]> { self.rows }

    /// Byte serialization for hashing / wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.rows.len() * 16);
        for row in &self.rows {
            buf.extend_from_slice(&row[0].val().to_le_bytes());
            buf.extend_from_slice(&row[1].val().to_le_bytes());
        }
        buf
    }
}

// ---------------------------------------------------------------------------
// Commitment
// ---------------------------------------------------------------------------

/// Full commitment: (C_mat, gauge_hash).
///
/// The gauge hash H(g) is included to block the cross-gauge attack
/// L(−m,−r)·(−g) = L(m,r)·g.
#[derive(Clone, Debug)]
pub struct Commitment<const Q: u64> {
    /// Commitment matrix C = L(m,r)·g.
    pub matrix:     CommitMatrix<Q>,
    /// BLAKE3 hash of the gauge: H(g) = BLAKE3(g.to_bytes()).
    pub gauge_hash: [u8; 32],
}

// ---------------------------------------------------------------------------
// Core operations
// ---------------------------------------------------------------------------

/// Lift map: L(m, r) ∈ Fq^{2n×2}.
///
/// Row 2i   = [ m[i],  r[i]]
/// Row 2i+1 = [ r[i], −m[i]]
pub fn lift<const Q: u64>(w: &Witness<Q>) -> Vec<[Fp<Q>; 2]> {
    let mut rows = Vec::with_capacity(2 * w.n);
    for i in 0..w.n {
        rows.push([w.m[i], w.r[i]]);
        rows.push([w.r[i], w.m[i].neg()]);
    }
    rows
}

/// Matrix product (2n×2) · (2×2) mod Q.
fn mat_mul_2x2<const Q: u64>(lhs: &[[Fp<Q>; 2]], g: &SL2<Q>) -> Vec<[Fp<Q>; 2]> {
    lhs.iter().map(|row| [
        row[0].mul(g.a).add(row[1].mul(g.c)),
        row[0].mul(g.b).add(row[1].mul(g.d)),
    ]).collect()
}

/// BLAKE3 hash of g's byte encoding — gauge hash H(g).
pub fn gauge_hash<const Q: u64>(g: &SL2<Q>) -> [u8; 32] {
    *blake3::hash(&g.to_bytes()).as_bytes()
}

/// Commit: C = (L(m,r)·g, H(g)).
pub fn commit<const Q: u64>(w: &Witness<Q>, g: &SL2<Q>) -> Commitment<Q> {
    let l_rows = lift(w);
    let c_rows = mat_mul_2x2(&l_rows, g);
    Commitment {
        matrix:     CommitMatrix { rows: c_rows },
        gauge_hash: gauge_hash(g),
    }
}

/// Verify: recompute commitment and compare, fully constant-time.
///
/// Returns `Ok(())` if valid, `Err(EgocError::Witness(…))` otherwise.
pub fn verify<const Q: u64>(
    w:   &Witness<Q>,
    g:   &SL2<Q>,
    cmt: &Commitment<Q>,
) -> Result<(), EgocError> {
    let expected = commit(w, g);
    if expected.matrix.rows.len() != cmt.matrix.rows.len() {
        return Err(EgocError::Witness(format!(
            "commitment row count mismatch: expected {}, got {}",
            expected.matrix.rows.len(), cmt.matrix.rows.len()
        )));
    }

    let mut ok = Choice::from(1u8);
    for (a, b) in expected.matrix.rows.iter().zip(cmt.matrix.rows.iter()) {
        ok &= a[0].ct_eq(&b[0]) & a[1].ct_eq(&b[1]);
    }
    ok &= expected.gauge_hash.ct_eq(&cmt.gauge_hash);

    if bool::from(ok) {
        Ok(())
    } else {
        Err(EgocError::Witness("commitment verification failed".into()))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use egoc_sl2::random_sl2;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    const N: usize = 4;
    type W = Witness<101>;
    type G = SL2<101>;

    #[test]
    fn commit_verify_roundtrip() {
        let mut rng = StdRng::seed_from_u64(42);
        let w: W = Witness::random(N, &mut rng);
        let g: G = random_sl2(&mut rng);
        let cmt = commit(&w, &g);
        assert!(verify(&w, &g, &cmt).is_ok());
    }

    #[test]
    fn wrong_message_fails() {
        let mut rng = StdRng::seed_from_u64(1);
        let w:  W = Witness::random(N, &mut rng);
        let w2: W = Witness::random(N, &mut rng);
        let g:  G = random_sl2(&mut rng);
        let cmt = commit(&w, &g);
        assert!(verify(&w2, &g, &cmt).is_err());
    }

    #[test]
    fn cross_gauge_attack_blocked() {
        let mut rng = StdRng::seed_from_u64(99);
        let w: W = Witness::random(N, &mut rng);
        let g: G = random_sl2(&mut rng);

        let neg_m: Vec<Fp<101>> = w.m.iter().map(|x| x.neg()).collect();
        let neg_r: Vec<Fp<101>> = w.r.iter().map(|x| x.neg()).collect();
        let w_neg = Witness::new(neg_m, neg_r);
        let g_neg = g.neg();

        let c1 = commit(&w, &g);
        let c2_mat = {
            let l = lift(&w_neg);
            mat_mul_2x2(&l, &g_neg)
        };
        // Matrix equality holds (attack works at matrix level)
        assert_eq!(c1.matrix.rows, c2_mat);
        // But gauge hashes differ — blocking the attack
        assert_ne!(gauge_hash(&g), gauge_hash(&g_neg));
    }

    #[test]
    fn binding_different_messages() {
        let mut rng = StdRng::seed_from_u64(5);
        let w1: W = Witness::random(N, &mut rng);
        let w2: W = Witness::random(N, &mut rng);
        let g:  G = random_sl2(&mut rng);
        assert_ne!(commit(&w1, &g).matrix.rows, commit(&w2, &g).matrix.rows);
    }

    #[test]
    fn witness_zero_r_hiding_broken() {
        // Demonstrates: r=[0..0] completely breaks hiding.
        // m[i] can be recovered from C[2i][0] as m[i] = C[2i][0] * g.a^{-1} mod Q.
        // Construct directly (bypassing debug_assert) to test the attack itself.
        let mut rng = StdRng::seed_from_u64(0);
        let g: G = random_sl2(&mut rng);

        let m_vals: Vec<Fp<101>> = (1u64..=N as u64).map(Fp::new).collect();
        let r_zero: Vec<Fp<101>> = vec![Fp::zero(); N];

        // Direct construction — bypasses new() to allow r=0 in test context.
        let w = Witness::<101> { m: m_vals.clone(), r: r_zero, n: N };
        let cmt = commit(&w, &g);

        // Recover: C[2i] = [m[i]*g.a, m[i]*g.b], so m[i] = C[2i][0] * g.a^{-1}
        let ga_inv = g.a.invert().expect("g.a invertible");
        for i in 0..N {
            let row_even = cmt.matrix.rows()[2 * i];
            let recovered = row_even[0].mul(ga_inv);
            assert_eq!(recovered, m_vals[i],
                "m[{i}] recoverable from commitment when r=0 — hiding is broken");
        }
    }

    #[test]
    #[should_panic(expected = "hiding is completely broken")]
    #[cfg(debug_assertions)]
    fn witness_new_zero_r_asserts_in_debug() {
        // debug_assert! in Witness::new() must fire when r=[0..0].
        let m: Vec<Fp<101>> = (1u64..=4).map(Fp::new).collect();
        let r: Vec<Fp<101>> = vec![Fp::zero(); 4];
        let _ = Witness::<101>::new(m, r);
    }

    #[test]
    fn from_params_validates_length() {
        use egoc_field::zero_vec;
        let params = EgocParams::LEVEL1;
        let mut rng = StdRng::seed_from_u64(77);
        let w: Witness<257> = Witness::random_from_params(&params, &mut rng);
        assert!(w.validate(&params).is_ok());

        // wrong length
        let m_short = zero_vec::<257>(3);
        let r_ok    = zero_vec::<257>(params.n);
        assert!(Witness::<257>::from_params(&params, m_short, r_ok).is_err());
    }
}