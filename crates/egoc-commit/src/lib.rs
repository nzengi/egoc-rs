//! `egoc-commit` — E-GOC commitment scheme.
//!
//! # Design (Committee: A1, A3, A6)
//! - `Witness` holds (m, r) ∈ Fq^n × Fq^n — zeroized on drop
//! - `lift(m,r)` → L(m,r) ∈ Fq^{2n×2}
//! - `commit(w,g)` → (C_mat, H(g)) where C_mat = L(m,r)·g
//! - `verify(w,g,commitment)` → bool (constant-time comparison)
//! - `gauge_hash(g)` → [u8;32] — BLAKE3(g.to_bytes())
//!
//! # Cross-gauge binding
//! `commit` includes H(g) so that L(-m,-r)·(-g) = L(m,r)·g
//! cannot produce a collision: H(-g) ≠ H(g) (BLAKE3 collision resistance).

use egoc_field::{EgocError, EgocParams, Fp};
use egoc_sl2::SL2;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Secret witness (m, r) ∈ Fq^n × Fq^n.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Witness {
    pub m: Vec<Fp>,
    pub r: Vec<Fp>,
    pub n: usize,
    pub q: u64,
}

impl Witness {
    /// Construct a witness from raw vectors.
    ///
    /// Panics in debug mode if `m` is empty or `m.len() != r.len()`.
    /// For validated construction, prefer [`Witness::from_params`].
    pub fn new(m: Vec<Fp>, r: Vec<Fp>) -> Self {
        debug_assert!(!m.is_empty(), "witness m must be non-empty");
        debug_assert_eq!(m.len(), r.len(), "m and r must have equal length");
        let n = m.len();
        let q = m[0].q();
        Self { m, r, n, q }
    }

    /// Construct and validate a witness against `EgocParams`.
    ///
    /// Returns `Err` if:
    /// - `m.len() != params.n` or `r.len() != params.n`
    /// - any element has a different modulus than `params.q`
    pub fn from_params(
        params: &EgocParams,
        m: Vec<Fp>,
        r: Vec<Fp>,
    ) -> Result<Self, EgocError> {
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
        for (i, v) in m.iter().chain(r.iter()).enumerate() {
            if v.q() != params.q {
                return Err(EgocError::Witness(format!(
                    "element[{}] has q={} but params.q={}", i, v.q(), params.q
                )));
            }
        }
        Ok(Self::new(m, r))
    }

    /// Validate this witness against the given `EgocParams`.
    pub fn validate(&self, params: &EgocParams) -> Result<(), EgocError> {
        if self.n != params.n {
            return Err(EgocError::Witness(format!(
                "witness n={} != params.n={}", self.n, params.n
            )));
        }
        if self.q != params.q {
            return Err(EgocError::Witness(format!(
                "witness q={} != params.q={}", self.q, params.q
            )));
        }
        Ok(())
    }

    /// Sample a random witness for the given parameters.
    pub fn random(n: usize, q: u64, rng: &mut impl rand::RngCore) -> Self {
        let m = egoc_field::random_vec(n, q, rng);
        let r = egoc_field::random_vec(n, q, rng);
        Self::new(m, r)
    }

    /// Sample a random witness for the given `EgocParams`.
    pub fn random_from_params(
        params: &EgocParams,
        rng: &mut impl rand::RngCore,
    ) -> Self {
        Self::random(params.n, params.q, rng)
    }
}

// Custom Debug — never print secret values
impl std::fmt::Debug for Witness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Witness {{ n={}, q={}, [REDACTED] }}", self.n, self.q)
    }
}

/// Commitment matrix C_mat = L(m,r)·g ∈ Fq^{2n×2}.
/// Stored as a flat Vec of length 2n*2 in row-major order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitMatrix {
    rows: Vec<[Fp; 2]>,  // private — access via rows() / rows_mut()
    pub q: u64,
}

impl CommitMatrix {
    /// Number of message/randomness pairs (n = row_count / 2).
    pub fn n(&self) -> usize { self.rows.len() / 2 }

    /// Read-only view of the matrix rows.
    pub fn rows(&self) -> &[[Fp; 2]] { &self.rows }

    /// Byte serialisation for hashing / benchmarks.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.rows.len() * 2 * 8);
        for row in &self.rows {
            buf.extend_from_slice(&row[0].val().to_le_bytes());
            buf.extend_from_slice(&row[1].val().to_le_bytes());
        }
        buf
    }
}

/// Full commitment: (C_mat, gauge_hash).
#[derive(Clone, Debug)]
pub struct Commitment {
    pub matrix:     CommitMatrix,
    pub gauge_hash: [u8; 32],
}

// ---------------------------------------------------------------------------
// Core operations
// ---------------------------------------------------------------------------

/// Lift map: L(m, r) ∈ Fq^{2n×2}.
///
/// Row 2i   = [m[i],  r[i]]
/// Row 2i+1 = [r[i], -m[i]]
pub fn lift(w: &Witness) -> Vec<[Fp; 2]> {
    let mut rows = Vec::with_capacity(2 * w.n);
    for i in 0..w.n {
        rows.push([w.m[i], w.r[i]]);
        rows.push([w.r[i], w.m[i].neg()]);
    }
    rows
}

/// Compute matrix product (2n×2) · (2×2) mod q.
fn mat_mul_2x2(lhs: &[[Fp; 2]], g: &SL2) -> Vec<[Fp; 2]> {
    lhs.iter().map(|row| {
        [
            row[0].mul(g.a).add(row[1].mul(g.c)),
            row[0].mul(g.b).add(row[1].mul(g.d)),
        ]
    }).collect()
}

/// BLAKE3 hash of g's byte encoding — gauge hash H(g).
pub fn gauge_hash(g: &SL2) -> [u8; 32] {
    *blake3::hash(&g.to_bytes()).as_bytes()
}

/// Commit: C = (L(m,r)·g,  H(g)).
pub fn commit(w: &Witness, g: &SL2) -> Commitment {
    let l_rows = lift(w);
    let c_rows = mat_mul_2x2(&l_rows, g);
    Commitment {
        matrix:     CommitMatrix { rows: c_rows, q: w.q },
        gauge_hash: gauge_hash(g),
    }
}

/// Verify: recompute commit and compare, fully constant-time.
///
/// Returns `Ok(())` if the commitment is valid, `Err(EgocError::Witness(…))`
/// with a reason otherwise.  All secret comparisons use `subtle::Choice`
/// accumulation — no short-circuit branches on secret data.
pub fn verify(w: &Witness, g: &SL2, cmt: &Commitment) -> Result<(), EgocError> {
    let expected = commit(w, g);
    if expected.matrix.rows.len() != cmt.matrix.rows.len() {
        return Err(EgocError::Witness(format!(
            "commitment row count mismatch: expected {}, got {}",
            expected.matrix.rows.len(), cmt.matrix.rows.len()
        )));
    }

    // Accumulate matrix comparison with bitwise AND of Choice values.
    let mut ok = Choice::from(1u8);
    for (a, b) in expected.matrix.rows.iter().zip(cmt.matrix.rows.iter()) {
        ok &= a[0].ct_eq(&b[0]) & a[1].ct_eq(&b[1]);
    }

    // Constant-time 32-byte hash comparison via subtle.
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

    const Q: u64 = 101;
    const N: usize = 4;

    #[test]
    fn commit_verify_roundtrip() {
        let mut rng = StdRng::seed_from_u64(42);
        let w = Witness::random(N, Q, &mut rng);
        let g = random_sl2(Q, &mut rng);
        let cmt = commit(&w, &g);
        assert!(verify(&w, &g, &cmt).is_ok());
    }

    #[test]
    fn wrong_message_fails() {
        let mut rng = StdRng::seed_from_u64(1);
        let w  = Witness::random(N, Q, &mut rng);
        let w2 = Witness::random(N, Q, &mut rng);
        let g  = random_sl2(Q, &mut rng);
        let cmt = commit(&w, &g);
        assert!(verify(&w2, &g, &cmt).is_err());
    }

    #[test]
    fn from_params_validates_length() {
        use egoc_field::{EgocParams, Fp};
        let params = EgocParams::LEVEL1;
        let mut rng = StdRng::seed_from_u64(77);
        let w = Witness::random_from_params(&params, &mut rng);
        assert!(w.validate(&params).is_ok());

        // wrong length
        let m_short = vec![Fp::zero(params.q); 3];
        let r_ok    = vec![Fp::zero(params.q); params.n];
        assert!(Witness::from_params(&params, m_short, r_ok).is_err());
    }

    #[test]
    fn cross_gauge_attack_blocked() {
        // Attack: L(-m,-r)·(-g) = L(m,r)·g  (matrix equality)
        // Blocked by: H(-g) ≠ H(g)
        let mut rng = StdRng::seed_from_u64(99);
        let w = Witness::random(N, Q, &mut rng);
        let g = random_sl2(Q, &mut rng);
        let _cmt = commit(&w, &g);

        // Construct attack witness w' = (-m, -r) and gauge -g
        let neg_m: Vec<Fp> = w.m.iter().map(|x| x.neg()).collect();
        let neg_r: Vec<Fp> = w.r.iter().map(|x| x.neg()).collect();
        let w_neg = Witness::new(neg_m, neg_r);
        let g_neg = g.neg();

        // The matrices should be equal (attack works at matrix level)
        let c1 = commit(&w, &g);
        let c2_mat = {
            let l = lift(&w_neg);
            mat_mul_2x2(&l, &g_neg)
        };
        assert_eq!(c1.matrix.rows, c2_mat, "matrix equality should hold");

        // But gauge hashes must differ — blocking the attack
        assert_ne!(
            gauge_hash(&g), gauge_hash(&g_neg),
            "H(g) must differ from H(-g)"
        );
    }

    #[test]
    fn binding_different_messages() {
        let mut rng = StdRng::seed_from_u64(5);
        let w1 = Witness::random(N, Q, &mut rng);
        let w2 = Witness::random(N, Q, &mut rng);
        let g  = random_sl2(Q, &mut rng);
        assert_ne!(commit(&w1, &g).matrix.rows, commit(&w2, &g).matrix.rows);
    }
}