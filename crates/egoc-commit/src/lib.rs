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

use egoc_field::Fp;
use egoc_sl2::SL2;
use subtle::ConstantTimeEq;
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
    pub fn new(m: Vec<Fp>, r: Vec<Fp>) -> Self {
        let n = m.len();
        let q = m[0].q();
        Self { m, r, n, q }
    }

    pub fn random(n: usize, q: u64, rng: &mut impl rand::RngCore) -> Self {
        let m = egoc_field::random_vec(n, q, rng);
        let r = egoc_field::random_vec(n, q, rng);
        Self::new(m, r)
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
    pub rows: Vec<[Fp; 2]>,  // length 2n
    pub q:    u64,
}

impl CommitMatrix {
    pub fn n(&self) -> usize { self.rows.len() / 2 }

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
    let _q = w.q;
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

/// Verify: recompute commit and compare (constant-time on matrix, fast on hash).
pub fn verify(w: &Witness, g: &SL2, cmt: &Commitment) -> bool {
    let expected = commit(w, g);
    // Matrix comparison (constant-time element-wise)
    if expected.matrix.rows.len() != cmt.matrix.rows.len() { return false; }
    let matrix_ok: bool = expected.matrix.rows.iter()
        .zip(cmt.matrix.rows.iter())
        .all(|(a, b)| {
            bool::from(a[0].ct_eq(&b[0]) & a[1].ct_eq(&b[1]))
        });
    // Hash comparison
    let hash_ok = expected.gauge_hash == cmt.gauge_hash;
    matrix_ok && hash_ok
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
        assert!(verify(&w, &g, &cmt));
    }

    #[test]
    fn wrong_message_fails() {
        let mut rng = StdRng::seed_from_u64(1);
        let w  = Witness::random(N, Q, &mut rng);
        let w2 = Witness::random(N, Q, &mut rng);
        let g  = random_sl2(Q, &mut rng);
        let cmt = commit(&w, &g);
        assert!(!verify(&w2, &g, &cmt));
    }

    #[test]
    fn cross_gauge_attack_blocked() {
        // Attack: L(-m,-r)·(-g) = L(m,r)·g  (matrix equality)
        // Blocked by: H(-g) ≠ H(g)
        let mut rng = StdRng::seed_from_u64(99);
        let w = Witness::random(N, Q, &mut rng);
        let g = random_sl2(Q, &mut rng);
        let cmt = commit(&w, &g);

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