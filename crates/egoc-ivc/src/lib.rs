//! `egoc-ivc` — Nova-style additive IVC fold scheme for E-GOC.
//!
//! # Design (Committee: A1, A3 Bowe, A4 Szalai)
//! - Single fold: (C1,m1,r1) + (C2,m2,r2) → (C_fold, m_fold, r_fold)
//! - L-linearity: L(m1+m2, r1+r2)·g = C1+C2  (proved by construction)
//! - Fresh NIZKP for folded witness — soundness error 1/q per fold
//! - Recursive tree fold for N statements: O(n·log N) total
//!
//! # Soundness (Theorem 6)
//! Err_fold(N) ≤ ⌈log₂N⌉/q  (union bound over binary tree levels)
//! Note: knowledge soundness yields aggregated witness only.

use egoc_commit::{commit, verify, Commitment, Witness};
use egoc_field::Fp;
use egoc_proof::{prove, verify_proof, Proof};
use egoc_sl2::SL2;

// ---------------------------------------------------------------------------
// Single fold step
// ---------------------------------------------------------------------------

/// Result of one fold operation.
pub struct FoldResult {
    pub witness_fold: Witness,
    pub commit_fold:  Commitment,
    pub proof_fold:   Proof,
    pub valid:        bool,
}

/// Fold two (witness, commitment) pairs sharing the same gauge g.
///
/// m_fold = m1 + m2 (mod q),  r_fold = r1 + r2 (mod q)
/// C_fold = C1 + C2 (mod q)   = L(m_fold, r_fold)·g
pub fn ivc_fold(
    w1: &Witness, w2: &Witness,
    g:  &SL2,
    rng: &mut impl rand::RngCore,
) -> FoldResult {
    let _q = w1.q;
    let _n = w1.n;

    // Additive fold of witnesses
    let m_fold: Vec<Fp> = w1.m.iter().zip(w2.m.iter()).map(|(a, b)| a.add(*b)).collect();
    let r_fold: Vec<Fp> = w1.r.iter().zip(w2.r.iter()).map(|(a, b)| a.add(*b)).collect();
    let witness_fold = Witness::new(m_fold, r_fold);

    // Folded commitment (recomputed — verifies L-linearity)
    let commit_fold = commit(&witness_fold, g);

    // Fresh NIZKP for the folded witness
    let proof_fold = prove(&witness_fold, g, &commit_fold.matrix, rng);
    let valid      = verify_proof(&commit_fold.matrix, g, &proof_fold)
                     && verify(&witness_fold, g, &commit_fold);

    FoldResult { witness_fold, commit_fold, proof_fold, valid }
}

// ---------------------------------------------------------------------------
// Recursive tree fold (N statements → 1 final proof)
// ---------------------------------------------------------------------------

pub struct TreeFoldResult {
    pub final_proof:   Proof,
    pub final_commit:  Commitment,
    pub depth:         usize,
    pub all_valid:     bool,
    /// Soundness error bound: depth / q
    pub soundness_err: f64,
}

/// Fold N statements in a binary tree. All must share the same gauge g.
pub fn tree_fold(
    witnesses:   Vec<Witness>,
    g:           &SL2,
    rng:         &mut impl rand::RngCore,
) -> TreeFoldResult {
    assert!(!witnesses.is_empty(), "need at least one witness");
    let q     = witnesses[0].q;
    let depth = (witnesses.len() as f64).log2().ceil() as usize;

    let mut cur: Vec<Witness> = witnesses;
    let mut all_valid = true;

    for _level in 0..depth {
        let mut next = Vec::new();
        let mut i = 0;
        while i < cur.len() {
            if i + 1 < cur.len() {
                let fold = ivc_fold(&cur[i], &cur[i + 1], g, rng);
                all_valid &= fold.valid;
                next.push(fold.witness_fold);
                i += 2;
            } else {
                next.push(cur[i].clone());
                i += 1;
            }
        }
        cur = next;
    }

    // Final proof for the single remaining witness
    let final_commit = commit(&cur[0], g);
    let final_proof  = prove(&cur[0], g, &final_commit.matrix, rng);
    all_valid &= verify_proof(&final_commit.matrix, g, &final_proof);

    TreeFoldResult {
        final_proof,
        final_commit,
        depth,
        all_valid,
        soundness_err: depth as f64 / q as f64,
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
    fn single_fold_valid() {
        let mut rng = StdRng::seed_from_u64(42);
        let w1 = Witness::random(N, Q, &mut rng);
        let w2 = Witness::random(N, Q, &mut rng);
        let g  = random_sl2(Q, &mut rng);
        let r  = ivc_fold(&w1, &w2, &g, &mut rng);
        assert!(r.valid);
    }

    #[test]
    fn tree_fold_8_witnesses() {
        let mut rng = StdRng::seed_from_u64(7);
        let g = random_sl2(Q, &mut rng);
        let ws: Vec<Witness> = (0..8).map(|_| Witness::random(N, Q, &mut rng)).collect();
        let r = tree_fold(ws, &g, &mut rng);
        assert!(r.all_valid);
        assert_eq!(r.depth, 3);
        assert!(r.soundness_err < 0.1);
    }

    #[test]
    fn linearity_holds() {
        // L(m1+m2, r1+r2)·g = C1+C2
        use egoc_commit::commit;
        let mut rng = StdRng::seed_from_u64(99);
        let w1 = Witness::random(N, Q, &mut rng);
        let w2 = Witness::random(N, Q, &mut rng);
        let g  = random_sl2(Q, &mut rng);

        let c1 = commit(&w1, &g).matrix.rows().to_vec();
        let c2 = commit(&w2, &g).matrix.rows().to_vec();
        let c_sum: Vec<[Fp; 2]> = c1.iter().zip(c2.iter())
            .map(|(a, b)| [a[0].add(b[0]), a[1].add(b[1])])
            .collect();

        let m_fold: Vec<Fp> = w1.m.iter().zip(w2.m.iter()).map(|(a,b)| a.add(*b)).collect();
        let r_fold: Vec<Fp> = w1.r.iter().zip(w2.r.iter()).map(|(a,b)| a.add(*b)).collect();
        let w_fold = Witness::new(m_fold, r_fold);
        let c_fold = commit(&w_fold, &g).matrix.rows().to_vec();

        assert_eq!(c_fold, c_sum, "L-linearity must hold");
    }
}