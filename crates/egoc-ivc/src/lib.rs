//! `egoc-ivc` — Additive IVC fold scheme for E-GOC.
//!
//! # Design
//! - Single fold: (C1,m1,r1) + (C2,m2,r2) → (C_fold, m_fold, r_fold)
//! - L-linearity: L(m1+m2, r1+r2)·g = C1+C2  (proved by construction)
//! - Fresh NIZKP for folded witness — soundness error 1/Q per fold
//!
//! # Complexity
//! - Single fold: O(n) — n field additions + one commit/prove
//! - Tree fold (N witnesses): O(n·N) sequential — binary tree has N-1
//!   fold operations total; depth is ⌈log₂N⌉ but total work is O(N).
//! - Parallel: O(n·log N) wall-clock with ⌊N/2⌋ processors.
//!
//! # Soundness (Theorem 6)
//! Err_fold(N) ≤ ⌈log₂N⌉/Q  (union bound over binary tree depth)
//! Soundness is returned as exact rational (depth, Q) — no float.
//!
//! # Relationship to Nova
//! E-GOC fold uses additive witness combination exploiting the linearity
//! of L(m,r) over Fq. This is native to E-GOC's construction, not a
//! general SNARK technique.

use egoc_commit::{commit, verify, Commitment, Witness};
use egoc_field::{EgocError, Fp};
use egoc_proof::{prove, verify_proof, Proof};
use egoc_sl2::SL2;

// ---------------------------------------------------------------------------
// Single fold
// ---------------------------------------------------------------------------

/// Result of one fold operation.
pub struct FoldResult<const Q: u64> {
    /// The combined witness (m_fold, r_fold).
    pub witness_fold: Witness<Q>,
    /// The combined commitment C_fold = C1+C2.
    pub commit_fold:  Commitment<Q>,
    /// Fresh NIZKP for the folded witness.
    pub proof_fold:   Proof<Q>,
    /// True if both verify_proof and verify passed.
    pub valid:        bool,
}

/// Fold two witness/commitment pairs sharing the same gauge g.
///
/// Returns `Err` if `w1` and `w2` have incompatible length.
///
/// m_fold = m1+m2 (mod Q),  r_fold = r1+r2 (mod Q)
/// C_fold = C1+C2 = L(m_fold, r_fold)·g  by L-linearity.
pub fn ivc_fold<const Q: u64>(
    w1:  &Witness<Q>,
    w2:  &Witness<Q>,
    g:   &SL2<Q>,
    rng: &mut impl rand::RngCore,
) -> Result<FoldResult<Q>, EgocError> {
    if w1.n != w2.n {
        return Err(EgocError::Fold(format!(
            "witness n mismatch: {} vs {}", w1.n, w2.n
        )));
    }

    let m_fold: Vec<Fp<Q>> = w1.m.iter().zip(w2.m.iter()).map(|(a, b)| a.add(*b)).collect();
    let r_fold: Vec<Fp<Q>> = w1.r.iter().zip(w2.r.iter()).map(|(a, b)| a.add(*b)).collect();
    let witness_fold = Witness::new(m_fold, r_fold);

    let commit_fold = commit(&witness_fold, g);
    let proof_fold  = prove(&witness_fold, g, &commit_fold.matrix, rng);
    let valid = verify_proof(&commit_fold.matrix, g, &proof_fold).is_ok()
             && verify(&witness_fold, g, &commit_fold).is_ok();

    Ok(FoldResult { witness_fold, commit_fold, proof_fold, valid })
}

// ---------------------------------------------------------------------------
// Tree fold
// ---------------------------------------------------------------------------

/// Result of a binary tree fold over N witnesses.
pub struct TreeFoldResult<const Q: u64> {
    /// Final proof after all fold levels.
    pub final_proof:  Proof<Q>,
    /// Final commitment after all fold levels.
    pub final_commit: Commitment<Q>,
    /// Binary tree depth = ⌈log₂N⌉.
    pub depth:        usize,
    /// True if every fold step and the final proof verified.
    pub all_valid:    bool,
    /// Soundness error bound as exact rational (numerator=depth, denominator=Q).
    /// Error ≤ depth/Q.
    pub soundness_err: (usize, u64),
}

/// Fold N witnesses in a binary tree. All must share the same gauge g.
///
/// Returns `Err` if any witness pair has incompatible length, or if
/// the witness list is empty.
pub fn tree_fold<const Q: u64>(
    witnesses: Vec<Witness<Q>>,
    g:         &SL2<Q>,
    rng:       &mut impl rand::RngCore,
) -> Result<TreeFoldResult<Q>, EgocError> {
    if witnesses.is_empty() {
        return Err(EgocError::Fold("need at least one witness".into()));
    }

    let depth = (witnesses.len() as f64).log2().ceil() as usize;
    let mut cur: Vec<Witness<Q>> = witnesses;
    let mut all_valid = true;

    for _level in 0..depth {
        let mut next = Vec::new();
        let mut i = 0;
        while i < cur.len() {
            if i + 1 < cur.len() {
                let fold = ivc_fold(&cur[i], &cur[i + 1], g, rng)?;
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

    let final_commit = commit(&cur[0], g);
    let final_proof  = prove(&cur[0], g, &final_commit.matrix, rng);
    all_valid &= verify_proof(&final_commit.matrix, g, &final_proof).is_ok();

    Ok(TreeFoldResult {
        final_proof,
        final_commit,
        depth,
        all_valid,
        soundness_err: (depth, Q),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use egoc_commit::commit;
    use egoc_sl2::random_sl2;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    const N: usize = 4;
    type W = Witness<101>;
    type G = SL2<101>;

    #[test]
    fn single_fold_valid() {
        let mut rng = StdRng::seed_from_u64(42);
        let w1: W = Witness::random(N, &mut rng);
        let w2: W = Witness::random(N, &mut rng);
        let g:  G = random_sl2(&mut rng);
        let r = ivc_fold(&w1, &w2, &g, &mut rng).expect("fold ok");
        assert!(r.valid);
    }

    #[test]
    fn fold_incompatible_n_fails() {
        let mut rng = StdRng::seed_from_u64(42);
        let w1: W = Witness::random(N, &mut rng);
        let w2: W = Witness::random(N + 1, &mut rng);
        let g:  G = random_sl2(&mut rng);
        assert!(ivc_fold(&w1, &w2, &g, &mut rng).is_err());
    }

    #[test]
    fn tree_fold_8_witnesses() {
        let mut rng = StdRng::seed_from_u64(7);
        let g: G = random_sl2(&mut rng);
        let ws: Vec<W> = (0..8).map(|_| Witness::random(N, &mut rng)).collect();
        let r = tree_fold(ws, &g, &mut rng).expect("tree fold ok");
        assert!(r.all_valid);
        assert_eq!(r.depth, 3);
        let (num, den) = r.soundness_err;
        assert_eq!(num, 3);
        assert_eq!(den, 101u64);
        assert!(num < (den / 10) as usize);
    }

    #[test]
    fn linearity_holds() {
        let mut rng = StdRng::seed_from_u64(99);
        let w1: W = Witness::random(N, &mut rng);
        let w2: W = Witness::random(N, &mut rng);
        let g:  G = random_sl2(&mut rng);

        let c1 = commit(&w1, &g).matrix.rows().to_vec();
        let c2 = commit(&w2, &g).matrix.rows().to_vec();
        let c_sum: Vec<[Fp<101>; 2]> = c1.iter().zip(c2.iter())
            .map(|(a, b)| [a[0].add(b[0]), a[1].add(b[1])])
            .collect();

        let m_fold: Vec<Fp<101>> = w1.m.iter().zip(w2.m.iter()).map(|(a,b)| a.add(*b)).collect();
        let r_fold: Vec<Fp<101>> = w1.r.iter().zip(w2.r.iter()).map(|(a,b)| a.add(*b)).collect();
        let w_fold = Witness::new(m_fold, r_fold);
        let c_fold = commit(&w_fold, &g).matrix.rows().to_vec();

        assert_eq!(c_fold, c_sum, "L-linearity must hold");
    }
}