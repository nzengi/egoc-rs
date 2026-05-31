//! `egoc-proof` — Σ-GOC Sigma protocol + Fiat-Shamir NIZKP.
//!
//! # Design (Committee: A1, A2, A3, A5)
//! - Prover: (m,r,g) → π = (A, z_m, z_r)
//! - Challenge: e = BLAKE3(C ‖ g ‖ A) mod (q-1) + 1  ∈ Fq*
//! - Verifier: L(z_m,z_r)·g = A + e·C  (mod q)
//! - Soundness error: 1/q per challenge
//! - Perfect HVZK: simulator outputs uniform (z_m, z_r) ← Fq^n

use egoc_commit::{lift, CommitMatrix, Witness};
use egoc_field::Fp;
use egoc_sl2::SL2;
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Non-interactive ZKP: π = (A, z_m, z_r).
/// `e` is not stored — verifier recomputes from (C, g, A).
#[derive(Clone, Debug)]
pub struct Proof {
    /// Commitment to prover randomness: A = L(k,s)·g
    pub a_rows:  Vec<[Fp; 2]>,
    /// Response vectors
    pub z_m: Vec<Fp>,
    pub z_r: Vec<Fp>,
}

impl Proof {
    /// Byte length: (2n*2 + 2n) field elements * ceil(log2(q)/8) bytes each.
    pub fn byte_len(&self, bytes_per_elem: usize) -> usize {
        (self.a_rows.len() * 2 + self.z_m.len() + self.z_r.len()) * bytes_per_elem
    }
}

// ---------------------------------------------------------------------------
// Fiat-Shamir challenge
// ---------------------------------------------------------------------------

/// e = BLAKE3(C_bytes ‖ g_bytes ‖ A_bytes) mod (q-1) + 1 ∈ {1,..,q-1}.
pub fn fiat_shamir_challenge(
    c_mat:  &CommitMatrix,
    g:      &SL2,
    a_rows: &[[Fp; 2]],
    q:      u64,
) -> Fp {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&c_mat.to_bytes());
    hasher.update(&g.to_bytes());
    for row in a_rows {
        hasher.update(&row[0].val().to_le_bytes());
        hasher.update(&row[1].val().to_le_bytes());
    }
    let digest = hasher.finalize();
    let raw = u64::from_le_bytes(digest.as_bytes()[..8].try_into().unwrap());
    Fp::new(raw % (q - 1) + 1, q)  // e ∈ {1,..,q-1}
}

// ---------------------------------------------------------------------------
// Matrix helpers
// ---------------------------------------------------------------------------

fn mat_mul_2x2(lhs: &[[Fp; 2]], g: &SL2) -> Vec<[Fp; 2]> {
    lhs.iter().map(|row| {
        [
            row[0].mul(g.a).add(row[1].mul(g.c)),
            row[0].mul(g.b).add(row[1].mul(g.d)),
        ]
    }).collect()
}

fn mat_add(a: &[[Fp; 2]], b: &[[Fp; 2]]) -> Vec<[Fp; 2]> {
    a.iter().zip(b.iter())
     .map(|(x, y)| [x[0].add(y[0]), x[1].add(y[1])])
     .collect()
}

fn mat_scale(m: &[[Fp; 2]], e: Fp) -> Vec<[Fp; 2]> {
    m.iter().map(|row| [row[0].mul(e), row[1].mul(e)]).collect()
}

// ---------------------------------------------------------------------------
// Prove
// ---------------------------------------------------------------------------

/// Generate NIZKP π for statement (C, g) with witness (m, r).
pub fn prove(w: &Witness, g: &SL2, c_mat: &CommitMatrix, rng: &mut impl rand::RngCore) -> Proof {
    let n = w.n;
    let q = w.q;

    // Prover randomness k, s ← Fq^n  (zeroized after use)
    let mut k = egoc_field::random_vec(n, q, rng);
    let mut s = egoc_field::random_vec(n, q, rng);

    // A = L(k,s)·g
    let k_witness = Witness::new(k.clone(), s.clone());
    let a_lift    = lift(&k_witness);
    let a_rows    = mat_mul_2x2(&a_lift, g);

    // e = FS(C, g, A)
    let e = fiat_shamir_challenge(c_mat, g, &a_rows, q);

    // z_m[i] = k[i] + e * m[i],  z_r[i] = s[i] + e * r[i]
    let z_m: Vec<Fp> = k.iter().zip(w.m.iter()).map(|(ki, mi)| ki.add(e.mul(*mi))).collect();
    let z_r: Vec<Fp> = s.iter().zip(w.r.iter()).map(|(si, ri)| si.add(e.mul(*ri))).collect();

    // Zeroize prover randomness
    k.iter_mut().for_each(|x| x.zeroize());
    s.iter_mut().for_each(|x| x.zeroize());

    Proof { a_rows, z_m, z_r }
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

/// Verify NIZKP π for statement (C_mat, g).
///
/// Checks: L(z_m, z_r)·g  =  A + e·C_mat  (mod q)
pub fn verify_proof(c_mat: &CommitMatrix, g: &SL2, proof: &Proof) -> bool {
    let q = c_mat.q;
    let n = proof.z_m.len();
    if proof.a_rows.len() != 2 * n { return false; }

    // Recompute e = FS(C, g, A)
    let e = fiat_shamir_challenge(c_mat, g, &proof.a_rows, q);

    // LHS: L(z_m, z_r)·g
    let z_witness = Witness::new(proof.z_m.clone(), proof.z_r.clone());
    let lhs_lift  = lift(&z_witness);
    let lhs       = mat_mul_2x2(&lhs_lift, g);

    // RHS: A + e·C_mat
    let ec = mat_scale(&c_mat.rows, e);
    let rhs = mat_add(&proof.a_rows, &ec);

    // Compare
    lhs.iter().zip(rhs.iter()).all(|(l, r)| {
        l[0] == r[0] && l[1] == r[1]
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

    const Q: u64 = 101;
    const N: usize = 4;

    #[test]
    fn prove_verify_roundtrip() {
        let mut rng = StdRng::seed_from_u64(42);
        let w   = Witness::random(N, Q, &mut rng);
        let g   = random_sl2(Q, &mut rng);
        let cmt = commit(&w, &g);
        let pf  = prove(&w, &g, &cmt.matrix, &mut rng);
        assert!(verify_proof(&cmt.matrix, &g, &pf));
    }

    #[test]
    fn wrong_witness_fails() {
        let mut rng = StdRng::seed_from_u64(3);
        let w1  = Witness::random(N, Q, &mut rng);
        let w2  = Witness::random(N, Q, &mut rng);
        let g   = random_sl2(Q, &mut rng);
        let cmt = commit(&w1, &g);
        let pf  = prove(&w2, &g, &cmt.matrix, &mut rng);
        assert!(!verify_proof(&cmt.matrix, &g, &pf));
    }

    #[test]
    fn challenge_deterministic() {
        let mut rng = StdRng::seed_from_u64(7);
        let w   = Witness::random(N, Q, &mut rng);
        let g   = random_sl2(Q, &mut rng);
        let cmt = commit(&w, &g);
        let pf  = prove(&w, &g, &cmt.matrix, &mut rng);
        let e1  = fiat_shamir_challenge(&cmt.matrix, &g, &pf.a_rows, Q);
        let e2  = fiat_shamir_challenge(&cmt.matrix, &g, &pf.a_rows, Q);
        assert_eq!(e1, e2);
        assert!(e1.val() >= 1 && e1.val() < Q);
    }
}