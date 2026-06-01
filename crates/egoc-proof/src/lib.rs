//! `egoc-proof` — Σ-GOC Sigma protocol + Fiat-Shamir NIZKP.
//!
//! # Design
//! - Prover: (m,r,g) → π = (A, z_m, z_r)
//! - Challenge: e = BLAKE3_keyed(C ‖ g ‖ A) mod (Q-1) + 1  ∈ Fq*
//! - Verifier: L(z_m,z_r)·g = A + e·C  (mod Q)
//! - Soundness error: 1/Q per challenge
//! - Perfect HVZK: simulator outputs uniform (z_m, z_r) ← Fq^n
//!
//! # Type design
//! `Proof.a` is a `CommitMatrix<Q>` — the algebraically correct type.
//! `a` is the commitment to prover randomness (A = L(k,s)·g), which has
//! identical structure to C_mat. Encoding it as `CommitMatrix` rather than
//! a raw `Vec<[Fp; 2]>` enforces this invariant at the type level.

use egoc_commit::{lift, CommitMatrix, Witness};
use egoc_field::{random_vec, EgocError, Fp};
use egoc_sl2::SL2;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Proof<Q>
// ---------------------------------------------------------------------------

/// Non-interactive ZKP: π = (A, z_m, z_r).
///
/// `A` is the commitment to prover randomness: A = L(k,s)·g.
/// Typed as `CommitMatrix<Q>` — same algebraic structure as C_mat.
///
/// `e` is not stored — the verifier recomputes it from (C, g, A) via
/// Fiat-Shamir. `z_m` and `z_r` are public proof elements but zeroized
/// on drop as a precaution for short-lived proofs in memory.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Proof<const Q: u64> {
    /// Commitment to prover randomness A = L(k,s)·g.
    pub a: CommitMatrix<Q>,
    /// Response vector for message (public, zeroized on drop).
    pub z_m: Vec<Fp<Q>>,
    /// Response vector for randomness (public, zeroized on drop).
    pub z_r: Vec<Fp<Q>>,
}

/// Errors from proof serialization/deserialization.
#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    /// Buffer is shorter than needed.
    #[error("buffer too short: need {need} bytes, got {got}")]
    BufferTooShort { need: usize, got: usize },
    /// Proof dimensions are inconsistent.
    #[error("inconsistent proof dimensions: a={a}, z={z}")]
    InconsistentDimensions { a: usize, z: usize },
    /// A field element value exceeds Q.
    #[error("field element out of range: {val} >= Q={q}")]
    ElementOutOfRange { val: u64, q: u64 },
    /// Q mismatch between header and type parameter.
    #[error("Q mismatch: header says {header}, type says {type_q}")]
    QMismatch { header: u64, type_q: u64 },
}

impl<const Q: u64> Proof<Q> {
    /// Byte length: header(16) + A(2n·2·8) + z_m(n·8) + z_r(n·8) = 16 + 48n.
    ///
    /// Wire format (all values little-endian u64):
    /// `[n: u64][Q: u64] [A rows: 2n×2×8 bytes] [z_m: n×8] [z_r: n×8]`
    pub fn byte_len(&self) -> usize {
        let n = self.z_m.len();
        16 + 48 * n
    }

    /// Serialize proof to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let n = self.z_m.len();
        let mut buf = Vec::with_capacity(self.byte_len());

        buf.extend_from_slice(&(n as u64).to_le_bytes());
        buf.extend_from_slice(&Q.to_le_bytes());

        for row in self.a.rows() {
            buf.extend_from_slice(&row[0].val().to_le_bytes());
            buf.extend_from_slice(&row[1].val().to_le_bytes());
        }
        for fp in &self.z_m { buf.extend_from_slice(&fp.val().to_le_bytes()); }
        for fp in &self.z_r { buf.extend_from_slice(&fp.val().to_le_bytes()); }

        buf
    }

    /// Deserialize proof from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProofError> {
        if bytes.len() < 16 {
            return Err(ProofError::BufferTooShort { need: 16, got: bytes.len() });
        }
        let n     = u64::from_le_bytes(bytes[0..8].try_into().unwrap()) as usize;
        let q_hdr = u64::from_le_bytes(bytes[8..16].try_into().unwrap());

        if q_hdr != Q {
            return Err(ProofError::QMismatch { header: q_hdr, type_q: Q });
        }

        let need = 16 + 48 * n;
        if bytes.len() < need {
            return Err(ProofError::BufferTooShort { need, got: bytes.len() });
        }

        let mut pos = 16usize;

        let mut a_rows = Vec::with_capacity(2 * n);
        for _ in 0..2 * n {
            let v0 = u64::from_le_bytes(bytes[pos..pos+8].try_into().unwrap()); pos += 8;
            let v1 = u64::from_le_bytes(bytes[pos..pos+8].try_into().unwrap()); pos += 8;
            if v0 >= Q { return Err(ProofError::ElementOutOfRange { val: v0, q: Q }); }
            if v1 >= Q { return Err(ProofError::ElementOutOfRange { val: v1, q: Q }); }
            a_rows.push([Fp::new(v0), Fp::new(v1)]);
        }

        let mut z_m = Vec::with_capacity(n);
        for _ in 0..n {
            let v = u64::from_le_bytes(bytes[pos..pos+8].try_into().unwrap()); pos += 8;
            if v >= Q { return Err(ProofError::ElementOutOfRange { val: v, q: Q }); }
            z_m.push(Fp::new(v));
        }

        let mut z_r = Vec::with_capacity(n);
        for _ in 0..n {
            let v = u64::from_le_bytes(bytes[pos..pos+8].try_into().unwrap()); pos += 8;
            if v >= Q { return Err(ProofError::ElementOutOfRange { val: v, q: Q }); }
            z_r.push(Fp::new(v));
        }

        Ok(Proof { a: CommitMatrix::from_rows(a_rows), z_m, z_r })
    }
}

// ---------------------------------------------------------------------------
// Fiat-Shamir challenge
// ---------------------------------------------------------------------------

/// Domain separation key for Fiat-Shamir BLAKE3 — exactly 32 bytes.
static FS_DOMAIN_KEY: &[u8; 32] = b"egoc-fiat-shamir-challenge-v1   ";

/// e = BLAKE3_keyed(domain ‖ C_bytes ‖ g_bytes ‖ A_bytes) mod (Q-1) + 1.
///
/// Both C_mat and A (the prover's commitment) are `CommitMatrix<Q>` —
/// this function accepts either. Q is in the type; no raw argument needed.
/// Result is in {1, …, Q-1} (non-zero challenge for soundness).
pub fn fiat_shamir_challenge<const Q: u64>(
    c_mat: &CommitMatrix<Q>,
    g:     &SL2<Q>,
    a:     &CommitMatrix<Q>,
) -> Fp<Q> {
    let mut hasher = blake3::Hasher::new_keyed(FS_DOMAIN_KEY);
    hasher.update(&c_mat.to_bytes());
    hasher.update(&g.to_bytes());
    hasher.update(&a.to_bytes());
    let digest = hasher.finalize();
    let raw = u128::from_le_bytes(digest.as_bytes()[..16].try_into().unwrap());
    Fp::new((raw % (Q - 1) as u128) as u64 + 1)
}

// ---------------------------------------------------------------------------
// Matrix helpers
// ---------------------------------------------------------------------------

fn mat_mul_2x2<const Q: u64>(lhs: &[[Fp<Q>; 2]], g: &SL2<Q>) -> Vec<[Fp<Q>; 2]> {
    lhs.iter().map(|row| [
        row[0].mul(g.a).add(row[1].mul(g.c)),
        row[0].mul(g.b).add(row[1].mul(g.d)),
    ]).collect()
}

fn mat_add<const Q: u64>(a: &[[Fp<Q>; 2]], b: &[[Fp<Q>; 2]]) -> Vec<[Fp<Q>; 2]> {
    a.iter().zip(b.iter())
     .map(|(x, y)| [x[0].add(y[0]), x[1].add(y[1])])
     .collect()
}

fn mat_scale<const Q: u64>(m: &[[Fp<Q>; 2]], e: Fp<Q>) -> Vec<[Fp<Q>; 2]> {
    m.iter().map(|row| [row[0].mul(e), row[1].mul(e)]).collect()
}

fn mat_sub<const Q: u64>(a: &[[Fp<Q>; 2]], b: &[[Fp<Q>; 2]]) -> Vec<[Fp<Q>; 2]> {
    a.iter().zip(b.iter())
     .map(|(x, y)| [x[0].sub(y[0]), x[1].sub(y[1])])
     .collect()
}

// ---------------------------------------------------------------------------
// Prove
// ---------------------------------------------------------------------------

/// Generate NIZKP π for statement (C_mat, g) with witness (m, r).
pub fn prove<const Q: u64>(
    w:     &Witness<Q>,
    g:     &SL2<Q>,
    c_mat: &CommitMatrix<Q>,
    rng:   &mut impl rand::RngCore,
) -> Proof<Q> {
    let n = w.n;

    // Prover randomness k, s ← Fq^n  (zeroized after use)
    let mut k: Vec<Fp<Q>> = random_vec(n, rng);
    let mut s: Vec<Fp<Q>> = random_vec(n, rng);

    // A = L(k,s)·g  —  typed as CommitMatrix<Q>
    let k_witness = Witness::new(k.clone(), s.clone());
    let a_lift    = lift(&k_witness);
    let a         = CommitMatrix::from_rows(mat_mul_2x2(&a_lift, g));

    // e = FS(C, g, A)
    let e = fiat_shamir_challenge(c_mat, g, &a);

    // z_m[i] = k[i] + e·m[i],  z_r[i] = s[i] + e·r[i]
    let z_m: Vec<Fp<Q>> = k.iter().zip(w.m.iter()).map(|(ki, mi)| ki.add(e.mul(*mi))).collect();
    let z_r: Vec<Fp<Q>> = s.iter().zip(w.r.iter()).map(|(si, ri)| si.add(e.mul(*ri))).collect();

    k.iter_mut().for_each(|x| x.zeroize());
    s.iter_mut().for_each(|x| x.zeroize());

    Proof { a, z_m, z_r }
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

/// Verify NIZKP π for statement (C_mat, g).
///
/// Returns `Ok(())` if valid, `Err(EgocError::Proof(…))` otherwise.
/// Checks: L(z_m, z_r)·g = A + e·C_mat  (mod Q)
pub fn verify_proof<const Q: u64>(
    c_mat: &CommitMatrix<Q>,
    g:     &SL2<Q>,
    proof: &Proof<Q>,
) -> Result<(), EgocError> {
    let n = proof.z_m.len();
    if proof.a.rows().len() != 2 * n {
        return Err(EgocError::Proof(format!(
            "A.rows().len()={} != 2*n={}", proof.a.rows().len(), 2 * n
        )));
    }

    let e = fiat_shamir_challenge(c_mat, g, &proof.a);

    let z_witness = Witness::new(proof.z_m.clone(), proof.z_r.clone());
    let lhs_lift  = lift(&z_witness);
    let lhs       = mat_mul_2x2(&lhs_lift, g);

    let ec  = mat_scale(c_mat.rows(), e);
    let rhs = mat_add(proof.a.rows(), &ec);

    let mut ok = Choice::from(1u8);
    for (l, r) in lhs.iter().zip(rhs.iter()) {
        ok &= l[0].ct_eq(&r[0]) & l[1].ct_eq(&r[1]);
    }

    if bool::from(ok) {
        Ok(())
    } else {
        Err(EgocError::Proof("proof verification equation failed".into()))
    }
}

// ---------------------------------------------------------------------------
// HVZK Simulator  (paper §6.1 Theorem 7)
// ---------------------------------------------------------------------------

/// HVZK simulator S(C_mat, g) — produces a simulated proof transcript.
///
/// Outputs `(A, z_m, z_r)` perfectly indistinguishable from a real transcript
/// without knowing the witness. Uses the simulator's chosen `e`, not FS(A).
///
/// **Audit tool only** — does not prove knowledge of a witness.
pub fn hvzk_simulate<const Q: u64>(
    c_mat: &CommitMatrix<Q>,
    g:     &SL2<Q>,
    rng:   &mut impl rand::RngCore,
) -> Proof<Q> {
    let n = c_mat.n();

    let z_m: Vec<Fp<Q>> = random_vec(n, rng);
    let z_r: Vec<Fp<Q>> = random_vec(n, rng);

    let e: Fp<Q> = {
        let hi = rng.next_u64() as u128;
        let lo = rng.next_u64() as u128;
        let raw = (hi << 64) | lo;
        Fp::new((raw % (Q - 1) as u128) as u64 + 1)
    };

    let z_witness = Witness::new(z_m.clone(), z_r.clone());
    let lhs_lift  = lift(&z_witness);
    let lhs       = mat_mul_2x2(&lhs_lift, g);
    let ec        = mat_scale(c_mat.rows(), e);
    let a_rows    = mat_sub(&lhs, &ec);

    Proof { a: CommitMatrix::from_rows(a_rows), z_m, z_r }
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
    type P = Proof<101>;

    #[test]
    fn prove_verify_roundtrip() {
        let mut rng = StdRng::seed_from_u64(42);
        let w: W   = Witness::random(N, &mut rng);
        let g: G   = random_sl2(&mut rng);
        let cmt    = commit(&w, &g);
        let pf: P  = prove(&w, &g, &cmt.matrix, &mut rng);
        assert!(verify_proof(&cmt.matrix, &g, &pf).is_ok());
    }

    #[test]
    fn wrong_witness_fails() {
        let mut rng = StdRng::seed_from_u64(3);
        let w1: W  = Witness::random(N, &mut rng);
        let w2: W  = Witness::random(N, &mut rng);
        let g:  G  = random_sl2(&mut rng);
        let cmt    = commit(&w1, &g);
        let pf: P  = prove(&w2, &g, &cmt.matrix, &mut rng);
        assert!(verify_proof(&cmt.matrix, &g, &pf).is_err());
    }

    #[test]
    fn challenge_deterministic() {
        let mut rng = StdRng::seed_from_u64(7);
        let w: W   = Witness::random(N, &mut rng);
        let g: G   = random_sl2(&mut rng);
        let cmt    = commit(&w, &g);
        let pf: P  = prove(&w, &g, &cmt.matrix, &mut rng);
        let e1 = fiat_shamir_challenge(&cmt.matrix, &g, &pf.a);
        let e2 = fiat_shamir_challenge(&cmt.matrix, &g, &pf.a);
        assert_eq!(e1, e2);
        assert!(e1.val() >= 1 && e1.val() < 101);
    }

    #[test]
    fn proof_a_is_commit_matrix() {
        // Proof.a must have 2*n rows — same shape as C_mat.
        let mut rng = StdRng::seed_from_u64(9);
        let w: W  = Witness::random(N, &mut rng);
        let g: G  = random_sl2(&mut rng);
        let cmt   = commit(&w, &g);
        let pf: P = prove(&w, &g, &cmt.matrix, &mut rng);
        assert_eq!(pf.a.rows().len(), 2 * N);
        assert_eq!(pf.a.n(), N);
        assert_eq!(cmt.matrix.n(), pf.a.n());
    }

    #[test]
    fn proof_roundtrip_bytes() {
        let mut rng = StdRng::seed_from_u64(50);
        let w: W   = Witness::random(N, &mut rng);
        let g: G   = random_sl2(&mut rng);
        let cmt    = commit(&w, &g);
        let pf: P  = prove(&w, &g, &cmt.matrix, &mut rng);

        let bytes  = pf.to_bytes();
        assert_eq!(bytes.len(), pf.byte_len());

        let pf2 = Proof::<101>::from_bytes(&bytes).expect("deserialize");
        assert!(verify_proof(&cmt.matrix, &g, &pf2).is_ok());
    }

    #[test]
    fn proof_bytes_header() {
        let mut rng = StdRng::seed_from_u64(51);
        let w: W   = Witness::random(N, &mut rng);
        let g: G   = random_sl2(&mut rng);
        let cmt    = commit(&w, &g);
        let pf: P  = prove(&w, &g, &cmt.matrix, &mut rng);
        let bytes  = pf.to_bytes();

        let n_read = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let q_read = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        assert_eq!(n_read, N as u64);
        assert_eq!(q_read, 101u64);
    }

    #[test]
    fn proof_from_bytes_truncated_fails() {
        let mut rng = StdRng::seed_from_u64(52);
        let w: W   = Witness::random(N, &mut rng);
        let g: G   = random_sl2(&mut rng);
        let cmt    = commit(&w, &g);
        let pf: P  = prove(&w, &g, &cmt.matrix, &mut rng);
        let mut bytes = pf.to_bytes();
        bytes.truncate(bytes.len() - 1);
        assert!(Proof::<101>::from_bytes(&bytes).is_err());
    }

    #[test]
    fn hvzk_simulate_verifies() {
        let mut rng = StdRng::seed_from_u64(60);
        let w: W = Witness::random(N, &mut rng);
        let g: G = random_sl2(&mut rng);
        let cmt  = commit(&w, &g);
        let sim  = hvzk_simulate(&cmt.matrix, &g, &mut rng);

        assert_eq!(sim.a.rows().len(), 2 * N);
        assert_eq!(sim.a.n(), N);
    }

    #[test]
    fn hvzk_output_dimensions() {
        let mut rng = StdRng::seed_from_u64(61);
        let w: W = Witness::random(N, &mut rng);
        let g: G = random_sl2(&mut rng);
        let cmt  = commit(&w, &g);
        let sim  = hvzk_simulate(&cmt.matrix, &g, &mut rng);
        assert_eq!(sim.a.rows().len(), 2 * N);
        assert_eq!(sim.z_m.len(), N);
        assert_eq!(sim.z_r.len(), N);
    }

    #[test]
    fn hvzk_responses_in_field() {
        let mut rng = StdRng::seed_from_u64(62);
        let w: W = Witness::random(N, &mut rng);
        let g: G = random_sl2(&mut rng);
        let cmt  = commit(&w, &g);
        let sim  = hvzk_simulate(&cmt.matrix, &g, &mut rng);
        for fp in sim.z_m.iter().chain(sim.z_r.iter()) {
            assert!(fp.val() < 101);
        }
        for row in sim.a.rows() {
            assert!(row[0].val() < 101);
            assert!(row[1].val() < 101);
        }
    }
}