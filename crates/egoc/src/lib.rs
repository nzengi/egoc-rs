//! `egoc` — Unified E-GOC session API.
//!
//! # Design
//! `EgocSession<Q>` bundles two things every E-GOC operation needs:
//!   - `params: EgocParams` — message length n and prime q (runtime)
//!   - `gauge:  SL2<Q>`    — the group generator (per-session)
//!
//! Instead of passing `(&Witness, &SL2, &CommitMatrix, &mut rng)` to every
//! function, callers build a session once and call `session.commit(w)`,
//! `session.prove(w, rng)`, `session.verify(w, cmt)`, etc.
//!
//! # Example
//! ```rust,ignore
//! use egoc::{EgocSession, EgocParams};
//! use rand::SeedableRng;
//! use rand::rngs::StdRng;
//!
//! let mut rng = StdRng::seed_from_u64(0);
//! let session = EgocSession::<257>::random(EgocParams::LEVEL1, &mut rng);
//! let witness = session.random_witness(&mut rng);
//! let cmt     = session.commit(&witness);
//! let proof   = session.prove(&witness, &mut rng);
//! assert!(session.verify_proof(&proof).is_ok());
//! ```
//!
//! # Re-exports
//! All sub-crate types are re-exported for single-import convenience.

pub use egoc_commit::{commit as raw_commit, verify as raw_verify,
                      Commitment, CommitMatrix, Witness};
pub use egoc_field::{EgocError, EgocParams, Fp};
pub use egoc_ivc::{ivc_fold, tree_fold, FoldResult, TreeFoldResult};
pub use egoc_proof::{fiat_shamir_challenge, hvzk_simulate, prove as raw_prove,
                     verify_proof as raw_verify_proof, Proof};
pub use egoc_sl2::{random_sl2, SL2};

// ---------------------------------------------------------------------------
// EgocSession<Q>
// ---------------------------------------------------------------------------

/// A session context for E-GOC operations.
///
/// Holds the security parameters and the gauge element.
/// All cryptographic operations on `Witness`, `Commitment`, and `Proof`
/// are available as methods — no need to pass `g` and `params` separately.
///
/// `EgocSession` is cheap to clone (params are 2 u64s; SL2 is 4 Fp<Q> = 32 bytes).
#[derive(Clone, Debug)]
pub struct EgocSession<const Q: u64> {
    /// Security parameters (n, q).  q must equal Q.
    pub params: EgocParams,
    /// Gauge element g ∈ SL(2,Fq).
    pub gauge:  SL2<Q>,
}

impl<const Q: u64> EgocSession<Q> {
    /// Construct with an explicit gauge. Panics if `params.q != Q`.
    pub fn new(params: EgocParams, gauge: SL2<Q>) -> Self {
        assert_eq!(params.q, Q,
            "EgocSession<Q>: params.q={} must equal type parameter Q={}", params.q, Q);
        Self { params, gauge }
    }

    /// Construct with a random gauge element.
    pub fn random(params: EgocParams, rng: &mut impl rand::RngCore) -> Self {
        assert_eq!(params.q, Q,
            "EgocSession<Q>: params.q={} must equal type parameter Q={}", params.q, Q);
        let gauge = random_sl2::<Q>(rng);
        Self { params, gauge }
    }

    /// Sample a random witness for this session's n.
    pub fn random_witness(&self, rng: &mut impl rand::RngCore) -> Witness<Q> {
        Witness::random(self.params.n, rng)
    }

    // -----------------------------------------------------------------------
    // Commitment operations
    // -----------------------------------------------------------------------

    /// Compute commitment C = (L(m,r)·g, H(g)).
    pub fn commit(&self, w: &Witness<Q>) -> Commitment<Q> {
        raw_commit(w, &self.gauge)
    }

    /// Verify a commitment against a witness.
    ///
    /// Returns `Ok(())` if valid.
    pub fn verify(&self, w: &Witness<Q>, cmt: &Commitment<Q>) -> Result<(), EgocError> {
        raw_verify(w, &self.gauge, cmt)
    }

    // -----------------------------------------------------------------------
    // Proof operations
    // -----------------------------------------------------------------------

    /// Generate NIZKP proof for `(w, cmt)`.
    pub fn prove(
        &self,
        w:   &Witness<Q>,
        cmt: &Commitment<Q>,
        rng: &mut impl rand::RngCore,
    ) -> Proof<Q> {
        raw_prove(w, &self.gauge, &cmt.matrix, rng)
    }

    /// Verify NIZKP proof against a commitment matrix.
    ///
    /// Returns `Ok(())` if valid.
    pub fn verify_proof(
        &self,
        c_mat: &CommitMatrix<Q>,
        proof: &Proof<Q>,
    ) -> Result<(), EgocError> {
        raw_verify_proof(c_mat, &self.gauge, proof)
    }

    /// HVZK simulator — generates a simulated transcript without a witness.
    ///
    /// Audit tool only.
    pub fn hvzk_simulate(
        &self,
        c_mat: &CommitMatrix<Q>,
        rng:   &mut impl rand::RngCore,
    ) -> Proof<Q> {
        hvzk_simulate(c_mat, &self.gauge, rng)
    }

    // -----------------------------------------------------------------------
    // IVC operations
    // -----------------------------------------------------------------------

    /// Fold two witnesses using this session's gauge.
    pub fn fold(
        &self,
        w1:  &Witness<Q>,
        w2:  &Witness<Q>,
        rng: &mut impl rand::RngCore,
    ) -> Result<FoldResult<Q>, EgocError> {
        ivc_fold(w1, w2, &self.gauge, rng)
    }

    /// Tree-fold N witnesses using this session's gauge.
    pub fn tree_fold(
        &self,
        witnesses: Vec<Witness<Q>>,
        rng:       &mut impl rand::RngCore,
    ) -> Result<TreeFoldResult<Q>, EgocError> {
        tree_fold(witnesses, &self.gauge, rng)
    }

    // -----------------------------------------------------------------------
    // Convenience: commit + prove in one call
    // -----------------------------------------------------------------------

    /// Commit and immediately prove knowledge — returns `(Commitment, Proof)`.
    pub fn commit_and_prove(
        &self,
        w:   &Witness<Q>,
        rng: &mut impl rand::RngCore,
    ) -> (Commitment<Q>, Proof<Q>) {
        let cmt   = self.commit(w);
        let proof = raw_prove(w, &self.gauge, &cmt.matrix, rng);
        (cmt, proof)
    }

    // -----------------------------------------------------------------------
    // Sizing helpers
    // -----------------------------------------------------------------------

    /// Byte length of a commitment for this session.
    pub fn commit_bytes(&self) -> usize { self.params.commit_bytes() }

    /// Byte length of a proof for this session.
    pub fn proof_bytes(&self) -> usize { self.params.proof_bytes() }

    /// Security level in bits.
    pub fn security_bits(&self) -> u32 { self.params.security_bits() }
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

    fn make_session(seed: u64) -> EgocSession<Q> {
        let params = EgocParams { n: 4, q: Q };
        let mut rng = StdRng::seed_from_u64(seed);
        EgocSession::random(params, &mut rng)
    }

    #[test]
    fn session_commit_verify_roundtrip() {
        let mut rng = StdRng::seed_from_u64(1);
        let session = make_session(0);
        let w       = session.random_witness(&mut rng);
        let cmt     = session.commit(&w);
        assert!(session.verify(&w, &cmt).is_ok());
    }

    #[test]
    fn session_wrong_witness_fails() {
        let mut rng = StdRng::seed_from_u64(2);
        let session = make_session(0);
        let w1      = session.random_witness(&mut rng);
        let w2      = session.random_witness(&mut rng);
        let cmt     = session.commit(&w1);
        assert!(session.verify(&w2, &cmt).is_err());
    }

    #[test]
    fn session_prove_verify_roundtrip() {
        let mut rng = StdRng::seed_from_u64(3);
        let session = make_session(0);
        let w       = session.random_witness(&mut rng);
        let cmt     = session.commit(&w);
        let proof   = session.prove(&w, &cmt, &mut rng);
        assert!(session.verify_proof(&cmt.matrix, &proof).is_ok());
    }

    #[test]
    fn session_commit_and_prove() {
        let mut rng = StdRng::seed_from_u64(4);
        let session = make_session(0);
        let w       = session.random_witness(&mut rng);
        let (cmt, proof) = session.commit_and_prove(&w, &mut rng);
        assert!(session.verify(&w, &cmt).is_ok());
        assert!(session.verify_proof(&cmt.matrix, &proof).is_ok());
    }

    #[test]
    fn session_fold() {
        let mut rng = StdRng::seed_from_u64(5);
        let session = make_session(0);
        let w1      = session.random_witness(&mut rng);
        let w2      = session.random_witness(&mut rng);
        let fold    = session.fold(&w1, &w2, &mut rng).expect("fold ok");
        assert!(fold.valid);
    }

    #[test]
    fn session_tree_fold() {
        let mut rng = StdRng::seed_from_u64(6);
        let session = make_session(0);
        let ws: Vec<Witness<Q>> = (0..8).map(|_| session.random_witness(&mut rng)).collect();
        let result = session.tree_fold(ws, &mut rng).expect("tree ok");
        assert!(result.all_valid);
        assert_eq!(result.depth, 3);
    }

    #[test]
    fn session_hvzk() {
        let mut rng = StdRng::seed_from_u64(7);
        let session = make_session(0);
        let w       = session.random_witness(&mut rng);
        let cmt     = session.commit(&w);
        let sim     = session.hvzk_simulate(&cmt.matrix, &mut rng);
        assert_eq!(sim.a.n(), 4);
    }

    #[test]
    fn session_sizing() {
        let session = make_session(0);
        // n=4, q=101: commit=2*4*2*8=128 bytes, proof=16+48*4=208 bytes
        assert_eq!(session.commit_bytes(), 128);
        assert_eq!(session.proof_bytes(), 208);
    }

    #[test]
    fn session_params_q_mismatch_panics() {
        let result = std::panic::catch_unwind(|| {
            let params = EgocParams { n: 4, q: 257 };
            let mut rng = StdRng::seed_from_u64(0);
            EgocSession::<101>::random(params, &mut rng)
        });
        assert!(result.is_err(), "should panic on q mismatch");
    }
}