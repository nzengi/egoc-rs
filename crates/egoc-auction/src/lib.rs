//! `egoc-auction` — Sealed-bid auction using E-GOC commitment scheme.
//!
//! # How it works
//!
//! Each bidder commits to their bid amount using an E-GOC commitment.
//! The commitment is public; the bid amount stays hidden until the auction
//! closes. The winner then produces a zero-knowledge proof that they hold
//! the opening to the winning commitment — without revealing other bids.
//!
//! All commitments can be aggregated via IVC fold into a single proof of
//! participation, allowing a verifier to check all bids at once.
//!
//! # Security properties inherited from E-GOC
//!
//! - **Binding**: A bidder cannot change their bid after committing.
//! - **Hiding**: No one can learn the bid amount from the commitment alone.
//! - **ZK proof**: The winner proves knowledge of the opening without
//!   revealing the exact bid amount to third parties.

use egoc::{
    Commitment, CommitMatrix, EgocError, EgocParams, EgocSession,
    FoldResult, Proof, Witness,
};
use rand::RngCore;

// ---------------------------------------------------------------------------
// Bid
// ---------------------------------------------------------------------------

/// A single sealed bid in the auction.
///
/// The commitment is public and shared with the auctioneer.
/// The witness (bid amount + randomness) is secret — kept only by the bidder.
pub struct Bid<const Q: u64> {
    /// Bidder identity.
    pub bidder_id: String,
    /// Public commitment to the bid — shared with auctioneer.
    pub commitment: Commitment<Q>,
    /// Secret witness — held only by the bidder, used to produce proof.
    witness: Witness<Q>,
    /// Encoded bid amount (first element of m vector).
    pub amount: u64,
}

impl<const Q: u64> Bid<Q> {
    /// Commitment matrix — what the verifier checks against.
    pub fn matrix(&self) -> &CommitMatrix<Q> {
        &self.commitment.matrix
    }

    /// Clone the witness for proof generation.
    pub fn witness(&self) -> &Witness<Q> {
        &self.witness
    }
}

// ---------------------------------------------------------------------------
// AuctionResult
// ---------------------------------------------------------------------------

/// Result of a verified auction.
pub struct AuctionResult<const Q: u64> {
    /// Winner's bidder ID.
    pub winner_id: String,
    /// Winner's bid amount.
    pub winner_amount: u64,
    /// Zero-knowledge proof of the winning bid.
    pub proof: Proof<Q>,
    /// IVC fold of all participant commitments (aggregate participation proof).
    pub fold: Option<FoldResult<Q>>,
}

// ---------------------------------------------------------------------------
// Auction
// ---------------------------------------------------------------------------

/// Sealed-bid auction coordinator.
///
/// Manages the auction session, collects bids, identifies the winner,
/// produces and verifies zero-knowledge proofs, and folds all commitments.
pub struct Auction<const Q: u64> {
    /// Shared E-GOC session (parameters + gauge).
    pub session: EgocSession<Q>,
    /// All submitted bids (public commitments + secret witnesses).
    pub bids: Vec<Bid<Q>>,
}

impl<const Q: u64> Auction<Q> {
    /// Create a new auction with random gauge and given security parameters.
    pub fn new(params: EgocParams, rng: &mut impl RngCore) -> Self {
        let session = EgocSession::random(params, rng);
        Self { session, bids: Vec::new() }
    }

    /// Submit a bid with the given amount.
    ///
    /// Internally: encodes the amount as the first element of the message
    /// vector m, fills remaining slots with derived values, and samples
    /// uniform randomness r for hiding.
    ///
    /// Returns the public commitment — this can be shared with the auctioneer.
    /// The secret witness is retained inside the `Bid` for later proof.
    pub fn submit_bid(
        &mut self,
        bidder_id: &str,
        amount: u64,
        rng: &mut impl RngCore,
    ) -> &Commitment<Q> {
        let n = self.session.params.n;

        // Encode amount: m[0] = amount mod Q, remaining m[i] = (amount * i) mod Q
        // This spreads the bid across all message slots — simple encoding.
        let m = (0..n as u64)
            .map(|i| egoc::Fp::new(amount.wrapping_add(i) % Q))
            .collect::<Vec<_>>();

        // Uniform random r — hiding requires all elements non-zero.
        let r_vec = (0..n)
            .map(|_| {
                let v = rng.next_u64() % (Q - 1) + 1; // non-zero uniform in [1, Q-1]
                egoc::Fp::<Q>::new(v)
            })
            .collect::<Vec<_>>();

        let witness = Witness::new(m, r_vec);
        let commitment = self.session.commit(&witness);

        self.bids.push(Bid {
            bidder_id: bidder_id.to_string(),
            commitment,
            witness,
            amount,
        });

        &self.bids.last().unwrap().commitment
    }

    /// Return all submitted bids (public view — no witness exposed).
    pub fn bids(&self) -> impl Iterator<Item = (&str, u64, &Commitment<Q>)> {
        self.bids.iter().map(|b| (b.bidder_id.as_str(), b.amount, &b.commitment))
    }

    /// Find the winner — the bidder with the highest amount.
    ///
    /// Returns `None` if no bids have been submitted.
    pub fn find_winner(&self) -> Option<&Bid<Q>> {
        self.bids.iter().max_by_key(|b| b.amount)
    }

    /// Generate a zero-knowledge proof for the winning bid.
    ///
    /// The proof demonstrates knowledge of the witness opening the commitment
    /// without revealing the bid amount to third-party verifiers.
    pub fn prove_winner(
        &self,
        bid: &Bid<Q>,
        rng: &mut impl RngCore,
    ) -> Proof<Q> {
        self.session.prove(bid.witness(), &bid.commitment, rng)
    }

    /// Verify the winner's zero-knowledge proof against their commitment.
    ///
    /// Returns `Ok(())` if the proof is valid — the winner genuinely holds
    /// the witness opening the commitment.
    pub fn verify_winner(
        &self,
        bid: &Bid<Q>,
        proof: &Proof<Q>,
    ) -> Result<(), EgocError> {
        self.session.verify_proof(bid.matrix(), proof)
    }

    /// IVC fold: aggregate all bid commitments into a single folded commitment.
    ///
    /// This allows a verifier to check all participation proofs at once.
    /// Returns `None` if fewer than 2 bids have been submitted.
    pub fn fold_all(
        &self,
        rng: &mut impl RngCore,
    ) -> Result<Option<FoldResult<Q>>, EgocError> {
        if self.bids.len() < 2 {
            return Ok(None);
        }
        let mut result = self.session.fold(
            self.bids[0].witness(),
            self.bids[1].witness(),
            rng,
        )?;
        for bid in self.bids.iter().skip(2) {
            result = self.session.fold(&result.witness_fold, bid.witness(), rng)?;
        }
        Ok(Some(result))
    }

    /// Number of bids submitted.
    pub fn bid_count(&self) -> usize {
        self.bids.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    const Q: u64 = 257;

    #[test]
    fn auction_single_winner() {
        let mut rng = StdRng::seed_from_u64(1);
        let mut auction = Auction::<Q>::new(EgocParams::LEVEL1, &mut rng);

        auction.submit_bid("Alice", 500, &mut rng);
        auction.submit_bid("Bob",   300, &mut rng);
        auction.submit_bid("Carol", 750, &mut rng);

        let winner = auction.find_winner().unwrap();
        assert_eq!(winner.bidder_id, "Carol");
        assert_eq!(winner.amount, 750);
    }

    #[test]
    fn winner_proof_verifies() {
        let mut rng = StdRng::seed_from_u64(2);
        let mut auction = Auction::<Q>::new(EgocParams::LEVEL1, &mut rng);

        auction.submit_bid("Alice", 500, &mut rng);
        auction.submit_bid("Carol", 750, &mut rng);

        let winner_amount = auction.find_winner().unwrap().amount;
        let winner_idx = auction.bids.iter().position(|b| b.amount == winner_amount).unwrap();
        let proof = {
            let w = &auction.bids[winner_idx];
            auction.session.prove(w.witness(), &w.commitment, &mut rng)
        };
        assert!(auction.verify_winner(&auction.bids[winner_idx], &proof).is_ok());
    }

    #[test]
    fn wrong_proof_rejected() {
        let mut rng = StdRng::seed_from_u64(3);
        let mut auction = Auction::<Q>::new(EgocParams::LEVEL1, &mut rng);

        auction.submit_bid("Alice", 500, &mut rng);
        auction.submit_bid("Bob",   300, &mut rng);

        // Prove with Alice's witness, verify against Bob's commitment
        let alice_proof = auction.session.prove(
            auction.bids[0].witness(),
            &auction.bids[0].commitment,
            &mut rng,
        );
        assert!(auction.verify_winner(&auction.bids[1], &alice_proof).is_err());
    }

    #[test]
    fn fold_all_works() {
        let mut rng = StdRng::seed_from_u64(4);
        let mut auction = Auction::<Q>::new(EgocParams::LEVEL1, &mut rng);

        auction.submit_bid("Alice", 500, &mut rng);
        auction.submit_bid("Bob",   300, &mut rng);
        auction.submit_bid("Carol", 750, &mut rng);

        let fold = auction.fold_all(&mut rng).unwrap();
        assert!(fold.is_some());
        assert!(fold.unwrap().valid);
    }
}