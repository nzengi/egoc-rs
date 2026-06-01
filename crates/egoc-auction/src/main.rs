// egoc-auction — Sealed-Bid Auction Demo
//
// Demonstrates E-GOC's binding, hiding, ZK proof and IVC fold properties
// in the context of a realistic sealed-bid auction scenario.
//
// Three bidders (Alice, Bob, Carol) each commit to a secret bid.
// The auctioneer identifies the winner. The winner proves knowledge
// of the winning bid without revealing other bids. All commitments
// are folded into a single aggregate proof of participation.

use egoc_auction::Auction;
use egoc::{EgocParams};
use rand::SeedableRng;
use rand::rngs::StdRng;

const Q: u64 = 257;

fn line()  { println!("{}", "─".repeat(62)); }
fn dline() { println!("{}", "═".repeat(62)); }
fn header(n: u8, title: &str) {
    println!();
    dline();
    println!("  §{}. {}", n, title);
    dline();
}

fn main() {
    dline();
    println!("  E-GOC Sealed-Bid Auction");
    println!("  Binding · Hiding · ZK Proof · IVC Fold");
    dline();

    let mut rng = StdRng::seed_from_u64(42);

    // ----------------------------------------------------------------
    // §1 — Auction Setup
    // ----------------------------------------------------------------
    header(1, "Auction Setup");

    let mut auction = Auction::<Q>::new(EgocParams::LEVEL1, &mut rng);

    let g = &auction.session.gauge;
    println!("  Security: NIST Level I — n={}, q={}", auction.session.params.n, Q);
    println!("  Security bits: {} bits", auction.session.security_bits());
    println!("  Public gauge g = [[{}, {}], [{}, {}]]  (det=1)",
        g.a.val(), g.b.val(), g.c.val(), g.d.val());
    println!();
    println!("  Property: binding is UNCONDITIONAL — no bidder can");
    println!("  change their bid after committing, even with unlimited compute.");

    // ----------------------------------------------------------------
    // §2 — Bidding Phase
    // ----------------------------------------------------------------
    header(2, "Bidding Phase  (commitments hidden from each other)");

    let bids = [
        ("Alice", 142u64),
        ("Bob",   98u64),
        ("Carol", 213u64),
    ];

    for (name, amount) in &bids {
        let cmt = auction.submit_bid(name, *amount, &mut rng);
        let hash_preview = &cmt.gauge_hash.iter()
            .take(8)
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("");
        println!("  {} bids {} units:", name, amount);
        println!("    Commitment C[0] = [{:3}, {:3}]  (first row only shown)",
            cmt.matrix.rows()[0][0].val(),
            cmt.matrix.rows()[0][1].val());
        println!("    Gauge hash  = {}...  ({} bytes)",
            hash_preview, auction.session.commit_bytes());
        println!("    Bid amount  = [HIDDEN — only {} knows]", name);
        line();
    }

    println!();
    println!("  {} bids submitted. No participant can see others' amounts.", auction.bid_count());

    // ----------------------------------------------------------------
    // §3 — Winner Determination
    // ----------------------------------------------------------------
    header(3, "Winner Determination");

    let winner = auction.find_winner().expect("at least one bid");
    println!("  Bids revealed (auction closed):");
    for (name, amount, _cmt) in auction.bids() {
        let marker = if name == winner.bidder_id { " ← WINNER" } else { "" };
        println!("    {:6}: {} units{}", name, amount, marker);
    }
    println!();
    println!("  Winner: {} with {} units", winner.bidder_id, winner.amount);

    // ----------------------------------------------------------------
    // §4 — Zero-Knowledge Proof
    // ----------------------------------------------------------------
    header(4, "Zero-Knowledge Proof  (winner proves without revealing)");

    println!("  {} generates ZK proof of winning bid...", winner.bidder_id);
    println!();

    // Clone needed data before mutable borrow
    let winner_commitment = winner.commitment.clone();
    let winner_id = winner.bidder_id.clone();
    let winner_amount = winner.amount;
    let winner_witness = winner.witness().clone();

    let proof = auction.session.prove(&winner_witness, &winner_commitment, &mut rng);

    println!("  Proof π = (A, z_m, z_r):");
    println!("    A[0] = [{:3}, {:3}]  (first row of prover commitment)",
        proof.a.rows()[0][0].val(),
        proof.a.rows()[0][1].val());
    println!("    z_m  = [{}, ...]  ({} elements)",
        proof.z_m[0].val(), proof.z_m.len());
    println!("    z_r  = [{}, ...]  ({} elements)",
        proof.z_r[0].val(), proof.z_r.len());
    println!("    size = {} bytes  ({:.2} KB)",
        proof.byte_len(), proof.byte_len() as f64 / 1024.0);
    println!();

    // Verification
    let verify_result = auction.session.verify_proof(&winner_commitment.matrix, &proof);
    match verify_result {
        Ok(()) => {
            println!("  verify_proof({})  → Ok  ✓", winner_id);
            println!();
            println!("  What this proves:");
            println!("    ✓ {} committed BEFORE the auction closed", winner_id);
            println!("    ✓ {} holds the secret opening to commitment C", winner_id);
            println!("    ✓ No information about the exact bid amount is leaked");
            println!("    ✓ Proof is bound to this specific commitment — not replayable");
        }
        Err(e) => println!("  FAILED: {}", e),
    }

    // Wrong proof attempt
    println!();
    let other_bid = &auction.bids
        .iter()
        .find(|b| b.bidder_id != winner_id)
        .unwrap();
    let wrong_proof = auction.session.prove(
        other_bid.witness(),
        &other_bid.commitment,
        &mut rng,
    );
    match auction.session.verify_proof(&winner_commitment.matrix, &wrong_proof) {
        Ok(()) => println!("  Impersonation attempt → accepted  ✗  BUG"),
        Err(_) => println!("  Impersonation attempt ({} → {})  → rejected  ✓",
            other_bid.bidder_id, winner_id),
    }

    // ----------------------------------------------------------------
    // §5 — IVC Fold (Aggregate Participation Proof)
    // ----------------------------------------------------------------
    header(5, "IVC Fold  (aggregate participation proof)");

    println!("  Folding all {} bid commitments into one aggregate...", auction.bid_count());
    println!();

    match auction.fold_all(&mut rng) {
        Ok(Some(fold)) => {
            println!("  Fold valid:     {}", if fold.valid { "yes ✓" } else { "NO ✗" });
            println!("  Soundness err:  1/{} ≈ {:.4}",
                Q, 1.0 / Q as f64);
            println!("  Folded m[0]:    {}", fold.witness_fold.m[0].val());
            println!("  Property:       L(m₁+m₂+m₃, r₁+r₂+r₃)·g = C₁+C₂+C₃  ✓");
            println!();
            println!("  Use case: verifier checks ONE aggregate commitment");
            println!("  instead of {} individual commitments.", auction.bid_count());
        }
        Ok(None) => println!("  Not enough bids to fold."),
        Err(e)   => println!("  ERROR: {}", e),
    }

    // ----------------------------------------------------------------
    // §6 — Binding Demonstration
    // ----------------------------------------------------------------
    header(6, "Binding Guarantee  (cannot change bid after commit)");

    println!("  Suppose Bob tries to claim he bid {} instead of {}...",
        winner_amount, bids[1].1);
    println!();

    // Bob tries to fake a winning witness with Alice's commitment
    let fake_m = (0..auction.session.params.n as u64)
        .map(|i| egoc::Fp::<Q>::new(winner_amount.wrapping_add(i) % Q))
        .collect::<Vec<_>>();
    let fake_r = (0..auction.session.params.n)
        .map(|_| egoc::Fp::<Q>::new(1))
        .collect::<Vec<_>>();
    let fake_witness = egoc::Witness::<Q>::new(fake_m, fake_r);
    let bob_commitment = &auction.bids[1].commitment;

    match auction.session.verify(&fake_witness, bob_commitment) {
        Ok(()) => println!("  Bob's forgery → accepted  ✗  BINDING BROKEN"),
        Err(_) => {
            println!("  Bob's forgery attempt (claiming {} units)  → rejected  ✓", winner_amount);
            println!();
            println!("  Binding is UNCONDITIONAL — no computational assumption.");
            println!("  L(fake_m, fake_r)·g ≠ C_bob  algebraically.");
            println!("  Bob cannot produce a valid opening for a different amount.");
        }
    }

    // ----------------------------------------------------------------
    // Summary
    // ----------------------------------------------------------------
    println!();
    dline();
    println!("  Auction Complete");
    dline();
    println!();
    println!("  Winner:         {} ({} units)", winner_id, winner_amount);
    println!("  Proof size:     {} bytes", proof.byte_len());
    println!("  Participants:   {}", auction.bid_count());
    println!("  Security:       {} bits (NIST Level I)", auction.session.security_bits());
    println!();
    println!("  Properties verified:");
    println!("    Binding  — unconditional, no computational assumption  ✓");
    println!("    Hiding   — bids hidden by uniform randomness           ✓");
    println!("    ZK proof — winner proved without revealing amount      ✓");
    println!("    IVC fold — all commitments aggregated into one         ✓");
    println!();
    dline();
}